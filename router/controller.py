"""Host-network routing supervisor. Logs deliberately exclude config/check output."""
import concurrent.futures
from functools import lru_cache
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import secrets
import sqlite3
import subprocess
import time
import urllib.request

from routing import atomic_json, compile_config, effective_exit

DATA = Path(os.getenv('PORTAL_DATA', '/data'))
STATE = Path('/routing-status')
WORK = Path('/router-state')
BASE = Path('/etc/sing-box/config.json')
CONFIGS = '/ru-configs'
AWG_IP = str(ipaddress.IPv4Address(os.environ['AWG_CONTAINER_IP']))
DOCKER_CIDR = str(ipaddress.IPv4Network(os.environ['VPN_DOCKER_CIDR']))
VPN_CIDR = os.getenv('VPN_CLIENT_CIDR', '')
process = None
stopping = False
CONTROL_ADDRESS = '127.0.0.1:19090'
CONTROL_URL = 'http://127.0.0.1:19090'


def event(name, **fields):
    # Only caller-supplied IDs/state are logged, never configs or subprocess output.
    print(json.dumps({'time': int(time.time()), 'event': name, **fields}), flush=True)


def configure_control_api(config):
    path = WORK / 'controller-api-secret'
    try:
        secret = path.read_text().strip()
        if len(secret) != 64 or any(c not in '0123456789abcdef' for c in secret):
            raise ValueError('invalid controller API secret')
    except FileNotFoundError:
        secret = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secret)
    os.chmod(path, 0o600)
    config.setdefault('experimental', {}).setdefault('clash_api', {}).update({
        'external_controller': CONTROL_ADDRESS, 'secret': secret,
        'access_control_allow_origin': ['http://127.0.0.1'],
        'access_control_allow_private_network': False})
    return secret


def select_outbound(tag, target, secret):
    request = urllib.request.Request(f'{CONTROL_URL}/proxies/{tag}',
        data=json.dumps({'name': target}).encode(), method='PUT',
        headers={'Authorization': f'Bearer {secret}', 'Content-Type': 'application/json'})
    # The controller must always talk to the loopback API, never an env proxy.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as response:
        if response.status != 204:
            raise RuntimeError('selector update failed')


def sync_selectors(config, health, selected, secret):
    for outbound in config.get('outbounds', []):
        if outbound.get('type') != 'selector' or not outbound['tag'].startswith('ru-policy-'):
            continue
        target = next((tag for tag in outbound['outbounds'] if tag.startswith('ru-')
                       and health.get(tag[3:], False)), 'ru-unavailable')
        tag = outbound['tag']
        if selected.get(tag, 'ru-unavailable') != target:
            select_outbound(tag, target, secret)
            event('selector_changed', selector=tag, previous=selected.get(tag, 'ru-unavailable'), target=target)
            selected[tag] = target


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, **kwargs)


def network_guard():
    """Persist across process/container restarts; never remove the fail-closed rule."""
    route = json.loads(run('ip', '-j', 'route', 'get', AWG_IP).stdout)[0]
    bridge = route['dev']
    if not (Path('/sys/class/net') / bridge / 'bridge').exists():
        raise ValueError('AWG route is not a Docker bridge')
    bridge_network = str(ipaddress.ip_network(DOCKER_CIDR))
    # Prevent forwarding *any* un-NATed traffic from this bridge directly to WAN.
    # Also catch old SNAT flows from wg-easy during upgrades.
    check = subprocess.run(['nft', 'list', 'table', 'inet', 'aas_guard'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    prefix = 'delete table inet aas_guard\n' if check.returncode == 0 else ''
    rules = prefix + f'''table inet aas_guard {{
      chain forward {{ type filter hook forward priority -10; policy accept;
        iifname "{bridge}" ip saddr {AWG_IP} udp sport 1234 ct direction reply ct status dnat counter accept comment "aas-awg-encrypted-replies"
        iifname "{bridge}" ip saddr {AWG_IP} ip daddr != {bridge_network} oifname != "sbtun0" drop
        iifname "{bridge}" ip saddr != {bridge_network} oifname != "sbtun0" ip daddr != {bridge_network} drop
        iifname "{bridge}" meta nfproto ipv6 drop
      }}
    }}\n'''
    # Docker DNAT preserves public client addresses. Its encrypted tunnel replies
    # must reach WAN before the guard rejects direct forwarding of inner traffic.
    # Reply direction plus DNAT status excludes client-initiated outbound flows.
    run('nft', '-f', '-', input=rules.encode())
    # Loose reverse-path validation is required for intercepted traffic.
    # Docker mounts /proc/sys read-only in a host-network container. Deploy sets
    # these host sysctls; inspect them here instead of attempting a forbidden write.
    values = [int(Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text()) for name in ['all', bridge]]
    if max(values) == 1:
        raise ValueError('Set host net.ipv4.conf.all.rp_filter=2 before starting router')
    return bridge


def sync_network_routes(bridge):
    """Read actual controller subnets; never guess or replace a connected RU route."""
    network_file = Path(os.getenv('AWG_NETWORK_FILE', '/awg-network/wg-network.json'))
    networks = [VPN_CIDR] if VPN_CIDR else []
    mtus = {}
    if network_file.exists():
        network_state = json.loads(network_file.read_text())
        networks, mtus = network_state['cidrs'], network_state.get('mtus', {})
    if not networks:
        raise ValueError('Waiting for AWG network snapshot')
    connected = json.loads(run('ip', '-j', '-4', 'route', 'show', 'scope', 'link').stdout)
    networks = [ipaddress.IPv4Network(network) for network in networks]
    protected = [ipaddress.IPv4Network(route['dst']) for route in connected if 'dst' in route]
    protected.append(ipaddress.IPv4Network(DOCKER_CIDR))
    if any(network.overlaps(other) for network in networks for other in protected):
        raise ValueError('VPN subnet overlaps a connected host network')
    for network in networks:
        mtu = int(mtus.get(str(network), 0))
        metrics = ['mtu', str(mtu)] if 576 <= mtu <= 9000 else []
        run('ip', 'route', 'replace', str(network), 'via', AWG_IP, 'dev', bridge, *metrics)


def snapshot():
    con = sqlite3.connect(f'file:{DATA}/portal.db?mode=ro', uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        settings = {r['key']: r['value'] for r in con.execute("SELECT key,value FROM settings WHERE key IN ('ru_default','routing_revision')")}
        return {'exits': [dict(r) for r in con.execute('SELECT * FROM ru_exits')],
                'devices': [dict(r) for r in con.execute('''SELECT d.id,d.vpn_ip,d.ru_exit_id,d.account_id,
                    u.ru_exit_id account_ru_exit_id FROM devices d LEFT JOIN users u ON u.account_id=d.account_id''')],
                'rules': [dict(r) for r in con.execute('SELECT * FROM routing_rules')] +
                         [dict(r) for r in con.execute('SELECT * FROM scoped_routing_rules')],
                'default': int(settings['ru_default']), 'revision': int(settings['routing_revision'])}
    finally:
        con.close()


def stop_child():
    global process
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
    process = None


def start_child(path):
    global process
    process = subprocess.Popen(['sing-box', 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    if process.poll() is not None:
        raise RuntimeError('start failed')
    event('router_started', pid=process.pid)


def apply(config):
    candidate, good = WORK / 'candidate.json', WORK / 'working.json'
    atomic_json(candidate, config)
    run('sing-box', 'check', '-c', str(candidate))
    event('router_reconfigure')
    stop_child()
    try:
        start_child(candidate)
    except RuntimeError:
        stop_child()
        if good.exists():
            start_child(good)
        raise
    atomic_json(good, config)


def probe(node_id):
    # This dedicated inbound routes directly through the node, never its fallback.
    result = subprocess.run(['curl', '--silent', '--fail', '--max-time', '5',
                             '--proxy', f'socks5h://127.0.0.1:{19000 + node_id}',
                             '--noproxy', '', 'https://one.one.one.one/cdn-cgi/trace'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=7)
    return result.returncode == 0


def advance(previous, ok):
    previous = dict(previous)
    previous['successes'] = previous.get('successes', 0) + 1 if ok else 0
    previous['failures'] = 0 if ok else previous.get('failures', 0) + 1
    if previous['successes'] >= 2:
        previous['healthy'] = True
    if previous['failures'] >= 2:
        previous['healthy'] = False
    return previous


@lru_cache(maxsize=2048)
def endpoint_transport(host, _minute):
    """Refresh DNS/route selection each minute, including VPN-reachable peers."""
    try:
        try:
            address = str(ipaddress.IPv4Address(host))
        except ValueError:
            result = subprocess.run(['getent', 'hosts', host], capture_output=True, text=True, check=True, timeout=2)
            address = str(ipaddress.IPv4Address(result.stdout.split()[0]))
        route = json.loads(run('ip', '-j', 'route', 'get', address, 'mark', '0x2024').stdout)[0]
        metrics = [metric['mtu'] for metric in route.get('metrics', []) if 'mtu' in metric]
        mtu = min(metrics) if metrics else json.loads(run('ip', '-j', 'link', 'show', 'dev', route['dev']).stdout)[0]['mtu']
        # Leave room for outer IP, UDP and WireGuard, including nested tunnels.
        return {'address': address, 'interface': route['dev'], 'mtu': max(576, min(1408, mtu - 80))}
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        return None


def bind_endpoint_interfaces(config, previous=None):
    """Pin resolved peers so DNS changes participate in the applied signature."""
    hosts = {peer['address'] for endpoint in config.get('endpoints', [])
             for peer in endpoint.get('peers', []) if peer.get('address')}
    minute = int(time.monotonic() // 60)
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        bindings = dict(zip(hosts, pool.map(lambda host: endpoint_transport(host, minute), hosts)))
    if previous is not None:
        bindings = {host: path or previous.get(host) for host, path in bindings.items()}
        previous.clear()
        previous.update(bindings)
    for endpoint in config.get('endpoints', []):
        paths = [bindings[peer['address']] for peer in endpoint.get('peers', []) if bindings.get(peer.get('address'))]
        for peer in endpoint.get('peers', []):
            path = bindings.get(peer.get('address'))
            if path:
                peer['address'] = path['address']
        interfaces = {path['interface'] for path in paths}
        if len(interfaces) == 1:
            endpoint['bind_interface'] = interfaces.pop()
        if paths and 'mtu' not in endpoint:
            endpoint['mtu'] = min(path['mtu'] for path in paths)


APPLY_ERRORS = (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError, RuntimeError)


class Supervisor:
    def __init__(self, bridge):
        self.bridge = bridge
        self.health = {}
        self.fingerprints = {}
        self.applied = 0
        self.signature = None
        self.compiled_key = None
        self.compiled = None
        self.active = None
        self.active_base = None
        self.installed_health = {}
        self.endpoint_bindings = {}
        self.selected = {}
        self.model_path = WORK / 'working-model.json'
        self.last_probe = 0
        try:
            model = json.loads(self.model_path.read_text())
            self.active, self.active_base = model['snapshot'], model['base']
            self.applied = self.active['revision']
            self.fingerprints = self.config_fingerprints(self.active)
        except (OSError, ValueError, KeyError):
            pass

    @staticmethod
    def config_fingerprints(model):
        return {node['id']: node.get('config_file') for node in model['exits']}

    def probe_nodes(self):
        if not process or process.poll() is not None or time.monotonic() - self.last_probe < 15:
            return
        nodes = (self.active or {}).get('exits', [])
        self.last_probe = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            results = list(pool.map(probe, [node['id'] for node in nodes]))
        for node, ok in zip(nodes, results):
            key = str(node['id'])
            previous = self.health.get(key, {})
            self.health[key] = advance(previous, ok)
            if previous.get('healthy') != self.health[key].get('healthy'):
                event('exit_health_changed', exit_id=node['id'], healthy=self.health[key].get('healthy', False))

    def candidate_health(self, desired):
        result = {}
        for node in desired['exits']:
            key = str(node['id'])
            unchanged = node['id'] in self.fingerprints and self.fingerprints[node['id']] == node.get('config_file')
            result[key] = self.health.get(key, {}) if unchanged else {}
        return result

    def install(self, base, model, health):
        healthy = {key: value.get('healthy', False) for key, value in health.items()}
        key = (model['revision'], json.dumps(base, sort_keys=True), self.bridge)
        if key != self.compiled_key:
            self.compiled = compile_config(base, model['exits'], model['devices'], model['rules'], model['default'], healthy, self.bridge, CONFIGS, live_selectors=True)
            self.compiled_key = key
        config = json.loads(json.dumps(self.compiled))
        bind_endpoint_interfaces(config, self.endpoint_bindings)
        secret = configure_control_api(config)
        digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        if digest != self.signature or not process or process.poll() is not None:
            apply(config)
            self.signature = digest
            self.selected.clear()
        sync_selectors(config, healthy, self.selected, secret)
        self.installed_health = healthy

    def restore(self):
        # Recompute failover even while edits are rejected or after a restart.
        if self.active:
            try:
                self.install(self.active_base, self.active, self.health)
            except APPLY_ERRORS:
                pass

    def reconcile(self):
        desired = None
        try:
            sync_network_routes(self.bridge)
            self.probe_nodes()
            desired = snapshot()
            base = json.loads(BASE.read_text())
            health = self.candidate_health(desired)
            self.install(base, desired, health)
            self.applied, self.active, self.active_base = desired['revision'], desired, base
            self.health = health
            self.fingerprints = self.config_fingerprints(self.active)
            atomic_json(self.model_path, {'snapshot': self.active, 'base': self.active_base})
            return 'applied'
        except APPLY_ERRORS as error:
            event('reconcile_failed', error_type=type(error).__name__)
            self.restore()
            return 'error' if self.active or desired else 'pending'

    def device_states(self, running):
        devices = {}
        if not self.active:
            return devices
        for device in self.active['devices']:
            assigned = device['ru_exit_id'] or device.get('account_ru_exit_id') or self.active['default']
            effective = None
            if device['vpn_ip'] and running:
                effective = effective_exit(device['ru_exit_id'], self.active['default'], self.installed_health, device.get('account_ru_exit_id'))
            devices[str(device['id'])] = {'effective': effective, 'fallback': effective is not None and effective != assigned}
        return devices

    def publish(self, state, boot_id):
        running = bool(process and process.poll() is None)
        atomic_json(STATE / 'status.json', {'state': state, 'boot_id': boot_id, 'running': running,
                                          'applied_revision': self.applied, 'updated_at': int(time.time()),
                                          'exits': self.health, 'devices': self.device_states(running)}, 0o640)
        return running

    def wait(self, running):
        delay = min(3, max(0.1, 15 - (time.monotonic() - self.last_probe))) if running else 3
        deadline = time.monotonic() + delay
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))


def main():
    os.umask(0o077)
    STATE.mkdir(exist_ok=True)
    WORK.mkdir(exist_ok=True)
    os.chmod(STATE, 0o750)
    supervisor = Supervisor(network_guard())
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    while not stopping:
        state = supervisor.reconcile()
        running = supervisor.publish(state, boot_id)
        supervisor.wait(running)
    stop_child()


def shutdown(signum, frame):
    global stopping
    stopping = True


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    main()
