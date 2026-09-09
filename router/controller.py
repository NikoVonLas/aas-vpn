"""Host-network routing supervisor. Logs deliberately exclude config/check output."""
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import time

from routing import atomic_json, compile_config, effective_exit

DATA = Path(os.getenv('PORTAL_DATA', '/data'))
STATE = Path('/routing-status')
WORK = Path('/router-state')
BASE = Path('/etc/sing-box/config.json')
CONFIGS = '/ru-configs'
AWG_IP = os.getenv('AWG_CONTAINER_IP', '10.42.42.45')
VPN_CIDR = os.getenv('VPN_CLIENT_CIDR', '')
process = None
stopping = False


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, **kwargs)


def network_guard():
    """Persist across process/container restarts; never remove the fail-closed rule."""
    route = json.loads(run('ip', '-j', 'route', 'get', AWG_IP).stdout)[0]
    bridge = route['dev']
    if not (Path('/sys/class/net') / bridge / 'bridge').exists():
        raise ValueError('AWG route is not a Docker bridge')
    bridge_network = str(ipaddress.ip_network(os.getenv('VPN_DOCKER_CIDR', '10.42.42.0/24')))
    # Prevent forwarding *any* un-NATed traffic from this bridge directly to WAN.
    # Also catch old SNAT flows from wg-easy during upgrades.
    check = subprocess.run(['nft', 'list', 'table', 'inet', 'aas_guard'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    prefix = 'delete table inet aas_guard\n' if check.returncode == 0 else ''
    rules = prefix + f'''table inet aas_guard {{
      chain forward {{ type filter hook forward priority -10; policy accept;
        iifname "{bridge}" ip saddr {AWG_IP} ip daddr != {bridge_network} oifname != "sbtun0" drop
        iifname "{bridge}" ip saddr != {bridge_network} oifname != "sbtun0" ip daddr != {bridge_network} drop
        iifname "{bridge}" meta nfproto ipv6 drop
      }}
    }}\n'''
    run('nft', '-f', '-', input=rules.encode())
    # Loose reverse-path validation is required for intercepted traffic.
    # Docker mounts /proc/sys read-only in a host-network container. Deploy sets
    # these host sysctls; inspect them here instead of attempting a forbidden write.
    values = [int(Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').read_text()) for name in ['all', bridge]]
    if max(values) == 1:
        raise ValueError('Set host net.ipv4.conf.all.rp_filter=2 before starting router')
    return bridge


def sync_network_routes(bridge):
    """Read actual wg-easy subnets; never guess or replace a connected RU route."""
    network_file = DATA / 'wg-network.json'
    networks = json.loads(network_file.read_text())['cidrs'] if network_file.exists() else [VPN_CIDR] if VPN_CIDR else []
    if not networks:
        raise ValueError('Waiting for wg-easy network snapshot')
    connected = json.loads(run('ip', '-j', '-4', 'route', 'show', 'scope', 'link').stdout)
    networks = [ipaddress.IPv4Network(network) for network in networks]
    protected = [ipaddress.IPv4Network(route['dst']) for route in connected if 'dst' in route]
    protected.append(ipaddress.IPv4Network(os.getenv('VPN_DOCKER_CIDR', '10.42.42.0/24')))
    if any(network.overlaps(other) for network in networks for other in protected):
        raise ValueError('VPN subnet overlaps a connected host network')
    for network in networks:
        run('ip', 'route', 'replace', str(network), 'via', AWG_IP, 'dev', bridge)


def snapshot():
    con = sqlite3.connect(f'file:{DATA}/portal.db?mode=ro', uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        settings = {r['key']: r['value'] for r in con.execute("SELECT key,value FROM settings WHERE key IN ('ru_default','routing_revision')")}
        return dict(exits=[dict(r) for r in con.execute('SELECT * FROM ru_exits')],
                    devices=[dict(r) for r in con.execute('SELECT id,vpn_ip,ru_exit_id FROM devices')],
                    rules=[dict(r) for r in con.execute('SELECT * FROM routing_rules')],
                    default=int(settings['ru_default']), revision=int(settings['routing_revision']))
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


def apply(config):
    candidate, good = WORK / 'candidate.json', WORK / 'working.json'
    atomic_json(candidate, config)
    run('sing-box', 'check', '-c', str(candidate))
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
                             '--noproxy', '', 'https://1.1.1.1/cdn-cgi/trace'],
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


def main():
    os.umask(0o077)
    STATE.mkdir(exist_ok=True); WORK.mkdir(exist_ok=True)
    os.chmod(STATE, 0o755)
    bridge = network_guard()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    health, fingerprints = {}, {}
    applied, signature, active, active_base = 0, None, None, None
    installed_health = {}
    model_path = WORK / 'working-model.json'
    try:
        model = json.loads(model_path.read_text())
        active, active_base = model['snapshot'], model['base']
        applied = active['revision']
        fingerprints = {n['id']: n.get('config_file') for n in active['exits']}
    except (OSError, ValueError, KeyError):
        pass
    last_probe = 0
    while not stopping:
        state, desired = 'pending', None
        try:
            sync_network_routes(bridge)
            if process and process.poll() is None and time.monotonic() - last_probe >= 15:
                # Health follows the installed config, even while a new config is rejected.
                nodes = (active or {}).get('exits', [])
                last_probe = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
                    results = list(pool.map(probe, [n['id'] for n in nodes]))
                for node, ok in zip(nodes, results):
                    key = str(node['id'])
                    health[key] = advance(health.get(key, {}), ok)
            desired = snapshot()
            base = json.loads(BASE.read_text())
            candidate_health = {}
            for node in desired['exits']:
                key = str(node['id'])
                candidate_health[key] = health.get(key, {}) if node['id'] in fingerprints and fingerprints[node['id']] == node.get('config_file') else {}
            healthy = {key: value.get('healthy', False) for key, value in candidate_health.items()}
            config = compile_config(base, desired['exits'], desired['devices'], desired['rules'], desired['default'], healthy, bridge, CONFIGS)
            digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
            if digest != signature or not process or process.poll() is not None:
                apply(config)
                signature = digest
            applied, active, active_base = desired['revision'], desired, base
            installed_health, health = healthy, candidate_health
            fingerprints = {n['id']: n.get('config_file') for n in active['exits']}
            atomic_json(model_path, {'snapshot': active, 'base': active_base})
            state = 'applied'
        except (OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError, RuntimeError):
            state = 'error' if active or desired else 'pending'
            # Rebuild the accepted model with fresh health. Bad edits must not disable
            # failover, including after the controller itself has restarted.
            if active:
                try:
                    healthy = {key: value.get('healthy', False) for key, value in health.items()}
                    config = compile_config(active_base, active['exits'], active['devices'], active['rules'], active['default'], healthy, bridge, CONFIGS)
                    digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
                    if digest != signature or not process or process.poll() is not None:
                        apply(config)
                        signature = digest
                    installed_health = healthy
                except (OSError, ValueError, KeyError, subprocess.SubprocessError, RuntimeError):
                    pass
            # No exception text or sing-box output: both can contain secrets.
        running = bool(process and process.poll() is None)
        devices = {}
        if active:
            for device in active['devices']:
                assigned = device['ru_exit_id'] or active['default']
                effective = effective_exit(device['ru_exit_id'], active['default'], installed_health) if device['vpn_ip'] and running else None
                devices[str(device['id'])] = {'effective': effective, 'fallback': effective is not None and effective != assigned}
        atomic_json(STATE / 'status.json', {'state': state, 'boot_id': boot_id, 'running': running,
                                          'applied_revision': applied, 'updated_at': int(time.time()),
                                          'exits': health, 'devices': devices}, 0o644)
        delay = min(3, max(0.1, 15 - (time.monotonic() - last_probe))) if running else 3
        deadline = time.monotonic() + delay
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    stop_child()


def shutdown(signum, frame):
    global stopping
    stopping = True


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    main()
