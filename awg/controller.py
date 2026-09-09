"""AWG controller: Unix-only API, durable intent, and bounded kernel operations."""
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import signal
import socketserver
import threading
import time

from model import Store, run, server_config
import ipaddress

STORE = Store(os.getenv('AWG_DATA', '/awg-data'))
CONTROL = Path(os.getenv('AWG_CONTROL', '/awg-control'))
NETWORK = Path(os.getenv('AWG_NETWORK', '/awg-network'))
GUARD = Path('/routing-status/status.json')
APPLY_LOCK = threading.Lock()
STOP = threading.Event()
STATE = {'state': 'starting', 'updated_at': 0}


def atomic(path, content, mode=0o600):
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def guard_ready():
    try:
        state = json.loads(GUARD.read_text())
        return state['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and time.time() - state['updated_at'] < 45
    except (OSError, ValueError, KeyError):
        return False


def prepare_interface(server):
    # These fixed rules retain original VPN source addresses for the host router.
    for table, chain, rules in [
        ('mangle', 'PREROUTING', ['-i', 'wg0', '-j', 'MARK', '--set-xmark', '0xa450/0xffff']),
        ('nat', 'POSTROUTING', ['-m', 'mark', '--mark', '0xa450/0xffff', '-j', 'RETURN']),
        ('filter', 'INPUT', ['-p', 'udp', '-m', 'udp', '--dport', str(server['port']), '-j', 'ACCEPT']),
        ('filter', 'FORWARD', ['-i', 'wg0', '-j', 'ACCEPT']),
        ('filter', 'FORWARD', ['-o', 'wg0', '-j', 'ACCEPT']),
    ]:
        try:
            run('iptables', '-t', table, '-C', chain, *rules)
        except RuntimeError:
            run('iptables', '-t', table, '-I', chain, '1', *rules)
    if 'wg0' not in run('awg', 'show', 'interfaces').split():
        run('ip', 'link', 'add', 'wg0', 'type', 'amneziawg')
    network = ipaddress.IPv4Network(server['ipv4_cidr'], strict=False)
    run('ip', '-4', 'address', 'replace', f'{network.network_address + 1}/{network.prefixlen}', 'dev', 'wg0')
    run('ip', 'link', 'set', 'dev', 'wg0', 'mtu', str(server['mtu']))


def apply():
    with APPLY_LOCK:
        server, _, clients, revision = STORE.snapshot()
        network = str(ipaddress.IPv4Network(server['ipv4_cidr'], strict=False))
        atomic(NETWORK / 'wg-network.json', json.dumps({'cidrs': [network], 'mtus': {network: server['mtu']}}), 0o640)
        if not guard_ready():
            return {'state': 'waiting', 'revision': revision}
        candidate = server_config(server, clients)
        digest = hashlib.sha256(candidate.encode()).hexdigest()
        working = STORE.directory / 'working.conf'
        if STATE.get('digest') != digest or 'wg0' not in run('awg', 'show', 'interfaces').split():
            prepare_interface(server)
            path = STORE.directory / 'candidate.conf'
            atomic(path, candidate)
            try:
                run('awg', 'syncconf', 'wg0', str(path))
                run('ip', 'link', 'set', 'dev', 'wg0', 'up')
            except RuntimeError:
                if working.exists():
                    run('awg', 'syncconf', 'wg0', str(working))
                else:
                    run('ip', 'link', 'set', 'dev', 'wg0', 'down')
                raise
            os.replace(path, working)
        with STORE.db() as con:
            con.execute("UPDATE settings SET value=? WHERE key='applied'", (str(revision),))
        return {'state': 'applied', 'revision': revision, 'digest': digest}


def reconcile():
    global STATE
    while not STOP.is_set():
        try:
            STATE = apply()
        except (OSError, RuntimeError, ValueError, KeyError):
            STATE = {'state': 'error'}
        STATE['updated_at'] = int(time.time())
        atomic(CONTROL / 'status.json', json.dumps({key: value for key, value in STATE.items() if key != 'digest'}), 0o640)
        STOP.wait(1)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # No request bodies, configurations, credentials or peer identities in logs.

    def respond(self, code, value, content_type='application/json'):
        body = (json.dumps(value) if content_type == 'application/json' else value).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def dispatch(self):
        try:
            self.route()
        except KeyError:
            self.respond(404, {'detail': 'Client not found'})
        except (ValueError, TypeError, json.JSONDecodeError):
            self.respond(409, {'detail': 'Invalid or unapplied client operation'})
        except (OSError, RuntimeError):
            self.respond(503, {'detail': 'Controller unavailable'})

    def payload(self):
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 4096:
            raise ValueError('Invalid length')
        return json.loads(self.rfile.read(length))

    def route(self):
        if self.path == '/health' and self.command == 'GET':
            self.respond(200, {key: value for key, value in STATE.items() if key != 'digest'})
            return
        if self.path == '/clients' and self.command == 'GET':
            self.respond(200, STORE.list_clients())
            return
        match = re.fullmatch(r'/clients/([a-zA-Z0-9-]{1,64})(/configuration)?', self.path)
        if not match:
            self.respond(404, {'detail': 'Not found'})
            return
        client_id, suffix = match.groups()
        if self.command == 'GET' and suffix:
            self.respond(200, STORE.configuration(client_id), 'text/plain')
        elif self.command == 'PUT' and not suffix:
            payload = self.payload()
            if not isinstance(payload, dict):
                raise ValueError('Invalid payload')
            name = payload.get('name')
            if not isinstance(name, str) or not 1 <= len(name) <= 100 or set(payload) != {'name'}:
                raise ValueError('Invalid name')
            self.respond(200, STORE.create(client_id, name))
        elif self.command == 'DELETE' and not suffix:
            self.respond(200, STORE.delete(client_id))
        elif self.command == 'PATCH' and not suffix:
            self.respond(200, STORE.configure(client_id, self.payload()))
        else:
            self.respond(405, {'detail': 'Method not allowed'})

    do_GET = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch
    do_PATCH = dispatch


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(20)
        return connection, address


def main():
    STORE.initialize()
    for directory in [CONTROL, NETWORK]:
        directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    socket_path = CONTROL / 'control.sock'
    socket_path.unlink(missing_ok=True)
    with Server(str(socket_path), Handler) as server:
        os.chmod(socket_path, 0o660)
        threading.Thread(target=reconcile, daemon=True).start()
        server.timeout = 1
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, lambda *_: STOP.set())
        while not STOP.is_set():
            server.handle_request()


if __name__ == '__main__':
    main()
