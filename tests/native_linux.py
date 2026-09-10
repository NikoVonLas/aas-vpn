"""Isolated Docker/Linux tunnel checks. Only generated disposable keys are used."""
from contextlib import closing
from http.client import HTTPConnection
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awg.model import Store

IMAGE = os.getenv('AWG_TEST_IMAGE', 'aas-vpn-awg:native-test')
NETWORK = 'aas-native-check'
SERVER = 'aas-native-check-server'
CLIENTS = ['aas-native-check-one', 'aas-native-check-two']
CAPS = ['/usr/sbin/capsh', '--inh=cap_net_admin,cap_net_raw', '--addamb=cap_net_admin,cap_net_raw', '--shell=/bin/sh', '--', '-c']


def docker(*args, input=None, check=True):
    result = subprocess.run(['docker', *args], input=input, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise RuntimeError('Docker test operation failed: ' + ' '.join(args[:3]))
    return result


class UnixHTTP(HTTPConnection):
    def __init__(self, path):
        super().__init__('controller', timeout=10)
        self.socket_path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(self.socket_path)


class Check:
    def __init__(self, root):
        self.root = root
        self.store = Store(root/'data')

    def guard(self, valid=True):
        data = {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip() if valid else 'previous-boot', 'updated_at': int(time.time())}
        (self.root/'guard/status.json').write_text(json.dumps(data))
        os.chmod(self.root/'guard/status.json', 0o644)

    def api(self, method, path, data=None):
        with closing(UnixHTTP(self.root/'control/control.sock')) as connection:
            connection.request(method, path, json.dumps(data) if data is not None else None)
            response = connection.getresponse()
            body = response.read().decode()
            if response.status != 200:
                raise RuntimeError('Controller test request failed')
            return body if path.endswith('/configuration') else json.loads(body)

    def until(self, predicate, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.guard()
            try:
                if predicate():
                    return
            except (OSError, RuntimeError):
                pass
            time.sleep(1)
        raise RuntimeError('Native Linux acceptance check timed out')

    def ping(self, client, success=True):
        result = docker('exec', client, *CAPS, 'exec ping -c 1 -W 2 10.91.0.1', check=False)
        return (result.returncode == 0) == success

    def start(self):
        for directory in ['data', 'control', 'network', 'guard']:
            path = self.root/directory
            path.mkdir()
            os.chown(path, 1000, 65532)
            os.chmod(path, 0o750)
        docker('network', 'create', '--internal', NETWORK)
        self.guard()
        docker('run', '--rm', '--network', 'none', '-v', f'{self.root}/data:/awg-data', '--entrypoint', 'python', IMAGE,
               'bootstrap.py', '--endpoint', SERVER, '--public-port', '1234', '--network', '10.91.0.0/24', '--dns', '192.0.2.53')
        docker('run', '-d', '--name', SERVER, '--network', NETWORK, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
               '-v', f'{self.root}/data:/awg-data', '-v', f'{self.root}/control:/awg-control',
               '-v', f'{self.root}/network:/awg-network', '-v', f'{self.root}/guard:/routing-status:ro', IMAGE)
        self.until(lambda: self.api('GET', '/health')['state'] == 'applied')
        docker('run', '--rm', '--network', 'none', '--cap-drop', 'ALL', '--user', '65532:65532',
               '-v', f'{self.root}/control:/awg-control:ro', '--entrypoint', 'python',
               os.getenv('PORTAL_TEST_IMAGE', 'aas-vpn-portal:native-test'), '-c',
               "import httpx; c=httpx.Client(transport=httpx.HTTPTransport(uds='/awg-control/control.sock'), base_url='http://controller'); assert c.get('/health').json()['state']=='applied'")
        print('Unprivileged portal connects through read-only socket mount: passed', flush=True)
        for index, client in enumerate(CLIENTS):
            client_id = 'test-' + str(index)
            self.api('PUT', '/clients/'+client_id, {'name':client})
            self.until(lambda: self.api('PUT', '/clients/'+client_id, {'name':client})['applied'])
            configuration = self.api('GET', '/clients/'+client_id+'/configuration')
            docker('run', '-d', '--name', client, '--network', NETWORK, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
                   '-v', f'{ROOT}/tests:/checks:ro', '--entrypoint', CAPS[0], IMAGE, *CAPS[1:], 'exec sleep 600')
            address = json.loads(docker('inspect', SERVER).stdout)[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
            ipaddress.IPv4Address(address)
            docker('exec', '-i', client, *CAPS, 'exec python /checks/native_peer.py',
                   input=json.dumps({'configuration':configuration, 'endpoint':address+':1234', 'server':'10.91.0.1'}))
            self.until(lambda: self.ping(client))
        print('Two independent native AWG clients: passed', flush=True)

    def checks(self):
        with self.store.db() as con:
            original = self.store.setting(con, 'server')
            broken = {**original, 'h1':'invalid-header'}
            con.execute("UPDATE settings SET value=? WHERE key='server'", (json.dumps(broken),))
            self.store.bump(con)
        self.until(lambda: self.api('GET', '/health')['state'] == 'error')
        assert all(self.ping(client) for client in CLIENTS)
        with self.store.db() as con:
            con.execute("UPDATE settings SET value=? WHERE key='server'", (json.dumps(original),))
            self.store.bump(con)
        self.until(lambda: self.api('GET', '/health')['state'] == 'applied')
        print('Invalid configuration rollback: passed', flush=True)
        self.api('DELETE', '/clients/test-0')
        self.until(lambda: self.api('DELETE', '/clients/test-0')['applied'])
        assert self.ping(CLIENTS[0], False) and self.ping(CLIENTS[1])
        docker('restart', SERVER)
        self.until(lambda: self.api('GET', '/health')['state'] == 'applied')
        self.until(lambda: self.ping(CLIENTS[1]))
        assert self.ping(CLIENTS[0], False)
        print('Deletion and controller restart preserve peer state: passed', flush=True)
        self.guard(False)
        docker('restart', SERVER)
        time.sleep(3)
        assert self.ping(CLIENTS[1], False)
        self.until(lambda: self.api('GET', '/health')['state'] == 'applied')
        self.until(lambda: self.ping(CLIENTS[1]))
        print('Stale boot guard blocks startup; recovery: passed', flush=True)


def main():
    for name in [SERVER, *CLIENTS]:
        if docker('inspect', name, check=False).returncode == 0:
            raise SystemExit('A test container already exists; inspect it before rerunning')
    root = Path(tempfile.mkdtemp(prefix='aas-native-linux-'))
    try:
        check = Check(root)
        check.start()
        check.checks()
    finally:
        for name in [SERVER, *CLIENTS]:
            docker('rm', '-f', name, check=False)
        docker('network', 'rm', NETWORK, check=False)
        shutil.rmtree(root)


if __name__ == '__main__':
    main()
