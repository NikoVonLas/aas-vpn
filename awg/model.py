"""Native client storage and deterministic AWG configuration generation."""
from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import subprocess

PARAMS = {'Jc': 'j_c', 'Jmin': 'j_min', 'Jmax': 'j_max', **{f'S{i}': f's{i}' for i in range(1, 5)},
          **{f'H{i}': f'h{i}' for i in range(1, 5)}, **{f'I{i}': f'i{i}' for i in range(1, 6)}}
PUBLIC = ('id', 'name', 'ipv4_address', 'enabled', 'expires_at', 'created_at')


def run(*args, input=None):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError('AWG command failed')
    return result.stdout.strip()


def array(value):
    return json.loads(value) if isinstance(value, str) else (value or [])


def line(name, value):
    value = str(value)
    if any(character in value for character in '\r\n\x00'):
        raise ValueError('Invalid configuration value')
    return f'{name} = {value}'


def parameters(data):
    return [line(name, data[field]) for name, field in PARAMS.items() if data.get(field)]


def active(client, now=None):
    if not client.get('enabled', 1):
        return False
    expiration = client.get('expires_at')
    if not expiration:
        return True
    expiry = datetime.fromisoformat(expiration.replace('Z', '+00:00'))
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.timestamp() > (datetime.now(timezone.utc).timestamp() if now is None else now)


def client_config(server, defaults, client):
    awg = {**client, **{key: server.get(key) for key in PARAMS.values() if key.startswith(('s', 'h'))}}
    rows = ['[Interface]', line('PrivateKey', client['private_key']), line('Address', client['ipv4_address'] + '/32'),
            line('MTU', client['mtu'])]
    dns = array(client.get('dns') if client.get('dns') is not None else defaults['default_dns'])
    if dns:
        rows.append(line('DNS', ', '.join(dns)))
    rows.extend(parameters(awg))
    rows.extend(['', '[Peer]', line('PublicKey', server['public_key']), line('PresharedKey', client['pre_shared_key']),
                 line('AllowedIPs', ', '.join(array(client.get('allowed_ips') if client.get('allowed_ips') is not None else defaults['default_allowed_ips']))),
                 line('PersistentKeepalive', client['persistent_keepalive']), line('Endpoint', f"{defaults['host']}:{defaults['port']}")])
    return '\n'.join(rows) + '\n'


def server_config(server, clients):
    rows = ['[Interface]', line('PrivateKey', server['private_key']), line('ListenPort', server['port']), *parameters(server)]
    for client in clients:
        if not active(client):
            continue
        addresses = [client['ipv4_address'] + '/32', *array(client.get('server_allowed_ips'))]
        rows.extend(['', '[Peer]', line('PublicKey', client['public_key']), line('PresharedKey', client['pre_shared_key']),
                     line('AllowedIPs', ', '.join(addresses))])
        if client.get('server_endpoint'):
            rows.append(line('Endpoint', client['server_endpoint']))
    return '\n'.join(rows) + '\n'


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = self.directory / 'native.db'

    @contextmanager
    def db(self):
        con = sqlite3.connect(self.path, timeout=20)
        con.row_factory = sqlite3.Row
        try:
            con.execute('BEGIN IMMEDIATE')
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as con:
            con.executescript('''
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS retired_ids(id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS clients(
                    id TEXT PRIMARY KEY, address TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
                    data TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL);
                INSERT OR IGNORE INTO settings VALUES('revision','0');
                INSERT OR IGNORE INTO settings VALUES('applied','-1');
            ''')
        os.chmod(self.path, 0o600)

    @staticmethod
    def setting(con, key):
        row = con.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        if not row:
            raise ValueError('Controller has not been initialized')
        return json.loads(row[0])

    @staticmethod
    def bump(con):
        con.execute("UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='revision'")
        return Store.setting(con, 'revision')

    def snapshot(self):
        with self.db() as con:
            return (self.setting(con, 'server'), self.setting(con, 'defaults'),
                    [json.loads(row[0]) for row in con.execute('SELECT data FROM clients WHERE deleted=0 ORDER BY id')],
                    self.setting(con, 'revision'))

    def result(self, con, row):
        data = json.loads(row['data'])
        return {**{key: data.get(key) for key in PUBLIC}, 'ipv4Address': row['address'],
                'applied': row['revision'] <= self.setting(con, 'applied'), 'deleted': bool(row['deleted'])}

    def create(self, client_id, name):
        with self.db() as con:
            if con.execute('SELECT 1 FROM retired_ids WHERE id=?', (client_id,)).fetchone():
                raise ValueError('Client was deleted')
            row = con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if row:
                if row['deleted']:
                    raise ValueError('Client was deleted')
                return self.result(con, row)
            server, defaults = self.setting(con, 'server'), self.setting(con, 'defaults')
            network = ipaddress.IPv4Network(server['ipv4_cidr'], strict=False)
            used = {row[0] for row in con.execute('SELECT address FROM clients')}
            used.add(str(network.network_address + 1))
            address = next((str(ip) for ip in network.hosts() if str(ip) not in used), None)
            if not address:
                raise ValueError('Address pool exhausted')
            private_key = run('awg', 'genkey')
            data = {'id': client_id, 'name': name, 'ipv4_address': address, 'private_key': private_key,
                    'public_key': run('awg', 'pubkey', input=private_key + '\n'), 'pre_shared_key': run('awg', 'genpsk'),
                    'enabled': 1, 'expires_at': None, 'created_at': datetime.now(timezone.utc).isoformat(),
                    'mtu': defaults['default_mtu'], 'persistent_keepalive': defaults['default_persistent_keepalive'],
                    'dns': None, 'allowed_ips': None, 'server_allowed_ips': None, 'server_endpoint': None}
            for key in ['j_c', 'j_min', 'j_max', 'i1', 'i2', 'i3', 'i4', 'i5']:
                data[key] = defaults.get('default_' + key)
            revision = self.bump(con)
            con.execute('INSERT INTO clients(id,address,public_key,data,revision) VALUES(?,?,?,?,?)',
                        (client_id, address, data['public_key'], json.dumps(data), revision))
            return self.result(con, con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone())

    def delete(self, client_id):
        with self.db() as con:
            con.execute('INSERT OR IGNORE INTO retired_ids VALUES(?)', (client_id,))
            row = con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone()
            if not row:
                return {'applied': True, 'deleted': True}
            if not row['deleted']:
                revision = self.bump(con)
                con.execute('UPDATE clients SET deleted=1,revision=? WHERE id=?', (revision, client_id))
            return self.result(con, con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone())

    def list_clients(self):
        with self.db() as con:
            return [self.result(con, row) for row in con.execute('SELECT * FROM clients WHERE deleted=0 ORDER BY id')]

    def configure(self, client_id, settings):
        if not isinstance(settings, dict) or not settings or not set(settings) <= {'enabled', 'expires_at'}:
            raise ValueError('Invalid client settings')
        if 'enabled' in settings and not isinstance(settings['enabled'], bool):
            raise ValueError('Invalid enabled state')
        expiration = settings.get('expires_at')
        if expiration is not None:
            if not isinstance(expiration, str):
                raise ValueError('Invalid expiration')
            datetime.fromisoformat(expiration.replace('Z', '+00:00'))
        with self.db() as con:
            row = con.execute('SELECT * FROM clients WHERE id=? AND deleted=0', (client_id,)).fetchone()
            if not row:
                raise KeyError('Client not found')
            data = json.loads(row['data'])
            if any(data.get(key) != value for key, value in settings.items()):
                data.update(settings)
                revision = self.bump(con)
                con.execute('UPDATE clients SET data=?,revision=? WHERE id=?', (json.dumps(data), revision, client_id))
            return self.result(con, con.execute('SELECT * FROM clients WHERE id=?', (client_id,)).fetchone())

    def configuration(self, client_id):
        with self.db() as con:
            row = con.execute('SELECT * FROM clients WHERE id=? AND deleted=0', (client_id,)).fetchone()
            if not row:
                raise KeyError('Client not found')
            if not self.result(con, row)['applied']:
                raise ValueError('Configuration not applied')
            return client_config(self.setting(con, 'server'), self.setting(con, 'defaults'), json.loads(row['data']))
