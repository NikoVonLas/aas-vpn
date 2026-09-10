"""Stopped-stack migration. Dry-run by default; never prints private source data."""
import argparse
import base64
import configparser
import hashlib
import json
import ipaddress
from pathlib import Path
import sqlite3
import sys

from auth import Auth

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from awg.model import Store, array, client_config, server_config


INSERT_SETTING = 'INSERT INTO settings VALUES(?,?)'


def read_source(source):
    con = sqlite3.connect(Path(source).resolve().as_uri() + '?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        result = {table: [dict(row) for row in con.execute(f'SELECT * FROM {table}')] for table in
                  ['interfaces_table', 'users_table', 'clients_table', 'user_configs_table', 'general_table', 'hooks_table', 'one_time_links_table']}
    finally:
        con.close()
    return result


def key_valid(value):
    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_source(data):
    require(len(data['interfaces_table']) == 1 and len(data['user_configs_table']) == 1, 'Exactly one configured interface is required')
    server = data['interfaces_table'][0]
    require(server['name'] == 'wg0' and server['enabled'], 'An enabled wg0 interface is required')
    require(not server.get('firewall_enabled'), 'Per-client firewall requires a reviewed migration')
    require(server.get('routing_table') in (None, '', 'auto', 'off'), 'Custom routing table requires a reviewed migration')
    require(not data['one_time_links_table'], 'Active one-time links require a reviewed migration')
    require(key_valid(server['private_key']) and key_valid(server['public_key']), 'Invalid interface keys')
    validate_hooks(data['hooks_table'])
    network = ipaddress.IPv4Network(server['ipv4_cidr'], strict=False)
    admins = [row for row in data['users_table'] if row['role'] == 1]
    require(any(row['enabled'] and row['password'] for row in admins), 'An enabled password administrator is required')
    require(all(not row['enabled'] or row['password'] for row in admins), 'OAuth-only administrators require an explicit credential migration')
    require(all(not row['totp_verified'] or row['totp_key'] for row in admins), 'Invalid TOTP state')
    addresses, keys = set(), set()
    for client in data['clients_table']:
        address = ipaddress.IPv4Address(client['ipv4_address'])
        require(address in network and address not in {network.network_address, network.network_address + 1, network.broadcast_address}, 'Invalid client address')
        require(not any(client.get(field) for field in ['pre_up', 'post_up', 'pre_down', 'post_down']), 'Client hooks require a reviewed migration')
        require(not array(client.get('firewall_ips')), 'Client firewall requires a reviewed migration')
        require(not array(client.get('server_allowed_ips')), 'Additional client routes require a reviewed migration')
        require(all(key_valid(client[field]) for field in ['private_key', 'public_key', 'pre_shared_key']), 'Invalid client keys')
        require(client['ipv4_address'] not in addresses and client['public_key'] not in keys, 'Duplicate client identity')
        addresses.add(client['ipv4_address'])
        keys.add(client['public_key'])
    server_config(server, data['clients_table'])
    for client in data['clients_table']:
        client_config(server, data['user_configs_table'][0], client)
    return admins


def validate_hooks(rows):
    require(len(rows) == 1, 'Exactly one hook configuration is required')
    hooks = rows[0]
    require(not hooks.get('pre_up') and not hooks.get('pre_down'), 'Custom interface hooks require review')
    for field, operation in [('post_up', '-A'), ('post_down', '-D')]:
        allowed = {
            f'iptables -t nat {operation} POSTROUTING -s {{{{ipv4Cidr}}}} -o {{{{device}}}} -j MASQUERADE',
            f'iptables {operation} INPUT -p udp -m udp --dport {{{{port}}}} -j ACCEPT',
            f'iptables {operation} FORWARD -i wg0 -j ACCEPT',
            f'iptables {operation} FORWARD -o wg0 -j ACCEPT',
        }
        statements = {statement.strip() for statement in (hooks.get(field) or '').split(';') if statement.strip()}
        require(statements <= allowed, 'Custom interface hooks require review')


def compare_configs(data, reference):
    configs = json.loads(Path(reference).read_text())
    require(set(configs) == {str(peer['id']) for peer in data['clients_table']}, 'Reference client set differs')
    for peer in data['clients_table']:
        expected, actual = (configparser.ConfigParser(interpolation=None) for _ in range(2))
        expected.read_string(configs[str(peer['id'])])
        actual.read_string(client_config(data['interfaces_table'][0], data['user_configs_table'][0], peer))
        require({section: dict(expected[section]) for section in expected} == {section: dict(actual[section]) for section in actual},
                'Generated client configuration differs from legacy API')
    return len(configs)


def migration(source, portal_path, auth_path, target, apply=False, reference=None):
    data = read_source(source)
    admins = validate_source(data)
    compared = compare_configs(data, reference) if reference else 0
    fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    con = sqlite3.connect(Path(portal_path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        columns = {row[1] for row in con.execute('PRAGMA table_info(devices)')}
        client_column = 'wg_client_id' if 'wg_client_id' in columns else 'client_id'
        links = con.execute(f'SELECT id,{client_column} FROM devices').fetchall()
        phones = con.execute('SELECT count(*) FROM users').fetchone()[0]
        old_secret = con.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()
    finally:
        con.close()
    ids = {str(client['id']) for client in data['clients_table']}
    require(all(str(client_id) in ids for _, client_id in links), 'Portal has orphaned client references')
    report = {'admins': len(admins), 'phone_accounts': phones, 'clients': len(ids), 'linked': len(links), 'unowned': len(ids) - len(links), 'configs_compared': compared}
    if not apply:
        return {**report, 'mode': 'dry-run'}
    store = Store(target)
    store.initialize()
    with store.db() as native:
        existing = native.execute("SELECT value FROM settings WHERE key='migration_source'").fetchone()
        if existing:
            require(json.loads(existing[0]) == fingerprint, 'Source changed since migration; refusing to overwrite native data')
        else:
            require(native.execute('SELECT count(*) FROM clients').fetchone()[0] == 0, 'Native data already exists')
            native.execute(INSERT_SETTING, ('server', json.dumps(data['interfaces_table'][0])))
            native.execute(INSERT_SETTING, ('defaults', json.dumps(data['user_configs_table'][0])))
            for client in data['clients_table']:
                client['id'] = str(client['id'])
                native.execute('INSERT INTO clients(id,address,public_key,data,revision) VALUES(?,?,?,?,0)',
                               (client['id'], client['ipv4_address'], client['public_key'], json.dumps(client)))
            native.execute(INSERT_SETTING, ('migration_source', json.dumps(fingerprint)))
    auth = Auth(auth_path)
    auth.initialize(old_secret[0] if old_secret else None)
    with auth.db() as credentials:
        marker = credentials.execute("SELECT value FROM settings WHERE key='migration_source'").fetchone()
        if not marker:
            require(credentials.execute('SELECT count(*) FROM admins').fetchone()[0] == 0, 'Native administrators already exist')
            for admin in admins:
                credentials.execute('INSERT INTO admins(id,username,password_hash,totp_key,totp_verified,enabled) VALUES(?,?,?,?,?,?)',
                                    tuple(admin[key] for key in ['id', 'username', 'password', 'totp_key', 'totp_verified', 'enabled']))
            credentials.execute("UPDATE settings SET value=? WHERE key='remember_seconds'", (str(data['general_table'][0]['session_timeout']),))
            credentials.execute(INSERT_SETTING, ('migration_source', fingerprint))
        else:
            require(marker[0] == fingerprint, 'Authentication migration source changed')
    return {**report, 'mode': 'migrated' if not existing else 'already-migrated'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--reference', action='store_true', help='Compare the private legacy API export mounted at /reference.json')
    args = parser.parse_args()
    try:
        print(json.dumps(migration('/legacy/wg-easy.db', '/data/portal.db', '/auth/auth.db', '/awg-data', args.apply, '/reference.json' if args.reference else None)))
    except (ValueError, KeyError, sqlite3.Error, OSError):
        raise SystemExit('Migration validation failed. Source data was retained; inspect schema and compatibility using the dry-run tests.') from None


if __name__ == '__main__':
    main()
