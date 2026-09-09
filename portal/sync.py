"""Read-only wg-easy snapshot; never exports WireGuard keys."""
import ipaddress
import json
import os
import sqlite3
import time

from routing import atomic_json, changed

SOURCE = os.getenv('WG_DB', '/wg-easy/wg-easy.db')
TARGET = os.getenv('WG_AUTH_SNAPSHOT', '/data/wg-auth.json')
PORTAL_DB = os.getenv('PORTAL_DB', '/data/portal.db')


def snapshot():
    con = sqlite3.connect(f'file:{SOURCE}?mode=ro', uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        con.execute('BEGIN')
        user = con.execute('SELECT id,username,password,totp_key,totp_verified,enabled FROM users_table WHERE role=1 ORDER BY id LIMIT 1').fetchone()
        general = con.execute('SELECT session_password,session_timeout FROM general_table WHERE id=1').fetchone()
        networks = [str(ipaddress.IPv4Network(r[0], strict=False)) for r in con.execute('SELECT ipv4_cidr FROM interfaces_table')]
        clients = con.execute('SELECT id,ipv4_address FROM clients_table').fetchall()
    finally:
        con.close()
    atomic_json(os.path.join(os.path.dirname(TARGET), 'wg-network.json'), {'cidrs': networks}, 0o640)
    if user and general:
        data = {
            'user_id': user['id'], 'username': user['username'], 'password_hash': user['password'],
            'totp_key': user['totp_key'], 'totp_verified': user['totp_verified'], 'enabled': user['enabled'],
            'session_password': general['session_password'], 'session_timeout': general['session_timeout'],
            'synced_at': int(time.time()),
        }
        atomic_json(TARGET, data, 0o640)
    # Only update portal-owned records; external wg-easy clients never get imported.
    mapping = {str(c['id']): str(ipaddress.IPv4Address(c['ipv4_address'])) for c in clients}
    with sqlite3.connect(PORTAL_DB, timeout=5) as portal:
        portal.execute('BEGIN IMMEDIATE')
        for device_id, client_id, old_ip in portal.execute('SELECT id,wg_client_id,vpn_ip FROM devices').fetchall():
            new_ip = mapping.get(client_id)
            if new_ip != old_ip:
                portal.execute('UPDATE devices SET vpn_ip=? WHERE id=?', (new_ip, device_id))
                changed(portal)


def main():
    while True:
        try:
            snapshot()
        except (OSError, ValueError, sqlite3.Error):
            print('auth sync waiting for databases', flush=True)
        time.sleep(15)


if __name__ == '__main__':
    main()
