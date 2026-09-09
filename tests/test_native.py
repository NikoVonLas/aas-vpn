import base64
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import time

import httpx
import pyotp
import pytest

from conftest import ROOT, admin_login, phone_login, post
from auth import Auth
from migrate_native import migration, read_source, validate_source
from awg.model import Store, active, client_config, server_config
import awg.model as model


def key(number):
    return base64.b64encode(bytes([number]) * 32).decode()


def legacy_source(tmp_path, portal):
    app, _ = portal
    source = tmp_path / 'legacy.db'
    server = dict(name='wg0', device='eth0', ipv4_cidr='10.8.0.0/24', ipv6_cidr='fd00::/64', mtu=1280, port=1234,
                  private_key=key(1), public_key=key(2), enabled=1, firewall_enabled=0, routing_table='auto',
                  j_c=4, j_min=40, j_max=70, s1=15, s2=20, s3=0, s4=0, h1='100', h2='200', h3='300', h4='400')
    defaults = dict(default_dns='["10.42.42.44"]', default_allowed_ips='["0.0.0.0/0", "::/0"]', host='vpn.example.test', port=443,
                    default_mtu=1280, default_persistent_keepalive=25, default_j_c=4, default_j_min=40, default_j_max=70)
    admins = [dict(id=1, username='admin', password=app.password_hasher.hash('test-password'), role=1, enabled=1, totp_key=None, totp_verified=0),
              dict(id=2, username='second', password=app.password_hasher.hash('second-password'), role=1, enabled=1, totp_key=pyotp.random_base32(), totp_verified=1)]
    peers = [dict(id=number, name='Legacy device', ipv4_address=f'10.8.0.{number-39}', private_key=key(number), public_key=key(number+10), pre_shared_key=key(number+20),
                  expires_at=None, enabled=1, mtu=1280, persistent_keepalive=25, dns=None, allowed_ips=None,
                  server_allowed_ips=None, server_endpoint=None, pre_up='', post_up='', pre_down='', post_down='', firewall_ips=None,
                  j_c=4, j_min=40, j_max=70, created_at='2026-01-01T00:00:00Z') for number in [41,42]]
    tables = {'interfaces_table':[server], 'user_configs_table':[defaults], 'users_table':admins, 'clients_table':peers,
              'general_table':[dict(session_timeout=3600)], 'hooks_table':[dict(pre_up='', post_up='', pre_down='', post_down='')],
              'one_time_links_table':[]}
    with sqlite3.connect(source) as con:
        for table, rows in tables.items():
            columns = list(rows[0]) if rows else ['id']
            con.execute(f'CREATE TABLE {table} (' + ','.join(columns) + ')')
            for row in rows:
                con.execute(f'INSERT INTO {table} VALUES(' + ','.join('?' for _ in columns) + ')', list(row.values()))
    with app.db() as con:
        con.execute("INSERT INTO settings VALUES('session_secret',?)", (app.auth_store.setting('phone_secret'),))
    return source, server, defaults, peers, admins


def test_migration_preserves_all_admins_clients_and_repeat(tmp_path, portal):
    app, _ = portal
    source, server, defaults, peers, admins = legacy_source(tmp_path, portal)
    target = tmp_path / 'native'
    auth_path = tmp_path / 'private/auth.db'
    args = (source, app.DB, auth_path, target)
    assert migration(*args)['clients'] == 2
    assert not target.exists()
    assert migration(*args, apply=True)['admins'] == 2
    store = Store(target)
    assert store.snapshot()[:3] == (server, defaults, [{**peer, 'id': str(peer['id'])} for peer in peers])
    imported = Auth(auth_path)
    assert imported.setting('phone_secret') == app.auth_store.setting('phone_secret')
    token, _ = imported.login('second', 'second-password', pyotp.TOTP(admins[1]['totp_key']).now(), 'test')
    assert imported.session(token)['id'] == 2
    with imported.db() as con:
        con.execute("UPDATE admins SET username='new-name' WHERE id=1")
    assert migration(*args, apply=True)['mode'] == 'already-migrated'
    with imported.db() as con:
        assert con.execute('SELECT username FROM admins WHERE id=1').fetchone()[0] == 'new-name'
    assert auth_path.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(source) as con:
        con.execute("UPDATE clients_table SET name='Changed'")
    with pytest.raises(ValueError, match='Source changed'):
        migration(*args, apply=True)


def test_migration_rejects_orphans_and_unknown_features(tmp_path, portal):
    app, _ = portal
    source, *_ = legacy_source(tmp_path, portal)
    with sqlite3.connect(source) as con:
        con.execute("UPDATE clients_table SET post_up='unexpected hook'")
    with pytest.raises(ValueError, match='hooks'):
        validate_source(read_source(source))
    with sqlite3.connect(source) as con:
        con.execute("UPDATE clients_table SET post_up=''")
        con.execute('DELETE FROM clients_table WHERE id=42')
    with pytest.raises(ValueError, match='orphaned'):
        migration(source, app.DB, tmp_path/'auth', tmp_path/'native')


def test_native_retries_reserve_keys_and_addresses(tmp_path, portal, monkeypatch):
    app, _ = portal
    source, *_ = legacy_source(tmp_path, portal)
    migration(source, app.DB, tmp_path/'credentials/auth.db', tmp_path/'native', True)
    store = Store(tmp_path/'native')
    calls = []
    def fake_run(*args, **kwargs):
        calls.append(args)
        return key(100 + len(calls))
    monkeypatch.setattr(model, 'run', fake_run)
    created = store.create('new-client', 'Phone')
    assert not created['applied'] and created['ipv4Address'] == '10.8.0.4'
    assert store.create('new-client', 'Retry') == created
    assert len(calls) == 3
    with pytest.raises(ValueError, match='not applied'):
        store.configuration('new-client')
    with store.db() as con:
        con.execute("UPDATE settings SET value='1' WHERE key='applied'")
    config = store.configuration('new-client')
    assert 'MTU = 1280' in config and 'Endpoint = vpn.example.test:443' in config
    assert store.delete('new-client')['applied'] is False
    assert store.delete('new-client')['applied'] is False
    with pytest.raises(ValueError, match='deleted'):
        store.create('new-client', 'Do not resurrect')
    next_client = store.create('another', 'Tablet')
    assert next_client['ipv4Address'] == '10.8.0.5'
    assert key(101) not in json.dumps(store.list_clients())


def test_config_uses_exact_legacy_values_and_expiry(tmp_path, portal):
    _, server, defaults, peers, _ = legacy_source(tmp_path, portal)
    text = client_config(server, defaults, peers[0])
    assert f'PrivateKey = {peers[0]["private_key"]}' in text
    assert f'PublicKey = {server["public_key"]}' in text
    assert 'AllowedIPs = 0.0.0.0/0, ::/0' in text
    assert 'Address = 10.8.0.2/32' in text and 'S1 = 15' in text
    assert 'DNS = 10.42.42.44' in text and 'Jc = 4' in text
    peers[0]['expires_at'] = '2000-01-01T00:00:00Z'
    assert not active(peers[0])
    assert peers[0]['public_key'] not in server_config(server, peers)
    peers[1]['enabled'] = 0
    assert '[Peer]' not in server_config(server, peers)


def test_admin_management_reauth_last_admin_and_revocation(portal):
    app, client = portal
    admin_login(app, client)
    route = '/admin/administrators'
    assert client.get(route).status_code == 200
    assert post(client, route+'/1', {'action':'toggle', 'password':'test-password'}).status_code == 400
    assert post(client, route, {'username':'new', 'new_password':'temporary-password', 'password':'wrong'}).status_code == 400
    assert post(client, route, {'username':'new', 'new_password':'temporary-password', 'password':'test-password'}).status_code == 303
    assert post(client, '/admin/logout').status_code == 303
    assert post(client, '/admin/login', {'username':'new','password':'temporary-password'}).headers['location'] == route
    assert client.get('/admin').headers['location'] == route
    assert post(client, '/admin/user', {'name':'No', 'phone':'+79990000001', 'device_limit':'5'}).headers['location'] == route
    assert post(client, route+'/2', {'action':'password','password':'temporary-password','new_password':'permanent-password'}).status_code == 303
    assert client.get('/admin').headers['location'] == '/admin/login'
    assert post(client, '/admin/login', {'username':'new','password':'permanent-password'}).status_code == 303
    token = client.cookies.get(app.auth.COOKIE)
    assert post(client, route+'/1', {'action':'toggle','password':'permanent-password'}).status_code == 303
    assert app.auth_store.session(token)['id'] == 2
    assert post(client, route+'/2', {'action':'toggle','password':'permanent-password'}).status_code == 400
    phone_login(app, client)
    assert client.get(route).status_code == 303
    assert post(client, route, {'username':'denied','new_password':'temporary-password','password':'test-password'}).status_code == 303


def test_totp_replay_and_throttling(portal):
    app, _ = portal
    secret = pyotp.random_base32()
    with app.auth_store.db() as con:
        con.execute('UPDATE admins SET totp_key=?,totp_verified=1', (secret,))
    code = pyotp.TOTP(secret).now()
    token, _ = app.auth_store.login('admin', 'test-password', code, 'test')
    assert app.auth_store.session(token)
    with pytest.raises(ValueError, match='Неверный'):
        app.auth_store.login('admin', 'test-password', code, 'test')
    for _ in range(9):
        with pytest.raises(ValueError):
            app.auth_store.login('admin', 'incorrect', '', 'test')
    with pytest.raises(ValueError, match='Слишком много'):
        app.auth_store.login('admin', 'incorrect', '', 'test')


def test_portal_pending_creation_recovers_without_new_identity(portal, monkeypatch):
    app, client = portal
    admin_login(app, client)
    identities = []
    ready = False
    def api(request):
        identities.append(request.url.path)
        if not ready:
            raise httpx.ReadTimeout('Timed out')
        return httpx.Response(200, json={'applied':True, 'ipv4Address':'10.8.0.4'})
    monkeypatch.setattr(app, 'wg_session', lambda: httpx.AsyncClient(transport=httpx.MockTransport(api), base_url='http://controller'))
    assert post(client, '/device', {'name':'Pending', 'phone':'+79990000001'}).status_code == 303
    with app.db() as con:
        row = con.execute("SELECT * FROM devices WHERE name='Pending'").fetchone()
        assert row['operation'] == 'create'
    assert client.get(f'/device/{row["id"]}/config').status_code == 409
    ready = True
    client.portal.call(app.process_device_operations)
    with app.db() as con:
        assert con.execute('SELECT operation FROM devices WHERE id=?', (row['id'],)).fetchone()[0] == 'applied'
    assert len(set(identities)) == 1


def test_totp_enrollment_and_unowned_permissions(portal, monkeypatch):
    app, client = portal
    admin_login(app, client)
    path = '/admin/administrators'
    assert post(client, path+'/1', {'action':'totp-start','password':'test-password'}).status_code == 303
    with app.auth_store.db() as con:
        secret = con.execute('SELECT pending_totp FROM admins WHERE id=1').fetchone()[0]
    assert secret not in client.get(path).text
    assert client.get(path+'/totp/qr').headers['content-type'] == 'image/png'
    assert post(client, path+'/totp/confirm', {'totp':'wrong'}).status_code == 400
    assert post(client, path+'/totp/confirm', {'totp':pyotp.TOTP(secret).now()}).status_code == 303
    assert client.get('/admin').headers['location'] == '/admin/login'
    admin_login(app, client)
    rows = [{'id':'999','name':'Imported','ipv4Address':'10.8.0.9','applied':True}]
    monkeypatch.setattr(app, 'wg_session', lambda: httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=rows)), base_url='http://controller'))
    assert 'Imported' in client.get('/admin/unowned').text
    assert post(client, '/admin/unowned/999/assign', {'phone':'+79990000001'}).status_code == 303
    assert 'Imported' not in client.get('/admin/unowned').text
    phone_login(app, client)
    assert client.get('/admin/unowned').status_code == 303
    assert post(client, '/admin/unowned/999/assign', {'phone':'+79990000002'}).status_code == 303


def test_native_disable_and_expiration_configuration(tmp_path, portal):
    app, _ = portal
    source, *_ = legacy_source(tmp_path, portal)
    migration(source, app.DB, tmp_path/'credentials/auth.db', tmp_path/'native', True)
    store = Store(tmp_path/'native')
    result = store.configure('41', {'enabled':False})
    assert not result['applied']
    _, _, clients, revision = store.snapshot()
    assert not active(next(peer for peer in clients if peer['id']=='41'))
    store.configure('41', {'enabled':False})
    assert store.snapshot()[3] == revision
    store.configure('41', {'enabled':True, 'expires_at':'2000-01-01T00:00:00Z'})
    assert not active(next(peer for peer in store.snapshot()[2] if peer['id']=='41'))
    with pytest.raises(ValueError):
        store.configure('42', {'private_key':key(5)})
