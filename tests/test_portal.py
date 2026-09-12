import json
import re
import subprocess
import time

import httpx
import pyotp
import pytest
import identity
from test_identity import accounts, give
from conftest import admin_login, phone_login, post, WG, KEY


def test_migration_repeat_and_nullable_password(portal):
    app, client = portal
    app.startup(); app.startup()
    with app.db() as con:
        assert con.execute('SELECT count(*) FROM ru_exits').fetchone()[0] == 1
        assert con.execute('SELECT count(*) FROM devices').fetchone()[0] == 2
        assert con.execute('SELECT can_change_ru_exit FROM users').fetchone()[0] == 0
    with app.auth_store.db() as con:
        con.execute('UPDATE admins SET password_hash=NULL')
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'anything'}).status_code == 401
    admin_login(app, client)
    assert client.get('/admin').status_code == 200


def test_session_integrity_and_expiration(portal):
    app, client = portal
    token, _ = app.auth_store.login('admin', 'test-password', '', 'test')
    assert app.auth_store.session(token)['id'] == 1
    assert app.auth_store.session(token + '!') is None
    with app.auth_store.db() as con:
        con.execute('UPDATE identity_sessions SET expires=0')
    assert app.auth_store.session(token) is None
    client.cookies.set(app.auth.COOKIE, token)
    assert client.get('/admin').status_code == 303


def test_legacy_verification_routes_are_retired(portal):
    app, client = portal
    assert post(client, '/start', {'phone': '+79990000001'}).status_code == 404
    assert client.get('/verify/legacy-token/status').status_code == 404
    assert client.get('/verify/legacy-token').status_code == 404


def test_logout_cookies_and_form_js(portal, tmp_path):
    app, client = portal
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password'}).status_code == 303
    response = client.get('/admin')
    assert response.status_code == 200
    assert 'action="/admin/logout"' in response.text
    assert "/assets/js/forms.js" in response.text
    for n, script in enumerate(re.findall(r'<script>(.*?)</script>', response.text, re.S)):
        path = tmp_path / f'script{n}.js'; path.write_text(script)
        subprocess.run(['node', '--check', str(path)], check=True, capture_output=True)
    first = accounts(app)[1]
    assert post(client, '/accounts/' + first + '/save', {'name': 'Changed', 'device_limit': '3'}).status_code == 303
    response = post(client, '/admin/logout')
    assert response.status_code == 303
    assert response.headers['location'] == '/admin/login'
    cookies = response.headers.get_list('set-cookie')
    assert any('Domain=.example.test' in x and 'Max-Age=0' in x for x in cookies)
    assert any('Domain=' not in x and x.startswith('wg-easy=') for x in cookies)
    assert client.get('/admin').headers['location'] == '/'
    assert post(client, '/accounts/' + first + '/save', {'name': 'X', 'device_limit': '3'}, headers={'X-Requested-With': 'fetch'}).headers['location'] == '/'


def test_totp_and_csrf(portal):
    app, client = portal
    secret = pyotp.random_base32()
    with app.auth_store.db() as con:
        con.execute('UPDATE admins SET totp_key=?,totp_verified=1', (secret,))
        con.execute('UPDATE accounts SET voluntary_2fa=1 WHERE admin_id=1')
    assert client.post('/admin/login', data={'username': 'admin', 'password': 'test-password'}).status_code == 403
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password'}).headers['location'] == '/security'
    assert client.get('/admin').headers['location'] == '/security'
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password', 'totp': pyotp.TOTP(secret).now()}).status_code == 303
    assert post(client, '/admin/logout', headers={'sec-fetch-site': 'cross-site'}).status_code == 403


def test_permissions_and_assignment_lifecycle(portal):
    app, client = portal
    admin_login(app, client)
    assert post(client, '/admin/ru-exits', {'name': 'Second', 'config_text': WG}).status_code == 303
    assert post(client, '/device/1/ru-exit', {'ru_exit_id': '2'}).status_code == 303
    phone_login(app, client)
    for suffix in ['config', 'qr', 'connect']:
        assert client.get('/device/2/' + suffix).status_code == 404
    for suffix, data in [('rename', {'name':'stolen'}), ('delete', {}), ('ru-exit', {'ru_exit_id':'2'})]:
        assert post(client, '/device/2/' + suffix, data).status_code == 404
    assert post(client, '/device/1/ru-exit', {'ru_exit_id':'1'}).status_code == 404
    assert client.get('/admin/users/+79990000002/devices').status_code == 403
    admin_login(app, client)
    assert client.get('/admin/users/+79990000002/devices').status_code == 200
    owner, first, _ = accounts(app)
    saved = {'name': 'Первый', 'device_limit': '3'}
    assert post(client, '/accounts/' + first + '/save', saved).status_code == 303
    with app.db() as con:
        row = con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()
        assert tuple(row) == (2, 'admin')
    assignment = give(app, first, 'exit-choice')
    phone_login(app, client)
    assert post(client, '/device/1/ru-exit', {'ru_exit_id':'1'}).status_code == 303
    admin_login(app, client)
    app.identities.assign(owner, first, '', 'self', remove=assignment)
    with app.db() as con:
        assert tuple(con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()) == (1, 'user')
    assert post(client, '/admin/ru-exits/2/default').status_code == 303
    assert post(client, '/admin/ru-exits/2/delete').status_code == 409
    assert post(client, '/device/1/ru-exit', {'ru_exit_id':'1'}).status_code == 303
    assert post(client, '/admin/ru-exits/1/delete').status_code == 409
    assert post(client, '/device/1/ru-exit').status_code == 303
    assert post(client, '/admin/ru-exits/1/delete').status_code == 303


def test_config_privacy_and_rules(portal):
    app, client = portal
    admin_login(app, client)
    result = post(client, '/admin/ru-exits', {'name':'Upload'}, files={'config_upload':('test.conf', WG, 'text/plain')})
    assert result.status_code == 303, result.text
    assert KEY in client.get('/admin/ru-exits').text
    files = list(app.RU_CONFIG_DIR.iterdir())
    assert len(files) == 2
    for file in files:
        assert file.stat().st_mode & 0o777 == 0o600
    result = post(client, '/admin/ru-exits', {'name': 'bad', 'config_text': WG + '\nPostUp = ' + KEY})
    assert result.status_code == 400
    assert KEY not in result.text
    assert post(client, '/admin/routing', {'ru': '.RU\n.рф\n10.0.0.0/8', 'direct': 'EXAMPLE.RU\n10.2.0.0/16'}).status_code == 303
    with app.db() as con:
        assert con.execute("SELECT 1 FROM routing_rules WHERE value='xn--p1ai'").fetchone()
    result = post(client, '/accounts/' + accounts(app)[1] + '/save', {'name':'x', 'device_limit':KEY}, headers={'X-Requested-With':'fetch'})
    assert result.status_code == 422
    assert KEY not in result.text
    assert isinstance(result.json()['detail'], list)


def test_legacy_exit_config_can_be_replaced_without_losing_assignments(portal):
    app, client = portal
    admin_login(app, client)
    assert post(client, '/device/1/ru-exit', {'ru_exit_id': '1'}).status_code == 303
    assert post(client, '/admin/ru-exits/1', {'name': 'Домашний', 'config_text': WG}).status_code == 303
    with app.db() as con:
        node = con.execute('SELECT * FROM ru_exits WHERE id=1').fetchone()
        assert node['legacy'] == 0
        assert node['config_file']
        assert con.execute("SELECT value FROM settings WHERE key='ru_default'").fetchone()[0] == '1'
        assert con.execute('SELECT ru_exit_id FROM devices WHERE id=1').fetchone()[0] == 1
    assert KEY in client.get('/admin/ru-exits').text


def test_admin_device_crud_and_client_id(portal, monkeypatch):
    app, client = portal
    admin_login(app, client)
    calls = []
    async def api(request):
        calls.append((request.method, request.url.path))
        if request.method == 'PUT':
            return httpx.Response(200, json={'applied':True, 'ipv4Address':'10.8.0.4'})
        if request.url.path.endswith('/configuration'):
            return httpx.Response(200, text=WG)
        if request.method == 'DELETE':
            return httpx.Response(200, json={'applied':True, 'deleted':True})
        return httpx.Response(200, json=[{'id':41,'ipv4Address':'10.8.0.2'}, {'id':42,'ipv4Address':'10.8.0.3'}, {'id':99,'ipv4Address':'10.8.0.4'}, {'id':100,'ipv4Address':'10.8.0.5'}])
    def session():
        return httpx.AsyncClient(transport=httpx.MockTransport(api), base_url='http://awg.test')
    monkeypatch.setattr(app, 'wg_session', session)
    result = post(client, '/device', {'name':'New', 'phone':'+79990000002'})
    assert result.status_code == 303
    assert result.headers['location'] == '/accounts/' + accounts(app)[2]
    with app.db() as con:
        row = con.execute("SELECT * FROM devices WHERE name='New'").fetchone()
        assert row['phone'] == '+79990000002'
        assert row['vpn_ip'] == '10.8.0.4'
        assert not con.execute("SELECT 1 FROM devices WHERE client_id='100'").fetchone()
    assert post(client, f"/device/{row['id']}/rename", {'name':'Renamed'}).status_code == 303
    assert client.get(f"/device/{row['id']}/config").text == WG
    assert client.get(f"/device/{row['id']}/qr").headers['content-type'] == 'image/png'
    with app.db() as con:
        con.execute("UPDATE users SET device_limit=2 WHERE phone='+79990000002'")
    assert post(client, '/device', {'name':'Over limit', 'phone':'+79990000002'}).status_code == 403
    assert post(client, f"/device/{row['id']}/delete").status_code == 303
    assert ('DELETE', '/clients/' + row['client_id']) in calls


def test_recovery_uses_native_post_response(portal):
    app, client = portal
    admin_login(app, client)
    key = accounts(app)[1]
    body = client.get('/accounts/' + key + '/edit').text
    assert 'form="recovery-' + key + '"' in body
    assert 'action="/admin/accounts/' + key + '/recovery"' in body
    response = post(client, '/admin/accounts/' + key + '/recovery')
    assert response.status_code == 200
    assert 'Одноразовое восстановление' in response.text
    assert '<pre>' in response.text


def test_live_status_exposes_only_owned_devices(portal):
    app, client = portal
    phone_login(app, client)
    result = client.get('/routing/status').json()
    assert set(result['devices']) == {'1'}
    assert result['exits'] == {}
    assert client.get('/routing/status?admin_view=true').status_code == 403
    admin_login(app, client)
    result = client.get('/routing/status?admin_view=true').json()
    assert set(result['devices']) == {'1','2'}
    assert KEY not in json.dumps(result)


def test_saved_exit_editor_roundtrip_and_access(portal):
    app, client = portal
    admin_login(app, client)
    original = WG + '\n# comment </textarea><script>alert(1)</script>\n'
    assert post(client, '/admin/ru-exits', {'name': 'Editor', 'config_text': original}).status_code == 303
    page = client.get('/admin/ru-exits')
    assert page.headers['cache-control'] == 'no-store'
    assert '&lt;/textarea&gt;&lt;script&gt;' in page.text
    assert '<script>alert(1)</script>' not in page.text
    with app.db() as con:
        filename = con.execute('SELECT config_file FROM ru_exits WHERE id=2').fetchone()[0]
    assert app.stored_config_text(app.RU_CONFIG_DIR, filename) == original
    assert post(client, '/admin/ru-exits/2', {'name': 'Renamed', 'config_text': original}).status_code == 303
    with app.db() as con:
        assert con.execute('SELECT config_file FROM ru_exits WHERE id=2').fetchone()[0] == filename
    edited = original.replace('10.55.0.2', '10.55.0.3')
    assert post(client, '/admin/ru-exits/2', {'name': 'Edited', 'config_text': edited}).status_code == 303
    assert '10.55.0.3/32' in client.get('/admin/ru-exits').text
    assert KEY not in client.get('/routing/status?admin_view=true').text
    phone_login(app, client)
    denied = client.get('/admin/ru-exits')
    assert denied.status_code == 403
    assert KEY not in denied.text
    assert KEY not in client.get('/cabinet').text
    assert post(client, '/admin/ru-exits/2', {'name': 'Denied', 'config_text': WG}).status_code == 403
    client.cookies.clear()
    assert KEY not in client.get('/admin/ru-exits').text


def test_combined_device_save_is_atomic_and_permission_checked(portal):
    app, client = portal
    admin_login(app, client)
    assert post(client, '/device/2/update', {'name': 'Admin name', 'ru_exit_id': '1'}).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id,assigned_by FROM devices WHERE id=2').fetchone()) == ('Admin name', 1, 'admin')
    assert post(client, '/device/2/update', {'name': 'Must not save', 'ru_exit_id': '999'}).status_code == 400
    phone_login(app, client, '+79990000002')
    page = client.get('/cabinet').text
    assert 'action="/device/2/update"' in page
    assert '<select name=ru_exit_id>' not in page
    assert post(client, '/device/2/update', {'name': 'Forbidden', 'ru_exit_id': '0'}).status_code == 404
    assert post(client, '/device/1/update', {'name': 'Stolen'}).status_code == 404
    with app.db() as con:
        assert con.execute('SELECT name FROM devices WHERE id=2').fetchone()[0] == 'Admin name'
    assert post(client, '/device/2/update', {'name': 'Owner name'}).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id,assigned_by FROM devices WHERE id=2').fetchone()) == ('Owner name', 1, 'admin')
    give(app, accounts(app)[2], 'exit-choice')
    assert post(client, '/device/2/update', {'name': 'Same assignment', 'ru_exit_id': '1'}).status_code == 303
    with app.db() as con:
        assert con.execute('SELECT assigned_by FROM devices WHERE id=2').fetchone()[0] == 'admin'
    assert post(client, '/device/2/update', {'name': 'Default', 'ru_exit_id': '0'}).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id,assigned_by FROM devices WHERE id=2').fetchone()) == ('Default', None, None)
    assert client.post('/device/2/update', data={'name': 'No CSRF'}).status_code == 403
