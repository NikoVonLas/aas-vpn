import json
import re
import subprocess
import time

import httpx
import pyotp
import pytest
from conftest import admin_login, phone_login, post, WG, KEY


def test_migration_repeat_and_nullable_password(portal):
    app, client = portal
    app.startup(); app.startup()
    with app.db() as con:
        assert con.execute('SELECT count(*) FROM ru_exits').fetchone()[0] == 1
        assert con.execute('SELECT count(*) FROM devices').fetchone()[0] == 2
        assert con.execute('SELECT can_change_ru_exit FROM users').fetchone()[0] == 0
        con.execute('UPDATE auth_cache SET password_hash=NULL')
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'anything'}).status_code == 401
    admin_login(app, client)
    assert client.get('/admin').status_code == 200


def test_session_integrity_and_expiration(portal):
    app, client = portal
    payload = {'data': {'userId': 1}}
    sealed = app.iron_seal(payload, 'a' * 64)
    assert app.iron_unseal(sealed, 'a' * 64) == payload
    for value, secret in [(sealed[:-1] + '!', 'a' * 64), (sealed, 'b' * 64), (app.iron_seal(payload, 'a' * 64, -120), 'a' * 64)]:
        with pytest.raises(ValueError, match='Invalid session'):
            app.iron_unseal(value, secret)
    client.cookies.set('wg-easy', sealed[:-1] + '!', domain='.example.test')
    assert client.get('/admin').status_code == 303


def test_verification_token_never_enters_html_and_disabled_user_rejected(portal):
    app, client = portal
    token = "';alert(1);//"
    # A malformed stored token must not become executable page content either.
    with app.db() as con:
        con.execute('INSERT INTO verifications(token,phone,created_at) VALUES(?,?,?)', (token, '+79990000001', int(time.time())))
        con.execute("UPDATE users SET enabled=0 WHERE phone='+79990000001'")
    response = app.verify(token)
    assert token.encode() not in response.body
    assert b"fetch(location.pathname + '/status'" in response.body
    assert post(client, '/start', {'phone': '+79990000001'}).status_code == 403


def test_logout_cookies_and_form_js(portal, tmp_path):
    app, client = portal
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password'}).status_code == 303
    response = client.get('/admin')
    assert response.status_code == 200
    assert 'action=/admin/logout' in response.text
    assert "hasAttribute('formaction')" in response.text
    for n, script in enumerate(re.findall(r'<script>(.*?)</script>', response.text, re.S)):
        path = tmp_path / f'script{n}.js'; path.write_text(script)
        subprocess.run(['node', '--check', str(path)], check=True, capture_output=True)
    assert post(client, '/admin/user', {'name': 'Changed', 'phone': '+79990000001', 'device_limit': '3'}).status_code == 303
    response = post(client, '/admin/logout')
    assert response.status_code == 303
    assert response.headers['location'] == '/admin/login'
    cookies = response.headers.get_list('set-cookie')
    assert any('Domain=.example.test' in x and 'Max-Age=0' in x for x in cookies)
    assert any('Domain=' not in x and x.startswith('wg-easy=') for x in cookies)
    assert client.get('/admin').headers['location'] == '/admin/login'
    assert post(client, '/admin/user', {'name': 'X', 'phone': '+79990000001', 'device_limit': '3'}, headers={'X-Requested-With': 'fetch'}).headers['location'] == '/admin/login'


def test_totp_and_csrf(portal):
    app, client = portal
    secret = pyotp.random_base32()
    with app.db() as con:
        con.execute('UPDATE auth_cache SET totp_key=?,totp_verified=1', (secret,))
    assert client.post('/admin/login', data={'username': 'admin', 'password': 'test-password'}).status_code == 403
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password'}).status_code == 401
    assert post(client, '/admin/login', {'username': 'admin', 'password': 'test-password', 'totp': pyotp.TOTP(secret).now()}).status_code == 303
    assert post(client, '/admin/logout', headers={'sec-fetch-site': 'cross-site'}).status_code == 403


def test_permissions_and_assignment_lifecycle(portal):
    app, client = portal
    admin_login(app, client)
    assert post(client, '/admin/ru-exits', {'name': 'Second', 'config_text': WG}).status_code == 303
    assert post(client, '/device/1/ru-exit', {'ru_exit_id': '2'}).status_code == 303
    phone_login(app, client)
    for suffix in ['config', 'qr']:
        assert client.get('/device/2/' + suffix).status_code == 404
    for suffix, data in [('rename', {'name':'stolen'}), ('delete', {}), ('ru-exit', {'ru_exit_id':'2'})]:
        assert post(client, '/device/2/' + suffix, data).status_code == 404
    assert post(client, '/device/1/ru-exit', {'ru_exit_id':'1'}).status_code == 403
    assert client.get('/admin/users/+79990000002/devices').status_code == 303
    admin_login(app, client)
    assert client.get('/admin/users/+79990000002/devices').status_code == 200
    saved = {'phone': '+79990000001', 'name': 'Первый', 'device_limit': '3'}
    assert post(client, '/admin/user', saved).status_code == 303
    with app.db() as con:
        row = con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()
        assert tuple(row) == (2, 'admin')
    assert post(client, '/admin/user', {**saved, 'can_change_ru_exit':'1'}).status_code == 303
    phone_login(app, client)
    assert post(client, '/device/1/ru-exit', {'ru_exit_id':'1'}).status_code == 303
    admin_login(app, client)
    assert post(client, '/admin/user', saved).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()) == (None, None)
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
    result = post(client, '/admin/user', {'name':'x', 'phone':'+79990000001', 'device_limit':KEY}, headers={'X-Requested-With':'fetch'})
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
        if request.method == 'POST':
            return httpx.Response(200, json={'success':True, 'clientId':99})
        if request.url.path.endswith('/configuration'):
            return httpx.Response(200, text=WG)
        if request.method == 'DELETE':
            return httpx.Response(200)
        return httpx.Response(200, json=[{'id':41,'ipv4Address':'10.8.0.2'}, {'id':42,'ipv4Address':'10.8.0.3'}, {'id':99,'ipv4Address':'10.8.0.4'}, {'id':100,'ipv4Address':'10.8.0.5'}])
    def session():
        return httpx.AsyncClient(transport=httpx.MockTransport(api), base_url='http://awg.test')
    monkeypatch.setattr(app, 'wg_session', session)
    result = post(client, '/device', {'name':'New', 'phone':'+79990000002'})
    assert result.status_code == 303
    assert result.headers['location'].endswith('/+79990000002/devices')
    with app.db() as con:
        row = con.execute("SELECT * FROM devices WHERE wg_client_id='99'").fetchone()
        assert row['phone'] == '+79990000002'
        assert row['vpn_ip'] == '10.8.0.4'
        assert not con.execute("SELECT 1 FROM devices WHERE wg_client_id='100'").fetchone()
    assert post(client, f"/device/{row['id']}/rename", {'name':'Renamed'}).status_code == 303
    assert client.get(f"/device/{row['id']}/config").text == WG
    assert client.get(f"/device/{row['id']}/qr").headers['content-type'] == 'image/png'
    with app.db() as con:
        con.execute("UPDATE users SET device_limit=2 WHERE phone='+79990000002'")
    assert post(client, '/device', {'name':'Over limit', 'phone':'+79990000002'}).status_code == 403
    assert post(client, f"/device/{row['id']}/delete").status_code == 303
    assert ('DELETE', '/api/client/99') in calls


def test_admin_javascript_submit_routing(portal, tmp_path):
    app, client = portal
    admin_login(app, client)
    scripts = re.findall(r'<script>(.*?)</script>', client.get('/admin').text, re.S)
    script = next(s for s in scripts if 'let adminSaving' in s)
    # Browser-shaped DOM stubs reproduce the default button.formAction trap,
    # successful AJAX replacement, explicit formaction, validation and expiry.
    harness = r'''
const assert=require('node:assert/strict');
const handlers={}; let requests=[], alerts=[], redirects=[], replaced=0, mode='ok';
global.location={href:'https://portal.example.test/admin',origin:'https://portal.example.test',pathname:'/admin',assign:x=>redirects.push(x)};
global.document={querySelectorAll:()=>[],addEventListener:(n,f)=>{handlers[n]=f},querySelector:()=>({replaceWith:()=>{replaced++}})};
global.window={}; global.FormData=class {}; global.DOMParser=class {parseFromString(){return {querySelector:()=>({})}}};
global.alert=x=>alerts.push(x);
global.fetch=async url=>{
 requests.push(String(url));
 if(mode==='expired')return {ok:true,redirected:true,url:'https://portal.example.test/admin/login'};
 if(mode==='invalid')return {ok:false,status:422,json:async()=>({detail:[{loc:['body','device_limit'],msg:'Укажите число'}]})};
 return {ok:true,redirected:false,text:async()=>'<main></main>'};
};
'''
    checks = r'''
async function submit(action, own){
 let prevented=false;
 await handlers.submit({target:{action,method:'post'},submitter:{formAction:own||location.href,hasAttribute:()=>!!own,setAttribute(){},removeAttribute(){}},preventDefault(){prevented=true}});
 return prevented;
}
(async()=>{
 assert.equal(await submit('https://portal.example.test/admin/logout'),false);
 assert.equal(requests.length,0);
 assert.equal(await submit('https://portal.example.test/admin/user'),true);
 assert.equal(requests[0],'https://portal.example.test/admin/user');
 assert.equal(replaced,1);
 requests=[];
 assert.equal(await submit('https://portal.example.test/admin/logout'),false);
 assert.equal(requests.length,0);
 await submit('https://portal.example.test/admin/user','https://portal.example.test/admin/toggle/+79990000001');
 assert.equal(requests[0],'https://portal.example.test/admin/toggle/+79990000001');
 mode='invalid'; await submit('https://portal.example.test/admin/user');
 assert.equal(alerts[0],'Лимит устройств: Укажите число');
 assert.equal(formError({unrecognized:true},500),'Ошибка HTTP 500');
 mode='expired'; await submit('https://portal.example.test/admin/user');
 assert.equal(redirects[0],'/admin/login');
})().catch(e=>{console.error(e);process.exit(1)});
'''
    path=tmp_path/'submit.js'; path.write_text(harness+script+checks)
    subprocess.run(['node', str(path)], check=True, capture_output=True)


def test_live_status_exposes_only_owned_devices(portal):
    app, client = portal
    phone_login(app, client)
    result = client.get('/routing/status').json()
    assert set(result['devices']) == {'1'}
    assert result['exits'] == {}
    assert client.get('/routing/status?admin_view=true').headers['location'] == '/admin/login'
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
    assert denied.status_code == 303
    assert KEY not in denied.text
    assert KEY not in client.get('/cabinet').text
    assert post(client, '/admin/ru-exits/2', {'name': 'Denied', 'config_text': WG}).status_code == 303
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
    assert 'action=\'/device/2/update\'' in page
    assert '<select name=ru_exit_id>' not in page
    assert post(client, '/device/2/update', {'name': 'Forbidden', 'ru_exit_id': '0'}).status_code == 403
    assert post(client, '/device/1/update', {'name': 'Stolen'}).status_code == 404
    with app.db() as con:
        assert con.execute('SELECT name FROM devices WHERE id=2').fetchone()[0] == 'Admin name'
    assert post(client, '/device/2/update', {'name': 'Owner name'}).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id,assigned_by FROM devices WHERE id=2').fetchone()) == ('Owner name', 1, 'admin')
        con.execute('UPDATE users SET can_change_ru_exit=1')
    assert post(client, '/device/2/update', {'name': 'Same assignment', 'ru_exit_id': '1'}).status_code == 303
    with app.db() as con:
        assert con.execute('SELECT assigned_by FROM devices WHERE id=2').fetchone()[0] == 'admin'
    assert post(client, '/device/2/update', {'name': 'Default', 'ru_exit_id': '0'}).status_code == 303
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id,assigned_by FROM devices WHERE id=2').fetchone()) == ('Default', None, None)
    assert client.post('/device/2/update', data={'name': 'No CSRF'}).status_code == 403
