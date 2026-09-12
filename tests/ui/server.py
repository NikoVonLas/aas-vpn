"""Local-only UI fixture: disposable data, real portal routes and authentication."""
import base64
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import subprocess
from fastapi import Request

import uvicorn
import httpx

ROOT = Path(__file__).resolve().parents[2]
PORT = int(os.environ.get('AAS_UI_PORT', '8765'))
temporary = tempfile.TemporaryDirectory(prefix='aas-ui-')
data = Path(temporary.name)
os.environ.update(COOKIE_DOMAIN='localhost', PORTAL_DB=str(data / 'portal.db'),
                  AUTH_DB=str(data / 'auth.db'), RU_CONFIG_DIR=str(data / 'configs'),
                  ROUTER_STATUS=str(data / 'missing-status.json'), AWG_API_URL='http://127.0.0.1:1', AUTH_ORIGIN=f'https://localhost:{PORT}',
                  ZVONOK_PUBLIC_KEY='fixture-key', ZVONOK_CAMPAIGN_ID='fixture')
os.chdir(ROOT / 'portal')
sys.path.insert(0, str(ROOT / 'portal'))
import app as portal  # noqa: E402

def fixture_awg(request):
    if request.url.path.endswith('/configuration'):
        return httpx.Response(200, text=device_config)
    return httpx.Response(200, json=[])

portal.wg_session = lambda: httpx.AsyncClient(transport=httpx.MockTransport(fixture_awg), base_url='http://fixture')
portal.startup()
portal.app.router.on_startup = [handler for handler in portal.app.router.on_startup if handler != portal.start_device_worker]
key = base64.b64encode(b'a' * 32).decode()
config = f'[Interface]\nPrivateKey = {key}\nAddress = 10.55.0.2/32\nListenPort = 51820\nDNS = 10.19.0.1\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 100\nS2 = 120\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n'
device_config = config
config = ''.join(line for line in config.splitlines(keepends=True) if not line.startswith(('Jc =', 'Jmin =', 'Jmax =', 'S1 =', 'S2 =')))

portal.store_config(portal.RU_CONFIG_DIR, 'fixture.json', portal.parse_wireguard(config), config)
portal.auth_store.add('admin', 'visual-test-password', must_change=False)
with portal.db() as connection:
    connection.executemany('INSERT INTO users(phone,name,device_limit,enabled,created_at,can_change_ru_exit) VALUES(?,?,3,1,0,?)',
                           [('+79990000001', 'Александр Константинопольский', 1), ('+79990000002', 'Мария', 0)])
    connection.executemany('INSERT INTO devices(phone,name,client_id,created_at,vpn_ip) VALUES(?,?,?,0,?)',
                           [('+79990000001', 'Рабочий ноутбук', '41', '10.19.0.2'),
                            ('+79990000001', 'Телефон с длинным названием устройства', '42', '10.19.0.3'),
                            ('+79990000002', 'Личный телефон', '43', '10.19.0.4')])
    connection.execute("UPDATE ru_exits SET config_file='fixture.json' WHERE id=1")
    connection.execute("INSERT INTO ru_exits(name,legacy,config_file) VALUES('Домашний Keenetic с длинным названием выхода',0,'fixture.json')")
    connection.execute("INSERT INTO settings(key,value) VALUES('dial_numbers',?)", ('+79990000003',))

portal.identities.migrate()
with portal.auth_store.db() as connection:
    connection.execute("DELETE FROM grants WHERE role_id='exit-choice'")
    connection.execute("DELETE FROM roles WHERE id='exit-choice'")
    connection.execute("UPDATE roles SET primary_methods='[\"phone\"]' WHERE id='user'")

@portal.app.get('/fixture/reset-sessions')
def reset_sessions():
    with portal.auth_store.db() as connection:
        connection.execute('DELETE FROM identity_sessions')
        connection.execute('DELETE FROM attempts')
        connection.execute('DELETE FROM backup_codes')
        connection.execute("DELETE FROM grants WHERE role_id='fixture-exit'")
        connection.execute("DELETE FROM roles WHERE id='fixture-exit'")
    return {'ok': True}

@portal.app.get('/fixture/phone-login/{phone}')
def fixture_phone_login(phone: str):
    if phone not in {'+79990000001', '+79990000002'}:
        raise portal.HTTPException(404)
    reset_sessions()
    response = portal.RedirectResponse('/cabinet', 303)
    with portal.auth_store.db() as connection:
        account_id = connection.execute('SELECT id FROM accounts WHERE phone=?', (phone,)).fetchone()[0]
        if phone == '+79990000001':
            connection.execute("INSERT OR IGNORE INTO roles VALUES('fixture-exit','Выбор выхода','[\"device.exit\"]','[]','[]',0,0)")
            portal.identity.grant(connection, account_id, 'fixture-exit')
        token = portal.identities.new_session(connection, account_id, ['phone'])
    response.set_cookie(portal.auth.COOKIE, token, secure=True, httponly=True, samesite='lax')
    return response


@portal.app.get('/fixture/complete-login')
def complete_login(request: Request):
    """Stub only the second factor proof; primary login and session checks are real."""
    from security_pages import SecurityPages
    actor = portal.current_account(request, limited=True)
    with portal.auth_store.db() as con:
        token = portal.identities.new_session(con, actor['account_id'], ['password', 'totp'])
        con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (actor['token_hash'],))
    return SecurityPages(portal).finish(token)


with portal.auth_store.db() as connection:
    login_roles = [(row['primary_methods'], row['require_2fa'], row['id']) for row in connection.execute('SELECT * FROM roles')]
    login_providers = [(row['enabled'], row['id']) for row in connection.execute('SELECT * FROM providers')]


@portal.app.get('/fixture/login-options/{methods}')
def fixture_login_options(methods: str):
    with portal.auth_store.db() as connection:
        if methods == 'restore':
            connection.executemany('UPDATE roles SET primary_methods=?,require_2fa=? WHERE id=?', login_roles)
            connection.executemany('UPDATE providers SET enabled=? WHERE id=?', login_providers)
        else:
            selected = set() if methods == 'none' else set(methods.split(','))
            if not selected <= {'password', 'phone', 'email', 'webauthn', 'oidc'}:
                raise portal.HTTPException(400)
            connection.execute('UPDATE roles SET primary_methods=?', (json.dumps(sorted(selected)),))
            connection.execute('UPDATE providers SET enabled=1')
    return {'ok': True}



@portal.app.get('/fixture/components')
def fixture_components():
    from views import component_catalog
    return component_catalog(portal)



@portal.app.get('/fixture/state/{name}')
def fixture_state(name: str, request: Request):
    with portal.auth_store.db() as con:
        owner = con.execute('SELECT id FROM accounts WHERE admin_id=1').fetchone()[0]
        first = con.execute("SELECT id FROM accounts WHERE phone='+79990000001'").fetchone()[0]
        con.execute('UPDATE admins SET totp_key=NULL,totp_verified=0,pending_totp=NULL,pending_at=NULL,must_change=0 WHERE id=1')
        con.execute("UPDATE roles SET require_2fa=0 WHERE id='administrator'")
        con.execute('UPDATE accounts SET voluntary_2fa=0 WHERE id=?', (owner,))
        con.executemany('UPDATE roles SET primary_methods=?,require_2fa=? WHERE id=?', login_roles)
        con.executemany('UPDATE providers SET enabled=? WHERE id=?', login_providers)
        con.execute('DELETE FROM oidc_links')
        con.execute("UPDATE providers SET config='{}' WHERE id='oidc'")
        if name in {'oidc-configured', 'oidc-unlinked', 'oidc-linked'}:
            con.execute("UPDATE providers SET enabled=1,config=? WHERE id='oidc'", (json.dumps({'issuer': 'https://sso.example.test/realms/vpn', 'client_id': 'aas-vpn', 'client_secret': 'fixture-only'}),))
            con.execute("UPDATE roles SET primary_methods='[\"password\",\"oidc\"]' WHERE id='administrator'")
            if name == 'oidc-configured':
                con.execute("UPDATE providers SET enabled=0 WHERE id='oidc'")
            if name == 'oidc-linked':
                con.execute('INSERT INTO oidc_links VALUES(?,?,?)', (owner, 'https://sso.example.test/realms/vpn', 'fixture-person'))
        if name == 'optional-mfa':
            con.execute("UPDATE roles SET require_2fa=0 WHERE id='administrator'")
        if name == 'methods-disabled':
            con.execute("UPDATE providers SET enabled=0 WHERE id IN ('totp','webauthn')")
        if name == 'role-disabled-methods':
            con.execute("UPDATE providers SET enabled=0 WHERE id='webauthn'")
        if name == 'totp':
            con.execute("UPDATE admins SET pending_totp='JBSWY3DPEHPK3PXP',pending_at=? WHERE id=1", (int(time.time()),))
        if name in {'mfa', 'required'}:
            con.execute("UPDATE roles SET require_2fa=1 WHERE id='administrator'")
            con.execute("UPDATE admins SET totp_key='JBSWY3DPEHPK3PXP',totp_verified=1 WHERE id=1")
        if name in {'mfa', 'mfa-setup'}:
            con.execute("UPDATE identity_sessions SET methods='[\"password\"]' WHERE account_id=?", (owner,))
        if name == 'must-change':
            con.execute('UPDATE admins SET must_change=1 WHERE id=1')
        if name == 'reauth':
            con.execute('UPDATE identity_sessions SET confirmed=0 WHERE account_id=?', (owner,))
        if name == 'required':
            session = portal.identities.new_session(con, owner, ['password', 'totp'])
            response = portal.RedirectResponse('/security', 303)
            response.set_cookie(portal.auth.COOKIE, session, secure=True, httponly=True, samesite='lax')
            return response
    with portal.db() as con:
        con.execute("UPDATE devices SET operation='applied',native_enabled=1 WHERE id=1")
        con.execute("UPDATE users SET device_limit=3 WHERE account_id=?", (first,))
        if name == 'limit':
            con.execute('UPDATE users SET device_limit=2 WHERE account_id=?', (first,))
        if name in {'creating', 'disabled'}:
            con.execute('UPDATE devices SET operation=?,native_enabled=? WHERE id=1', ('create' if name == 'creating' else 'applied', int(name != 'disabled')))
        revision = int(con.execute("SELECT value FROM settings WHERE key='routing_revision'").fetchone()[0])
    Path(portal.DB).with_name('maintenance').unlink(missing_ok=True)
    portal.ROUTER_STATUS.unlink(missing_ok=True)
    if name == 'maintenance':
        Path(portal.DB).with_name('maintenance').touch()
    if name in {'applied', 'error', 'stale', 'fallback', 'applying'}:
        status = dict(state='applied' if name in {'fallback', 'applying'} else name,
                      updated_at=0 if name == 'stale' else int(time.time()),
                      applied_revision=revision - int(name == 'applying'),
                      exits={'1': {'healthy': name != 'fallback'}, '2': {'healthy': True}},
                      devices={'1': {'effective': 2 if name == 'fallback' else 1, 'fallback': name == 'fallback'}})
        portal.ROUTER_STATUS.write_text(json.dumps(status))
    return {'account': first}


@portal.app.get('/fixture/confirmation/{method}')
def fixture_confirmation(method: str, request: Request):
    from security_pages import SecurityPages
    pages = SecurityPages(portal)
    with portal.auth_store.db() as con:
        key = con.execute("SELECT id FROM accounts WHERE phone='+79990000001'").fetchone()[0]
        if method == 'email':
            con.execute("UPDATE roles SET primary_methods='[\"phone\",\"email\"]' WHERE id='user'")
            con.execute("UPDATE providers SET enabled=1 WHERE id='email'")
        challenge = pages.confirmations.start(con, key, 'login', method,
                         request.cookies.get('__Host-aas_csrf', ''), {'dial': '+79990000003', 'call_id': 'ui-fixture'}, '123456', 'fixture-link')
    return portal.RedirectResponse('/login/verify/' + challenge, 303)


# Never contact the call provider from deterministic browser fixtures.
from login_methods import ZvonokProvider
real_phone_verify = ZvonokProvider.verify


async def fixture_phone_verify(config, payload):
    if payload.get('call_id') == 'ui-fixture':
        return False
    return await real_phone_verify(config, payload)


ZvonokProvider.verify = staticmethod(fixture_phone_verify)


# Browser tests cross a different host; cryptographic verification is covered in test_oidc.py.
import oidc
real_oidc_discovery = oidc.discovery
real_oidc_exchange = oidc.exchange


async def fixture_oidc_discovery(client, config):
    if config['issuer'] != 'https://sso.example.test/realms/vpn':
        return await real_oidc_discovery(client, config)
    return {'authorization_endpoint': f'https://127.0.0.1:{PORT}/fixture/oidc-authorize'}


async def fixture_oidc_exchange(client, config, payload, code):
    if config['issuer'] != 'https://sso.example.test/realms/vpn':
        return await real_oidc_exchange(client, config, payload, code)
    if code != 'fixture-code':
        raise ValueError('Invalid fixture code')
    return 'fixture-person'


oidc.discovery = fixture_oidc_discovery
oidc.exchange = fixture_oidc_exchange


@portal.app.get('/fixture/oidc-authorize')
def fixture_oidc_authorize(state: str):
    from urllib.parse import urlencode
    return portal.RedirectResponse(f'https://localhost:{PORT}/login/oidc/callback?' + urlencode({'state': state, 'code': 'fixture-code'}), 303)


if __name__ == '__main__':
    certificate, private_key = data / 'fixture-cert.pem', data / 'fixture-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(private_key), '-out', str(certificate), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
    uvicorn.run(portal.app, host='127.0.0.1', port=PORT, log_level='warning', ssl_certfile=str(certificate), ssl_keyfile=str(private_key))
