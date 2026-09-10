"""Local-only UI fixture: disposable data, real portal routes and authentication."""
import base64
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

import uvicorn
import httpx

ROOT = Path(__file__).resolve().parents[2]
temporary = tempfile.TemporaryDirectory(prefix='aas-ui-')
data = Path(temporary.name)
os.environ.update(COOKIE_DOMAIN='localhost', PORTAL_DB=str(data / 'portal.db'),
                  AUTH_DB=str(data / 'auth.db'), RU_CONFIG_DIR=str(data / 'configs'),
                  ROUTER_STATUS=str(data / 'missing-status.json'), AWG_API_URL='http://127.0.0.1:1', AUTH_ORIGIN='http://localhost:8765',
                  ZVONOK_PUBLIC_KEY='fixture-key', ZVONOK_CAMPAIGN_ID='fixture')
os.chdir(ROOT / 'portal')
sys.path.insert(0, str(ROOT / 'portal'))
import app as portal  # noqa: E402

portal.wg_session = lambda: httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])), base_url='http://fixture')
portal.startup()
key = base64.b64encode(b'a' * 32).decode()
config = f'[Interface]\nPrivateKey = {key}\nAddress = 10.55.0.2/32\nListenPort = 51820\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\n'
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

@portal.app.get('/fixture/reset-sessions')
def reset_sessions():
    with portal.auth_store.db() as connection:
        connection.execute('DELETE FROM identity_sessions')
        connection.execute('DELETE FROM attempts')
    return {'ok': True}

@portal.app.get('/fixture/phone-login/{phone}')
def fixture_phone_login(phone: str):
    if phone not in {'+79990000001', '+79990000002'}:
        raise portal.HTTPException(404)
    reset_sessions()
    response = portal.RedirectResponse('/cabinet', 303)
    with portal.auth_store.db() as connection:
        account_id = connection.execute('SELECT id FROM accounts WHERE phone=?', (phone,)).fetchone()[0]
        token = portal.identities.new_session(connection, account_id, ['phone'])
    response.set_cookie(portal.auth.COOKIE, token, secure=True, httponly=True, samesite='lax')
    return response


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
            selected = set(methods.split(','))
            if not selected <= {'password', 'phone', 'email', 'webauthn'}:
                raise portal.HTTPException(400)
            connection.execute('UPDATE roles SET primary_methods=?', (json.dumps(sorted(selected)),))
            connection.execute('UPDATE providers SET enabled=1')
    return {'ok': True}


if __name__ == '__main__':
    uvicorn.run(portal.app, host='127.0.0.1', port=8765, log_level='warning')
