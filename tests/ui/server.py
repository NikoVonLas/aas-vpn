"""Local-only UI fixture: disposable data, real portal routes and authentication."""
import base64
import os
from pathlib import Path
import secrets
import sys
import tempfile

import uvicorn

ROOT = Path(__file__).resolve().parents[2]
temporary = tempfile.TemporaryDirectory(prefix='aas-ui-')
data = Path(temporary.name)
os.environ.update(COOKIE_DOMAIN='localhost', PORTAL_DB=str(data / 'portal.db'),
                  WG_AUTH_SNAPSHOT=str(data / 'missing.json'), RU_CONFIG_DIR=str(data / 'configs'),
                  ROUTER_STATUS=str(data / 'missing-status.json'), AWG_API_URL='http://127.0.0.1:1')
os.chdir(ROOT / 'portal')
sys.path.insert(0, str(ROOT / 'portal'))
import app as portal  # noqa: E402

portal.startup()
key = base64.b64encode(b'a' * 32).decode()
config = f'[Interface]\nPrivateKey = {key}\nAddress = 10.55.0.2/32\nListenPort = 51820\n\n[Peer]\nPublicKey = {key}\nAllowedIPs = 0.0.0.0/0\n'
portal.store_config(portal.RU_CONFIG_DIR, 'fixture.json', portal.parse_wireguard(config), config)
with portal.db() as connection:
    connection.execute("INSERT INTO auth_cache VALUES(1,1,'admin',?,NULL,0,1,?,3600,0)",
                       (portal.password_hasher.hash('visual-test-password'), secrets.token_hex(32)))
    connection.executemany('INSERT INTO users(phone,name,device_limit,enabled,created_at,can_change_ru_exit) VALUES(?,?,3,1,0,?)',
                           [('+79990000001', 'Александр Константинопольский', 1), ('+79990000002', 'Мария', 0)])
    connection.executemany('INSERT INTO devices(phone,name,wg_client_id,created_at,vpn_ip) VALUES(?,?,?,0,?)',
                           [('+79990000001', 'Рабочий ноутбук', '41', '10.19.0.2'),
                            ('+79990000001', 'Телефон с длинным названием устройства', '42', '10.19.0.3'),
                            ('+79990000002', 'Личный телефон', '43', '10.19.0.4')])
    connection.execute("UPDATE ru_exits SET config_file='fixture.json' WHERE id=1")
    connection.execute("INSERT INTO ru_exits(name,legacy,config_file) VALUES('Домашний Keenetic с длинным названием выхода',0,'fixture.json')")
    connection.execute("INSERT INTO settings(key,value) VALUES('dial_numbers',?)", ('+79990000003',))

@portal.app.get('/fixture/phone-login/{phone}')
def fixture_phone_login(phone: str):
    if phone not in {'+79990000001', '+79990000002'}:
        raise portal.HTTPException(404)
    response = portal.RedirectResponse('/cabinet', 303)
    response.set_cookie('aas_session', portal.phone_signer().dumps({'phone': phone}), httponly=True, samesite='lax')
    return response


if __name__ == '__main__':
    uvicorn.run(portal.app, host='127.0.0.1', port=8765, log_level='warning')
