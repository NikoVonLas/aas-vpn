import base64
import importlib
import json
import os
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault('AWG_CONTAINER_IP', '192.0.2.45')
os.environ.setdefault('VPN_DOCKER_CIDR', '192.0.2.0/24')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'portal'))
sys.path.insert(0, str(ROOT / 'router'))


@pytest.fixture
def portal(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT / 'portal')
    monkeypatch.setenv('COOKIE_DOMAIN', '.example.test')
    monkeypatch.setenv('PORTAL_DB', str(tmp_path / 'portal.db'))
    monkeypatch.setenv('WG_AUTH_SNAPSHOT', str(tmp_path / 'auth.json'))
    monkeypatch.setenv('RU_CONFIG_DIR', str(tmp_path / 'configs'))
    monkeypatch.setenv('ROUTER_STATUS', str(tmp_path / 'status.json'))
    monkeypatch.setenv('AWG_API_URL', 'http://awg.test')
    app = importlib.import_module('app')
    app = importlib.reload(app)
    with TestClient(app.app, base_url='https://portal.example.test', follow_redirects=False) as client:
        with app.db() as con:
            con.execute("INSERT INTO auth_cache VALUES(1,1,'admin',?,NULL,0,1,?,3600,0)", (app.password_hasher.hash('test-password'), 'a' * 64))
            con.executemany('INSERT INTO users(phone,name,device_limit,enabled,created_at) VALUES(?,?,3,1,0)', [('+79990000001', 'Первый'), ('+79990000002', 'Второй')])
            con.executemany('INSERT INTO devices(phone,name,wg_client_id,created_at,vpn_ip) VALUES(?,?,?,0,?)', [('+79990000001', 'phone1', '41', '10.8.0.2'), ('+79990000002', 'phone2', '42', '10.8.0.3')])
        client.get('/admin/login')
        yield app, client


def admin_login(app, client):
    client.cookies.set('wg-easy', app.make_wg_cookie(1), domain='.example.test')


def phone_login(app, client, phone='+79990000001'):
    client.cookies.clear()
    client.cookies.set('aas_session', app.phone_signer().dumps({'phone': phone}))
    client.get('/cabinet')


def post(client, path, data=None, **kwargs):
    return client.post(path, data={**(data or {}), 'csrf_token': client.cookies.get('__Host-aas_csrf')}, **kwargs)


KEY = base64.b64encode(b'a' * 32).decode()
WG = f'''[Interface]
PrivateKey = {KEY}
Address = 10.55.0.2/32
DNS = 8.8.8.8
[Peer]
PublicKey = {KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
'''
