import base64
import importlib
import json
import os
from pathlib import Path
import sys
import secrets
import time

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
    monkeypatch.setenv('AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.setenv('RU_CONFIG_DIR', str(tmp_path / 'configs'))
    monkeypatch.setenv('ROUTER_STATUS', str(tmp_path / 'status.json'))
    monkeypatch.setenv('AWG_API_URL', 'http://awg.test')
    app = importlib.import_module('app')
    app = importlib.reload(app)
    with TestClient(app.app, base_url='https://portal.example.test', follow_redirects=False) as client:
        with app.auth_store.db() as con:
            con.execute("INSERT INTO admins(id,username,password_hash) VALUES(1,'admin',?)", (app.password_hasher.hash('test-password'),))
        with app.db() as con:
            con.executemany('INSERT INTO users(phone,name,device_limit,enabled,created_at) VALUES(?,?,3,1,0)', [('+79990000001', 'Первый'), ('+79990000002', 'Второй')])
            con.executemany('INSERT INTO devices(phone,name,client_id,created_at,vpn_ip) VALUES(?,?,?,0,?)', [('+79990000001', 'phone1', '41', '10.8.0.2'), ('+79990000002', 'phone2', '42', '10.8.0.3')])
        client.get('/admin/login')
        yield app, client


def admin_login(app, client):
    token = secrets.token_urlsafe(32)
    with app.auth_store.db() as con:
        con.execute('INSERT INTO sessions VALUES(?,?,?)', (app.auth_store.digest(token), 1, int(time.time()) + 3600))
    client.cookies.set(app.auth.COOKIE, token, domain='portal.example.test')


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
