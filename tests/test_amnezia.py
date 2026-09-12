import base64
import json
import zlib

import httpx
import pytest

from amnezia import connection_url
from conftest import WG, KEY, admin_login


def decode(url):
    encoded = url.removeprefix('vpn://')
    data = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    raw = zlib.decompress(data[4:])
    assert int.from_bytes(data[:4], 'big') == len(raw)
    return json.loads(raw)


def test_amnezia_import_preserves_connection_and_awg_parameters():
    config = WG.replace('DNS = 8.8.8.8', 'DNS = 10.19.0.1\nMTU = 1320\nJc = 4\nS4 = 12\nI1 = <b 0x1234>')
    config = config.replace('192.0.2.1:51820', '[2001:db8::1]:443')
    payload = decode(connection_url(config, 'Телефон'))
    assert payload['description'] == 'Телефон'
    assert payload['hostName'] == '2001:db8::1'
    assert payload['dns1'] == payload['dns2'] == '10.19.0.1'
    assert payload['defaultContainer'] == 'amnezia-awg'
    protocol = payload['containers'][0]['awg']
    assert protocol['isThirdPartyConfig'] is True
    assert protocol['transport_proto'] == 'udp'
    last = json.loads(protocol['last_config'])
    assert last['config'] == config
    assert last['client_priv_key'] == last['server_pub_key'] == KEY
    assert last['allowed_ips'] == ['0.0.0.0/0', '::/0']
    assert last['port'] == 443
    assert last['mtu'] == '1320'
    assert last['Jc'] == '4'
    assert last['S4'] == '12'
    assert last['I1'] == '<b 0x1234>'


@pytest.mark.parametrize('config', [KEY, WG.replace('Endpoint', 'Missing'), WG.replace(':51820', ':0')])
def test_invalid_connection_does_not_disclose_config(config):
    with pytest.raises(ValueError) as error:
        connection_url(config, 'Test')
    assert KEY not in str(error.value)


def test_connect_and_qr_share_authorized_non_cached_key(portal, monkeypatch):
    app, client = portal
    admin_login(app, client)
    monkeypatch.setattr(app, 'wg_session', lambda: httpx.AsyncClient(
        base_url='http://awg.test', transport=httpx.MockTransport(lambda request: httpx.Response(200, text=WG))))
    result = client.get('/device/1/connect')
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    url = result.json()['url']
    assert decode(url)['containers']
    captured = []
    make = app.qrcode.make
    def capture(value):
        captured.append(value)
        return make(value)
    monkeypatch.setattr(app.qrcode, 'make', capture)
    assert client.get('/device/1/qr').headers['content-type'] == 'image/png'
    assert captured == [url]
    with app.db() as con:
        con.execute("UPDATE devices SET operation='create' WHERE id=1")
    assert client.get('/device/1/connect').status_code == 409
    client.cookies.clear()
    assert client.get('/device/1/connect').status_code == 303
