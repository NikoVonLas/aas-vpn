"""AmneziaVPN import format (client/core/controllers/selfhosted/importController.cpp)."""
import base64
import configparser
import json
import zlib


def connection_url(config: str, name: str) -> str:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        parser.read_string(config)
        interface, peer = parser['Interface'], parser['Peer']
        host, port = peer['Endpoint'].rsplit(':', 1)
        port_number = int(port)
        if not host or not 1 <= port_number <= 65535:
            raise ValueError
        last = {
            'config': config, 'hostName': host.strip('[]'), 'port': port_number,
            'client_priv_key': interface['PrivateKey'], 'client_ip': interface['Address'],
            'server_pub_key': peer['PublicKey'], 'psk_key': peer.get('PresharedKey', ''),
            'mtu': interface.get('MTU', '1280'),
            'persistent_keep_alive': peer.get('PersistentKeepalive', '25'),
            'allowed_ips': [item.strip() for item in peer['AllowedIPs'].split(',')],
        }
        # Preserve all AWG parameters, including newer protocol versions.
        ordinary = {'PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort'}
        last.update({key: value for key, value in interface.items() if key not in ordinary})
        dns = [item.strip() for item in interface.get('DNS', '').split(',') if item.strip()]
    except (configparser.Error, KeyError, ValueError):
        raise ValueError('Не удалось подготовить подключение. Попробуйте позже.') from None
    payload = {
        'containers': [{'container': 'amnezia-awg', 'awg': {
            'last_config': json.dumps(last, ensure_ascii=False),
            'isThirdPartyConfig': True, 'port': port, 'transport_proto': 'udp',
        }}],
        'defaultContainer': 'amnezia-awg', 'description': name, 'hostName': last['hostName'],
    }
    if dns:
        payload.update(dns1=dns[0], dns2=dns[1] if len(dns) > 1 else dns[0])
    data = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    # Qt qCompress prepends the uncompressed size, then writes a zlib stream.
    compressed = len(data).to_bytes(4, 'big') + zlib.compress(data, 8)
    return 'vpn://' + base64.urlsafe_b64encode(compressed).decode().rstrip('=')
