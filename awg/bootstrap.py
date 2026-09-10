"""Initialize a new server explicitly; never replace existing configuration."""
import argparse
import ipaddress
import json
import os
import re
import secrets

from model import Store, run


def bootstrap(endpoint, public_port, network, dns, directory):
    if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', endpoint) or not 1 <= public_port <= 65535:
        raise ValueError('Invalid public endpoint')
    network = str(ipaddress.IPv4Network(network, strict=False))
    dns = str(ipaddress.IPv4Address(dns))
    store = Store(directory)
    store.initialize()
    with store.db() as con:
        if con.execute("SELECT 1 FROM settings WHERE key='server'").fetchone():
            raise ValueError('Server already initialized')
        private = run('awg', 'genkey')
        server = {'name': 'wg0', 'device': 'eth0', 'port': 1234, 'private_key': private,
                  'public_key': run('awg', 'pubkey', input=private + '\n'), 'ipv4_cidr': network, 'mtu': 1280,
                  'enabled': 1, 'j_c': 4, 'j_min': 40, 'j_max': 70, 's1': 15, 's2': 20, 's3': 0, 's4': 0}
        headers = set()
        while len(headers) < 4:
            headers.add(secrets.randbelow(2147483640) + 5)
        server.update({f'h{i}': str(header) for i, header in enumerate(sorted(headers), 1)})
        defaults = {'host': endpoint, 'port': public_port, 'default_dns': [dns], 'default_allowed_ips': ['0.0.0.0/0'],
                    'default_mtu': 1280, 'default_persistent_keepalive': 25, 'default_j_c': 4, 'default_j_min': 40, 'default_j_max': 70}
        con.executemany('INSERT INTO settings VALUES(?,?)', [('server', json.dumps(server)), ('defaults', json.dumps(defaults))])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--public-port', type=int, default=443)
    parser.add_argument('--network', help='Client IPv4 subnet selected for this server')
    parser.add_argument('--dns', help='AdGuard IPv4 address reachable by this server')
    args = parser.parse_args()
    if args.check:
        store = Store(os.getenv('AWG_DATA', '/awg-data'))
        store.initialize()
        with store.db() as con:
            ready = con.execute("SELECT 1 FROM settings WHERE key='server'").fetchone()
        raise SystemExit(0 if ready else 1)
    if not all([args.endpoint, args.network, args.dns]):
        parser.error('--endpoint, --network and --dns are required for initialization')
    bootstrap(args.endpoint, args.public_port, args.network, args.dns, os.getenv('AWG_DATA', '/awg-data'))
    print('Server initialized')


if __name__ == '__main__':
    main()
