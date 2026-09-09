"""Configure a disposable Linux test peer from stdin; never print its keys."""
import configparser
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys


def run(*args):
    result = subprocess.run(args, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError('Test peer command failed')


def main():
    data = json.load(sys.stdin)
    config = configparser.ConfigParser(interpolation=None)
    config.optionxform = str
    config.read_string(data['configuration'])
    address = config['Interface'].pop('Address')
    mtu = config['Interface'].pop('MTU')
    config['Interface'].pop('DNS', None)
    config['Peer']['Endpoint'] = data['endpoint']
    path = Path('/tmp/test-peer.conf')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        config.write(stream)
    run('ip', 'link', 'add', 'wgtest', 'type', 'amneziawg')
    run('ip', 'address', 'add', address, 'dev', 'wgtest')
    run('awg', 'syncconf', 'wgtest', str(path))
    run('ip', 'link', 'set', 'wgtest', 'mtu', mtu, 'up')
    route = str(ipaddress.IPv4Address(data['server'])) + '/32'
    run('ip', 'route', 'add', route, 'dev', 'wgtest')


if __name__ == '__main__':
    main()
