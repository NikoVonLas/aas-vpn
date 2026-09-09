"""Check running legacy identities against its database without exposing keys."""
import json
from pathlib import Path
import sqlite3
import subprocess


def output(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


def main():
    metadata = json.loads(output('docker', 'inspect', 'awg2'))[0]
    source = next(mount['Source'] for mount in metadata['Mounts'] if mount['Destination'] == '/etc/wireguard')
    con = sqlite3.connect(f'file:{Path(source)/"wg-easy.db"}?mode=ro', uri=True)
    try:
        expected = {row[0] for row in con.execute('SELECT public_key FROM clients_table WHERE enabled=1')}
        public_key = con.execute('SELECT public_key FROM interfaces_table').fetchone()[0]
    finally:
        con.close()
    actual = set(output('docker', 'exec', '--user', '0:0', 'awg2', 'awg', 'show', 'wg0', 'peers').split())
    server = output('docker', 'exec', '--user', '0:0', 'awg2', 'awg', 'show', 'wg0', 'public-key')
    if actual != expected or server != public_key:
        raise SystemExit('Running tunnel identities differ from stored configuration; migration stopped')
    print(f'Running peer identities verified: {len(actual)}')


if __name__ == '__main__':
    main()
