"""Disposable Docker networks exercise DNAT replies and the forwarding guard."""
import json
import os
from pathlib import Path
import subprocess

IMAGE = os.getenv('ROUTER_TEST_IMAGE', 'aas-vpn-router:native-test')
PREFIX = 'aas-guard-check'
ROOT = Path(__file__).resolve().parents[1]


def docker(*args, input=None, check=True):
    result = subprocess.run(['docker', *args], input=input, text=True,
                            capture_output=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError('Guard check failed: ' + ' '.join(args[:3]))
    return result.stdout


def execute(name, *args, input=None):
    return docker('exec', '-i', PREFIX + '-' + name, *args, input=input)


def address(name, network):
    state = json.loads(docker('inspect', PREFIX + '-' + name))[0]
    return state['NetworkSettings']['Networks'][PREFIX + '-' + network]['IPAddress']


def start(name, network):
    docker('run', '-d', '--name', PREFIX + '-' + name,
           '--network', PREFIX + '-' + network, '--user', '0:0',
           '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--cap-add', 'NET_RAW',
           '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv4.conf.all.rp_filter=2',
           '--sysctl', 'net.ipv4.conf.default.rp_filter=2',
           '-v', f'{ROOT}:/source:ro', '--entrypoint', 'sleep', IMAGE, '300')


def exchange(name, target, port, expected, source=''):
    program = '''import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1)
if sys.argv[4]: s.bind((sys.argv[4],1234))
s.sendto(b'guard-check',(sys.argv[1],int(sys.argv[2])))
try:
 data,peer=s.recvfrom(100)
 ok=data==b'guard-check' and peer==(sys.argv[1],int(sys.argv[2]))
except TimeoutError: ok=False
assert ok==(sys.argv[3]=='True'), 'Unexpected forwarding result'
'''
    execute(name, 'python', '-c', program, target, str(port), str(expected), source)


def apply_guard(awg_ip, cidr):
    execute('router', 'python', '-c',
            "import os,sys; os.environ.update(AWG_CONTAINER_IP=sys.argv[1], VPN_DOCKER_CIDR=sys.argv[2]); "
            "sys.path[:0]=['/source/portal','/source/router']; import controller; controller.network_guard()",
            awg_ip, cidr)


def check():
    for network in ['inner', 'outer']:
        docker('network', 'create', '--internal', PREFIX + '-' + network)
    start('router', 'outer')
    docker('network', 'connect', PREFIX + '-inner', PREFIX + '-router')
    start('server', 'inner')
    start('client', 'outer')
    inner = address('router', 'inner')
    outer = address('router', 'outer')
    server = address('server', 'inner')
    client = address('client', 'outer')
    network = json.loads(docker('network', 'inspect', PREFIX + '-inner'))[0]
    cidr = network['IPAM']['Config'][0]['Subnet']
    execute('router', 'python', '-c', '''import json,subprocess,sys
def run(*a): return subprocess.check_output(a,text=True)
address=sys.argv[1]
row=next(r for r in json.loads(run('ip','-j','addr')) if any(a.get('local')==address for a in r['addr_info']))
prefix=next(a['prefixlen'] for a in row['addr_info'] if a.get('local')==address)
run('ip','link','add','br-check','type','bridge')
run('ip','addr','del',f'{address}/{prefix}','dev',row['ifname'])
run('ip','link','set',row['ifname'],'master','br-check')
run('ip','link','set','br-check','up')
run('ip','addr','add',f'{address}/{prefix}','dev','br-check')
''', inner)
    execute('server', 'ip', 'route', 'replace', client + '/32', 'via', inner)
    echo = '''import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',1234))
while True:
 data,peer=s.recvfrom(100); s.sendto(data,peer)
'''
    for name in ['server', 'client']:
        docker('exec', '-d', PREFIX + '-' + name, 'python', '-c', echo)
    execute('router', 'nft', '-f', '-', input=f'''table ip test_nat {{
chain prerouting {{ type nat hook prerouting priority dstnat; policy accept;
ip daddr {outer} udp dport 443 dnat to {server}:1234
}}
}}
''')
    apply_guard(server, cidr)
    rules = execute('router', 'nft', '-a', 'list', 'chain', 'inet', 'aas_guard', 'forward')
    line = next(line for line in rules.splitlines() if 'aas-awg-encrypted-replies' in line)
    handle = line.rsplit('# handle ', 1)[1].strip()
    execute('router', 'nft', 'delete', 'rule', 'inet', 'aas_guard', 'forward', 'handle', handle)
    exchange('client', outer, 443, False)
    print('Original guard reproduces lost DNAT replies: passed', flush=True)
    apply_guard(server, cidr)
    exchange('client', outer, 443, True)
    print('Public UDP 443 replies retain port after DNAT to 1234: passed', flush=True)
    # Sending from the tunnel port is insufficient: this is an original flow.
    docker('exec', PREFIX + '-server', 'pkill', '-f', 's.bind', check=False)
    exchange('server', client, 1234, False, server)
    execute('server', 'ip', 'addr', 'add', '10.91.0.2/32', 'dev', 'lo')
    exchange('server', client, 1234, False, '10.91.0.2')
    print('Container and inner client traffic remain blocked without router: passed', flush=True)
    docker('exec', '-d', PREFIX + '-server', 'python', '-c', echo)
    apply_guard(server, cidr)
    exchange('client', outer, 443, True)
    print('Guard recreation preserves transport exception: passed', flush=True)


if __name__ == '__main__':
    try:
        check()
    finally:
        for name in ['client', 'server', 'router']:
            docker('rm', '-f', PREFIX + '-' + name, check=False)
        for network in ['inner', 'outer']:
            docker('network', 'rm', PREFIX + '-' + network, check=False)
