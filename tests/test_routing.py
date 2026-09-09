import copy
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from conftest import WG, KEY, ROOT
from routing import parse_wireguard, normalize_rule, compile_config, effective_exit, rule_order, migrate
from controller import advance


@pytest.mark.parametrize('line', ['PreUp = secret', 'PostUp = secret', 'PreDown = secret', 'PostDown = secret', 'SaveConfig = true', 'Something = secret'])
def test_reject_hooks_and_unknowns(line):
    with pytest.raises(ValueError) as exc:
        parse_wireguard(WG.replace('[Peer]', line + '\n[Peer]'))
    assert 'secret' not in str(exc.value) and KEY not in str(exc.value)


def test_wireguard_and_keenetic():
    wg = parse_wireguard(WG)
    assert wg['peers'][0]['port'] == 51820 and wg['peers'][0]['allowed_ips'] == ['0.0.0.0/0']
    assert 'dns' not in wg
    keenetic = WG.replace('Address =', 'ListenPort = 51820\nMTU = 1380\nAddress =').replace('Endpoint = 192.0.2.1:51820\n', '')
    wg = parse_wireguard(keenetic)
    assert wg['listen_port'] == 51820 and 'address' not in wg['peers'][0]
    for bad in [WG.replace(KEY, 'invalid'), WG.replace('Endpoint = 192.0.2.1:51820\n', ''), WG.replace('0.0.0.0/0, ::/0', '10.0.0.0/8'), WG * 2]:
        with pytest.raises(ValueError):
            parse_wireguard(bad)


@pytest.mark.parametrize('value,expected', [('EXAMPLE.RU.', ('domain','example.ru')), ('.РФ', ('suffix','xn--p1ai')), ('10.3.2.1/16', ('ip','10.3.0.0/16')), ('192.0.2.1', ('ip','192.0.2.1/32'))])
def test_normalization(value, expected):
    assert normalize_rule(value) == expected


@pytest.mark.parametrize('bad', ['http://example.ru', '*.ru', '..ru', 'example..ru', '0.0.0.999', '::/0', '-bad.ru', 'name/path', 'a b.ru'])
def test_invalid_rules(bad):
    with pytest.raises(ValueError):
        normalize_rule(bad)


def build(tmp_path, health=None, default=1):
    base = json.loads((ROOT / 'config/sing-box.json').read_text())
    (tmp_path / 'node.json').write_text(json.dumps(parse_wireguard(WG)))
    exits = [{'id':1, 'legacy':True}, {'id':2, 'legacy':False, 'config_file':'node.json'}]
    devices = [{'id':1,'vpn_ip':'10.8.0.2', 'ru_exit_id':2}, {'id':2,'vpn_ip':'10.8.0.3','ru_exit_id':None}]
    rules = []
    for target, values in [('ru',['.ru','.рф','10.0.0.0/8','10.2.0.0/16','same.ru']),('direct',['example.ru','.sub.ru','10.2.0.0/16'])]:
        for value in values:
            kind, normalized = normalize_rule(value)
            rules.append({'target':target,'kind':kind,'value':normalized})
    return compile_config(base, exits, devices, rules, default, health or {'1':True,'2':True}, 'br-actual', tmp_path)


def route(config, source, domain='', ip='203.0.113.1'):
    # Evaluate the generated sing-box rules against concrete domain/address cases.
    domain = domain.encode('idna').decode().lower()
    for rule in config['route']['rules']:
        if rule.get('inbound') != 'vpn-clients' or rule['action'] == 'sniff':
            continue
        if 'domain' in rule and domain not in rule['domain']:
            continue
        if 'domain_suffix' in rule and not any(domain == x or domain.endswith('.' + x) for x in rule['domain_suffix']):
            continue
        if 'ip_cidr' in rule and not any(ipaddress.ip_address(ip) in ipaddress.ip_network(x) for x in rule['ip_cidr']):
            continue
        if 'source_ip_cidr' in rule and not any(ipaddress.ip_address(source) in ipaddress.ip_network(x) for x in rule['source_ip_cidr']):
            continue
        return rule.get('outbound', 'reject')
    return config['route']['final']


def test_specificity_per_device_fallback_and_boundaries(tmp_path):
    config = build(tmp_path)
    assert route(config,'10.8.0.2','other.ru') == 'ru-2'
    assert route(config,'10.8.0.3','other.ru') == 'ru-1'
    assert route(config,'10.8.0.2','example.ru', '10.1.1.1') == 'eu-direct'
    assert route(config,'10.8.0.2','www.example.ru') == 'ru-2'
    assert route(config,'10.8.0.2','www.sub.ru') == 'eu-direct'
    assert route(config,'10.8.0.2','notsub.ru') == 'ru-2'
    assert route(config,'10.8.0.2','evilru') == 'eu-direct'
    assert route(config,'10.8.0.2','сайт.рф') == 'ru-2'
    assert route(config,'10.8.0.2',ip='10.2.3.4') == 'eu-direct'
    assert route(config,'10.8.0.2',ip='10.1.1.1') == 'ru-2'
    assert route(config,'10.8.0.2','any.ru',ip='10.2.3.4') == 'ru-2'
    assert route(build(tmp_path, {'1':True,'2':False}),'10.8.0.2','any.ru') == 'ru-1'
    assert route(build(tmp_path, {'1':False,'2':False}),'10.8.0.2','any.ru') == 'reject'
    assert route(build(tmp_path, default=2),'10.8.0.3','any.ru') == 'ru-2'
    assert route(build(tmp_path, {'1':False,'2':True}),'10.8.0.2','any.ru') == 'ru-2'
    assert route(build(tmp_path, {'1':False,'2':True}),'10.8.0.3','any.ru') == 'reject'


def test_hysteresis():
    state = {'healthy':True}
    state = advance(state,False); assert state['healthy']
    state = advance(state,False); assert not state['healthy']
    state = advance(state,True); assert not state['healthy']
    state = advance(state,True); assert state['healthy']
    assert effective_exit(2,1,{'1':True,'2':False}) == 1
    assert effective_exit(2,1,{'1':False,'2':False}) is None


def test_sing_box_check(tmp_path):
    binary = os.getenv('SING_BOX_BINARY')
    if not binary:
        pytest.skip('Set SING_BOX_BINARY for sing-box check')
    config = build(tmp_path)
    if sys.platform != 'linux':
        # macOS cannot initialize Linux auto_redirect even in `check` mode.
        next(x for x in config['inbounds'] if x['type'] == 'tun')['auto_redirect'] = False
    for keenetic in [False, True]:
        if keenetic:
            endpoint = config['endpoints'][0]
            endpoint['listen_port'] = 51820
            endpoint['peers'][0].pop('address'); endpoint['peers'][0].pop('port')
        file = tmp_path / 'compiled.json'; file.write_text(json.dumps(config))
        subprocess.run([binary,'check','-c',str(file)], check=True, capture_output=True)


def test_migration_imports_server_rules_once(portal):
    app, _ = portal
    base = json.loads((ROOT / 'config/sing-box.json').read_text())
    base['route']['rules'].append({'domain':['custom.example'], 'outbound':'ru-direct'})
    base['route']['rules'].append({'ip_cidr':['192.0.2.99/24'], 'outbound':'eu-direct'})
    with app.db() as con:
        con.execute("DELETE FROM settings WHERE key IN ('routing_revision','ru_default')")
        con.execute('DELETE FROM ru_exits')
        con.execute('DELETE FROM routing_rules')
        migrate(con,base)
        assert con.execute("SELECT 1 FROM routing_rules WHERE value='custom.example' AND kind='domain' AND target='ru'").fetchone()
        assert con.execute("SELECT 1 FROM routing_rules WHERE value='192.0.2.0/24' AND target='direct'").fetchone()
        assert con.execute("SELECT 1 FROM routing_rules WHERE value='tiktok.com' AND target='direct'").fetchone()
        count = con.execute('SELECT count(*) FROM routing_rules').fetchone()[0]
        migrate(con, {'route':{'rules':[]}})
        assert con.execute('SELECT count(*) FROM routing_rules').fetchone()[0] == count
