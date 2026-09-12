import json
import subprocess

import pytest
import controller
from types import SimpleNamespace


def test_rejected_check_does_not_stop_working_process(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, 'WORK', tmp_path)
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, 'sing-box')
    monkeypatch.setattr(controller, 'run', fail)
    monkeypatch.setattr(controller, 'stop_child', lambda: pytest.fail('working process was stopped before validation'))
    with pytest.raises(subprocess.CalledProcessError):
        controller.apply({'bad':True})


def test_start_failure_restores_matching_working_config(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, 'WORK', tmp_path)
    working = {'accepted':True}
    (tmp_path / 'working.json').write_text(json.dumps(working))
    calls = []
    monkeypatch.setattr(controller, 'run', lambda *a, **k: None)
    monkeypatch.setattr(controller, 'stop_child', lambda: calls.append('stop'))
    def start(path):
        calls.append(path.name)
        if path.name == 'candidate.json':
            raise RuntimeError('bind failure')
    monkeypatch.setattr(controller, 'start_child', start)
    with pytest.raises(RuntimeError):
        controller.apply({'new':True})
    assert calls == ['stop','candidate.json','stop','working.json']
    assert json.loads((tmp_path / 'working.json').read_text()) == working


def test_success_updates_working_copy_after_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, 'WORK', tmp_path)
    monkeypatch.setattr(controller, 'run', lambda *a, **k: None)
    monkeypatch.setattr(controller, 'stop_child', lambda: None)
    monkeypatch.setattr(controller, 'start_child', lambda path: None)
    controller.apply({'new':True})
    assert json.loads((tmp_path / 'working.json').read_text()) == {'new':True}
    assert (tmp_path / 'working.json').stat().st_mode & 0o777 == 0o600


def test_network_snapshot_preserves_ru_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, 'DATA', tmp_path)
    monkeypatch.setenv('AWG_NETWORK_FILE', str(tmp_path / 'wg-network.json'))
    monkeypatch.setattr(controller, 'VPN_CIDR', '')
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=b'[{"dst":"10.8.0.0/24","dev":"wg-ru"}]')
    monkeypatch.setattr(controller, 'run', run)
    with pytest.raises(ValueError, match='Waiting'):
        controller.sync_network_routes('br-test')
    assert calls == []
    (tmp_path / 'wg-network.json').write_text('{"cidrs":["10.19.0.0/24"]}')
    controller.sync_network_routes('br-test')
    assert calls[-1] == ('ip','route','replace','10.19.0.0/24','via',controller.AWG_IP,'dev','br-test')
    (tmp_path / 'wg-network.json').write_text('{"cidrs":["10.19.0.0/24"],"mtus":{"10.19.0.0/24":1280}}')
    controller.sync_network_routes('br-test')
    assert calls[-1][-2:] == ('mtu', '1280')
    calls.clear()
    (tmp_path / 'wg-network.json').write_text('{"cidrs":["10.8.0.0/24"]}')
    with pytest.raises(ValueError, match='overlaps'):
        controller.sync_network_routes('br-test')
    assert not any('replace' in args for args in calls)


def test_wireguard_peer_uses_actual_underlay_route(monkeypatch):
    controller.endpoint_transport.cache_clear()
    calls = []
    def route(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=b'[{"dev":"br-vpn","gateway":"192.0.2.45","metrics":[{"mtu":1280}]}]')
    monkeypatch.setattr(controller, 'run', route)
    config = {'endpoints': [{'peers': [{'address': '10.19.0.45', 'port': 41495}]},
                            {'listen_port': 51820, 'peers': [{}]}]}
    controller.bind_endpoint_interfaces(config)
    assert config['endpoints'][0]['bind_interface'] == 'br-vpn'
    assert config['endpoints'][0]['mtu'] == 1200
    assert 'bind_interface' not in config['endpoints'][1]
    assert calls == [('ip','-j','route','get','10.19.0.45','mark','0x2024')]
    controller.endpoint_transport.cache_clear()


def test_endpoint_mtu_uses_link_and_preserves_explicit_value(monkeypatch):
    controller.endpoint_transport.cache_clear()
    def route(*args, **kwargs):
        return SimpleNamespace(stdout=b'[{"dev":"eth0"}]' if 'route' in args else b'[{"mtu":1500}]')
    monkeypatch.setattr(controller, 'run', route)
    config = {'endpoints': [{'peers': [{'address': '192.0.2.1'}]},
                            {'mtu': 1100, 'peers': [{'address': '192.0.2.1'}]}]}
    controller.bind_endpoint_interfaces(config)
    assert config['endpoints'][0]['mtu'] == 1408
    assert config['endpoints'][1]['mtu'] == 1100
    controller.endpoint_transport.cache_clear()


def test_supervisor_only_recompiles_changed_model_or_health(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, 'WORK', tmp_path)
    monkeypatch.setattr(controller, 'process', SimpleNamespace(poll=lambda: None))
    monkeypatch.setattr(controller, 'bind_endpoint_interfaces', lambda *args: None)
    monkeypatch.setattr(controller, 'apply', lambda config: None)
    builds = []
    def compile(*args):
        builds.append(args)
        return {'route': {'rules': []}}
    monkeypatch.setattr(controller, 'compile_config', compile)
    supervisor = controller.Supervisor('br-test')
    model = {'revision': 1, 'exits': [], 'devices': [], 'rules': [], 'default': 1}
    for _ in range(5):
        supervisor.install({}, model, {'1': {'healthy': True}})
    assert len(builds) == 1
    supervisor.install({}, model, {'1': {'healthy': False}})
    assert len(builds) == 2
    model['revision'] = 2
    supervisor.install({}, model, {'1': {'healthy': False}})
    assert len(builds) == 3


def test_dns_change_reconnects_with_same_underlay_and_retains_address_on_failure(tmp_path, monkeypatch):
    controller.endpoint_transport.cache_clear()
    monkeypatch.setattr(controller, 'WORK', tmp_path)
    monkeypatch.setattr(controller, 'process', SimpleNamespace(poll=lambda: None))
    clock = [0]
    answer = ['192.0.2.1']
    queries, applied = [], []
    monkeypatch.setattr(controller.time, 'monotonic', lambda: clock[0])

    def resolve(*args, **kwargs):
        queries.append(args)
        if answer[0] is None:
            raise subprocess.TimeoutExpired('getent', 2)
        return SimpleNamespace(stdout=answer[0] + ' exit.example\n')

    monkeypatch.setattr(controller.subprocess, 'run', resolve)
    monkeypatch.setattr(controller, 'run', lambda *a, **k: SimpleNamespace(
        stdout=b'[{"dev":"eth0","metrics":[{"mtu":1500}]}]'))
    compiled = {'endpoints': [{'peers': [{'address': 'exit.example', 'port': 41495}]}]}
    monkeypatch.setattr(controller, 'compile_config', lambda *args: compiled)
    monkeypatch.setattr(controller, 'apply', lambda config: applied.append(config))
    supervisor = controller.Supervisor('br-test')
    model = {'revision': 1, 'exits': [], 'devices': [], 'rules': [], 'default': 1}
    try:
        supervisor.install({}, model, {})
        assert applied[0]['endpoints'][0]['peers'][0]['address'] == '192.0.2.1'
        answer[0] = '192.0.2.2'
        clock[0] = 59
        supervisor.install({}, model, {})
        assert len(queries) == 1
        assert len(applied) == 1

        clock[0] = 60
        supervisor.install({}, model, {})
        assert len(applied) == 2
        assert applied[1]['endpoints'][0]['peers'][0] == {'address': '192.0.2.2', 'port': 41495}
        assert applied[1]['endpoints'][0]['bind_interface'] == 'eth0'
        assert compiled['endpoints'][0]['peers'][0]['address'] == 'exit.example'

        for timestamp, value in [(120, '192.0.2.2'), (180, None), (240, '192.0.2.2')]:
            clock[0], answer[0] = timestamp, value
            supervisor.install({}, model, {})
        assert len(applied) == 2
        assert len(queries) == 5

        clock[0], answer[0] = 300, '192.0.2.3'
        supervisor.install({}, model, {})
        assert len(applied) == 3
        assert applied[-1]['endpoints'][0]['peers'][0]['address'] == '192.0.2.3'
    finally:
        controller.endpoint_transport.cache_clear()


def test_failed_initial_dns_resolution_recovers_and_removed_peers_are_discarded(monkeypatch):
    path = {'address': '192.0.2.8', 'interface': 'eth0', 'mtu': 1408}
    bindings = {'removed.example': path}
    monkeypatch.setattr(controller, 'endpoint_transport', lambda *args: None)
    config = {'endpoints': [{'peers': [{'address': 'exit.example'}]}]}
    controller.bind_endpoint_interfaces(config, bindings)
    assert config['endpoints'][0]['peers'][0]['address'] == 'exit.example'
    assert 'removed.example' not in bindings
    monkeypatch.setattr(controller, 'endpoint_transport', lambda *args: path)
    controller.bind_endpoint_interfaces(config, bindings)
    assert config['endpoints'][0]['peers'][0]['address'] == '192.0.2.8'
