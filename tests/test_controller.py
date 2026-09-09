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
    calls.clear()
    (tmp_path / 'wg-network.json').write_text('{"cidrs":["10.8.0.0/24"]}')
    with pytest.raises(ValueError, match='overlaps'):
        controller.sync_network_routes('br-test')
    assert not any('replace' in args for args in calls)


def test_wireguard_peer_uses_actual_underlay_route(monkeypatch):
    controller.endpoint_interface.cache_clear()
    calls = []
    def route(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=b'[{"dev":"br-vpn","gateway":"192.0.2.45"}]')
    monkeypatch.setattr(controller, 'run', route)
    config = {'endpoints': [{'peers': [{'address': '10.19.0.45', 'port': 41495}]},
                            {'listen_port': 51820, 'peers': [{}]}]}
    controller.bind_endpoint_interfaces(config)
    assert config['endpoints'][0]['bind_interface'] == 'br-vpn'
    assert 'bind_interface' not in config['endpoints'][1]
    assert calls == [('ip','-j','route','get','10.19.0.45','mark','0x2024')]
    controller.endpoint_interface.cache_clear()
