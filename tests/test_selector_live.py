"""Exercise connection preservation against the pinned sing-box binary."""
import contextlib
import json
import os
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest
import controller


def free_ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(('127.0.0.1', 0))
        return [sock.getsockname()[1] for sock in sockets]


def receive(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise ConnectionError('connection closed')
        result += part
    return result


def socks_request(port, target, command=1):
    sock = socket.create_connection(('127.0.0.1', port), timeout=2)
    sock.sendall(b'\x05\x01\x00')
    assert receive(sock, 2) == b'\x05\x00'
    sock.sendall(b'\x05' + bytes([command, 0, 1]) + socket.inet_aton('127.0.0.1') + struct.pack('!H', target))
    header = receive(sock, 4)
    if header[1]:
        sock.close()
        raise ConnectionError('SOCKS rejected')
    assert header[3] == 1
    address = socket.inet_ntoa(receive(sock, 4))
    relay_port = struct.unpack('!H', receive(sock, 2))[0]
    return sock, (address, relay_port)


def tcp_echo(listener):
    def connection(sock):
        with sock:
            try:
                while data := sock.recv(4096):
                    sock.sendall(data)
            except OSError:
                pass
    while True:
        try:
            sock, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=connection, args=(sock,), daemon=True).start()


def udp_echo(sock):
    while True:
        try:
            data, address = sock.recvfrom(4096)
            sock.sendto(data, address)
        except OSError:
            return


def test_live_failover_preserves_tcp_udp_and_rejects_unavailable(tmp_path, monkeypatch):
    binary = os.getenv('SING_BOX_BINARY')
    if not binary:
        pytest.skip('Set SING_BOX_BINARY for live selector test')
    api, inbound, reject = free_ports(3)
    monkeypatch.setattr(controller, 'CONTROL_ADDRESS', f'127.0.0.1:{api}')
    secret = 'ephemeral-test-control-secret'
    config = {'log': {'level': 'error'}, 'inbounds': [
        {'type': 'socks', 'tag': 'client', 'listen': '127.0.0.1', 'listen_port': inbound},
        {'type': 'socks', 'tag': 'ru-reject', 'listen': '127.0.0.1', 'listen_port': reject}],
        'outbounds': [{'type': 'direct', 'tag': 'ru-1'}, {'type': 'direct', 'tag': 'ru-2'},
            {'type': 'socks', 'tag': 'ru-unavailable', 'server': '127.0.0.1', 'server_port': reject},
            {'type': 'selector', 'tag': 'ru-policy-2-1', 'outbounds': ['ru-2', 'ru-1', 'ru-unavailable'],
             'default': 'ru-unavailable', 'interrupt_exist_connections': False}],
        'route': {'rules': [{'inbound': 'ru-reject', 'action': 'reject'}], 'final': 'ru-policy-2-1'},
        'experimental': {'clash_api': {'external_controller': f'127.0.0.1:{api}', 'secret': secret}}}
    path = tmp_path / 'live.json'
    path.write_text(json.dumps(config))
    with contextlib.ExitStack() as stack:
        tcp = stack.enter_context(socket.socket())
        tcp.bind(('127.0.0.1', 0)); tcp.listen()
        udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        udp.bind(('127.0.0.1', 0))
        threading.Thread(target=tcp_echo, args=(tcp,), daemon=True).start()
        threading.Thread(target=udp_echo, args=(udp,), daemon=True).start()
        process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(process.wait, timeout=5)
        stack.callback(process.terminate)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = f'http://127.0.0.1:{api}/proxies/ru-policy-2-1'
        request = urllib.request.Request(url, headers={'Authorization': f'Bearer {secret}'})
        for _ in range(100):
            try:
                with opener.open(request, timeout=1):
                    break
            except urllib.error.URLError:
                if process.poll() is not None:
                    pytest.fail('sing-box failed to start')
                time.sleep(0.05)
        else:
            pytest.fail('selector API did not start')
        with pytest.raises(urllib.error.HTTPError) as denied:
            opener.open(url, timeout=1)
        assert denied.value.code == 401
        selected = {}
        controller.sync_selectors(config, {'1': True, '2': True}, selected, secret)
        stream, _ = socks_request(inbound, tcp.getsockname()[1])
        stack.enter_context(stream)
        association, relay = socks_request(inbound, 0, command=3)
        stack.enter_context(association)
        datagrams = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        datagrams.settimeout(2)
        packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.getsockname()[1])
        for index, health in enumerate([{'1': True, '2': True}, {'1': True, '2': False},
                                        {'1': False, '2': False}, {'1': True, '2': True}]):
            controller.sync_selectors(config, health, selected, secret)
            payload = f'ongoing-{index}'.encode()
            stream.sendall(payload)
            assert receive(stream, len(payload)) == payload
            datagrams.sendto(packet + payload, relay)
            assert datagrams.recvfrom(4096)[0].endswith(payload)
            assert process.poll() is None
            if not any(health.values()):
                with pytest.raises(ConnectionError):
                    socks_request(inbound, tcp.getsockname()[1])
            else:
                fresh, _ = socks_request(inbound, tcp.getsockname()[1])
                with fresh:
                    fresh.sendall(payload)
                    assert receive(fresh, len(payload)) == payload
        with opener.open(request, timeout=1) as response:
            assert json.load(response)['now'] == 'ru-2'
