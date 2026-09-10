"""Provider integration against a local TLS SMTP server and a Zvonok stub."""
import asyncio
from email import policy
from email.parser import BytesParser
import json
import queue
import socketserver
import ssl
import subprocess
import threading

import httpx
import pytest

from login_methods import EmailProvider, ZvonokProvider


class SMTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        connection = self.request
        if self.server.implicit:
            connection = self.server.tls.wrap_socket(connection, server_side=True)
        stream = connection.makefile('rwb')
        def reply(value):
            stream.write(value + b'\r\n'); stream.flush()
        reply(b'220 localhost fixture')
        try:
            while True:
                command = stream.readline()
                if not command:
                    return
                verb = command.split()[0].upper()
                if verb == b'EHLO':
                    reply(b'250-localhost\r\n250 STARTTLS')
                elif verb == b'STARTTLS':
                    reply(b'220 Start TLS')
                    stream.close()
                    connection = self.server.tls.wrap_socket(connection, server_side=True)
                    stream = connection.makefile('rwb')
                elif verb == b'DATA':
                    reply(b'354 Send message')
                    lines = []
                    while (line := stream.readline()) != b'.\r\n':
                        if not line:
                            return
                        lines.append(line)
                    self.server.messages.put(b''.join(lines))
                    reply(b'250 Accepted')
                elif verb == b'QUIT':
                    reply(b'221 Goodbye')
                    return
                else:
                    reply(b'250 OK')
        finally:
            stream.close()
            connection.close()


@pytest.mark.parametrize('mode', ['implicit', 'starttls'])
def test_smtp_verified_tls_one_email_contains_code_and_link(tmp_path, monkeypatch, mode):
    certificate, private_key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(private_key), '-out', str(certificate), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, private_key)
    client_context = ssl.create_default_context(cafile=str(certificate))
    assert client_context.check_hostname
    assert client_context.verify_mode == ssl.CERT_REQUIRED
    monkeypatch.setattr(ssl, 'create_default_context', lambda: client_context)
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), SMTPHandler) as server:
        server.tls, server.implicit, server.messages = server_context, mode == 'implicit', queue.Queue()
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            asyncio.run(EmailProvider.begin({'host': 'localhost', 'port': server.server_address[1], 'tls': mode, 'sender': 'sender@example.test'},
                                           'person@example.test', '123456', 'https://portal.example.test/login/link#fixture'))
            message = BytesParser(policy=policy.default).parsebytes(server.messages.get(timeout=2))
            assert message['To'] == 'person@example.test'
            body = message.get_content()
            assert '123456' in body
            assert 'https://portal.example.test/login/link#fixture' in body
            assert server.messages.empty()
        finally:
            server.shutdown(); worker.join(timeout=2)


def test_zvonok_begin_and_verify_are_bound_to_call(monkeypatch):
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path.endswith('/confirm/'):
            return httpx.Response(200, json={'call_id': 'fixture-call', 'confirm_phone': '+79990000009'})
        assert request.url.params['call_id'] == 'fixture-call'
        return httpx.Response(200, json={'status': 'confirmed'})
    original_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, 'AsyncClient', lambda **kwargs: original_client(transport=httpx.MockTransport(handler)))
    async def run():
        config = {'public_key': 'fixture', 'campaign_id': 'fixture'}
        attempt = await ZvonokProvider.begin(config, '+79990000001')
        assert attempt['phone'] == '+79990000001'
        assert await ZvonokProvider.verify(config, attempt)
    asyncio.run(run())
    assert len(calls) == 2
