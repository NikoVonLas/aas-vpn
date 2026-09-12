"""OIDC integration with a signed, deterministic provider stub; no external login."""
import hashlib
import base64
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from conftest import admin_login, post
import oidc

ISSUER = 'https://sso.example.test/realms/vpn'
CONFIG = {'issuer': ISSUER, 'client_id': 'vpn', 'client_secret': 'test-only-secret'}


@pytest.fixture
def provider(portal, monkeypatch):
    app, client = portal
    key = RSAKey.generate_key(2048)
    key.ensure_kid()
    wrong_key = RSAKey.generate_key(2048)
    state = {'claims': {}, 'subject': 'external-person', 'requests': []}
    with app.auth_store.db() as con:
        con.execute("UPDATE providers SET enabled=1,config=? WHERE id='oidc'", (json.dumps(CONFIG),))
        con.execute("UPDATE roles SET primary_methods='[\"password\",\"oidc\"]' WHERE id='administrator'")
    def handle(request):
        state['requests'].append(request)
        if request.url.path.endswith('openid-configuration'):
            return httpx.Response(200, json={'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/auth',
                'token_endpoint': ISSUER + '/token', 'jwks_uri': ISSUER + '/certs', 'id_token_signing_alg_values_supported': ['RS256']})
        if request.url.path.endswith('/certs'):
            return httpx.Response(200, json={'keys': [key.as_dict(private=False)]})
        assert request.url.path.endswith('/token')
        data = parse_qs(request.content.decode())
        challenge = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'][0].encode()).digest()).decode().rstrip('=')
        assert challenge == state['params']['code_challenge'][0]
        assert data['client_secret'] == [CONFIG['client_secret']]
        assert data['redirect_uri'] == ['https://portal.example.test' + oidc.CALLBACK]
        claims = {'iss': ISSUER, 'sub': state['subject'], 'aud': 'vpn', 'iat': int(time.time()),
                  'exp': int(time.time()) + 300, 'nonce': state['params']['nonce'][0], **state['claims']}
        return httpx.Response(200, json={'id_token': jwt.encode({'alg': 'RS256', 'kid': key.kid}, claims, wrong_key if state.get('wrong_key') else key)})
    original = httpx.AsyncClient
    monkeypatch.setattr(oidc.httpx, 'AsyncClient', lambda **kw: original(transport=httpx.MockTransport(handle), **kw))
    return app, client, state


def start(client, state, purpose='login'):
    response = post(client, '/login/oidc/start', {'purpose': purpose})
    assert response.status_code == 303
    state['params'] = parse_qs(urlsplit(response.headers['location']).query)
    assert state['params']['code_challenge_method'] == ['S256']
    return {'state': state['params']['state'][0], 'code': 'one-use-code'}


def link(app, client, state):
    admin_login(app, client)
    response = client.get(oidc.CALLBACK, params=start(client, state, 'link'))
    assert response.status_code == 303
    assert response.headers['location'] == '/security'


def test_link_login_mfa_and_no_changes_to_devices_or_grants(provider):
    app, client, state = provider
    with app.db() as con:
        before = [tuple(r) for r in con.execute('SELECT * FROM devices')]
    link(app, client, state)
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET require_2fa=1 WHERE id='administrator'")
    client.cookies.delete(app.auth.COOKIE)
    params = start(client, state)
    response = client.get(oidc.CALLBACK, params=params)
    assert response.status_code == 303
    assert response.headers['location'] == '/security'
    actor = app.identities.session(client.cookies.get(app.auth.COOKIE), limited=True)
    assert not actor['ready']
    assert json.loads(actor['methods']) == ['oidc']
    assert client.get(oidc.CALLBACK, params=params).status_code == 400
    with app.db() as con:
        assert [tuple(r) for r in con.execute('SELECT * FROM devices')] == before


@pytest.mark.parametrize('claims', [{'iss': 'https://attacker.test'}, {'aud': 'other'}, {'nonce': 'other'},
    {'exp': 1}, {'iat': int(time.time()) + 1000}, {'azp': 'other'}, {'sub': ''}, {'aud': ['vpn', 'other']}])
def test_reject_bad_signed_claims(provider, claims):
    app, client, state = provider
    admin_login(app, client)
    state['claims'] = claims
    assert client.get(oidc.CALLBACK, params=start(client, state, 'link')).status_code == 400
    with app.auth_store.db() as con:
        assert con.execute('SELECT count(*) FROM oidc_links').fetchone()[0] == 0


def test_no_automatic_link_by_email_or_admin_claim(provider):
    app, client, state = provider
    state['claims'] = {'email': 'admin@example.test', 'roles': ['administrator']}
    assert client.get(oidc.CALLBACK, params=start(client, state)).status_code == 400
    assert not client.cookies.get(app.auth.COOKIE)


def test_flow_browser_binding_and_expiry(provider):
    app, client, state = provider
    params = start(client, state)
    browser = client.cookies.get(oidc.COOKIE)
    client.cookies.delete(oidc.COOKIE)
    assert client.get(oidc.CALLBACK, params=params).status_code == 400
    client.cookies.set(oidc.COOKIE, browser, domain='portal.example.test')
    with app.auth_store.db() as con:
        con.execute('UPDATE oidc_flows SET expires=0')
    assert client.get(oidc.CALLBACK, params=params).status_code == 400
    assert not any(r.url.path.endswith('/token') for r in state['requests'])


@pytest.mark.parametrize('change', ['disabled', 'client', 'role', 'session'])
def test_changed_configuration_or_session_cannot_link(provider, change):
    app, client, state = provider
    admin_login(app, client)
    params = start(client, state, 'link')
    with app.auth_store.db() as con:
        if change == 'disabled':
            con.execute("UPDATE providers SET enabled=0 WHERE id='oidc'")
        elif change == 'client':
            con.execute("UPDATE providers SET config=? WHERE id='oidc'", (json.dumps({**CONFIG, 'client_id': 'other'}),))
        elif change == 'role':
            con.execute("UPDATE roles SET primary_methods='[\"password\"]' WHERE id='administrator'")
        else:
            con.execute('DELETE FROM identity_sessions')
    assert client.get(oidc.CALLBACK, params=params).status_code in {303, 400}
    with app.auth_store.db() as con:
        assert con.execute('SELECT count(*) FROM oidc_links').fetchone()[0] == 0


def test_last_login_guard_and_provider_disable_revokes_sessions(provider):
    app, client, state = provider
    link(app, client, state)
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET primary_methods='[\"oidc\"]' WHERE id='administrator'")
    assert client.get(oidc.CALLBACK, params=start(client, state)).status_code == 303
    assert post(client, '/security/oidc/delete').status_code == 400
    assert post(client, '/admin/login-methods/oidc', CONFIG).status_code == 400
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET primary_methods='[\"password\",\"oidc\"]' WHERE id='administrator'")
    token = client.cookies.get(app.auth.COOKIE)
    assert post(client, '/admin/login-methods/oidc', CONFIG).status_code == 303
    assert app.identities.session(token, limited=True) is None


def test_oidc_ui_and_csrf(provider):
    app, client, state = provider
    assert 'Войти через OpenID Connect' in client.get('/').text
    assert client.post('/login/oidc/start').status_code == 403
    admin_login(app, client)
    assert 'Привязать аккаунт' in client.get('/security').text
    response = client.get('/admin/login-methods')
    assert CONFIG['client_secret'] not in response.text
    assert 'https://portal.example.test/login/oidc/callback' in response.text


def test_reject_signature_from_another_key(provider):
    app, client, state = provider
    admin_login(app, client)
    state['wrong_key'] = True
    assert client.get(oidc.CALLBACK, params=start(client, state, 'link')).status_code == 400
    with app.auth_store.db() as con:
        assert con.execute('SELECT count(*) FROM oidc_links').fetchone()[0] == 0


def test_binding_cannot_replace_existing_subject(provider):
    app, client, state = provider
    link(app, client, state)
    state['subject'] = 'another-person'
    assert client.get(oidc.CALLBACK, params=start(client, state, 'link')).status_code == 400
    with app.auth_store.db() as con:
        assert con.execute('SELECT subject FROM oidc_links').fetchone()[0] == 'external-person'


@pytest.mark.parametrize('issuer', ['http://sso.example.test', 'https://user:secret@sso.example.test', 'https://sso.example.test?query=1'])
def test_provider_rejects_unsafe_urls(provider, issuer):
    app, client, state = provider
    admin_login(app, client)
    assert post(client, '/admin/login-methods/oidc', {**CONFIG, 'issuer': issuer, 'enabled': '1'}).status_code == 400
    with app.auth_store.db() as con:
        assert json.loads(con.execute("SELECT config FROM providers WHERE id='oidc'").fetchone()[0]) == CONFIG
