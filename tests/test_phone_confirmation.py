"""Automatic call checks preserve browser binding, policy and one-use completion."""
import time

import pytest

from conftest import post


@pytest.fixture
def call(portal, monkeypatch):
    from login_methods import ZvonokProvider
    app, client = portal
    state = {'confirmed': False, 'checks': 0}

    async def begin(config, address, code, link):
        return {'phone': address, 'call_id': 'fixture', 'dial': '+79990000003'}

    async def verify(config, payload):
        state['checks'] += 1
        return state['confirmed']

    monkeypatch.setattr(ZvonokProvider, 'begin', staticmethod(begin))
    monkeypatch.setattr(ZvonokProvider, 'verify', staticmethod(verify))
    response = post(client, '/login', {'identifier': '+79990000001'})
    assert response.status_code == 303
    return app, client, response.headers['location'], state


def allow_poll(app):
    with app.auth_store.db() as con:
        con.execute("UPDATE challenges SET payload=json_remove(payload,'$.next_poll')")


def test_waiting_does_not_use_attempts_and_limits_provider_requests(call):
    app, client, path, state = call
    for _ in range(12):
        assert post(client, path + '/status').json() == {'state': 'pending'}
    assert state['checks'] == 1
    with app.auth_store.db() as con:
        assert con.execute('SELECT attempts FROM challenges').fetchone()[0] == 0
    allow_poll(app)
    state['confirmed'] = True
    response = post(client, path + '/status')
    assert response.json() == {'location': '/cabinet'}
    assert client.get('/cabinet').status_code == 200
    assert post(client, path + '/status').status_code == 410


def test_poll_is_bound_to_browser_and_csrf(call):
    app, client, path, state = call
    assert client.post(path + '/status').status_code == 403
    client.cookies.clear()
    client.get('/')
    assert post(client, path + '/status').status_code == 410
    assert state['checks'] == 0


@pytest.mark.parametrize('change', ['expired', 'provider', 'role'])
def test_poll_rejects_expired_or_disabled_confirmation(call, change):
    app, client, path, state = call
    with app.auth_store.db() as con:
        if change == 'expired':
            con.execute('UPDATE challenges SET expires=?', (int(time.time()) - 1,))
        elif change == 'provider':
            con.execute("UPDATE providers SET enabled=0 WHERE id='zvonok'")
        else:
            con.execute("UPDATE roles SET primary_methods='[]' WHERE id='user'")
    assert post(client, path + '/status').status_code == (410 if change == 'expired' else 403)
    assert state['checks'] == 0


def test_poll_recovers_after_provider_failure(call, monkeypatch):
    import httpx
    from login_methods import ZvonokProvider
    app, client, path, state = call
    original = ZvonokProvider.verify

    async def unavailable(config, payload):
        raise httpx.ConnectError('Fixture outage')

    monkeypatch.setattr(ZvonokProvider, 'verify', staticmethod(unavailable))
    assert post(client, path + '/status').status_code == 503
    allow_poll(app)
    monkeypatch.setattr(ZvonokProvider, 'verify', staticmethod(original))
    state['confirmed'] = True
    assert post(client, path + '/status').json()['location'] == '/cabinet'


def test_automatic_login_preserves_required_second_factor(call):
    app, client, path, state = call
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET require_2fa=1,secondary_methods='[\"totp\"]' WHERE id='user'")
    state['confirmed'] = True
    assert post(client, path + '/status').json() == {'location': '/security'}
    assert client.get('/cabinet').status_code == 303


def test_enrollment_cannot_complete_after_session_is_revoked(call, monkeypatch):
    from conftest import phone_login
    from login_methods import ZvonokProvider
    app, client, path, state = call
    phone_login(app, client)
    response = post(client, '/security/enroll', {'method': 'phone', 'identifier': '+79990000003'})
    assert response.status_code == 303
    path = response.headers['location']

    async def revoked_while_checking(config, payload):
        with app.auth_store.db() as con:
            con.execute('DELETE FROM identity_sessions')
        return True

    monkeypatch.setattr(ZvonokProvider, 'verify', staticmethod(revoked_while_checking))
    assert post(client, path + '/status', headers={'X-Requested-With': 'fetch'}).status_code == 400
    with app.auth_store.db() as con:
        assert not con.execute("SELECT 1 FROM accounts WHERE phone='+79990000003'").fetchone()
    assert post(client, path + '/status').status_code == 403
