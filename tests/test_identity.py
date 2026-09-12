"""Security boundaries exercised through real routes and transactional stores."""
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from conftest import admin_login, phone_login, post
import identity
from login_methods import Confirmations


def accounts(app):
    with app.auth_store.db() as con:
        owner = con.execute('SELECT id FROM accounts WHERE admin_id=1').fetchone()[0]
        users = [r[0] for r in con.execute('SELECT id FROM accounts WHERE phone IS NOT NULL ORDER BY phone')]
    return owner, *users


def test_account_state_action_is_explicit_scoped_and_revokes_sessions(portal):
    app, client = portal
    owner, first, second = accounts(app)
    phone_login(app, client)
    assert post(client, f'/accounts/{second}/state', {'enabled': '0'}).status_code == 404
    admin_login(app, client)
    with app.auth_store.db() as con:
        token = app.identities.new_session(con, first, ['phone'])
    assert app.auth_store.session(token) is not None
    path = f'/accounts/{first}/state'
    assert client.post(path, data={'enabled': '0'}).status_code == 403
    assert post(client, path, {'enabled': 'false'}).status_code == 400
    for _ in range(2):
        assert post(client, path, {'enabled': '0', 'name': 'Ignored'}).status_code == 303
    assert app.auth_store.session(token) is None
    with app.db() as con:
        row = con.execute('SELECT name,enabled FROM users WHERE account_id=?', (first,)).fetchone()
        assert row['name'] != 'Ignored'
        assert row['enabled'] == 0
    assert post(client, path, {'enabled': '1'}).status_code == 303
    assert post(client, f'/accounts/{owner}/state', {'enabled': '0'}).status_code == 400
    with app.auth_store.db() as con:
        assert con.execute('SELECT enabled FROM accounts WHERE id=?', (owner,)).fetchone()[0] == 1


def test_account_cannot_be_enabled_without_a_login_method(portal):
    app, client = portal
    admin_login(app, client)
    first = accounts(app)[1]
    path = f'/accounts/{first}/state'
    assert post(client, path, {'enabled': '0'}).status_code == 303
    with app.auth_store.db() as con:
        con.execute('UPDATE accounts SET phone=NULL WHERE id=?', (first,))
    assert post(client, path, {'enabled': '1'}).status_code == 400
    with app.db() as con:
        assert con.execute('SELECT enabled FROM users WHERE account_id=?', (first,)).fetchone()[0] == 0
    with app.auth_store.db() as con:
        assert con.execute('SELECT enabled FROM accounts WHERE id=?', (first,)).fetchone()[0] == 0


def give(app, actor, role, scope='self', targets=()):
    with app.auth_store.db() as con:
        return identity.grant(con, actor, role, scope, targets)


def login_account(app, client, key, methods=None):
    with app.auth_store.db() as con:
        token = app.identities.new_session(con, key, methods or ['password'])
    client.cookies.clear()
    client.cookies.set(app.auth.COOKIE, token, domain='portal.example.test')
    client.get('/')
    return token


def test_repeat_migration_preserves_identity_credentials_and_assignments(portal):
    app, client = portal
    owner, first, second = accounts(app)
    with app.db() as con:
        before = [tuple(r) for r in con.execute('SELECT id,client_id,vpn_ip,account_id FROM devices')]
        con.execute("UPDATE devices SET ru_exit_id=1,assigned_by='user' WHERE id=1")
    app.identities.migrate(); app.startup()
    assert accounts(app) == (owner, first, second)
    with app.db() as con:
        assert before == [tuple(r) for r in con.execute('SELECT id,client_id,vpn_ip,account_id FROM devices')]
        assert tuple(con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()) == (1, 'user')
    with app.auth_store.db() as con:
        assert identity.policy(con, first)['primary'] == {'phone'}
        assert identity.owner(con, owner)
    client.cookies.set('aas_session', 'retired-phone-session')
    assert client.get('/cabinet').status_code == 303


@pytest.mark.parametrize('action', sorted(identity.ACTIONS))
def test_scope_and_permission_union(portal, action):
    app, _ = portal
    owner, first, second = accounts(app)
    with app.auth_store.db() as con:
        con.execute('DELETE FROM grants WHERE account_id=?', (first,))
        con.execute('INSERT INTO roles VALUES(?,?,?,?,?,0,0)', ('test', 'Тест', json.dumps([action]), '["phone"]', '[]'))
        grant_id = identity.grant(con, first, 'test', 'selected', [second])
        assert not identity.allowed(con, first, action, first)
        assert not identity.allowed(con, first, action)
        assert identity.allowed(con, first, action, second) == (action in identity.ACCOUNT_ACTIONS)
        con.execute('UPDATE grants SET scope=\'global\' WHERE id=?', (grant_id,))
        assert identity.allowed(con, first, action, owner)
        con.execute('DELETE FROM grants WHERE id=?', (grant_id,))
        assert not identity.allowed(con, first, action, second)


def test_operator_http_scope_filters_lists_status_and_secrets(portal):
    app, client = portal
    owner, first, second = accounts(app)
    with app.auth_store.db() as con:
        con.execute('INSERT INTO roles VALUES(?,?,?,?,?,0,0)', ('reader', 'Reader', json.dumps(['accounts.view', 'devices.view']), '["phone"]', '[]'))
        identity.grant(con, first, 'reader', 'selected', [second])
    phone_login(app, client)
    assert client.get('/accounts/' + second).status_code == 200
    assert client.get('/accounts/' + owner).status_code == 404
    assert client.get('/device/2/config').status_code == 404
    assert client.get('/device/2/qr').status_code == 404
    assert post(client, '/device/2/update', {'name': 'Denied'}).status_code == 404
    assert post(client, '/device/2/delete').status_code == 404
    page = client.get('/admin').text
    assert 'Первый' in page
    assert 'Второй' in page
    assert 'admin</h2>' not in page
    assert set(client.get('/routing/status').json()['devices']) == {'1', '2'}
    for path in ['/admin/roles', '/admin/login-methods', '/admin/administrators', '/admin/ru-exits', '/admin/routing']:
        assert client.get(path).status_code == 403, path
    assert post(client, '/admin/accounts', {'name': 'No', 'username': 'no', 'password': 'never-allow-this', 'device_limit': 2}).status_code == 403


def test_revoke_preserves_rules_and_assignments_and_is_immediate(portal):
    app, client = portal
    owner, first, _ = accounts(app)
    grant = give(app, first, 'exit-choice')
    phone_login(app, client)
    assert post(client, '/device/1/ru-exit', {'ru_exit_id': '1'}).status_code == 303
    app.identities.assign(owner, first, '', 'self', remove=grant)
    assert post(client, '/device/1/ru-exit', {'ru_exit_id': '0'}).status_code == 404
    with app.db() as con:
        assert tuple(con.execute('SELECT ru_exit_id,assigned_by FROM devices WHERE id=1').fetchone()) == (1, 'user')


def test_last_owner_and_fresh_confirmation(portal):
    app, client = portal
    owner, first, _ = accounts(app)
    admin_login(app, client)
    with app.auth_store.db() as con:
        grant = con.execute("SELECT id FROM grants WHERE account_id=? AND role_id='administrator'", (owner,)).fetchone()[0]
    assert post(client, '/admin/roles/assign', {'account_id': owner, 'remove': grant}).status_code == 400
    assert post(client, '/accounts/' + owner + '/save', {'state_present': '1'}).status_code == 400
    with app.auth_store.db() as con:
        con.execute('UPDATE identity_sessions SET confirmed=0')
    assert post(client, '/admin/roles/assign', {'account_id': first, 'role_id': 'operator', 'scope': 'global'}).headers['location'] == '/security/confirm'


def test_policy_union_and_new_requirement_downgrades_existing_session(portal):
    app, client = portal
    owner, first, _ = accounts(app)
    phone_login(app, client)
    assert client.get('/cabinet').status_code == 200
    app.identities.save_role(owner, 'mfa', 'MFA', [], [], ['totp'], True)
    app.identities.assign(owner, first, 'mfa', 'self')
    assert client.get('/cabinet').headers['location'] == '/security'
    assert client.get('/security').status_code == 200
    assert post(client, '/security/totp/start').status_code == 303
    assert post(client, '/security/password', {'username': 'phone-user', 'password': 'not-allowed-password'}).status_code == 403
    app.identities.save_role(owner, 'password-opt-in', 'Password opt-in', [], ['password'], [], False)
    app.identities.assign(owner, first, 'password-opt-in', 'self')
    assert post(client, '/security/password', {'username': 'phone-user', 'password': 'new-phone-password'}).status_code == 303
    result = post(client, '/login/password', {'username': 'phone-user', 'password': 'new-phone-password'})
    assert result.headers['location'] == '/security'


def test_new_password_account_without_phone_and_immutable_id(portal):
    app, client = portal
    admin_login(app, client)
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET primary_methods='[\"password\",\"phone\"]' WHERE id='user'")
    result = post(client, '/admin/accounts', {'name': 'Password user', 'username': 'password-user', 'password': 'temporary-password', 'device_limit': 3})
    assert result.status_code == 303
    with app.auth_store.db() as con:
        row = con.execute("SELECT a.* FROM accounts a JOIN admins c ON c.id=a.admin_id WHERE c.username='password-user'").fetchone()
        key = row['id']
        assert row['phone'] is None
        assert identity.policy(con, key)['primary'] == {'password', 'phone'}
    state_path = '/accounts/' + key + '/save'
    assert post(client, state_path, {'state_present': '1'}).status_code == 303
    with app.auth_store.db() as con:
        assert con.execute('SELECT enabled FROM admins WHERE id=?', (row['admin_id'],)).fetchone()[0] == 0
    assert post(client, state_path, {'state_present': '1', 'enabled': '1'}).status_code == 303
    with app.auth_store.db() as con:
        assert con.execute('SELECT enabled FROM admins WHERE id=?', (row['admin_id'],)).fetchone()[0] == 1
    post(client, '/admin/logout')
    assert post(client, '/login/password', {'username': 'password-user', 'password': 'temporary-password'}).headers['location'] == '/security'
    assert client.get('/cabinet').headers['location'] == '/security'
    assert post(client, '/security/password', {'username': 'new-login', 'password': 'permanent-password'}).status_code == 303
    assert post(client, '/login/password', {'username': 'new-login', 'password': 'permanent-password'}).headers['location'] == '/cabinet'
    assert client.get('/cabinet').status_code == 200
    with app.auth_store.db() as con:
        assert con.execute("SELECT a.id FROM accounts a JOIN admins c ON c.id=a.admin_id WHERE c.username='new-login'").fetchone()[0] == key


def email_setup(app):
    owner, first, _ = accounts(app)
    app.identities.save_role(owner, 'email-role', 'Email', [], ['email'], ['email'], False)
    app.identities.assign(owner, first, 'email-role', 'self')
    with app.auth_store.db() as con:
        con.execute("UPDATE providers SET enabled=1 WHERE id='email'")
        con.execute('UPDATE accounts SET email=? WHERE id=?', ('person@example.test', first))
    return first, Confirmations(app.identities)


def test_email_code_link_single_winner_and_resend(portal):
    app, _ = portal
    first, service = email_setup(app)
    with app.auth_store.db() as con:
        key = service.start(con, first, 'login', 'email', 'browser-one', code='123456', link='one-time-link')
    with pytest.raises(ValueError):
        service.attempt(key, 'browser-two')
    row1 = service.attempt(key, 'browser-one')
    row2 = service.attempt(key, 'browser-two', link=True)
    def consume(args):
        try:
            return service.consume(*args[0], **args[1])
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(consume, [((row1,), {'code': '123456'}), ((row2,), {'link': 'one-time-link'})]))
    assert sum(token is not None for token in results) == 1
    with app.auth_store.db() as con:
        old = service.start(con, first, 'login', 'email', 'browser-one', code='123456')
        service.start(con, first, 'login', 'email', 'browser-one', code='654321')
    with pytest.raises(ValueError):
        service.attempt(old, 'browser-one')


def test_email_scanner_other_browser_and_purpose_binding(portal):
    app, client = portal
    first, service = email_setup(app)
    with app.auth_store.db() as con:
        key = service.start(con, first, 'login', 'email', 'original', code='123456', link='link-secret')
    page = client.get('/login/link')
    assert page.status_code == 200
    assert 'link-secret' not in page.text
    with app.auth_store.db() as con:
        assert con.execute('SELECT 1 FROM challenges WHERE id=?', (key,)).fetchone()
    result = post(client, '/login/link', {'proof': key + '.link-secret'})
    assert result.status_code == 303
    assert app.identities.session(client.cookies.get(app.auth.COOKIE))['account_id'] == first
    with pytest.raises(ValueError):
        service.attempt(key, 'original')
    with app.auth_store.db() as con:
        key = service.start(con, first, 'enroll-email', 'email', 'original', {'address': 'new@example.test'}, code='123456')
    with pytest.raises(ValueError):
        service.attempt(key, 'original', purpose='login')
    assert post(client, '/login/link', {'proof': key + '.anything'}).status_code == 400


def test_attempt_limits_expiry_and_provider_disable_guard(portal):
    app, _ = portal
    first, service = email_setup(app)
    with app.auth_store.db() as con:
        key = service.start(con, first, 'login', 'email', 'browser', code='123456')
    for _ in range(10):
        row = service.attempt(key, 'browser')
        with pytest.raises(ValueError):
            service.consume(row, code='000000')
    with pytest.raises(ValueError):
        service.attempt(key, 'browser')
    with app.auth_store.db() as con:
        key = service.start(con, first, 'login', 'email', 'browser', code='123456')
        con.execute('UPDATE challenges SET expires=0 WHERE id=?', (key,))
    with pytest.raises(ValueError):
        service.attempt(key, 'browser')
    owner, _, second = accounts(app)
    def disable_phone_provider():
        with app.auth_store.db() as con:
            con.execute("UPDATE providers SET enabled=0 WHERE id='zvonok'")
            identity.ensure_login_paths(con)

    with pytest.raises(ValueError, match='способа входа'):
        disable_phone_provider()
    with app.auth_store.db() as con:
        assert con.execute("SELECT enabled FROM providers WHERE id='zvonok'").fetchone()[0] == 1
        assert identity.policy(con, second)['primary'] == {'phone'}


def test_backup_codes_hashed_single_use_and_session_revocation(portal):
    app, client = portal
    phone_login(app, client)
    page = post(client, '/security/backup/new')
    import re
    codes = re.search(r'<pre>(.*?)</pre>', page.text, re.S)[1].splitlines()
    with app.auth_store.db() as con:
        assert len(con.execute('SELECT * FROM backup_codes').fetchall()) == 10
        assert not con.execute('SELECT 1 FROM backup_codes WHERE digest=?', (codes[0],)).fetchone()
    assert post(client, '/security/backup', {'code': codes[0]}).status_code == 303
    assert post(client, '/security/backup', {'code': codes[0]}).status_code == 400
    with app.auth_store.db() as con:
        session = con.execute('SELECT token_hash FROM identity_sessions').fetchone()[0]
    assert post(client, '/security/sessions/revoke', {'key': session}).status_code == 303
    assert client.get('/cabinet').status_code == 303


def test_owner_recovery_is_one_time_and_limited_to_setup(portal):
    app, client = portal
    admin_login(app, client)
    owner, first, _ = accounts(app)
    page = post(client, '/admin/accounts/' + first + '/recovery')
    import re
    code = re.search(r'<pre>(.*?)</pre>', page.text, re.S)[1]
    client.cookies.clear(); client.get('/')
    assert post(client, '/login/recovery', {'account_id': first, 'code': code}).headers['location'] == '/security'
    assert client.get('/cabinet').headers['location'] == '/security'
    assert client.get('/admin').headers['location'] == '/security'
    assert post(client, '/security/totp/start').status_code == 303
    assert post(client, '/login/recovery', {'account_id': first, 'code': code}).status_code == 400
    with app.auth_store.db() as con:
        assert not con.execute('SELECT 1 FROM recovery_codes WHERE account_id=?', (first,)).fetchone()
        assert all(code not in str(tuple(row)) for row in con.execute('SELECT * FROM audit'))


def test_exit_permission_does_not_require_rename_or_route_edit(portal):
    app, client = portal
    _, first, _ = accounts(app)
    with app.auth_store.db() as con:
        con.execute('DELETE FROM grants WHERE account_id=?', (first,))
        con.execute('INSERT INTO roles VALUES(?,?,?,?,?,0,0)', ('exit-only', 'Выбор выхода', json.dumps(['devices.view', 'device.exit', 'account.routing.view', 'account.exit']), '["phone"]', '[]'))
        identity.grant(con, first, 'exit-only')
    with app.db() as con:
        name = con.execute('SELECT name FROM devices WHERE id=1').fetchone()[0]
        con.execute("INSERT INTO scoped_routing_rules VALUES('account',?,'ru','suffix','example.test')", (first,))
    phone_login(app, client)
    page = client.get('/cabinet').text
    assert 'name="name"' in page
    assert 'readonly' in page
    assert post(client, '/device/1/update', {'name': name, 'ru_exit_id': 1}).status_code == 303
    assert post(client, '/device/1/update', {'name': 'Forbidden', 'ru_exit_id': 0}).status_code == 404
    route = '/accounts/' + first + '/routing'
    assert 'Сохранить</button>' in client.get(route).text
    assert post(client, route, {'ru': '.example.test', 'ru_exit_id': 1}).status_code == 303
    assert post(client, route, {'ru': '.changed.test', 'ru_exit_id': 0}).status_code == 404
    with app.db() as con:
        assert tuple(con.execute('SELECT name,ru_exit_id FROM devices WHERE id=1').fetchone()) == (name, 1)
        assert con.execute('SELECT ru_exit_id FROM users WHERE account_id=?', (first,)).fetchone()[0] == 1
        assert con.execute('SELECT value FROM scoped_routing_rules WHERE owner_id=?', (first,)).fetchone()[0] == 'example.test'


def test_security_page_preserves_mfa_and_module_tls_selection(portal):
    app, client = portal
    admin_login(app, client)
    assert 'value="0" selected' in client.get('/security').text
    with app.auth_store.db() as con:
        con.execute('UPDATE providers SET config=? WHERE id=\'email\'', (json.dumps({'tls': 'implicit'}),))
    assert 'value="implicit" selected' in client.get('/admin/login-methods').text
    assert client.get('/admin/roles').status_code == 200


def test_maintenance_allows_signin_checks_but_freezes_device_changes(portal, monkeypatch):
    from pathlib import Path
    import pyotp
    from login_methods import ZvonokProvider
    app, client = portal
    secret = pyotp.random_base32()
    with app.auth_store.db() as con:
        con.execute('UPDATE admins SET totp_key=?,totp_verified=1 WHERE id=1', (secret,))
        con.execute('UPDATE roles SET require_2fa=1 WHERE id=\'administrator\'')
    Path(app.DB).with_name('maintenance').touch()
    response = post(client, '/login', {'identifier': 'admin', 'password': 'test-password'})
    assert response.headers['location'] == '/security'
    response = post(client, '/security/second', {'method': 'totp', 'code': pyotp.TOTP(secret).now()})
    assert response.headers['location'] == '/admin'
    assert client.get('/admin').status_code == 200
    assert post(client, '/device/1/update', {'name': 'Blocked'}).status_code == 503

    async def begin(config, address, code, link):
        return {'phone': address, 'call_id': 'fixture', 'dial': '+79990000003'}

    async def verify(config, payload):
        return True

    monkeypatch.setattr(ZvonokProvider, 'begin', staticmethod(begin))
    monkeypatch.setattr(ZvonokProvider, 'verify', staticmethod(verify))
    client.cookies.clear()
    client.get('/')
    response = post(client, '/login', {'identifier': '+79990000001'})
    assert response.status_code == 303
    assert post(client, response.headers['location']).headers['location'] == '/cabinet'
    assert client.get('/cabinet').status_code == 200


def test_common_login_dispatch_and_policy(portal, monkeypatch):
    from login_methods import EmailProvider, ZvonokProvider
    app, client = portal
    sent = []

    async def begin(config, address, code, link):
        sent.append(address)
        return {'dial': '+79990000003'}

    monkeypatch.setattr(ZvonokProvider, 'begin', staticmethod(begin))
    monkeypatch.setattr(EmailProvider, 'begin', staticmethod(begin))
    assert post(client, '/login', {'identifier': 'admin'}).status_code == 400
    assert post(client, '/login', {'identifier': '+79990000001', 'password': 'wrong'}).status_code == 401
    assert sent == []
    response = post(client, '/login', {'identifier': ' +7 (999) 000-00-01 '})
    assert response.status_code == 303
    assert sent == ['+79990000001']
    with app.auth_store.db() as con:
        challenge = con.execute('SELECT * FROM challenges WHERE id=?', (response.headers['location'].split('/')[-1],)).fetchone()
        assert challenge['method'] == 'phone'
        assert challenge['purpose'] == 'login'
        con.execute("UPDATE providers SET enabled=0 WHERE id='zvonok'")
    assert post(client, '/login', {'identifier': '+79990000002'}).status_code == 400
    with app.auth_store.db() as con:
        con.execute("UPDATE providers SET enabled=1 WHERE id='zvonok'")
    first, _ = email_setup(app)
    response = post(client, '/login', {'identifier': 'Person@Example.Test'})
    assert response.status_code == 303
    assert sent[-1] == 'person@example.test'
    with app.auth_store.db() as con:
        con.execute("DELETE FROM grants WHERE account_id=? AND role_id='email-role'", (first,))
    assert post(client, '/login', {'identifier': 'person@example.test'}).status_code == 403
    assert sent == ['+79990000001', 'person@example.test']


@pytest.mark.parametrize('mask', range(16))
def test_login_form_follows_every_method_combination(portal, mask):
    app, client = portal
    methods = {method for index, method in enumerate(['password', 'phone', 'email', 'webauthn']) if mask & (1 << index)}
    with app.auth_store.db() as con:
        con.execute('UPDATE roles SET primary_methods=?', (json.dumps(sorted(methods)),))
        con.execute('UPDATE providers SET enabled=1')
    body = client.get('/').text
    assert ('name="password" ' in body) == ('password' in methods)
    assert ('data-passkey-submit' in body) == ('webauthn' in methods)
    assert ('action="/login" ' in body) == bool(methods)
    for method, text in [('phone', 'телефон с кодом страны'), ('email', 'почту'), ('password', 'Пароль<input')]:
        assert (text in body) == (method in methods)


def test_login_form_ignores_disabled_modules_and_unassigned_roles(portal):
    app, client = portal
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET primary_methods=? WHERE id='operator'", (json.dumps(['email', 'webauthn']),))
        con.execute("UPDATE providers SET enabled=0 WHERE id='zvonok'")
    body = client.get('/').text
    assert '<label>Логин<input' in body
    assert 'телефон с кодом страны' not in body
    assert 'почту' not in body
    assert 'data-passkey-submit' not in body
    with app.auth_store.db() as con:
        con.execute("UPDATE providers SET enabled=1 WHERE id='zvonok'")
        con.execute('UPDATE accounts SET enabled=0 WHERE phone IS NOT NULL')
    assert 'телефон с кодом страны' not in client.get('/').text


def test_user_card_role_assignment_scope_and_revoke(portal):
    app, client = portal
    owner, first, second = accounts(app)
    admin_login(app, client)
    path = '/accounts/' + first + '/roles'
    assert 'class="account-roles"' in client.get('/accounts/' + first + '/edit').text
    assert 'class="account-roles"' in client.get('/admin').text
    assert '/admin/roles/assign' not in client.get('/admin/roles').text
    assert client.get('/admin/administrators').headers['location'] == '/admin'
    payload = {'role_id': 'observer', 'scope': 'selected', 'targets': [second]}
    response = post(client, path, payload)
    assert response.headers['location'] == '/accounts/' + first + '/edit'
    assert app.identities.allowed(first, 'accounts.view', second)
    assert not app.identities.allowed(first, 'accounts.view', owner)
    with app.auth_store.db() as con:
        assigned = con.execute("SELECT id FROM grants WHERE account_id=? AND role_id='observer'", (first,)).fetchone()[0]
    assert post(client, path, {'remove': assigned}).status_code == 303
    assert not app.identities.allowed(first, 'accounts.view', second)
    assert post(client, path, {'role_id': 'observer', 'scope': 'selected'}).status_code == 400
    with app.auth_store.db() as con:
        assert not con.execute("SELECT 1 FROM grants WHERE account_id=? AND role_id='observer'", (first,)).fetchone()
        protected = con.execute("SELECT id FROM grants WHERE account_id=? AND role_id='administrator'", (owner,)).fetchone()[0]
    assert post(client, '/accounts/' + owner + '/roles', {'remove': protected}).status_code == 400
    phone_login(app, client)
    assert 'class="account-roles"' not in client.get('/admin').text
    assert post(client, path, payload).status_code == 403
    admin_login(app, client)
    with app.auth_store.db() as con:
        con.execute('UPDATE identity_sessions SET confirmed=0')
    assert post(client, path, payload).headers['location'] == '/security/confirm'


def test_builtin_global_settings_are_persistent_and_enforced(portal):
    app, client = portal
    admin_login(app, client)
    owner = accounts(app)[0]
    assert post(client, '/security/totp/start').status_code == 303
    with app.auth_store.db() as con:
        pending = con.execute('SELECT pending_totp FROM admins WHERE id=1').fetchone()[0]
    for method in ('totp', 'webauthn'):
        response = post(client, '/admin/login-methods/' + method)
        assert response.status_code == 303
    import pyotp
    assert post(client, '/security/totp/start').status_code == 403
    assert client.get('/security/totp/qr').status_code == 403
    assert post(client, '/security/totp/confirm', {'code': pyotp.TOTP(pending).now()}).status_code == 403
    assert post(client, '/security/passkeys/start', {'purpose': 'enroll', 'name': 'Disabled'}).status_code == 403
    with app.auth_store.db() as con:
        assert identity.policy(con, owner)['secondary'] == set()
        assert con.execute('SELECT pending_totp FROM admins WHERE id=1').fetchone()[0] == pending
    app.startup()
    with app.auth_store.db() as con:
        assert identity.enabled_methods(con) == {'password', 'phone'}
    with app.auth_store.db() as con:
        con.execute("UPDATE roles SET require_2fa=0 WHERE id='administrator'")
    assert post(client, '/admin/login-methods/totp', {'enabled': '1'}).status_code == 303
    assert post(client, '/security/totp/start').status_code == 303


def test_global_password_disable_requires_another_path_and_blocks_old_sessions(portal):
    app, client = portal
    admin_login(app, client)
    owner = accounts(app)[0]
    assert post(client, '/admin/login-methods/password').status_code == 400
    with app.auth_store.db() as con:
        assert 'password' in identity.enabled_methods(con)
        con.execute("UPDATE accounts SET phone='+79990000999' WHERE id=?", (owner,))
        con.execute("UPDATE roles SET primary_methods='[\"password\",\"phone\"]' WHERE id='administrator'")
    assert post(client, '/admin/login-methods/password').status_code == 303
    assert client.get('/admin').headers['location'] == '/security'
    assert 'Войдите другим способом' in client.get('/security').text
    assert post(client, '/security/totp/start').status_code == 403
    assert 'name="password"' not in client.get('/').text
    assert post(client, '/login', {'identifier': 'admin', 'password': 'test-password'}).status_code == 401
    login_account(app, client, owner, ['phone'])
    assert post(client, '/admin/login-methods/password', {'enabled': '1'}).status_code == 303
    assert post(client, '/login', {'identifier': 'admin', 'password': 'test-password'}).status_code == 303


def test_global_switch_preserves_working_required_second_factor(portal):
    app, client = portal
    owner = accounts(app)[0]
    with app.auth_store.db() as con:
        con.execute("UPDATE admins SET totp_key='JBSWY3DPEHPK3PXP',totp_verified=1 WHERE id=1")
        con.execute("UPDATE roles SET require_2fa=1 WHERE id='administrator'")
    login_account(app, client, owner, ['password', 'totp'])
    response = post(client, '/admin/login-methods/totp')
    assert response.status_code == 400
    assert 'обязательный второй фактор' in response.text
    with app.auth_store.db() as con:
        assert 'totp' in identity.enabled_methods(con)


def test_in_flight_passkey_cannot_complete_after_global_disable(portal):
    app, client = portal
    admin_login(app, client)
    owner = accounts(app)[0]
    confirmation = Confirmations(app.identities)
    with app.auth_store.db() as con:
        key = confirmation.start(con, owner, 'enroll-webauthn', 'webauthn', 'fixture-browser')
    assert post(client, '/admin/login-methods/webauthn').status_code == 303
    row = confirmation.attempt(key, 'fixture-browser')
    with app.auth_store.db() as con, pytest.raises(PermissionError):
        confirmation.validate_policy(con, row)


def test_global_switches_are_owner_only(portal):
    app, client = portal
    accounts(app)
    phone_login(app, client)
    for method in ('password', 'webauthn', 'totp'):
        assert post(client, '/admin/login-methods/' + method).status_code == 403


def test_role_multiselect_saves_atomically_and_rejects_invalid_changes(portal):
    app, client = portal
    owner, first, second = accounts(app)
    admin_login(app, client)
    path = '/accounts/' + second + '/save'
    payload = {'name': 'Общее сохранение', 'device_limit': '5', 'roles_present': '1', 'roles': ['user', 'administrator']}
    assert post(client, path, payload).status_code == 303
    with app.identities.transaction() as con:
        assert con.execute('SELECT name,device_limit FROM portal.users WHERE account_id=?', (second,)).fetchone()[:] == ('Общее сохранение', 5)
        assert identity.owner(con, second)
        assert identity.allowed(con, second, 'devices.view', first)
    assert post(client, path, {**payload, 'name': 'Не сохранять', 'roles': ['missing']}).status_code == 400
    assert post(client, path, {**payload, 'name': 'Не сохранять', 'roles': []}).status_code == 400
    with app.db() as con:
        assert con.execute('SELECT name FROM users WHERE account_id=?', (second,)).fetchone()[0] == 'Общее сохранение'
    assert post(client, path, {**payload, 'roles': ['user']}).status_code == 303
    assert not app.identities.allowed(second, 'devices.view', first)
    assert post(client, '/accounts/' + owner + '/save', {'name': 'Не сохранять', 'roles_present': '1', 'roles': ['user']}).status_code == 400
    phone_login(app, client)
    assert post(client, '/accounts/' + first + '/save', {'roles': ['administrator']}).status_code == 403


def test_role_permissions_control_other_accounts_and_global_settings_independently(portal):
    app, _ = portal
    owner, first, second = accounts(app)
    with app.auth_store.db() as con:
        con.execute('INSERT INTO roles VALUES(?,?,?,?,?,0,0)', ('limited-global', 'Настройки', json.dumps(['settings.edit']), '["phone"]', '[]'))
        identity.replace_roles(con, owner, second, ['user', 'limited-global'])
        assert identity.allowed(con, second, 'devices.view', second)
        assert identity.allowed(con, second, 'settings.edit')
        assert not identity.allowed(con, second, 'devices.view', first)
        con.execute('UPDATE roles SET permissions=? WHERE id=?', (json.dumps(['settings.edit', identity.OTHER_ACCOUNTS]), 'limited-global'))
        assert identity.allowed(con, second, 'devices.view', first)
        assert not identity.allowed(con, second, 'accounts.edit', first)
        con.execute('UPDATE roles SET permissions=? WHERE id=?', (json.dumps([identity.OTHER_ACCOUNTS]), 'limited-global'))
        assert not identity.allowed(con, second, 'settings.edit')
        assert identity.allowed(con, second, 'devices.view', first)


def test_old_assignment_schema_migrates_without_widening_selected_access(portal):
    app, _ = portal
    _, first, second = accounts(app)
    with app.auth_store.db() as con:
        identity.grant(con, first, 'observer', 'selected', [second])
        con.execute('ALTER TABLE grants DROP COLUMN role_based')
    app.identities.initialize()
    assert app.identities.allowed(first, 'devices.view', second)
    assert not app.identities.allowed(first, 'settings.edit')
    with app.auth_store.db() as con:
        assert con.execute("SELECT role_based FROM grants WHERE role_id='observer'").fetchone()[0] == 0
