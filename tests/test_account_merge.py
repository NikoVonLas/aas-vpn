"""Default roles and lossless, atomic installation-specific account consolidation."""
import json
import sqlite3

import pytest
import identity
from account_merge import configure_server
from conftest import admin_login, post
from test_identity import accounts


def test_fresh_install_has_two_password_roles_with_admin_2fa(monkeypatch):
    monkeypatch.delenv('ZVONOK_PUBLIC_KEY', raising=False)
    with sqlite3.connect(':memory:') as con:
        con.row_factory = sqlite3.Row
        con.executescript(identity.SCHEMA)
        identity.seed_roles(con)
        roles = {row['id']: dict(row) for row in con.execute('SELECT * FROM roles')}
        assert set(roles) == {'administrator', 'user'}
        assert all(json.loads(row['primary_methods']) == ['password'] for row in roles.values())
        assert roles['administrator']['require_2fa'] == 1
        assert roles['user']['require_2fa'] == 0
        assert json.loads(roles['administrator']['permissions']) == sorted(identity.ACTIONS)


def test_owner_migrates_into_full_administrator_without_losing_login_policy(portal):
    app, _ = portal
    administrator = accounts(app)[0]
    with app.auth_store.db() as con:
        con.execute("INSERT INTO roles VALUES('owner','Владелец',?,'[\"phone\"]','[\"totp\"]',0,1)", (json.dumps(sorted(identity.ACTIONS)),))
        con.execute("UPDATE grants SET role_id='owner' WHERE account_id=?", (administrator,))
        identity.seed_roles(con)
        identity.seed_roles(con)
        assert not con.execute("SELECT 1 FROM roles WHERE id='owner'").fetchone()
        assert identity.owner(con, administrator)
        assert identity.policy(con, administrator)['required']
        assert identity.policy(con, administrator)['primary'] == {'password', 'phone'}


def test_administrator_cannot_remove_full_access_or_required_2fa(portal):
    app, client = portal
    key = accounts(app)[0]
    with app.auth_store.db() as con:
        identity.seed_roles(con)
        token = app.identities.new_session(con, key, ['password'])
    assert app.identities.session(token) is None
    assert not app.identities.session(token, limited=True)['ready']
    admin_login(app, client)
    payload = dict(role_id='administrator', name='Администратор', permissions=list(identity.ACTIONS), primary=['password'], secondary=['totp'])
    assert post(client, '/admin/roles/save', payload).status_code == 400
    assert post(client, '/admin/roles/save', {**payload, 'permissions': ['devices.view'], 'required': '1'}).status_code == 400
    assert post(client, '/admin/roles/save', {**payload, 'required': '1'}).status_code == 303


def test_phone_account_creation_follows_user_policy(portal):
    app, client = portal
    admin_login(app, client)
    response = post(client, '/admin/accounts', {'name': 'Новый пользователь', 'phone': '+79990000005', 'device_limit': '2'})
    assert response.status_code == 303
    with app.auth_store.db() as con:
        row = con.execute("SELECT * FROM accounts WHERE phone='+79990000005'").fetchone()
        assert row is not None
        assert row['admin_id'] is None
        assert identity.policy(con, row['id'])['primary'] == {'phone'}
    assert 'Телефон для входа' in client.get('/accounts/new').text


def test_merge_preserves_devices_keys_routes_and_admin_credentials(portal):
    app, _ = portal
    target, source, _ = accounts(app)
    with app.identities.transaction() as con:
        credential = dict(con.execute('SELECT * FROM admins WHERE id=1').fetchone())
        devices = [dict(row) for row in con.execute('SELECT * FROM portal.devices')]
        con.execute("INSERT INTO passkeys VALUES('fixture-key',?,'Key',X'0102',0,0,NULL)", (source,))
        con.execute("INSERT INTO backup_codes VALUES(?,'fixture-digest')", (source,))
        con.execute("INSERT INTO portal.scoped_routing_rules VALUES('account',?,'ru','domain','example.test')", (source,))
        con.execute('UPDATE portal.users SET ru_exit_id=1 WHERE account_id=?', (source,))
        app.identities.new_session(con, source, ['phone'])
        app.identities.new_session(con, target, ['password'])
        result = configure_server(con, '+79990000001')
        assert result['merged']
        assert con.execute('SELECT count(*) FROM accounts').fetchone()[0] == 2
        assert con.execute('SELECT account_id FROM portal.devices WHERE id=1').fetchone()[0] == target
        assert con.execute('SELECT account_id FROM passkeys').fetchone()[0] == target
        assert con.execute('SELECT account_id FROM backup_codes').fetchone()[0] == target
        assert con.execute('SELECT owner_id FROM portal.scoped_routing_rules').fetchone()[0] == target
        assert con.execute('SELECT ru_exit_id FROM portal.users WHERE account_id=?', (target,)).fetchone()[0] == 1
        assert dict(con.execute('SELECT * FROM admins WHERE id=1').fetchone()) == credential
        assert not con.execute('SELECT 1 FROM identity_sessions').fetchone()
        after = [dict(row) for row in con.execute('SELECT * FROM portal.devices')]
        assert all({k:v for k,v in before.items() if k not in {'phone','account_id'}} == {k:v for k,v in final.items() if k not in {'phone','account_id'}} for before,final in zip(devices, after))
        assert identity.policy(con, target)['primary'] == {'password', 'phone'}
        assert identity.policy(con, target)['required']
        assert not configure_server(con, '+79990000001')['merged']


@pytest.mark.parametrize('conflict', ['routing', 'exit', 'login', 'credential'])
def test_merge_conflict_rolls_back_both_databases(portal, conflict):
    app, _ = portal
    target, source, _ = accounts(app)
    with app.identities.transaction() as con:
        if conflict == 'routing':
            con.executemany("INSERT INTO portal.scoped_routing_rules VALUES('account',?,?,'domain','example.test')", [(target,'direct'),(source,'ru')])
        elif conflict == 'exit':
            con.execute("INSERT INTO portal.ru_exits(id,name) VALUES(2,'Другой')")
            con.execute('UPDATE portal.users SET ru_exit_id=1 WHERE account_id=?', (source,))
            con.execute('UPDATE portal.users SET ru_exit_id=2 WHERE account_id=?', (target,))
        elif conflict == 'credential':
            key = con.execute("INSERT INTO admins(username,password_hash) VALUES('separate','fixture-password-hash')").lastrowid
            con.execute('UPDATE accounts SET admin_id=? WHERE id=?', (key, source))
        else:
            con.execute("UPDATE providers SET enabled=0 WHERE id='zvonok'")
        before_accounts = [tuple(row) for row in con.execute('SELECT * FROM accounts')]
        before_devices = [tuple(row) for row in con.execute('SELECT * FROM portal.devices')]
    def merge():
        with app.identities.transaction() as con:
            configure_server(con, '+79990000001')
    with pytest.raises(ValueError):
        merge()
    with app.identities.transaction() as con:
        assert before_accounts == [tuple(row) for row in con.execute('SELECT * FROM accounts')]
        assert before_devices == [tuple(row) for row in con.execute('SELECT * FROM portal.devices')]


def test_merge_command_dry_run_then_apply(portal):
    import subprocess
    import sys
    from conftest import ROOT
    app, _ = portal
    target, source, _ = accounts(app)
    command = [sys.executable, str(ROOT / 'portal/account_merge.py'), '--auth-db', str(app.auth_store.path),
               '--portal-db', str(app.DB), '--phone', '+79990000001']
    preview = subprocess.run(command, capture_output=True, text=True, check=True)
    assert json.loads(preview.stdout)['applied'] is False
    with app.identities.transaction() as con:
        assert con.execute('SELECT id FROM accounts WHERE phone=?', ('+79990000001',)).fetchone()[0] == source
        assert con.execute('SELECT account_id FROM portal.devices WHERE id=1').fetchone()[0] == source
    applied = subprocess.run([*command, '--apply'], capture_output=True, text=True, check=True)
    assert json.loads(applied.stdout)['applied'] is True
    with app.identities.transaction() as con:
        assert con.execute('SELECT id FROM accounts WHERE phone=?', ('+79990000001',)).fetchone()[0] == target
        assert con.execute('SELECT account_id FROM portal.devices WHERE id=1').fetchone()[0] == target
