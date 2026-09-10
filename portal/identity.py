"""Account identities, scoped roles and coordinated main/auth database migration.

The router consumes only opaque account IDs and routing data. No credential or
permission is copied into its database. Attached databases use rollback journals
so SQLite's super-journal commits account and device changes together.
"""
from contextlib import contextmanager
import json
import os
import secrets
import sqlite3
import time
import uuid

ACCOUNT_ACTIONS = {
    'accounts.view': 'Просмотр аккаунтов', 'accounts.edit': 'Изменение данных аккаунтов',
    'accounts.limits': 'Изменение лимитов', 'accounts.state': 'Изменение состояния',
    'devices.view': 'Просмотр устройств', 'devices.create': 'Создание устройств',
    'devices.rename': 'Переименование устройств', 'devices.delete': 'Удаление устройств',
    'devices.config': 'Конфигурация и QR устройств',
    'account.routing.view': 'Просмотр маршрутов аккаунта',
    'account.routing.edit': 'Изменение маршрутов аккаунта',
    'account.exit': 'Выбор RU-выхода аккаунта',
    'device.routing.view': 'Просмотр маршрутов устройства',
    'device.routing.edit': 'Изменение маршрутов устройства',
    'device.exit': 'Выбор RU-выхода устройства',
}
GLOBAL_ACTIONS = {
    'accounts.create': 'Создание аккаунтов', 'routing.global': 'Глобальная маршрутизация',
    'exits.view': 'Просмотр RU-нод', 'exits.edit': 'Управление RU-нодами',
    'exits.private': 'Просмотр приватных RU-конфигов', 'exits.default': 'Глобальный RU-дефолт',
    'settings.edit': 'Общие настройки', 'devices.assign': 'Назначение устройств без владельца',
}
ACTIONS = {**ACCOUNT_ACTIONS, **GLOBAL_ACTIONS}
PRIMARY = {'password', 'phone', 'email', 'webauthn'}
SECONDARY = PRIMARY | {'totp'}
USER_ACTIONS = {'accounts.view', 'devices.view', 'devices.create', 'devices.rename',
                'devices.delete', 'devices.config', 'account.routing.view', 'device.routing.view'}
SCOPES = {'self', 'selected', 'global'}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS accounts(
 id TEXT PRIMARY KEY, admin_id INTEGER UNIQUE REFERENCES admins(id), phone TEXT UNIQUE,
 email TEXT UNIQUE, enabled INTEGER NOT NULL DEFAULT 1, voluntary_2fa INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS roles(
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, permissions TEXT NOT NULL,
 primary_methods TEXT NOT NULL, secondary_methods TEXT NOT NULL,
 require_2fa INTEGER NOT NULL DEFAULT 0, protected INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS grants(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 role_id TEXT NOT NULL REFERENCES roles(id), scope TEXT NOT NULL CHECK(scope IN ('self','selected','global')));
CREATE TABLE IF NOT EXISTS grant_targets(
 grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
 account_id TEXT NOT NULL REFERENCES accounts(id), PRIMARY KEY(grant_id,account_id));
CREATE INDEX IF NOT EXISTS grants_account ON grants(account_id);
CREATE TABLE IF NOT EXISTS identity_sessions(
 token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 created INTEGER NOT NULL, expires INTEGER NOT NULL, confirmed INTEGER NOT NULL,
 methods TEXT NOT NULL, user_verified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
 id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS providers(
 id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS challenges(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 purpose TEXT NOT NULL, method TEXT NOT NULL, browser_hash TEXT NOT NULL,
 expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 secret_hash TEXT, link_hash TEXT, payload TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS challenges_account ON challenges(account_id,purpose,method);
CREATE TABLE IF NOT EXISTS backup_codes(
 account_id TEXT NOT NULL REFERENCES accounts(id), digest TEXT NOT NULL,
 PRIMARY KEY(account_id,digest));
CREATE TABLE IF NOT EXISTS passkeys(
 id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 name TEXT NOT NULL, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
 created INTEGER NOT NULL, last_used INTEGER);
CREATE TABLE IF NOT EXISTS recovery_codes(
 account_id TEXT PRIMARY KEY REFERENCES accounts(id), digest TEXT NOT NULL,
 expires INTEGER NOT NULL);
'''


def seed_roles(con):
    initial = [
        ('owner', 'Владелец', set(ACTIONS), ['password'], ['totp', 'webauthn'], True),
        ('administrator', 'Администратор', set(ACTIONS), ['password'], ['totp', 'webauthn'], False),
        ('operator', 'Оператор', set(ACCOUNT_ACTIONS) - {'accounts.state'}, ['password'], ['totp', 'webauthn'], False),
        ('observer', 'Наблюдатель', {p for p in ACCOUNT_ACTIONS if p.endswith('.view')}, ['password'], ['totp', 'webauthn'], False),
        ('user', 'Пользователь', USER_ACTIONS, ['password'], ['totp', 'webauthn'], False),
        ('phone', 'Телефонный вход', USER_ACTIONS, ['phone'], ['totp', 'webauthn'], False),
        ('exit-choice', 'Выбор RU-выхода', {'device.exit'}, [], [], False),
    ]
    for key, name, permissions, primary, secondary, protected in initial:
        con.execute('INSERT OR IGNORE INTO roles VALUES(?,?,?,?,?,0,?)',
                    (key, name, json.dumps(sorted(permissions)), json.dumps(primary), json.dumps(secondary), int(protected)))
    for provider in ('zvonok', 'email'):
        enabled = provider == 'zvonok' and bool(os.getenv('ZVONOK_PUBLIC_KEY'))
        config = {key: os.getenv('ZVONOK_' + key.upper(), '') for key in ('public_key', 'campaign_id')} if provider == 'zvonok' else {}
        if provider == 'zvonok':
            config['success_statuses'] = os.getenv('ZVONOK_SUCCESS_STATUSES', 'processed,success,confirmed,pincode_ok')
        con.execute('INSERT OR IGNORE INTO providers(id,enabled,config) VALUES(?,?,?)', (provider, int(enabled), json.dumps(config)))


def grant(con, account_id, role_id, scope='self', targets=()):
    if scope not in SCOPES or (scope != 'selected' and targets) or (scope == 'selected' and not targets):
        raise ValueError('Укажите область назначения и аккаунты')
    if role_id == 'owner' and scope != 'global':
        raise ValueError('Роль владельца требует глобальной области')
    key = str(uuid.uuid4())
    con.execute('INSERT INTO grants VALUES(?,?,?,?)', (key, account_id, role_id, scope))
    con.executemany('INSERT INTO grant_targets VALUES(?,?)', [(key, target) for target in set(targets)])
    return key


def policy(con, account_id):
    rows = con.execute('''SELECT r.* FROM roles r JOIN grants g ON g.role_id=r.id
                          WHERE g.account_id=?''', (account_id,)).fetchall()
    account = con.execute('SELECT voluntary_2fa FROM accounts WHERE id=?', (account_id,)).fetchone()
    return {'primary': set().union(*(set(json.loads(r['primary_methods'])) for r in rows)),
            'secondary': set().union(*(set(json.loads(r['secondary_methods'])) for r in rows)),
            'required': bool(account and account[0]) or any(r['require_2fa'] for r in rows)}


def owner(con, account_id):
    return bool(con.execute('''SELECT 1 FROM grants g JOIN accounts a ON a.id=g.account_id
      LEFT JOIN admins c ON c.id=a.admin_id WHERE a.id=? AND a.enabled=1
      AND (c.id IS NULL OR c.enabled=1) AND g.role_id='owner' AND g.scope='global' ''', (account_id,)).fetchone())


def allowed(con, actor, action, target=None):
    if action not in ACTIONS:
        return False
    for row in con.execute('''SELECT g.id,g.scope,r.permissions FROM grants g
                              JOIN roles r ON r.id=g.role_id WHERE g.account_id=?''', (actor,)):
        if action not in json.loads(row['permissions']):
            continue
        if row['scope'] == 'global':
            return True
        if action in GLOBAL_ACTIONS or target is None:
            continue
        if row['scope'] == 'self' and target == actor:
            return True
        if row['scope'] == 'selected' and con.execute('SELECT 1 FROM grant_targets WHERE grant_id=? AND account_id=?', (row['id'], target)).fetchone():
            return True
    return False


def audit(con, actor, action, target):
    # Fixed action and resource identifiers only, never form values.
    con.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)', (int(time.time()), actor, action, target))


def ensure_owner(con):
    if not con.execute('''SELECT 1 FROM accounts a JOIN grants g ON g.account_id=a.id
       LEFT JOIN admins c ON c.id=a.admin_id WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)
       AND g.role_id='owner' AND g.scope='global' ''').fetchone():
        raise ValueError('Нельзя удалить, отключить или лишить роли последнего активного владельца')


def configured_methods(con, row):
    methods = set()
    credential = con.execute('SELECT password_hash,totp_verified FROM admins WHERE id=?', (row['admin_id'],)).fetchone()
    if credential and credential['password_hash']:
        methods.add('password')
    if credential and credential['totp_verified']:
        methods.add('totp')
    if con.execute('SELECT 1 FROM passkeys WHERE account_id=?', (row['id'],)).fetchone():
        methods.add('webauthn')
    for method, provider in (('phone', 'zvonok'), ('email', 'email')):
        if row[method] and con.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (provider,)).fetchone():
            methods.add(method)
    return methods


def ensure_login_paths(con):
    for row in con.execute('''SELECT a.* FROM accounts a LEFT JOIN admins c ON c.id=a.admin_id
                             WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)''').fetchall():
        rules = policy(con, row['id'])
        if not rules['primary'] & configured_methods(con, row):
            raise ValueError('Изменение лишает активный аккаунт настроенного способа входа')
        if rules['required'] and not rules['secondary'] and 'webauthn' not in rules['primary']:
            raise ValueError('Для обязательной 2FA нужен второй способ или WebAuthn с проверкой пользователя')


class Identity:
    def __init__(self, auth_store, main_path):
        self.auth = auth_store
        self.main_path = str(main_path)

    @contextmanager
    def transaction(self):
        with self.auth.db() as con:
            con.execute('ATTACH DATABASE ? AS portal', (self.main_path,))
            yield con

    def initialize(self):
        with self.auth.db() as con:
            con.executescript(SCHEMA)
            seed_roles(con)
        # Requiring rollback journals is essential for a cross-file atomic commit.
        for path in (self.auth.path, self.main_path):
            with sqlite3.connect(path) as con:
                if con.execute('PRAGMA journal_mode=DELETE').fetchone()[0] != 'delete':
                    raise RuntimeError('Identity migration requires SQLite rollback journals')
        self.migrate()

    def migrate(self):
        with self.transaction() as con:
            first = not con.execute("SELECT 1 FROM settings WHERE key='identity_migration'").fetchone()
            for credential in con.execute('SELECT * FROM admins').fetchall():
                if con.execute('SELECT 1 FROM accounts WHERE admin_id=?', (credential['id'],)).fetchone():
                    continue
                key = str(uuid.uuid4())
                con.execute('INSERT INTO accounts(id,admin_id,enabled,voluntary_2fa) VALUES(?,?,?,?)', (key, credential['id'], credential['enabled'], credential['totp_verified']))
                grant(con, key, 'owner' if first else 'user', 'global' if first else 'self')
                con.execute('INSERT INTO portal.users(phone,account_id,name,device_limit,enabled,created_at) VALUES(?,?,?,2,?,?)',
                            (key, key, credential['username'], credential['enabled'], int(time.time())))
            for user in con.execute('SELECT * FROM portal.users WHERE account_id IS NULL').fetchall():
                key = str(uuid.uuid4())
                con.execute('INSERT INTO accounts(id,phone,enabled) VALUES(?,?,?)', (key, user['phone'], user['enabled']))
                grant(con, key, 'phone')
                if user['can_change_ru_exit']:
                    grant(con, key, 'exit-choice')
                con.execute('UPDATE portal.users SET account_id=? WHERE phone=?', (key, user['phone']))
            con.execute('''UPDATE portal.devices SET account_id=(SELECT account_id FROM portal.users u
                           WHERE u.phone=devices.phone) WHERE account_id IS NULL''')
            if first:
                con.execute('DELETE FROM sessions')
                con.execute('DELETE FROM portal.verifications')
                con.execute("INSERT INTO settings VALUES('identity_migration','1')")

    def allowed(self, account_id, action, target=None):
        with self.auth.db() as con:
            return allowed(con, account_id, action, target)

    def owner(self, account_id):
        with self.auth.db() as con:
            return owner(con, account_id)

    def save_role(self, actor, role_id, name, permissions, primary, secondary, required):
        if not name.strip() or len(name) > 80 or not set(permissions) <= ACTIONS.keys():
            raise ValueError('Некорректное название или право')
        if not set(primary) <= PRIMARY or not set(secondary) <= SECONDARY:
            raise ValueError('Неизвестный способ входа')
        with self.auth.db() as con:
            if not owner(con, actor):
                raise PermissionError('Только владелец управляет ролями')
            row = con.execute('SELECT * FROM roles WHERE id=?', (role_id,)).fetchone()
            if row and row['protected'] and (set(permissions) != set(ACTIONS) or name != row['name']):
                raise ValueError('Права и название защищённой роли нельзя изменять')
            key = role_id or str(uuid.uuid4())
            con.execute('''INSERT INTO roles VALUES(?,?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET
             name=excluded.name,permissions=excluded.permissions,primary_methods=excluded.primary_methods,
             secondary_methods=excluded.secondary_methods,require_2fa=excluded.require_2fa''',
             (key, name.strip(), json.dumps(sorted(set(permissions))), json.dumps(sorted(set(primary))),
              json.dumps(sorted(set(secondary))), int(required)))
            ensure_login_paths(con)
            audit(con, actor, 'roles.save', key)
            return key

    def assign(self, actor, account_id, role_id, scope, targets=(), remove=''):
        with self.auth.db() as con:
            if not owner(con, actor):
                raise PermissionError('Только владелец управляет назначениями')
            if remove:
                con.execute('DELETE FROM grants WHERE id=? AND account_id=?', (remove, account_id))
            else:
                grant(con, account_id, role_id, scope, targets)
            ensure_owner(con)
            ensure_login_paths(con)
            audit(con, actor, 'grants.remove' if remove else 'grants.add', account_id)

    def new_session(self, con, account_id, methods, verified=False, ttl=28800):
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        con.execute('DELETE FROM identity_sessions WHERE expires<=?', (now,))
        con.execute('INSERT INTO identity_sessions VALUES(?,?,?,?,?,?,?)',
                    (self.auth.digest(token), account_id, now, now + ttl, now, json.dumps(methods), int(verified)))
        return token

    def session(self, token, limited=False):
        if not token or len(token) > 128:
            return None
        with self.auth.db() as con:
            row = con.execute('''SELECT a.*,s.confirmed,s.methods,s.user_verified,s.token_hash,
                 c.username,c.must_change,c.totp_key,c.totp_verified,c.pending_totp,c.pending_at
                 FROM accounts a JOIN identity_sessions s ON s.account_id=a.id
                 LEFT JOIN admins c ON c.id=a.admin_id WHERE s.token_hash=? AND s.expires>?
                 AND a.enabled=1 AND (c.id IS NULL OR c.enabled=1)''', (self.auth.digest(token), int(time.time()))).fetchone()
            if not row:
                return None
            row = dict(row)
            rules = policy(con, row['id'])
            methods = json.loads(row['methods'])
            available = {'password', 'totp', 'webauthn', 'backup'}
            for provider in con.execute('SELECT id FROM providers WHERE enabled=1'):
                available.add('phone' if provider['id'] == 'zvonok' else provider['id'])
            ready = bool(methods and methods[0] in rules['primary'] & available)
            if rules['required']:
                webauthn_permitted = methods[0] == 'webauthn' or 'webauthn' in rules['secondary']
                ready &= bool(('webauthn' in methods and row['user_verified'] and webauthn_permitted) or
                              (len(set(methods)) >= 2 and methods[-1] in available and (methods[-1] in rules['secondary'] or methods[-1] == 'backup')))
            row.update(account_id=row['id'], id=row['admin_id'], ready=ready, policy=rules)
            return row if ready or limited else None
