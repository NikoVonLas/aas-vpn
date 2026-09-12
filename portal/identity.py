"""Account identities, scoped roles and coordinated main/auth database migration.

The router consumes only opaque account IDs and routing data. No credential or
permission is copied into its database. Attached databases use rollback journals
so SQLite's super-journal commits account and device changes together.
"""
from contextlib import contextmanager
from enum import Enum
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
    'account.exit': 'Выбор альтернативного выхода аккаунта',
    'device.routing.view': 'Просмотр маршрутов устройства',
    'device.routing.edit': 'Изменение маршрутов устройства',
    'device.exit': 'Выбор альтернативного выхода устройства',
}
OTHER_ACCOUNTS = 'accounts.others'
GLOBAL_ACTIONS = {
    OTHER_ACCOUNTS: 'Доступ к чужим аккаунтам',
    'accounts.create': 'Создание аккаунтов', 'routing.global': 'Глобальная маршрутизация',
    'exits.view': 'Просмотр альтернативных выходов', 'exits.edit': 'Управление альтернативными выходами',
    'exits.private': 'Просмотр конфигураций альтернативных выходов', 'exits.default': 'Выбор глобального альтернативного выхода',
    'settings.edit': 'Общие настройки', 'devices.assign': 'Назначение устройств без владельца',
}
ACTIONS = {**ACCOUNT_ACTIONS, **GLOBAL_ACTIONS}
class LoginMethod(Enum):
    PASSWORD = 'password'
    PHONE = 'phone'
    EMAIL = 'email'
    WEBAUTHN = 'webauthn'
    TOTP = 'totp'
    OIDC = 'oidc'


PRIMARY = {method.value for method in LoginMethod if method != LoginMethod.TOTP}
SECONDARY = {method.value for method in LoginMethod if method != LoginMethod.OIDC}
BUILTIN_METHODS = {'password', 'webauthn', 'totp'}
METHOD_PROVIDERS = {method: ('zvonok' if method == 'phone' else method) for method in PRIMARY | SECONDARY}
USER_ACTIONS = {'accounts.view', 'devices.view', 'devices.create', 'devices.rename',
                'devices.delete', 'devices.config', 'account.routing.view', 'device.routing.view'}
SCOPES = {'self', 'selected', 'global'}
ROLE_QUERY = 'SELECT * FROM roles WHERE id=?'

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
 role_id TEXT NOT NULL REFERENCES roles(id), scope TEXT NOT NULL CHECK(scope IN ('self','selected','global')),
 role_based INTEGER NOT NULL DEFAULT 0);
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
CREATE TABLE IF NOT EXISTS oidc_links(
 account_id TEXT PRIMARY KEY REFERENCES accounts(id), issuer TEXT NOT NULL,
 subject TEXT NOT NULL, UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS oidc_flows(
 state_hash TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, expires INTEGER NOT NULL,
 payload TEXT NOT NULL);
'''


def seed_roles(con):
    initial = [
        ('administrator', 'Администратор', set(ACTIONS), 1, 1),
        ('user', 'Пользователь', USER_ACTIONS, 0, 0),
    ]
    for key, name, permissions, required, protected in initial:
        con.execute('INSERT OR IGNORE INTO roles VALUES(?,?,?,?,?,?,?)',
                    (key, name, json.dumps(sorted(permissions)), '["password"]', '["totp", "webauthn"]', required, protected))
    migrate_builtin_roles(con)
    con.execute("UPDATE grants SET role_based=1 WHERE (role_id='user' AND scope='self') OR (role_id='administrator' AND scope='global')")
    for method in sorted(BUILTIN_METHODS):
        con.execute('INSERT OR IGNORE INTO providers(id,enabled) VALUES(?,1)', (method,))
    for provider in ('zvonok', 'email', 'oidc'):
        enabled = provider == 'zvonok' and bool(os.getenv('ZVONOK_PUBLIC_KEY'))
        config = {key: os.getenv('ZVONOK_' + key.upper(), '') for key in ('public_key', 'campaign_id')} if provider == 'zvonok' else {}
        if provider == 'zvonok':
            config['success_statuses'] = os.getenv('ZVONOK_SUCCESS_STATUSES', 'processed,success,confirmed,pincode_ok')
        con.execute('INSERT OR IGNORE INTO providers(id,enabled,config) VALUES(?,?,?)', (provider, int(enabled), json.dumps(config)))


def migrate_builtin_roles(con):
    """Retire old defaults without discarding assigned custom access or login paths."""
    for old, new in [('owner', 'administrator'), ('phone', 'user')]:
        previous = con.execute(ROLE_QUERY, (old,)).fetchone()
        if not previous:
            continue
        current = con.execute(ROLE_QUERY, (new,)).fetchone()
        if con.execute('SELECT 1 FROM grants WHERE role_id=?', (old,)).fetchone():
            primary = sorted(set(json.loads(previous['primary_methods'])) | set(json.loads(current['primary_methods'])))
            secondary = sorted(set(json.loads(previous['secondary_methods'])) | set(json.loads(current['secondary_methods'])))
            con.execute('UPDATE roles SET primary_methods=?,secondary_methods=? WHERE id=?', (json.dumps(primary), json.dumps(secondary), new))
        con.execute('UPDATE grants SET role_id=? WHERE role_id=?', (new, old))
        con.execute('DELETE FROM roles WHERE id=?', (old,))
    con.execute("UPDATE roles SET protected=1,require_2fa=1,permissions=? WHERE id='administrator'", (json.dumps(sorted(ACTIONS)),))
    con.execute("DELETE FROM roles WHERE id IN ('operator','observer','exit-choice') AND id NOT IN (SELECT role_id FROM grants)")


def grant(con, account_id, role_id, scope='self', targets=(), *, role_based=False):
    if scope not in SCOPES or (scope != 'selected' and targets) or (scope == 'selected' and not targets):
        raise ValueError('Укажите область назначения и аккаунты')
    if role_id == 'administrator' and scope != 'global':
        raise ValueError('Роль администратора требует глобальной области')
    key = str(uuid.uuid4())
    con.execute('INSERT INTO grants(id,account_id,role_id,scope,role_based) VALUES(?,?,?,?,?)', (key, account_id, role_id, scope, int(role_based)))
    con.executemany('INSERT INTO grant_targets VALUES(?,?)', [(key, target) for target in set(targets)])
    return key


def enabled_methods(con):
    providers = {row['id'] for row in con.execute('SELECT id FROM providers WHERE enabled=1')}
    return {method for method, provider in METHOD_PROVIDERS.items() if provider in providers}


def policy(con, account_id):
    rows = con.execute('''SELECT r.* FROM roles r JOIN grants g ON g.role_id=r.id
                          WHERE g.account_id=?''', (account_id,)).fetchall()
    account = con.execute('SELECT voluntary_2fa FROM accounts WHERE id=?', (account_id,)).fetchone()
    enabled = enabled_methods(con)
    return {'primary': set().union(*(set(json.loads(r['primary_methods'])) for r in rows)) & enabled,
            'secondary': set().union(*(set(json.loads(r['secondary_methods'])) for r in rows)) & enabled,
            'required': bool(account and account[0]) or any(r['require_2fa'] for r in rows)}


def owner(con, account_id):
    return bool(con.execute('''SELECT 1 FROM grants g JOIN accounts a ON a.id=g.account_id
      LEFT JOIN admins c ON c.id=a.admin_id WHERE a.id=? AND a.enabled=1
      AND (c.id IS NULL OR c.enabled=1) AND g.role_id='administrator' AND g.scope='global' ''', (account_id,)).fetchone())


def legacy_allowed(con, row, actor, action, target):
    """Retain existing restrictions for older scoped assignments."""
    if row['scope'] == 'global':
        return True
    if action in GLOBAL_ACTIONS or target is None:
        return False
    if row['scope'] == 'self':
        return target == actor
    return bool(con.execute('SELECT 1 FROM grant_targets WHERE grant_id=? AND account_id=?', (row['id'], target)).fetchone())


def allowed(con, actor, action, target=None):
    if action not in ACTIONS:
        return False
    rows = con.execute('''SELECT g.*,r.permissions FROM grants g
                          JOIN roles r ON r.id=g.role_id WHERE g.account_id=?''', (actor,)).fetchall()
    permissions = set().union(*(set(json.loads(row['permissions'])) for row in rows if row['role_based']))
    if action in permissions and (action in GLOBAL_ACTIONS or target == actor or OTHER_ACCOUNTS in permissions):
        return True
    return any(not row['role_based'] and action in json.loads(row['permissions'])
               and legacy_allowed(con, row, actor, action, target) for row in rows)


def privileged(con, account_id):
    return any((set(json.loads(row['permissions'])) & GLOBAL_ACTIONS.keys()) if row['role_based'] else row['scope'] != 'self'
               for row in con.execute('SELECT g.*,r.permissions FROM grants g JOIN roles r ON r.id=g.role_id WHERE g.account_id=?', (account_id,)))


def replace_roles(con, actor, account_id, role_ids):
    if not owner(con, actor):
        raise PermissionError('Только администратор управляет ролями пользователей')
    selected = set(role_ids)
    known = {row['id'] for row in con.execute('SELECT id FROM roles')}
    if not selected or not selected <= known:
        raise ValueError('Выберите хотя бы одну существующую роль')
    current = {row['role_id'] for row in con.execute('SELECT role_id FROM grants WHERE account_id=?', (account_id,))}
    if selected == current:
        return
    for role_id in current - selected:
        con.execute('DELETE FROM grants WHERE account_id=? AND role_id=?', (account_id, role_id))
    for role_id in sorted(selected - current):
        grant(con, account_id, role_id, 'global' if role_id == 'administrator' else 'self', role_based=True)
    ensure_owner(con)
    ensure_login_paths(con)
    audit(con, actor, 'roles.replace', account_id)


def audit(con, actor, action, target):
    # Fixed action and resource identifiers only, never form values.
    con.execute('INSERT INTO audit(at,actor,action,target) VALUES(?,?,?,?)', (int(time.time()), actor, action, target))


def ensure_owner(con):
    if not con.execute('''SELECT 1 FROM accounts a JOIN grants g ON g.account_id=a.id
       LEFT JOIN admins c ON c.id=a.admin_id WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)
       AND g.role_id='administrator' AND g.scope='global' ''').fetchone():
        raise ValueError('Нельзя удалить, отключить или лишить роли последнего активного администратора')


def configured_methods(con, row):
    methods = set()
    provider = con.execute("SELECT config FROM providers WHERE id='oidc'").fetchone()
    issuer = json.loads(provider['config']).get('issuer') if provider else None
    if con.execute('SELECT 1 FROM oidc_links WHERE account_id=? AND issuer=?', (row['id'], issuer)).fetchone():
        methods.add('oidc')
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
    return methods & enabled_methods(con)


def ensure_login_paths(con):
    for row in con.execute('''SELECT a.* FROM accounts a LEFT JOIN admins c ON c.id=a.admin_id
                             WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)''').fetchall():
        rules = policy(con, row['id'])
        if not rules['primary'] & configured_methods(con, row):
            raise ValueError('Изменение лишает активный аккаунт настроенного способа входа')
        if rules['required'] and not rules['secondary'] and 'webauthn' not in rules['primary']:
            raise ValueError('Для обязательной 2FA нужен второй способ или WebAuthn с проверкой пользователя')


def ready_accounts(con):
    """Accounts that can currently complete sign-in with their configured factors."""
    ready = set()
    for row in con.execute('''SELECT a.* FROM accounts a LEFT JOIN admins c ON c.id=a.admin_id
                             WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)''').fetchall():
        rules = policy(con, row['id'])
        configured = configured_methods(con, row)
        primary = rules['primary'] & configured
        secondary = rules['secondary'] & configured
        if any(not rules['required'] or method == 'webauthn' or secondary - {method} for method in primary):
            ready.add(row['id'])
    return ready


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
            if 'role_based' not in {row['name'] for row in con.execute('PRAGMA table_info(grants)')}:
                con.execute('ALTER TABLE grants ADD COLUMN role_based INTEGER NOT NULL DEFAULT 0')
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
                grant(con, key, 'administrator' if first else 'user', 'global' if first else 'self', role_based=True)
                con.execute('INSERT INTO portal.users(phone,account_id,name,device_limit,enabled,created_at) VALUES(?,?,?,2,?,?)',
                            (key, key, credential['username'], credential['enabled'], int(time.time())))
            for user in con.execute('SELECT * FROM portal.users WHERE account_id IS NULL').fetchall():
                key = str(uuid.uuid4())
                con.execute('INSERT INTO accounts(id,phone,enabled) VALUES(?,?,?)', (key, user['phone'], user['enabled']))
                grant(con, key, 'user', role_based=True)
                methods = json.loads(con.execute("SELECT primary_methods FROM roles WHERE id='user'").fetchone()[0])
                con.execute("UPDATE roles SET primary_methods=? WHERE id='user'", (json.dumps(sorted(set(methods) | {'phone'})),))
                if user['can_change_ru_exit']:
                    con.execute("INSERT OR IGNORE INTO roles VALUES('exit-choice','Выбор альтернативного выхода','[\"device.exit\"]','[]','[]',0,0)")
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
                raise PermissionError('Только администратор управляет ролями')
            row = con.execute(ROLE_QUERY, (role_id,)).fetchone()
            if row and row['protected'] and (set(permissions) != set(ACTIONS) or name != row['name']):
                raise ValueError('Права и название защищённой роли нельзя изменять')
            if role_id == 'administrator' and not required:
                raise ValueError('Для администратора обязательна 2FA')
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
                raise PermissionError('Только администратор управляет назначениями')
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
            available = enabled_methods(con) | {'backup'}
            ready = bool(methods and methods[0] in rules['primary'] & available)
            if rules['required']:
                webauthn_permitted = 'webauthn' in available and (methods[0] == 'webauthn' or 'webauthn' in rules['secondary'])
                ready &= bool(('webauthn' in methods and row['user_verified'] and webauthn_permitted) or
                              (len(set(methods)) >= 2 and methods[-1] in available and (methods[-1] in rules['secondary'] or methods[-1] == 'backup')))
            row.update(account_id=row['id'], id=row['admin_id'], ready=ready, policy=rules)
            return row if ready or limited else None
