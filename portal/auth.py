"""Local administrator credentials and revocable, opaque sessions."""
import argparse
from contextlib import contextmanager
import getpass
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
import pyotp

ADDRESS_BUCKET = 'address:'
USER_BUCKET = 'user:'
ACCOUNT_BY_CREDENTIAL = 'SELECT id FROM accounts WHERE admin_id=?'


COOKIE = '__Host-aas_admin'
HASHER = PasswordHasher()
INVALID = 'Неверный логин, пароль или код 2FA'
REVOKE_SESSIONS = 'DELETE FROM sessions WHERE admin_id=?'
ADMIN_QUERY = 'SELECT * FROM admins WHERE id=?'


class Auth:
    def __init__(self, path):
        self.path = str(path)

    @contextmanager
    def db(self):
        con = sqlite3.connect(self.path, timeout=15)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        try:
            con.execute('BEGIN IMMEDIATE')
            yield con
            con.commit()
        finally:
            con.close()

    def initialize(self, phone_secret=None):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as con:
            con.executescript('''
                CREATE TABLE IF NOT EXISTS admins(
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT, totp_key TEXT, totp_verified INTEGER NOT NULL DEFAULT 0,
                    enabled INTEGER NOT NULL DEFAULT 1, must_change INTEGER NOT NULL DEFAULT 0,
                    last_totp INTEGER NOT NULL DEFAULT -1, pending_totp TEXT, pending_at INTEGER);
                CREATE TABLE IF NOT EXISTS sessions(
                    token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(
                    bucket TEXT PRIMARY KEY, started INTEGER NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            ''')
            con.execute("INSERT OR IGNORE INTO settings VALUES('phone_secret',?)",
                        (phone_secret or secrets.token_hex(32),))
            con.execute("INSERT OR IGNORE INTO settings VALUES('remember_seconds','2592000')")
        os.chmod(self.path, 0o600)

    def setting(self, name):
        with self.db() as con:
            return con.execute('SELECT value FROM settings WHERE key=?', (name,)).fetchone()[0]

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def throttle(self, username, address):
        now = int(time.time())
        limited = False
        with self.db() as con:
            con.execute('DELETE FROM attempts WHERE started<?', (now - 900,))
            for bucket, limit in [(USER_BUCKET + username, 10), (ADDRESS_BUCKET + address, 40)]:
                key = self.digest(bucket)
                con.execute('INSERT INTO attempts VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1', (key, now))
                limited |= con.execute('SELECT count FROM attempts WHERE bucket=?', (key,)).fetchone()[0] > limit
        if limited:
            raise ValueError('Слишком много попыток. Повторите через 15 минут')

    @staticmethod
    def password_matches(stored, supplied):
        if not stored:
            return False
        try:
            return HASHER.verify(stored, supplied)
        except (VerificationError, InvalidHashError):
            return False

    @staticmethod
    def verify(con, row, password, code):
        if not row or not row['enabled'] or not Auth.password_matches(row['password_hash'], password):
            raise ValueError(INVALID)
        if row['totp_verified']:
            if not row['totp_key']:
                raise ValueError(INVALID)
            counter = int(time.time()) // 30
            match = next((step for step in range(counter - 1, counter + 2)
                          if step > row['last_totp'] and secrets.compare_digest(pyotp.TOTP(row['totp_key']).at(step * 30), code)), None)
            if match is None:
                raise ValueError(INVALID)
            con.execute('UPDATE admins SET last_totp=? WHERE id=?', (match, row['id']))

    def login(self, username, password, code, address, remember=False):
        self.throttle(username, address)
        with self.db() as con:
            row = con.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
            if hasattr(self, 'identity'):
                import identity
                if not row or not row['enabled'] or not self.password_matches(row['password_hash'], password):
                    raise ValueError(INVALID)
                account = con.execute('SELECT * FROM accounts WHERE admin_id=?', (row['id'],)).fetchone()
                if not account or not account['enabled'] or 'password' not in identity.policy(con, account['id'])['primary']:
                    raise ValueError(INVALID)
                methods = ['password']
                if code:
                    from login_methods import totp_check
                    if 'totp' not in identity.policy(con, account['id'])['secondary'] or not totp_check(con, row, code):
                        raise ValueError(INVALID)
                    methods.append('totp')
                token = self.identity.new_session(con, account['id'], methods)
                con.executemany('DELETE FROM attempts WHERE bucket=?', [(self.digest(USER_BUCKET + username),), (self.digest(ADDRESS_BUCKET + address),)])
                return token, 28800
            self.verify(con, row, password, code)
            token = secrets.token_urlsafe(32)
            ttl = int(con.execute("SELECT value FROM settings WHERE key='remember_seconds'").fetchone()[0]) if remember else 28800
            con.execute('DELETE FROM sessions WHERE expires<=?', (int(time.time()),))
            con.execute('INSERT INTO sessions VALUES(?,?,?)', (self.digest(token), row['id'], int(time.time()) + ttl))
            con.executemany('DELETE FROM attempts WHERE bucket=?', [(self.digest(USER_BUCKET + username),), (self.digest(ADDRESS_BUCKET + address),)])
            return token, ttl

    def session(self, token):
        if hasattr(self, 'identity'):
            return self.identity.session(token, limited=True)
        if not token or len(token) > 128:
            return None
        with self.db() as con:
            row = con.execute('''SELECT a.* FROM admins a JOIN sessions s ON a.id=s.admin_id
                                 WHERE s.token_hash=? AND s.expires>? AND a.enabled=1''',
                              (self.digest(token), int(time.time()))).fetchone()
        return dict(row) if row else None

    def logout(self, token):
        with self.db() as con:
            con.execute('DELETE FROM sessions WHERE token_hash=?', (self.digest(token),))
            if hasattr(self, 'identity'):
                con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (self.digest(token),))

    @staticmethod
    def validate_password(password):
        if not 12 <= len(password) <= 128:
            raise ValueError('Пароль должен содержать от 12 до 128 символов')

    def add(self, username, password, must_change=True):
        self.validate_password(password)
        username = username.strip()
        if not username or len(username) > 64:
            raise ValueError('Укажите логин длиной до 64 символов')
        with self.db() as con:
            try:
                con.execute('INSERT INTO admins(username,password_hash,must_change) VALUES(?,?,?)',
                            (username, HASHER.hash(password), int(must_change)))
            except sqlite3.IntegrityError:
                raise ValueError('Такой логин уже существует') from None
        if hasattr(self, 'identity'):
            import identity
            self.identity.migrate()
            with self.db() as con:
                account = con.execute('SELECT a.id FROM accounts a JOIN admins c ON c.id=a.admin_id WHERE c.username=?', (username,)).fetchone()[0]
                con.execute('DELETE FROM grants WHERE account_id=?', (account,))
                identity.grant(con, account, 'administrator', 'global')

    def change(self, actor_id, target_id, action, password, code, new_password=''):
        if action in {'password', 'reset'}:
            self.validate_password(new_password)
        with self.db() as con:
            actor = con.execute(ADMIN_QUERY, (actor_id,)).fetchone()
            self.verify(con, actor, password, code)
            target = con.execute(ADMIN_QUERY, (target_id,)).fetchone()
            if not target:
                raise ValueError('Администратор не найден')
            if action in {'password', 'totp-start', 'totp-disable'} and actor_id != target_id:
                raise ValueError('Это действие доступно только владельцу аккаунта')
            self.apply_change(con, target, action, new_password)
            if hasattr(self, 'identity'):
                import identity
                identity.ensure_owner(con)
                identity.ensure_login_paths(con)
                account_id = con.execute(ACCOUNT_BY_CREDENTIAL, (target_id,)).fetchone()[0]
                if action != 'totp-start':
                    con.execute('DELETE FROM identity_sessions WHERE account_id=?', (account_id,))
                actor_account = con.execute(ACCOUNT_BY_CREDENTIAL, (actor_id,)).fetchone()[0]
                identity.audit(con, actor_account, 'credentials.' + action, account_id)

    @staticmethod
    def apply_change(con, target, action, password):
        target_id = target['id']
        if action == 'toggle':
            if target['enabled'] and con.execute('SELECT count(*) FROM admins WHERE enabled=1').fetchone()[0] <= 1:
                raise ValueError('Нельзя отключить последнего администратора')
            con.execute('UPDATE admins SET enabled=1-enabled WHERE id=?', (target_id,))
        elif action in {'password', 'reset'}:
            con.execute('UPDATE admins SET password_hash=?,must_change=? WHERE id=?',
                        (HASHER.hash(password), int(action == 'reset'), target_id))
        elif action in {'totp-disable', 'totp-reset'}:
            con.execute('UPDATE admins SET totp_key=NULL,totp_verified=0,last_totp=-1,pending_totp=NULL WHERE id=?', (target_id,))
        elif action == 'totp-start':
            con.execute('UPDATE admins SET pending_totp=?,pending_at=? WHERE id=?',
                        (pyotp.random_base32(), int(time.time()), target_id))
            return
        else:
            raise ValueError('Неизвестное действие')
        con.execute(REVOKE_SESSIONS, (target_id,))

    def confirm_totp(self, admin_id, code):
        with self.db() as con:
            row = con.execute(ADMIN_QUERY, (admin_id,)).fetchone()
            if not row or not row['pending_totp'] or int(time.time()) - (row['pending_at'] or 0) > 600:
                raise ValueError('Настройка устарела. Начните заново')
            if not pyotp.TOTP(row['pending_totp']).verify(code):
                raise ValueError('Неверный код 2FA')
            con.execute('UPDATE admins SET totp_key=pending_totp,totp_verified=1,pending_totp=NULL,last_totp=? WHERE id=?',
                        (int(time.time()) // 30, admin_id))
            con.execute(REVOKE_SESSIONS, (admin_id,))
            if hasattr(self, 'identity'):
                con.execute('UPDATE accounts SET voluntary_2fa=1 WHERE admin_id=?', (admin_id,))
                con.execute('DELETE FROM identity_sessions WHERE account_id=(SELECT id FROM accounts WHERE admin_id=?)', (admin_id,))


def main():
    parser = argparse.ArgumentParser(description='Create or recover a local administrator; passwords are read privately')
    parser.add_argument('action', choices=['create', 'recover'])
    parser.add_argument('username')
    args = parser.parse_args()
    store = Auth(os.getenv('AUTH_DB', '/auth/auth.db'))
    store.initialize()
    main_path = os.getenv('PORTAL_DB', '/data/portal.db')
    if Path(main_path).is_file():
        from identity import Identity
        store.identity = Identity(store, main_path)
        store.identity.initialize()
    password = getpass.getpass('New password: ')
    if password != getpass.getpass('Repeat password: '):
        raise SystemExit('Passwords differ')
    store.validate_password(password)
    if args.action == 'create':
        store.add(args.username, password, must_change=False)
    else:
        with store.db() as con:
            row = con.execute('SELECT id FROM admins WHERE username=?', (args.username,)).fetchone()
            if not row:
                raise SystemExit('Administrator not found')
            con.execute('UPDATE admins SET password_hash=?,enabled=1,must_change=0,totp_key=NULL,totp_verified=0,last_totp=-1,pending_totp=NULL WHERE id=?',
                        (HASHER.hash(password), row['id']))
            con.execute(REVOKE_SESSIONS, (row['id'],))
            if hasattr(store, 'identity'):
                from identity import audit, grant
                account = con.execute(ACCOUNT_BY_CREDENTIAL, (row['id'],)).fetchone()[0]
                con.execute('UPDATE accounts SET enabled=1,voluntary_2fa=0 WHERE id=?', (account,))
                for table in ('identity_sessions', 'passkeys', 'backup_codes', 'recovery_codes', 'challenges'):
                    con.execute(f'DELETE FROM {table} WHERE account_id=?', (account,))
                con.execute('''INSERT OR IGNORE INTO roles VALUES('ssh-recovery','Восстановление через SSH',
                    '[]','["password"]','["totp","webauthn"]',0,0)''')
                grant(con, account, 'ssh-recovery')
                audit(con, 'ssh', 'recovery.ssh', account)
    print('Administrator updated; existing sessions revoked on recovery')


if __name__ == '__main__':
    main()
