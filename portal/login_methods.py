"""Trusted, bundled confirmation providers. Secrets never leave auth.db."""
import asyncio
from email.message import EmailMessage
from datetime import datetime
import json
import os
import secrets
import smtplib
import ssl
import time

import httpx
import pyotp

import identity


class EmailProvider:
    @staticmethod
    async def begin(config, address, code, link):
        def send():
            message = EmailMessage()
            message['From'] = config['sender']
            message['To'] = address
            message['Subject'] = 'Подтверждение входа AAS VPN'
            message.set_content(f'Код подтверждения: {code}\n\nИли откройте ссылку и нажмите «Подтвердить»:\n{link}\n\nСрок действия — 10 минут. Используйте код или ссылку только один раз.')
            context = ssl.create_default_context()
            if config.get('tls', 'starttls') == 'implicit':
                client = smtplib.SMTP_SSL(config['host'], int(config.get('port', 465)), timeout=15, context=context)
            else:
                client = smtplib.SMTP(config['host'], int(config.get('port', 587)), timeout=15)
                client.starttls(context=context)
                client.ehlo()
            with client:
                if config.get('username'):
                    client.login(config['username'], config['password'])
                client.send_message(message)
        await asyncio.to_thread(send)
        return {}

    @staticmethod
    async def verify(config, payload):
        # Code/link proofs are checked and consumed in the shared transaction.
        return False


class ZvonokProvider:
    URL = 'https://zvonok.com/manager/cabapi_external/api/v1/phones'

    @staticmethod
    def settings(config):
        return {key: config.get(key) or os.getenv(env, '') for key, env in
                [('public_key', 'ZVONOK_PUBLIC_KEY'), ('campaign_id', 'ZVONOK_CAMPAIGN_ID')]}

    @classmethod
    async def begin(cls, config, address, code='', link=''):
        data = {**cls.settings(config), 'phone': address}
        if not data['public_key'] or not data['campaign_id']:
            raise ValueError('Сервис подтверждения недоступен')
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(cls.URL + '/confirm/', data=data)
            response.raise_for_status()
            result = response.json()
        return {'phone': address, 'call_id': str(result.get('call_id') or result.get('id') or ''),
                'dial': str(result.get('confirm_phone') or result.get('phone_to_call') or result.get('verification_phone') or result.get('call_phone') or ''),
                'created': int(time.time())}

    @classmethod
    async def verify(cls, config, payload):
        settings = cls.settings(config)
        if payload['call_id']:
            params = {'public_key': settings['public_key'], 'call_id': payload['call_id'], 'expand': 1}
            endpoint = 'call_by_id/'
        else:
            params = {**settings, 'phone': payload['phone'], 'expand': 1}
            endpoint = 'calls_by_phone/'
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(cls.URL + '/' + endpoint, params=params)
            response.raise_for_status()
            result = response.json()
        records = call_records(result)
        valid = [r for r in records if isinstance(r, dict) and
                 (payload['call_id'] or payload['created'] - 5 <= (call_activity(r) or 0) <= payload['created'] + 600)]
        statuses = set(config.get('success_statuses', os.getenv('ZVONOK_SUCCESS_STATUSES', 'processed,success,confirmed,pincode_ok')).split(','))
        return any(value in statuses for record in valid for value in call_status_values(record))


PROVIDERS = {'email': EmailProvider, 'zvonok': ZvonokProvider}


class Confirmations:
    def __init__(self, identities):
        self.identities = identities
        self.auth = identities.auth

    def provider(self, method):
        provider = {'phone': 'zvonok', 'email': 'email'}.get(method)
        with self.auth.db() as con:
            row = con.execute('SELECT * FROM providers WHERE id=? AND enabled=1', (provider,)).fetchone()
        if not row:
            raise ValueError('Способ входа отключён')
        return PROVIDERS[provider], json.loads(row['config'])

    def start(self, con, account_id, purpose, method, browser, payload=None, code=None, link=None):
        rules = identity.policy(con, account_id)
        allowed = confirmation_methods(rules, purpose)
        if method not in allowed:
            raise PermissionError('Способ подтверждения запрещён политикой роли')
        if method in {'phone', 'email'}:
            provider = 'zvonok' if method == 'phone' else 'email'
            if not con.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (provider,)).fetchone():
                raise ValueError('Способ входа отключён')
        payload = dict(payload or {})
        if method in {'phone', 'email'} and not purpose.startswith('enroll-'):
            account = con.execute('SELECT phone,email FROM accounts WHERE id=?', (account_id,)).fetchone()
            payload.setdefault('recipient', account[method])
        key = secrets.token_urlsafe(24)
        con.execute('DELETE FROM challenges WHERE expires<=? OR (account_id=? AND purpose=? AND method=?)', (int(time.time()), account_id, purpose, method))
        con.execute('INSERT INTO challenges(id,account_id,purpose,method,browser_hash,expires,secret_hash,link_hash,payload) VALUES(?,?,?,?,?,?,?,?,?)',
                    (key, account_id, purpose, method, self.auth.digest(browser), int(time.time()) + 600,
                     self.auth.digest(code) if code else None, self.auth.digest(link) if link else None, json.dumps(payload or {})))
        return key

    def attempt(self, key, browser, purpose=None, link=False):
        with self.auth.db() as con:
            row = con.execute('SELECT * FROM challenges WHERE id=?', (key,)).fetchone()
            if not row or row['expires'] < time.time() or row['attempts'] >= 10:
                raise ValueError('Подтверждение устарело или исчерпано')
            if purpose and row['purpose'] != purpose or not link and not secrets.compare_digest(row['browser_hash'], self.auth.digest(browser)):
                raise ValueError('Подтверждение недоступно в этом браузере')
            con.execute('UPDATE challenges SET attempts=attempts+1 WHERE id=?', (key,))
            return dict(row)

    def consume(self, row, code='', link='', external=False, verified=False, credential_id=None):
        with self.auth.db() as con:
            current = con.execute('SELECT * FROM challenges WHERE id=? AND expires>?', (row['id'], int(time.time()))).fetchone()
            if not current:
                raise ValueError('Подтверждение уже использовано')
            if credential_id is not None and not con.execute('SELECT 1 FROM passkeys WHERE id=? AND account_id=?', (credential_id, row['account_id'])).fetchone():
                raise ValueError('Ключ удалён')
            self.validate_policy(con, row)
            if not (external or self.matches(code, current['secret_hash']) or self.matches(link, current['link_hash'])):
                raise ValueError('Неверное подтверждение')
            con.execute('DELETE FROM challenges WHERE id=?', (row['id'],))
            payload = json.loads(current['payload'])
            account = con.execute('SELECT * FROM accounts WHERE id=? AND enabled=1', (row['account_id'],)).fetchone()
            if not account:
                raise ValueError('Аккаунт недоступен')
            if row['method'] in {'phone', 'email'} and not row['purpose'].startswith('enroll-') and payload.get('recipient') != account[row['method']]:
                raise ValueError('Реквизит изменён; начните подтверждение заново')
            if row['purpose'].startswith('enroll-'):
                field = {'enroll-email': 'email', 'enroll-phone': 'phone'}.get(row['purpose'])
                if not field:
                    raise ValueError('Неизвестная цель подтверждения')
                con.execute(f'UPDATE accounts SET {field}=? WHERE id=?', (payload['address'], row['account_id']))
                identity.audit(con, row['account_id'], row['purpose'], row['account_id'])
                return None
            methods = self.session_methods(con, row, payload)
            return self.identities.new_session(con, row['account_id'], methods, verified)

    def validate_policy(self, con, row):
        # Revalidate role and provider on every completion, including in-flight changes.
        rules = identity.policy(con, row['account_id'])
        methods = confirmation_methods(rules, row['purpose'])
        if row['method'] not in methods:
            raise PermissionError('Способ подтверждения больше не разрешён')
        if row['method'] in {'phone', 'email'}:
            provider = 'zvonok' if row['method'] == 'phone' else 'email'
            if not con.execute('SELECT 1 FROM providers WHERE id=? AND enabled=1', (provider,)).fetchone():
                raise PermissionError('Способ подтверждения отключён')

    def session_methods(self, con, row, payload):
        methods = [row['method']]
        if row['purpose'] == 'second':
            previous = con.execute('SELECT * FROM identity_sessions WHERE token_hash=? AND account_id=? AND expires>?', (payload.get('session'), row['account_id'], int(time.time()))).fetchone()
            if not previous:
                raise ValueError('Начните вход заново')
            methods = json.loads(previous['methods'])
            if row['method'] in methods:
                raise ValueError('Нужен другой способ подтверждения')
            methods.append(row['method'])
            con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (previous['token_hash'],))
        return methods

    def matches(self, proof, digest):
        return bool(proof and digest and secrets.compare_digest(self.auth.digest(proof), digest))

    def backup(self, session, code):
        if not session['methods'] or not json.loads(session['methods']):
            raise ValueError('Сначала подтвердите основной способ')
        with self.auth.db() as con:
            count = con.execute('DELETE FROM backup_codes WHERE account_id=? AND digest=?', (session['account_id'], self.auth.digest(code))).rowcount
            if not count:
                raise ValueError('Неверный резервный код')
            previous = con.execute('SELECT * FROM identity_sessions WHERE token_hash=? AND expires>?', (session['token_hash'], int(time.time()))).fetchone()
            if not previous:
                raise ValueError('Начните вход заново')
            con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (session['token_hash'],))
            return self.identities.new_session(con, session['account_id'], [json.loads(previous['methods'])[0], 'backup'])


def confirmation_methods(rules, purpose):
    if purpose == 'second':
        return rules['secondary']
    if purpose.startswith('enroll-'):
        return rules['primary'] | rules['secondary']
    return rules['primary']


def totp_check(con, credential, code):
    if not credential or not credential['totp_verified'] or not credential['totp_key']:
        return False
    counter = int(time.time()) // 30
    matched = next((step for step in range(counter - 1, counter + 2) if step > credential['last_totp'] and
                    secrets.compare_digest(pyotp.TOTP(credential['totp_key']).at(step * 30), code)), None)
    if matched is None:
        return False
    con.execute('UPDATE admins SET last_totp=? WHERE id=?', (matched, credential['id']))
    return True


def call_records(result):
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return next((result[key] for key in ("results", "calls", "data")
                     if isinstance(result.get(key), list)), [result])
    return []


def call_activity(call):
    timestamps = []
    for field in ("created", "updated"):
        try:
            timestamps.append(datetime.fromisoformat(str(call.get(field, "")).replace("Z", "+00:00")).timestamp())
        except ValueError:
            pass
    return max(timestamps) if timestamps else None


def call_status_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("call_status", "status", "status_name"):
                yield str(item).lower()
            yield from call_status_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from call_status_values(item)
