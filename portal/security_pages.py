"""Unified sign-in and profile security, including staged MFA and passkeys."""
import base64
import html
import io
import json
import os
import secrets
import smtplib
import time
import httpx
import pyotp
import qrcode
from fastapi import Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from webauthn import generate_authentication_options, generate_registration_options, verify_authentication_response, verify_registration_response
from webauthn.helpers import options_to_json, base64url_to_bytes
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement, PublicKeyCredentialDescriptor
from webauthn.helpers.exceptions import WebAuthnException
import identity
from access_pages import esc, METHODS
from login_methods import Confirmations, totp_check

SECURITY_PATH = '/security'
ACCOUNT_QUERY = 'SELECT * FROM accounts WHERE id=?'
SECTION_END = '</section>'
REVOKE_ACCOUNT_SESSIONS = 'DELETE FROM identity_sessions WHERE account_id=?'
MODULES_PATH = '/admin/login-methods'


def join_choices(choices):
    return choices[0] if len(choices) == 1 else ', '.join(choices[:-1]) + ' или ' + choices[-1]


def login_hint(methods):
    hints = ['Введите логин и пароль.'] if 'password' in methods else []
    contacts = [label for method, label in [('phone', 'телефон с кодом страны, например +7'), ('email', 'почту')] if method in methods]
    if contacts:
        hint = 'Для подтверждения укажите ' + join_choices(contacts)
        hints.append(hint + (' и оставьте пароль пустым.' if 'password' in methods else '.'))
    if methods == {'webauthn'}:
        hints.append('Укажите реквизит аккаунта и подтвердите вход ключом / passkey.')
    return ' '.join(hints)


def login_actions(methods):
    body = ''
    if 'webauthn' in methods:
        attributes = 'type=submit' if methods == {'webauthn'} else 'type=button class=secondary'
        body += f'<button {attributes} data-passkey-submit>Войти с ключом / passkey</button>'
    if methods - {'webauthn'}:
        body += '<button>' + ('Войти' if 'password' in methods else 'Продолжить') + '</button>'
    return body


def login_form(methods):
    labels = [label for method, label in [('password', 'логин'), ('phone', 'телефон'), ('email', 'почта')] if method in methods]
    label = join_choices(labels).capitalize() if labels else 'Аккаунт'
    attributes = 'autocomplete=username'
    if methods == {'phone'}:
        attributes = 'type=tel autocomplete=tel placeholder="+7 999 123-45-67"'
    elif methods == {'email'}:
        attributes = 'type=email autocomplete=email'
    body = f'''<form class=stack method=post action=/login data-passkey=login>
<label>{label}<input name=identifier {attributes} autocapitalize=none spellcheck=false maxlength=254 aria-describedby=login-hint required></label>'''
    if 'password' in methods:
        required = 'required' if methods == {'password'} else ''
        body += f'<label>Пароль<input name=password type=password autocomplete=current-password aria-describedby=login-hint {required}></label>'
    body += f'<p class=muted id=login-hint>{login_hint(methods)}</p>'
    body += login_actions(methods) + '</form>'
    if 'webauthn' in methods:
        body += '<script src=/assets/js/passkeys.js defer></script>'
    return body


class SecurityPages:

    def __init__(self, portal):
        self.p = portal
        self.confirmations = Confirmations(portal.identities)

    def browser(self, request):
        return request.cookies.get('__Host-aas_csrf', '')

    def finish(self, token):
        session = self.p.identities.session(token, limited=True)
        if not session:
            raise ValueError('Аккаунт недоступен')
        destination = '/cabinet'
        if not session['ready'] or session['must_change']:
            destination = SECURITY_PATH
        elif self.p.identities.owner(session['account_id']):
            destination = '/admin'
        response = RedirectResponse(destination, 303)
        response.set_cookie(self.p.auth.COOKIE, token, secure=True, httponly=True, samesite='lax', path='/')
        response.delete_cookie('aas_session', path='/')
        return response

    def profile_actor(self, request, enrollment=False):
        actor = self.p.current_account(request, limited=True)
        if not actor['ready']:
            with self.p.auth_store.db() as con:
                row = con.execute(ACCOUNT_QUERY, (actor['account_id'],)).fetchone()
                configured = identity.configured_methods(con, row)
            remaining = configured & actor['policy']['secondary'] - set(json.loads(actor['methods']))
            recovering = json.loads(actor['methods']) == ['recovery']
            if not enrollment or (remaining and (not recovering)):
                raise PermissionError('Сначала завершите подтверждение входа')
        if time.time() - actor['confirmed'] > 300:
            raise HTTPException(303, headers={'Location': '/security/confirm'})
        return actor

    def available_login_methods(self):
        with self.p.auth_store.db() as con:
            rows = con.execute('''SELECT DISTINCT r.primary_methods FROM roles r
JOIN grants g ON g.role_id=r.id JOIN accounts a ON a.id=g.account_id
LEFT JOIN admins c ON c.id=a.admin_id WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1)''').fetchall()
            enabled = {r['id'] for r in con.execute('SELECT id FROM providers WHERE enabled=1')}
        methods = {method for row in rows for method in json.loads(row['primary_methods'])} & identity.PRIMARY
        for method, provider in (('phone', 'zvonok'), ('email', 'email')):
            if provider not in enabled:
                methods.discard(method)
        return methods

    def login_page(self):
        methods = self.available_login_methods()
        if not methods:
            return self.p.page('Вход', '<section class=card><p>Способы входа пока не настроены. Обратитесь к владельцу сервиса.</p></section>')
        form = login_form(methods)
        return self.p.page('Вход', '<section class=card>' + form + SECTION_END)

    async def login(self, request: Request, identifier: str=Form(...), password: str=Form('')):
        identifier = identifier.strip()
        if password:
            return self.password_login(request, identifier, password, '')
        if identifier.startswith('+'):
            return await self.send_confirmation(request, 'phone', identifier)
        if '@' in identifier:
            return await self.send_confirmation(request, 'email', identifier)
        raise HTTPException(400, 'Введите пароль или воспользуйтесь ключом / passkey. Телефон укажите с кодом страны, начиная с +.')

    def password_login(self, request: Request, username: str=Form(...), password: str=Form(...), totp: str=Form('')):
        try:
            (token, _) = self.p.auth_store.login(username, password, totp, request.client.host)
        except ValueError as exc:
            raise HTTPException(401, str(exc)) from None
        return self.finish(token)

    def lookup(self, identifier, method=None):
        with self.p.auth_store.db() as con:
            query = {'phone': 'a.phone=?', 'email': 'a.email=?'}.get(method, '(c.username=? OR a.phone=? OR a.email=?)')
            parameters = (identifier,) if method else (identifier, identifier, identifier.lower())
            rows = con.execute(f'SELECT a.* FROM accounts a LEFT JOIN admins c ON c.id=a.admin_id\n               WHERE a.enabled=1 AND (c.id IS NULL OR c.enabled=1) AND {query}', parameters).fetchall()
        if len(rows) != 1:
            raise ValueError('Проверьте реквизиты и доступность способа входа')
        return dict(rows[0])

    def normalize_address(self, method, identifier):
        return self.p.phone_normalize(identifier) if method == 'phone' else identifier.strip().lower()

    def enrollment_address(self, method, identifier):
        address = self.normalize_address(method, identifier)
        if method == 'phone':
            return address
        if '@' not in address or len(address) > 254 or '\n' in address or '\r' in address:
            raise ValueError('Укажите корректный адрес почты')
        return address

    def confirmation_recipient(self, request, method, identifier, purpose):
        if method not in {'phone', 'email'}:
            raise ValueError('Неизвестный способ')
        payload = {}
        if purpose == 'login':
            address = self.normalize_address(method, identifier)
            account = self.lookup(address, method)
            if account[method] != address:
                raise ValueError('Проверьте реквизиты')
        else:
            actor = self.p.current_account(request, limited=True) if purpose == 'second' else self.profile_actor(request, enrollment=True)
            with self.p.auth_store.db() as con:
                account = dict(con.execute(ACCOUNT_QUERY, (actor['account_id'],)).fetchone())
            if purpose == 'second':
                if method in json.loads(actor['methods']):
                    raise ValueError('Нужен другой способ подтверждения')
                address = account[method]
                payload['session'] = actor['token_hash']
            else:
                address = self.enrollment_address(method, identifier)
                payload['address'] = address
        if not address:
            raise ValueError('Сначала настройте реквизит в профиле')
        payload['recipient'] = address
        return account, address, payload

    async def send_confirmation(self, request, method, identifier='', purpose='login'):
        account, address, payload = self.confirmation_recipient(request, method, identifier, purpose)
        self.p.auth_store.throttle('send:' + account['id'], request.client.host)
        (provider, config) = self.confirmations.provider(method)
        (code, link) = (f'{secrets.randbelow(1000000):06d}', secrets.token_urlsafe(32))
        with self.p.auth_store.db() as con:
            key = self.confirmations.start(con, account['id'], purpose, method, self.browser(request), payload, code, link)
        origin = os.getenv('AUTH_ORIGIN') or 'https://' + os.environ['PORTAL_DOMAIN']
        try:
            result = await provider.begin(config, address, code, origin + '/login/link#' + key + '.' + link)
            if method == 'phone':
                result['dial'] = self.p.next_dial_number() or result.get('dial', '')
            with self.p.auth_store.db() as con:
                con.execute('UPDATE challenges SET payload=? WHERE id=?', (json.dumps({**payload, **result}), key))
        except (httpx.HTTPError, OSError, smtplib.SMTPException, ValueError):
            with self.p.auth_store.db() as con:
                con.execute('DELETE FROM challenges WHERE id=?', (key,))
            raise HTTPException(503, 'Сервис подтверждения временно недоступен') from None
        return RedirectResponse('/login/verify/' + key, 303)

    async def login_start(self, request: Request, method: str=Form(...), identifier: str=Form(...)):
        return await self.send_confirmation(request, method, identifier)

    def verify_page(self, request: Request, key: str):
        with self.p.auth_store.db() as con:
            row = con.execute('SELECT * FROM challenges WHERE id=? AND browser_hash=? AND expires>?', (key, self.p.auth_store.digest(self.browser(request)), int(time.time()))).fetchone()
        if not row:
            raise HTTPException(410, 'Подтверждение устарело')
        if row['method'] == 'phone':
            dial = json.loads(row['payload']).get('dial', '')
            body = f'<p>Позвоните на номер кампании: <a href="tel:{esc(dial)}">{esc(dial)}</a></p>'
        else:
            body = '<label>Код из письма<input name=code inputmode=numeric pattern="[0-9]{6}" maxlength=6 autocomplete=one-time-code required></label>'
        return self.p.page('Подтверждение', f'<section class=card><form class=stack method=post action=/login/verify/{esc(key)}>{body}<button>Подтвердить</button></form><p class=muted>Подтверждение действует 10 минут.</p></section>')

    async def verify_confirmation(self, request: Request, key: str, code: str=Form('')):
        row = self.confirmations.attempt(key, self.browser(request))
        external = False
        if row['method'] == 'phone':
            (provider, config) = self.confirmations.provider('phone')
            try:
                external = await provider.verify(config, json.loads(row['payload']))
            except (httpx.HTTPError, ValueError):
                raise HTTPException(503, 'Сервис подтверждения временно недоступен') from None
        token = self.confirmations.consume(row, code=code, external=external)
        return self.finish(token) if token else RedirectResponse(SECURITY_PATH, 303)

    def email_link_page(self):
        return self.p.page('Подтверждение почты', '<section class=card><p>Нажмите кнопку, чтобы подтвердить вход в этом браузере.</p><form class=stack method=post action=/login/link id=email-link><input type=hidden name=proof><button>Подтвердить</button></form><script src=/assets/js/email-link.js defer></script></section>')

    def email_link_finish(self, request: Request, proof: str=Form(...)):
        (key, separator, secret) = proof.partition('.')
        if not separator:
            raise ValueError('Некорректная ссылка')
        row = self.confirmations.attempt(key, self.browser(request), link=True)
        if row['method'] != 'email' or row['purpose'].startswith('enroll-'):
            if row['purpose'].startswith('enroll-'):
                self.confirmations.attempt(key, self.browser(request), purpose=row['purpose'])
            else:
                raise ValueError('Некорректная ссылка')
        token = self.confirmations.consume(row, link=secret)
        return self.finish(token) if token else RedirectResponse(SECURITY_PATH, 303)

    def security_page(self, request: Request):
        actor = self.p.current_account(request, limited=True)
        key = actor['account_id']
        with self.p.auth_store.db() as con:
            keys = con.execute('SELECT id,name,last_used FROM passkeys WHERE account_id=?', (key,)).fetchall()
            sessions = con.execute('SELECT token_hash,created,expires FROM identity_sessions WHERE account_id=?', (key,)).fetchall()
            backup_count = con.execute('SELECT count(*) FROM backup_codes WHERE account_id=?', (key,)).fetchone()[0]
        body = self.p.admin_nav(SECURITY_PATH) if actor['ready'] and self.p.admin_ok(request) else '<p><a href=/cabinet>Устройства</a></p>'
        body += self.second_factor_form(actor)
        body += f"""<section class=card><h2>Безопасность профиля</h2><p>{('2FA обязательна' if actor['policy']['required'] else '2FA добровольная')} · резервных кодов: {backup_count}</p><a class="btn secondary" href=/security/confirm>Подтвердить вход заново</a></section>"""
        allowed = actor['policy']['primary'] | actor['policy']['secondary']
        body += self.credential_forms(actor, allowed)
        body += self.totp_form(actor, allowed)
        if 'webauthn' in allowed:
            body += '<section class=card><h2>Ключи и passkeys</h2><form class=device-form data-passkey=enroll><label>Название<input name=name maxlength=80 required></label><button>Добавить ключ / passkey</button></form>'
            for item in keys:
                used = time.strftime('%Y-%m-%d %H:%M', time.localtime(item['last_used'])) if item['last_used'] else 'ещё не использовался'
                body += f'''<form class=device-form method=post action=/security/passkeys/delete><input type=hidden name=key value="{esc(item['id'])}"><p>{esc(item['name'])} · {used}</p><button class=danger-soft>Удалить ключ</button></form>'''
            body += SECTION_END
        body += f"<section class=card><h2>Второй фактор и восстановление</h2><form class=stack method=post action=/security/mfa><label>Личная настройка 2FA<select name=enabled><option value=1 {'selected' if actor['voluntary_2fa'] else ''}>Включена</option><option value=0 {'' if actor['voluntary_2fa'] else 'selected'}>Выключена (если роль разрешает)</option></select></label><button>Сохранить</button></form><form method=post action=/security/backup/new><button class=secondary>Выпустить резервные коды</button></form></section>"
        body += '<section class=card><h2>Сессии</h2>'
        for session in sessions:
            body += f'''<form class=device-form method=post action=/security/sessions/revoke><input type=hidden name=key value="{session['token_hash']}"><p>{('Текущая' if session['token_hash'] == actor['token_hash'] else 'Другая сессия')} · {time.strftime('%Y-%m-%d %H:%M', time.localtime(session['created']))}</p><button class=danger-soft>Завершить</button></form>'''
        body += '</section><form method=post action=/admin/logout><button class=secondary>Выйти</button></form><script src=/assets/js/passkeys.js defer></script>'
        return self.p.page('Безопасность профиля', body, show_header=True)

    def second_factor_form(self, actor):
        body = ''
        if actor['ready']:
            return body
        body += '<section class=card><h2>Завершите подтверждение входа</h2><p>Устройства и управление станут доступны после обязательных проверок.</p>'
        remaining = actor['policy']['secondary'] - set(json.loads(actor['methods']))
        for method in sorted(remaining):
            body += f'<form class=device-form method=post action=/security/second><input type=hidden name=method value={method}>'
            if method in {'password', 'totp'}:
                body += f"<label>{METHODS[method]}<input name=code type={('password' if method == 'password' else 'text')} autocomplete={('current-password' if method == 'password' else 'one-time-code')} required></label>"
            body += f'<button>Подтвердить: {METHODS[method]}</button></form>' if method != 'webauthn' else '</form><form data-passkey=second><button>Подтвердить ключом / passkey</button></form>'
        body += '<form class=device-form method=post action=/security/backup><label>Резервный код<input name=code autocomplete=off required></label><button>Использовать код</button></form></section>'
        return body

    def credential_forms(self, actor, allowed):
        body = ''
        if 'password' in allowed:
            body += f'''<section class=card><h2>Логин и пароль</h2><form class=stack method=post action=/security/password><label>Логин<input name=username value="{esc(actor['username'] if actor['username'] and (not actor['username'].startswith('account-')) else '')}" maxlength=64 required autocomplete=username></label><label>Новый пароль<input name=password type=password minlength=12 maxlength=128 required autocomplete=new-password></label><button>Сохранить</button></form></section>'''
        for method in ('phone', 'email'):
            if method in allowed:
                body += f"<section class=card><h2>{METHODS[method]}</h2><p>{esc(actor[method])}</p><form class=device-form method=post action=/security/enroll><input type=hidden name=method value={method}><label>Новый реквизит<input name=identifier type={('tel' if method == 'phone' else 'email')} required></label><button>Подтвердить и сохранить</button></form></section>"
        return body

    def totp_form(self, actor, allowed):
        body = ''
        if 'totp' in allowed:
            body += '<section class=card><h2>TOTP</h2><form method=post action=/security/totp/start><button class=secondary>Настроить TOTP</button></form>'
            if actor['pending_totp'] and time.time() - (actor['pending_at'] or 0) <= 600:
                body += '<img src=/security/totp/qr width=240 height=240 alt="QR настройки TOTP"><form class=device-form method=post action=/security/totp/confirm><label>Код TOTP<input name=code inputmode=numeric required></label><button>Подтвердить</button></form>'
            if actor['totp_verified']:
                body += '<form method=post action=/security/totp/delete><button class=danger-soft>Удалить TOTP</button></form>'
            body += SECTION_END
        return body

    def reauthenticate(self, request: Request):
        self.p.current_account(request, limited=True)
        return self.p.page('Подтвердите вход', '<section class=card><p>Для изменения доступа и настроек безопасности нужен вход, подтверждённый не более пяти минут назад. Войдите заново разрешённым способом.</p><a class=btn href=/>Перейти ко входу</a></section>')

    async def second(self, request: Request, method: str=Form(...), code: str=Form('')):
        actor = self.p.current_account(request, limited=True)
        self.p.auth_store.throttle('second:' + actor['account_id'], request.client.host)
        if method not in actor['policy']['secondary'] or method in json.loads(actor['methods']):
            raise PermissionError('Нужен другой разрешённый способ')
        if method in {'phone', 'email'}:
            return await self.send_confirmation(request, method, purpose='second')
        with self.p.auth_store.db() as con:
            credential = con.execute('SELECT * FROM admins WHERE id=?', (actor['id'],)).fetchone()
            valid = totp_check(con, credential, code) if method == 'totp' else method == 'password' and credential and self.p.auth_store.password_matches(credential['password_hash'], code)
            if not valid:
                raise ValueError('Неверное подтверждение')
            previous = con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (actor['token_hash'],)).rowcount
            if not previous:
                raise ValueError('Сессия завершена')
            token = self.p.identities.new_session(con, actor['account_id'], [*json.loads(actor['methods']), method])
        return self.finish(token)

    async def enroll(self, request: Request, method: str=Form(...), identifier: str=Form(...)):
        return await self.send_confirmation(request, method, identifier, 'enroll-' + method)

    def ensure_credential(self, con, actor):
        if actor['id']:
            return actor['id']
        key = con.execute('INSERT INTO admins(username) VALUES(?)', ('account-' + actor['account_id'],)).lastrowid
        con.execute('UPDATE accounts SET admin_id=? WHERE id=?', (key, actor['account_id']))
        return key

    def save_password(self, request: Request, username: str=Form(...), password: str=Form(...)):
        actor = self.profile_actor(request, enrollment=True)
        if 'password' not in actor['policy']['primary'] | actor['policy']['secondary']:
            raise PermissionError('Пароль не разрешён')
        self.p.auth_store.validate_password(password)
        if not username.strip() or len(username) > 64 or username.startswith('account-'):
            raise ValueError('Укажите уникальный логин длиной до 64 символов')
        with self.p.auth_store.db() as con:
            credential_id = self.ensure_credential(con, actor)
            con.execute('UPDATE admins SET username=?,password_hash=?,must_change=0 WHERE id=?', (username.strip(), self.p.password_hasher.hash(password), credential_id))
            con.execute(REVOKE_ACCOUNT_SESSIONS, (actor['account_id'],))
            identity.audit(con, actor['account_id'], 'credentials.password', actor['account_id'])
        return RedirectResponse('/', 303)

    def totp_start(self, request: Request):
        actor = self.profile_actor(request, enrollment=True)
        if 'totp' not in actor['policy']['secondary']:
            raise PermissionError('TOTP не разрешён')
        with self.p.auth_store.db() as con:
            key = self.ensure_credential(con, actor)
            con.execute('UPDATE admins SET pending_totp=?,pending_at=? WHERE id=?', (pyotp.random_base32(), int(time.time()), key))
        return RedirectResponse(SECURITY_PATH, 303)

    def totp_qr(self, request: Request):
        actor = self.profile_actor(request, enrollment=True)
        if not actor['pending_totp'] or time.time() - (actor['pending_at'] or 0) > 600:
            raise HTTPException(404)
        out = io.BytesIO()
        qrcode.make(pyotp.TOTP(actor['pending_totp']).provisioning_uri(actor['username'] or actor['phone'] or actor['account_id'], issuer_name='AAS VPN')).save(out, format='PNG')
        return Response(out.getvalue(), media_type='image/png')

    def totp_confirm(self, request: Request, code: str=Form(...)):
        actor = self.profile_actor(request, enrollment=True)
        self.p.auth_store.throttle('totp-enroll:' + actor['account_id'], request.client.host)
        self.p.auth_store.confirm_totp(actor['id'], code)
        with self.p.auth_store.db() as con:
            con.execute(REVOKE_ACCOUNT_SESSIONS, (actor['account_id'],))
        return RedirectResponse('/', 303)

    def factor_removal(self, con, actor):
        row = con.execute(ACCOUNT_QUERY, (actor['account_id'],)).fetchone()
        configured = identity.configured_methods(con, row)
        if actor['policy']['required'] and (not configured & actor['policy']['secondary']):
            raise ValueError('Сначала настройте другой второй фактор')
        identity.ensure_login_paths(con)
        con.execute(REVOKE_ACCOUNT_SESSIONS, (actor['account_id'],))

    def totp_delete(self, request: Request):
        actor = self.profile_actor(request)
        with self.p.auth_store.db() as con:
            con.execute('UPDATE admins SET totp_key=NULL,totp_verified=0,last_totp=-1,pending_totp=NULL WHERE id=?', (actor['id'],))
            self.factor_removal(con, actor)
        return RedirectResponse('/', 303)

    def mfa(self, request: Request, enabled: str=Form(...)):
        actor = self.profile_actor(request)
        with self.p.auth_store.db() as con:
            role_requires = con.execute('SELECT 1 FROM roles r JOIN grants g ON g.role_id=r.id WHERE g.account_id=? AND r.require_2fa=1', (actor['account_id'],)).fetchone()
            if enabled != '1' and role_requires:
                raise ValueError('Обязательную 2FA роли нельзя отключить')
            con.execute('UPDATE accounts SET voluntary_2fa=? WHERE id=?', (int(enabled == '1'), actor['account_id']))
            identity.ensure_login_paths(con)
        return RedirectResponse(SECURITY_PATH, 303)

    def new_backup(self, request: Request):
        actor = self.profile_actor(request)
        codes = [secrets.token_hex(8) for _ in range(10)]
        with self.p.auth_store.db() as con:
            con.execute('DELETE FROM backup_codes WHERE account_id=?', (actor['account_id'],))
            con.executemany('INSERT INTO backup_codes VALUES(?,?)', [(actor['account_id'], self.p.auth_store.digest(code)) for code in codes])
        return self.p.page('Резервные коды', '<section class=card><p>Сохраните коды в безопасном месте. Каждый используется один раз после основного способа входа. Повторно увидеть их нельзя.</p><pre>' + '\n'.join(codes) + '</pre><a class="btn secondary" href=/security>Готово</a></section>')

    def use_backup(self, request: Request, code: str=Form(...)):
        actor = self.p.current_account(request, limited=True)
        self.p.auth_store.throttle('backup:' + actor['account_id'], request.client.host)
        return self.finish(self.confirmations.backup(actor, code))

    def revoke(self, request: Request, key: str=Form(...)):
        actor = self.p.current_account(request, limited=True)
        with self.p.auth_store.db() as con:
            con.execute('DELETE FROM identity_sessions WHERE token_hash=? AND account_id=?', (key, actor['account_id']))
        return RedirectResponse(SECURITY_PATH, 303)

    def webauthn_settings(self):
        origin = os.getenv('AUTH_ORIGIN') or 'https://' + os.environ['PORTAL_DOMAIN']
        from urllib.parse import urlsplit
        rp = os.getenv('WEBAUTHN_RP_ID') or urlsplit(origin).hostname
        if not rp or (urlsplit(origin).scheme != 'https' and (not (urlsplit(origin).scheme == 'http' and urlsplit(origin).hostname in {'localhost', '127.0.0.1'}))):
            raise ValueError('WebAuthn требует настроенного HTTPS origin')
        return (origin, rp)

    def passkey_start(self, request: Request, purpose: str=Form(...), identifier: str=Form(''), name: str=Form('')):
        (origin, rp) = self.webauthn_settings()
        payload = {'origin': origin, 'rp': rp}
        if purpose == 'login':
            actor = self.lookup(identifier)
            account_id = actor['id']
        elif purpose in {'enroll', 'second'}:
            actor = self.profile_actor(request, enrollment=True) if purpose == 'enroll' else self.p.current_account(request, limited=True)
            account_id = actor['account_id']
            payload['session'] = actor['token_hash']
            if 'webauthn' in json.loads(actor['methods']) and purpose == 'second':
                raise ValueError('Нужен другой способ')
        else:
            raise ValueError('Неизвестная цель')
        self.p.auth_store.throttle('webauthn:' + account_id, request.client.host)
        with self.p.auth_store.db() as con:
            descriptors = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r['id'])) for r in con.execute('SELECT id FROM passkeys WHERE account_id=?', (account_id,))]
            options = self.passkey_options(purpose, name, actor, account_id, rp, descriptors, payload)
            payload['challenge'] = base64.urlsafe_b64encode(options.challenge).decode()
            key = self.confirmations.start(con, account_id, 'enroll-webauthn' if purpose == 'enroll' else purpose, 'webauthn', self.browser(request), payload)
        return JSONResponse({'key': key, 'options': json.loads(options_to_json(options))})

    def passkey_options(self, purpose, name, actor, account_id, rp, descriptors, payload):
        if purpose == 'enroll':
            if not name.strip() or len(name) > 80 or len(descriptors) >= 20:
                raise ValueError('Укажите название; не более 20 ключей')
            payload['name'] = name.strip()
            options = generate_registration_options(rp_id=rp, rp_name='AAS VPN', user_id=account_id.encode(), user_name=actor['username'] or actor['phone'] or account_id, exclude_credentials=descriptors, authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
        else:
            if not descriptors:
                raise ValueError('Ключи не настроены')
            options = generate_authentication_options(rp_id=rp, allow_credentials=descriptors, user_verification=UserVerificationRequirement.REQUIRED)
        return options

    def passkey_finish(self, request: Request, key: str=Form(...), credential: str=Form(...)):
        row = self.confirmations.attempt(key, self.browser(request))
        if row['method'] != 'webauthn':
            raise ValueError('Некорректная попытка')
        payload = json.loads(row['payload'])
        (origin, rp) = self.webauthn_settings()
        expected = {'expected_challenge': base64url_to_bytes(payload['challenge']), 'expected_origin': origin, 'expected_rp_id': rp, 'require_user_verification': True}
        try:
            if row['purpose'] == 'enroll-webauthn':
                actor = self.profile_actor(request, enrollment=True)
                if actor['account_id'] != row['account_id'] or actor['token_hash'] != payload['session']:
                    raise ValueError('Другая сессия')
                verified = verify_registration_response(credential=credential, **expected)
                credential_id = base64.urlsafe_b64encode(verified.credential_id).decode().rstrip('=')
                with self.p.auth_store.db() as con:
                    if 'webauthn' not in identity.policy(con, row['account_id'])['primary'] | identity.policy(con, row['account_id'])['secondary']:
                        raise ValueError('Способ больше не разрешён')
                    if not con.execute('DELETE FROM challenges WHERE id=? AND expires>?', (key, int(time.time()))).rowcount:
                        raise ValueError('Подтверждение уже использовано')
                    con.execute('INSERT INTO passkeys VALUES(?,?,?,?,?,?,NULL)', (credential_id, row['account_id'], payload['name'], verified.credential_public_key, verified.sign_count, int(time.time())))
                return JSONResponse({'location': SECURITY_PATH})
            with self.p.auth_store.db() as con:
                response_data = json.loads(credential)
                user_handle = response_data['response'].get('userHandle')
                if user_handle is not None and base64url_to_bytes(user_handle) != row['account_id'].encode():
                    raise ValueError('Другой аккаунт')
                stored = con.execute('SELECT * FROM passkeys WHERE id=? AND account_id=?', (response_data['id'], row['account_id'])).fetchone()
                if not stored:
                    raise ValueError('Ключ удалён')
                verified = verify_authentication_response(credential=credential, credential_public_key=stored['public_key'], credential_current_sign_count=stored['sign_count'], **expected)
                con.execute('UPDATE passkeys SET sign_count=?,last_used=? WHERE id=?', (verified.new_sign_count, int(time.time()), stored['id']))
            token = self.confirmations.consume(row, external=True, verified=verified.user_verified, credential_id=stored['id'])
        except (ValueError, KeyError, TypeError, WebAuthnException):
            raise ValueError('Ключ не подтвердил запрос. Начните заново') from None
        response = self.finish(token)
        result = JSONResponse({'location': response.headers['location']})
        for cookie in response.headers.getlist('set-cookie'):
            result.headers.append('set-cookie', cookie)
        return result

    def delete_key(self, request: Request, key: str=Form(...)):
        actor = self.profile_actor(request)
        with self.p.auth_store.db() as con:
            con.execute('DELETE FROM passkeys WHERE id=? AND account_id=?', (key, actor['account_id']))
            self.factor_removal(con, actor)
        return RedirectResponse('/', 303)

    def modules(self, request: Request):
        self.p.require_owner(request)
        with self.p.auth_store.db() as con:
            providers = con.execute('SELECT * FROM providers ORDER BY id').fetchall()
        body = self.p.admin_nav(MODULES_PATH)
        fields = {'email': [('host', 'SMTP-сервер'), ('port', 'Порт'), ('sender', 'Отправитель'), ('username', 'Логин SMTP'), ('password', 'Пароль SMTP')], 'zvonok': [('campaign_id', 'Кампания'), ('public_key', 'Ключ API'), ('success_statuses', 'Успешные статусы')]}
        body += ''.join(self.provider_form(provider, fields) for provider in providers)
        return self.p.page('Способы входа', body, show_header=True)

    def provider_form(self, provider, fields):
        body = ''
        config = json.loads(provider['config'])
        body += f"<section class=card><h2>{('Почта' if provider['id'] == 'email' else 'Zvonok')}</h2><form class=stack method=post action=/admin/login-methods/{provider['id']}><label class=check-label><input type=checkbox name=enabled value=1 {('checked' if provider['enabled'] else '')}> Модуль включён</label>"
        for (key, caption) in fields[provider['id']]:
            secret = key in {'password', 'public_key'}
            body += f'''<label>{caption}<input name={key} type={('password' if secret else 'text')} value="{(esc(config.get(key, '')) if not secret else '')}" autocomplete=off></label>'''
        if provider['id'] == 'email':
            body += f"<label>TLS<select name=tls><option value=starttls>STARTTLS</option><option value=implicit {'selected' if config.get('tls') == 'implicit' else ''}>TLS при подключении</option></select></label>"
        body += '<p class=muted>Пустое поле секрета сохраняет прежнее значение.</p><button>Сохранить</button></form></section>'
        return body

    async def save_module(self, request: Request, provider_id: str):
        actor = self.p.require_owner(request, fresh=True)
        form = await request.form()
        fields = {'email': {'host', 'port', 'sender', 'username', 'password', 'tls'}, 'zvonok': {'campaign_id', 'public_key', 'success_statuses'}}
        if provider_id not in fields:
            raise HTTPException(404)
        with self.p.auth_store.db() as con:
            config = json.loads(con.execute('SELECT config FROM providers WHERE id=?', (provider_id,)).fetchone()[0])
            for key in fields[provider_id]:
                value = str(form.get(key, ''))
                if key not in {'password', 'public_key'}:
                    value = value.strip()
                if value or key not in {'password', 'public_key'}:
                    config[key] = value
            if provider_id == 'email' and form.get('enabled'):
                if not config.get('host') or not config.get('sender') or config.get('tls') not in {'starttls', 'implicit'} or (not 1 <= int(config.get('port', 0)) <= 65535):
                    raise ValueError('Укажите SMTP-сервер, порт, отправителя и TLS')
            if provider_id == 'zvonok' and form.get('enabled') and (not config.get('public_key') or not config.get('campaign_id')):
                raise ValueError('Укажите ключ API и кампанию Zvonok')
            con.execute('UPDATE providers SET config=?,enabled=? WHERE id=?', (json.dumps(config), int(bool(form.get('enabled'))), provider_id))
            identity.ensure_login_paths(con)
            identity.audit(con, actor['account_id'], 'providers.save', provider_id)
        return RedirectResponse(MODULES_PATH, 303)

    def issue_recovery(self, request: Request, account_id: str):
        actor = self.p.require_owner(request, fresh=True)
        code = secrets.token_urlsafe(32)
        with self.p.auth_store.db() as con:
            if not con.execute('SELECT 1 FROM accounts WHERE id=? AND enabled=1', (account_id,)).fetchone():
                raise HTTPException(404)
            con.execute('INSERT INTO recovery_codes VALUES(?,?,?) ON CONFLICT(account_id) DO UPDATE SET digest=excluded.digest,expires=excluded.expires', (account_id, self.p.auth_store.digest(code), int(time.time()) + 600))
            identity.audit(con, actor['account_id'], 'recovery.issue', account_id)
        return self.p.page('Одноразовое восстановление', f'<section class=card><p>Код позволяет настроить реквизиты в течение 10 минут и показывается только сейчас. Передайте его владельцу аккаунта безопасным способом.</p><p>ID аккаунта: {esc(account_id)}</p><pre>{esc(code)}</pre><p>Страница восстановления: /login/recovery</p></section>')

    def recovery_form(self):
        return self.p.page('Восстановление', '<section class=card><form class=stack method=post><label>ID аккаунта<input name=account_id required></label><label>Одноразовый код владельца<input name=code required autocomplete=off></label><button>Продолжить</button></form></section>')

    def recover(self, request: Request, account_id: str=Form(...), code: str=Form(...)):
        self.p.auth_store.throttle('recovery:' + account_id, request.client.host)
        with self.p.auth_store.db() as con:
            consumed = con.execute('DELETE FROM recovery_codes WHERE account_id=? AND digest=? AND expires>?', (account_id, self.p.auth_store.digest(code), int(time.time()))).rowcount
            if not consumed:
                raise ValueError('Код восстановления недоступен')
            con.execute(REVOKE_ACCOUNT_SESSIONS, (account_id,))
            token = self.p.identities.new_session(con, account_id, ['recovery'], ttl=600)
            identity.audit(con, account_id, 'recovery.consume', account_id)
        return self.finish(token)

def register(portal):
    pages = SecurityPages(portal)
    portal.app.add_api_route('/', pages.login_page, methods=['GET'])
    portal.app.add_api_route('/admin/login', pages.login_page, methods=['GET'])
    portal.app.add_api_route('/login', pages.login, methods=['POST'])
    portal.app.add_api_route('/login/password', pages.password_login, methods=['POST'])
    portal.app.add_api_route('/admin/login', pages.password_login, methods=['POST'])
    portal.app.add_api_route('/login/start', pages.login_start, methods=['POST'])
    portal.app.add_api_route('/login/verify/{key}', pages.verify_page, methods=['GET'])
    portal.app.add_api_route('/login/verify/{key}', pages.verify_confirmation, methods=['POST'])
    portal.app.add_api_route('/login/link', pages.email_link_page, methods=['GET'])
    portal.app.add_api_route('/login/link', pages.email_link_finish, methods=['POST'])
    portal.app.add_api_route(SECURITY_PATH, pages.security_page, methods=['GET'])
    portal.app.add_api_route('/security/confirm', pages.reauthenticate, methods=['GET'])
    portal.app.add_api_route('/security/second', pages.second, methods=['POST'])
    portal.app.add_api_route('/security/enroll', pages.enroll, methods=['POST'])
    portal.app.add_api_route('/security/password', pages.save_password, methods=['POST'])
    portal.app.add_api_route('/security/totp/start', pages.totp_start, methods=['POST'])
    portal.app.add_api_route('/security/totp/qr', pages.totp_qr, methods=['GET'])
    portal.app.add_api_route('/security/totp/confirm', pages.totp_confirm, methods=['POST'])
    portal.app.add_api_route('/security/totp/delete', pages.totp_delete, methods=['POST'])
    portal.app.add_api_route('/security/mfa', pages.mfa, methods=['POST'])
    portal.app.add_api_route('/security/backup/new', pages.new_backup, methods=['POST'])
    portal.app.add_api_route('/security/backup', pages.use_backup, methods=['POST'])
    portal.app.add_api_route('/security/sessions/revoke', pages.revoke, methods=['POST'])
    portal.app.add_api_route('/security/passkeys/start', pages.passkey_start, methods=['POST'])
    portal.app.add_api_route('/security/passkeys/finish', pages.passkey_finish, methods=['POST'])
    portal.app.add_api_route('/security/passkeys/delete', pages.delete_key, methods=['POST'])
    portal.app.add_api_route(MODULES_PATH, pages.modules, methods=['GET'])
    portal.app.add_api_route('/admin/login-methods/{provider_id}', pages.save_module, methods=['POST'])
    portal.app.add_api_route('/admin/accounts/{account_id}/recovery', pages.issue_recovery, methods=['POST'])
    portal.app.add_api_route('/login/recovery', pages.recovery_form, methods=['GET'])
    portal.app.add_api_route('/login/recovery', pages.recover, methods=['POST'])
