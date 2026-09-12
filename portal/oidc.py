"""Browser-bound OIDC code flow; external subjects never imply local permissions."""
import base64
import hashlib
import json
import secrets
import sqlite3
import time
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.oidc.core import CodeIDToken
from fastapi import Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

import identity

CALLBACK = '/login/oidc/callback'
COOKIE = '__Host-aas_oidc'
ERROR = 'Вход через провайдера не подтверждён. Начните заново.'
FIELDS = [('issuer', 'Issuer URL (для Keycloak — адрес realm)'),
          ('client_id', 'Client ID'), ('client_secret', 'Client secret')]


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Укажите HTTPS-адрес без параметров и реквизитов')
    return value


def validate_config(config):
    https_url(config.get('issuer', ''))
    if not config.get('client_id') or not config.get('client_secret'):
        raise ValueError('Укажите Client ID и Client secret')
    if any(len(value) > 4096 for value in config.values()):
        raise ValueError('Параметр провайдера слишком длинный')


def configuration(con):
    row = con.execute("SELECT * FROM providers WHERE id='oidc' AND enabled=1").fetchone()
    if not row:
        raise ValueError('OpenID Connect отключён')
    config = json.loads(row['config'])
    validate_config(config)
    return config


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


async def discovery(client, config):
    response = await client.get(config['issuer'].rstrip('/') + '/.well-known/openid-configuration')
    response.raise_for_status()
    metadata = response.json()
    if metadata.get('issuer') != config['issuer']:
        raise ValueError(ERROR)
    for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        https_url(metadata[name])
    if 'RS256' not in metadata.get('id_token_signing_alg_values_supported', []):
        raise ValueError('Провайдер должен поддерживать подпись RS256')
    return metadata


async def exchange(client, config, payload, code):
    metadata = await discovery(client, config)
    response = await client.post(metadata['token_endpoint'], data={
        'grant_type': 'authorization_code', 'code': code,
        'redirect_uri': payload['redirect_uri'], 'code_verifier': payload['verifier'],
        'client_id': config['client_id'], 'client_secret': config['client_secret']})
    response.raise_for_status()
    tokens = response.json()
    response = await client.get(metadata['jwks_uri'])
    response.raise_for_status()
    token = jwt.decode(tokens['id_token'], KeySet.import_key_set(response.json()), algorithms=['RS256'])
    claims = CodeIDToken(token.claims, token.header,
                         options={'iss': {'essential': True, 'value': config['issuer']},
                                  'aud': {'essential': True, 'value': config['client_id']}},
                         params={'nonce': payload['nonce'], 'client_id': config['client_id'],
                                 'access_token': tokens.get('access_token')})
    claims.validate(leeway=30)
    subject = claims['sub']
    if not isinstance(subject, str) or not subject or len(subject) > 255:
        raise ValueError(ERROR)
    return subject


def invalidate_configuration(con, previous, current):
    if any(previous.get(key) != current.get(key) for key in ('issuer', 'client_id')) and con.execute('SELECT 1 FROM oidc_links').fetchone():
        raise ValueError('Перед сменой провайдера или Client ID отвяжите аккаунты, сохранив другой способ входа')
    con.execute('DELETE FROM oidc_flows')
    for session in con.execute('SELECT token_hash,methods FROM identity_sessions').fetchall():
        if 'oidc' in json.loads(session['methods']):
            con.execute('DELETE FROM identity_sessions WHERE token_hash=?', (session['token_hash'],))


class OIDC:
    def __init__(self, pages):
        self.pages = pages
        self.p = pages.p

    def redirect_uri(self):
        origin, _ = self.pages.webauthn_settings()
        return https_url(origin.rstrip('/') + CALLBACK)

    async def start(self, request: Request, purpose: str = Form('login')):
        if purpose not in {'login', 'link'}:
            raise ValueError(ERROR)
        actor = self.pages.profile_actor(request) if purpose == 'link' else None
        if actor and (not actor['ready'] or actor['must_change'] or 'oidc' not in actor['policy']['primary']):
            raise PermissionError('Привязка доступна после полного входа, если разрешена ролью')
        self.p.auth_store.throttle('oidc:' + (actor['account_id'] if actor else request.client.host), request.client.host)
        with self.p.auth_store.db() as con:
            config = configuration(con)
        state, browser = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        payload = {'purpose': purpose, 'config': fingerprint(config),
                   'nonce': secrets.token_urlsafe(32), 'verifier': secrets.token_urlsafe(48),
                   'redirect_uri': self.redirect_uri(),
                   'session': request.cookies.get(self.p.auth.COOKIE, '') if actor else ''}
        # Store only the digest of the existing local session.
        payload['session'] = self.p.auth_store.digest(payload['session']) if actor else ''
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            metadata = await discovery(client, config)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(payload['verifier'].encode()).digest()).decode().rstrip('=')
        query = urlencode({'response_type': 'code', 'scope': 'openid', 'client_id': config['client_id'],
                           'redirect_uri': payload['redirect_uri'], 'state': state, 'nonce': payload['nonce'],
                           'code_challenge': challenge, 'code_challenge_method': 'S256', 'prompt': 'login'})
        with self.p.auth_store.db() as con:
            con.execute('DELETE FROM oidc_flows WHERE expires<=?', (int(time.time()),))
            con.execute('INSERT INTO oidc_flows VALUES(?,?,?,?)',
                        (self.p.auth_store.digest(state), self.p.auth_store.digest(browser), int(time.time()) + 600, json.dumps(payload)))
        response = RedirectResponse(metadata['authorization_endpoint'] + '?' + query, 303)
        response.set_cookie(COOKIE, browser, secure=True, httponly=True, samesite='lax', max_age=600, path='/')
        return response

    def consume(self, request):
        state = request.query_params.get('state', '')
        browser = request.cookies.get(COOKIE, '')
        if not state or len(state) > 128 or not browser:
            raise ValueError(ERROR)
        with self.p.auth_store.db() as con:
            row = con.execute('DELETE FROM oidc_flows WHERE state_hash=? AND browser_hash=? AND expires>? RETURNING payload',
                              (self.p.auth_store.digest(state), self.p.auth_store.digest(browser), int(time.time()))).fetchone()
        if not row:
            raise ValueError(ERROR)
        return json.loads(row['payload'])

    async def callback(self, request: Request):
        try:
            payload = self.consume(request)
            code = request.query_params.get('code', '')
            if request.query_params.get('error') or not code or len(code) > 8192:
                raise ValueError(ERROR)
            with self.p.auth_store.db() as con:
                config = configuration(con)
            if payload['config'] != fingerprint(config):
                raise ValueError(ERROR)
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                subject = await exchange(client, config, payload, code)
            response = self.complete(request, payload, config, subject)
        except (ValueError, KeyError, TypeError, PermissionError, HTTPException, JoseError, httpx.HTTPError, sqlite3.IntegrityError):
            response = self.p.message('Вход не завершён', ERROR + ' Для первой привязки войдите привычным способом и откройте безопасность профиля.',
                                      back_url='/', back_label='Перейти ко входу')
            response.status_code = 400
        response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='lax')
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    def complete(self, request, payload, config, subject):
        actor = self.pages.profile_actor(request) if payload['purpose'] == 'link' else None
        with self.p.auth_store.db() as con:
            if fingerprint(configuration(con)) != payload['config']:
                raise ValueError(ERROR)
            if actor:
                self.link(con, actor, payload, config, subject)
                return RedirectResponse('/security', 303)
            row = con.execute('SELECT account_id FROM oidc_links WHERE issuer=? AND subject=?', (config['issuer'], subject)).fetchone()
            if not row or 'oidc' not in identity.policy(con, row['account_id'])['primary']:
                raise ValueError(ERROR)
            token = self.p.identities.new_session(con, row['account_id'], ['oidc'])
        return self.pages.finish(token)

    @staticmethod
    def link(con, actor, payload, config, subject):
        rules = identity.policy(con, actor['account_id'])
        if not actor['ready'] or actor['must_change'] or actor['token_hash'] != payload['session'] or 'oidc' not in rules['primary']:
            raise ValueError(ERROR)
        # No email/phone matching or replacement of an existing binding.
        con.execute('INSERT INTO oidc_links VALUES(?,?,?)', (actor['account_id'], config['issuer'], subject))
        identity.audit(con, actor['account_id'], 'oidc.link', actor['account_id'])

    def unlink(self, request: Request):
        actor = self.pages.profile_actor(request)
        with self.p.auth_store.db() as con:
            ready_before = identity.ready_accounts(con)
            con.execute('DELETE FROM oidc_links WHERE account_id=?', (actor['account_id'],))
            identity.ensure_login_paths(con)
            if ready_before - identity.ready_accounts(con):
                raise ValueError('Сначала настройте другой способ входа')
            con.execute('DELETE FROM identity_sessions WHERE account_id=?', (actor['account_id'],))
            identity.audit(con, actor['account_id'], 'oidc.unlink', actor['account_id'])
        return RedirectResponse('/', 303)


def register(pages):
    handler = OIDC(pages)
    pages.p.app.add_api_route('/login/oidc/start', handler.start, methods=['POST'])
    pages.p.app.add_api_route(CALLBACK, handler.callback, methods=['GET'])
    pages.p.app.add_api_route('/security/oidc/delete', handler.unlink, methods=['POST'])
