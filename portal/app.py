import asyncio
import io
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

import httpx
import auth
import identity
import qrcode
from amnezia import connection_url
from views import render, request_context, local_path, DRAFT_FIELDS
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.exceptions import RequestValidationError
from pathlib import Path
from routing import migrate, changed, parse_wireguard, normalize_rule, atomic_json, stored_config_text, store_config
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

SECURITY_PATH = '/security'
EDIT_EXITS = 'exits.edit'
VIEW_EXITS = 'exits.view'
ACCOUNT_PREFIX = '/accounts/'
DEFAULT_EXIT_ACTION = 'exits.default'
GLOBAL_ROUTING = 'routing.global'
RENAME_DEVICE = 'devices.rename'
DEVICE_EXIT = 'device.exit'
DEVICE_CONFIG = 'devices.config'

ADMIN_LOGIN_PATH = '/admin/login'
ADMIN_PATH = '/admin'
CABINET_PATH = '/cabinet'
WG_CLIENT_PATH = '/clients'
USER_BY_PHONE = 'SELECT * FROM users WHERE phone=?'

BEGIN_WRITE = 'BEGIN IMMEDIATE'
DEFAULT_EXIT_QUERY = "SELECT value FROM settings WHERE key='ru_default'"
UNAVAILABLE_LABEL = 'Недоступен'
RU_EXITS_PATH = '/admin/ru-exits'
ROUTING_PATH = '/admin/routing'
NAME_REQUIRED = 'Укажите название'

HTTP_RESPONSES = {
    303: {"description": 'Session required or action completed; follow Location'},
    400: {"description": 'Invalid form or configuration'},
    401: {"description": 'Invalid administrator credentials'},
    403: {"description": 'CSRF check, account permission or device quota denied'},
    404: {"description": 'Requested resource not found'},
    409: {"description": 'Resource has assignments or conflicts with an existing account'},
    410: {"description": 'Verification expired'},
    413: {"description": 'Request body exceeds the limit'},
    422: {"description": 'Form field validation failed'},
    429: {"description": 'Verification attempt limit exceeded'},
    502: {"description": 'VPN API unavailable'},
    503: {"description": 'Authentication or phone verification service unavailable'},
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, responses=HTTP_RESPONSES)
app.mount("/assets", StaticFiles(directory="static"), name="assets")
DB = os.getenv("PORTAL_DB", "/data/portal.db")
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "")
auth_store = auth.Auth(os.getenv("AUTH_DB", str(Path(DB).with_name("auth.db"))))
identities = identity.Identity(auth_store, DB)
password_hasher = auth.HASHER
RU_CONFIG_DIR = Path(os.getenv("RU_CONFIG_DIR", "/ru-configs"))
ROUTER_STATUS = Path(os.getenv("ROUTER_STATUS", "/routing-status/status.json"))
device_lock = asyncio.Lock()


async def validate_csrf(request, token):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not request.headers.get("content-length", "0").isdigit():
            return friendly_http_error(request, HTTPException(400, "Некорректный размер запроса"))
        if int(request.headers.get("content-length", "0")) > 131072:
            return friendly_http_error(request, HTTPException(413, "Форма слишком большая"))
        if request.headers.get("sec-fetch-site") == "cross-site":
            return friendly_http_error(request, HTTPException(403, "Запрос с другого сайта запрещён"))
        # Double-submit token, host-only secure cookie; protect login/logout too.
        if len(await request.body()) > 131072:
            return friendly_http_error(request, HTTPException(413, "Форма слишком большая"))
        form = await request.form()
        supplied = request.headers.get("X-CSRF-Token") or form.get("csrf_token", "")
        if not isinstance(supplied, str) or not request.cookies.get("__Host-aas_csrf") or not secrets.compare_digest(supplied, token):
            return friendly_http_error(request, HTTPException(403, "Обновите страницу и повторите действие (CSRF)"))
        # BaseHTTPMiddleware must leave the original body available to FastAPI.
    return None


@app.middleware("http")
async def csrf_and_privacy(request, call_next):
    authentication = request.url.path in {'/login', '/admin/login', '/admin/logout'} or request.url.path.startswith(('/login/', '/security/'))
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and not authentication and Path(DB).with_name('maintenance').exists():
        return friendly_http_error(request, HTTPException(503, 'Сервис обновляется. Повторите действие через несколько минут', headers={'Retry-After': '30'}))
    token = request.cookies.get("__Host-aas_csrf") or secrets.token_urlsafe(32)
    error = await validate_csrf(request, token)
    if error is not None:
        return error
    request.state.csrf_token = token
    if request.method == 'POST':
        form = await request.form()
        request.state.form_draft = {key: [value for value in form.getlist(key) if isinstance(value, str)] for key in DRAFT_FIELDS if key in form}
    context_token = request_context.set(request)
    try:
        response = await call_next(request)
    finally:
        request_context.reset(context_token)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not request.cookies.get("__Host-aas_csrf"):
        response.set_cookie("__Host-aas_csrf", token, httponly=True, secure=True, samesite="strict", path="/")
    return response



@contextmanager
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


@app.on_event("startup")
def startup():
    with db() as con:
        con.executescript("""
          CREATE TABLE IF NOT EXISTS users(
            phone TEXT PRIMARY KEY, name TEXT NOT NULL, device_limit INTEGER NOT NULL DEFAULT 1,
            enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS verifications(
            token TEXT PRIMARY KEY, phone TEXT NOT NULL, call_id TEXT, dial_phone TEXT,
            created_at INTEGER NOT NULL, verified_at INTEGER);
          CREATE TABLE IF NOT EXISTS devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, name TEXT NOT NULL,
            client_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        base_path = Path(os.getenv("ROUTING_BASE_CONFIG", "/etc/sing-box/config.json"))
        migrate(con, json.loads(base_path.read_text()) if base_path.exists() else None)
        columns = {r[1] for r in con.execute('PRAGMA table_info(devices)')}
        if 'wg_client_id' in columns:
            if not Path(auth_store.path).is_file():
                raise RuntimeError('Run the stopped-stack native migration before starting the portal')
            with auth_store.db() as credentials:
                if not credentials.execute("SELECT 1 FROM settings WHERE key='migration_source'").fetchone():
                    raise RuntimeError('Native administrator migration has not completed')
            con.execute('ALTER TABLE devices RENAME COLUMN wg_client_id TO client_id')
        if 'operation' not in columns:
            con.execute("ALTER TABLE devices ADD COLUMN operation TEXT NOT NULL DEFAULT 'applied'")
        if 'native_enabled' not in columns:
            con.execute('ALTER TABLE devices ADD COLUMN native_enabled INTEGER NOT NULL DEFAULT 1')
        old_secret = con.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()
        auth_store.initialize(old_secret[0] if old_secret else None)
        con.execute('PRAGMA secure_delete=ON')
        con.execute("DELETE FROM settings WHERE key='session_secret'")
        con.execute('DROP TABLE IF EXISTS auth_cache')
    identities.initialize()
    auth_store.identity = identities
    Path(DB).with_name('wg-auth.json').unlink(missing_ok=True)
    RU_CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def page(title, body, show_header=False):
    request = request_context.get()
    actor = identities.session(request.cookies.get(auth.COOKIE, ''), limited=True) if request else None
    navigation = navigation_model(actor) if show_header and actor and actor['ready'] and not actor['must_change'] else []
    active = getattr(request.state, 'active_section', '') if request else ''
    return HTMLResponse(render('base.html', title=title, body=body, show_header=show_header,
                               actor=actor,
                               navigation=navigation, active=active,
                               active_label=dict(navigation).get(active, 'Разделы')))


def phone_normalize(value):
    if not value.strip().startswith("+"):
        raise HTTPException(400, "Выберите код страны")
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits[0] in "78":
        digits = "7" + digits[1:]
    if not 10 <= len(digits) <= 15:
        raise HTTPException(400, "Неверный номер")
    return "+" + digits


def latin_slug(value, fallback):
    translit = str.maketrans({
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo", "ж": "zh",
        "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o", "п": "p",
        "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts", "ч": "ch",
        "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    })
    value = value.lower().translate(translit)
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-")[:30] or fallback


def current_account(request, limited=False):
    row = identities.session(request.cookies.get(auth.COOKIE, ''), limited=limited)
    if not row:
        partial = identities.session(request.cookies.get(auth.COOKIE, ''), limited=True)
        raise HTTPException(303, headers={"Location": SECURITY_PATH if partial else '/'})
    if row['must_change'] and not limited:
        raise HTTPException(303, headers={"Location": SECURITY_PATH})
    return row


def session_phone(request):
    row = current_account(request)
    with db() as con:
        user = con.execute('SELECT phone FROM users WHERE account_id=?', (row['account_id'],)).fetchone()
    if not user:
        raise HTTPException(404, 'Аккаунт не найден')
    return user['phone']


def require_permission(request, action, target=None):
    actor = current_account(request)
    if not identities.allowed(actor['account_id'], action, target):
        raise HTTPException(404 if target else 403, 'Объект не найден' if target else 'Недостаточно прав')
    return actor


def require_owner(request, fresh=False):
    actor = current_account(request)
    if not identities.owner(actor['account_id']):
        raise HTTPException(403, 'Действие доступно только администратору')
    if fresh:
        require_fresh(actor)
    return actor


def require_fresh(actor):
    if time.time() - actor['confirmed'] > 300:
        raise HTTPException(303, headers={'Location': '/security/confirm'})


def audit_change(request, action, target=''):
    actor = current_account(request)
    with auth_store.db() as con:
        identity.audit(con, actor['account_id'], action, str(target))


def account_for_phone(phone):
    with db() as con:
        row = con.execute('SELECT account_id FROM users WHERE phone=?', (phone,)).fetchone()
    if not row:
        raise HTTPException(404, 'Аккаунт не найден')
    return row['account_id']


def admin_ok(request):
    row = identities.session(request.cookies.get(auth.COOKIE, ''))
    if not row or row['must_change']:
        return False
    with auth_store.db() as con:
        return identity.privileged(con, row['account_id'])


def require_admin(request, action=None):
    if action:
        actor = require_permission(request, action)
        if request.method == 'POST' and action in {'settings.edit', EDIT_EXITS, DEFAULT_EXIT_ACTION, GLOBAL_ROUTING}:
            require_fresh(actor)
        return actor
    current_account(request)
    if not admin_ok(request):
        raise HTTPException(403, 'Недостаточно прав')


def message(title, text, back_url='/', back_label='На главную', codes='', account_id='', recovery=False, error=False, not_found=False):
    return page(title, render('message.html', message=text, back_url=back_url, back_label=back_label,
                             codes=codes, account_id=account_id, recovery=recovery, error=error, not_found=not_found))


def return_signer():
    from itsdangerous import URLSafeTimedSerializer
    with auth_store.db() as con:
        secret = con.execute("SELECT value FROM settings WHERE key='phone_secret'").fetchone()[0]
    return URLSafeTimedSerializer(secret, salt='return-to-editor')


def return_path(request):
    from urllib.parse import urlsplit
    referer = urlsplit(request.headers.get('referer', ''))
    if referer.netloc == request.url.netloc and referer.scheme == request.url.scheme:
        return local_path(referer.path + ('?' + referer.query if referer.query else ''))
    if request.url.path.startswith(ACCOUNT_PREFIX):
        return ACCOUNT_PREFIX + request.url.path.split('/')[2] + '/edit'
    return CABINET_PATH


def failed_form(request, detail):
    """Re-render a permitted GET view; never replay a mutation or retain secrets."""
    if request.method != 'POST' or request_context.get() is None:
        return None
    from access_pages import AccessPages
    from security_pages import SecurityPages
    path = request.url.path
    access = AccessPages(__import__(__name__))
    request.state.form_failed = True
    request.state.form_error = detail
    try:
        if path == '/admin/accounts':
            return access.new_account(request)
        if path.startswith(ACCOUNT_PREFIX) and path.endswith('/save'):
            return access.edit_account(request, path.split('/')[2])
        if path == '/admin/roles/save':
            draft = getattr(request.state, 'form_draft', {})
            return access.edit_role(request, draft.get('role_id', [''])[0])
        if path.startswith('/device/') and path.endswith('/update'):
            device = owned_device(request, int(path.split('/')[2]))
            return cabinet(request, device['phone'])
        if path.endswith('/routing'):
            return failed_routing_form(request, access)
        if path.startswith('/admin/login-methods/'):
            return SecurityPages(__import__(__name__)).modules(request)
        if path.startswith('/login/verify/') and not path.endswith('/retry'):
            return SecurityPages(__import__(__name__)).verify_page(request, path.split('/')[-1])
    except (HTTPException, ValueError, PermissionError):
        pass
    return None


def failed_routing_form(request, access):
    path = request.url.path
    if path == ROUTING_PATH:
        return routing_page(request)
    if path.startswith('/device/'):
        return access.device_routes(request, int(path.split('/')[2]))
    if path.startswith(ACCOUNT_PREFIX):
        return access.account_routes(request, path.split('/')[2])
    return None


@app.exception_handler(HTTPException)
def friendly_http_error(request: Request, exc: HTTPException):
    location = (exc.headers or {}).get('Location')
    if 300 <= exc.status_code < 400 and location:
        response = RedirectResponse(location, status_code=exc.status_code)
        if location == '/security/confirm':
            response.set_cookie('__Host-aas_return', return_signer().dumps(return_path(request)),
                                secure=True, httponly=True, samesite='lax', max_age=600, path='/')
        return response
    detail = str(exc.detail or 'Не удалось выполнить запрос')
    if request.url.path.endswith('/status') or request.headers.get('X-Requested-With') == 'fetch':
        return JSONResponse({'detail': detail}, status_code=exc.status_code, headers=exc.headers)
    response = failed_form(request, detail) if exc.status_code in {400, 409, 422} else None
    if response is None:
        request.state.form_error = ''
        response = message('Не получилось', detail, back_url=return_path(request), back_label='Вернуться к странице', error=True)
    response.status_code = exc.status_code
    for key, value in (exc.headers or {}).items():
        response.headers[key] = value
    return response


@app.exception_handler(404)
def not_found_page(request: Request, exc):
    response = message('Страница не найдена', 'Такого адреса нет или страница была перемещена.', not_found=True)
    response.status_code = 404
    return response


def next_dial_number():
    numbers = dial_numbers()
    if not numbers:
        return ""
    with db() as con:
        con.execute(BEGIN_WRITE)
        row = con.execute("SELECT value FROM settings WHERE key='dial_number_index'").fetchone()
        index = int(row[0]) if row else 0
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str((index + 1) % len(numbers)),))
    return numbers[index % len(numbers)]


def dial_numbers():
    with db() as con:
        row = con.execute("SELECT value FROM settings WHERE key='dial_numbers'").fetchone()
    source = row[0] if row else os.getenv("ZVONOK_DIAL_NUMBERS", "")
    return [phone_normalize(value) for value in re.split(r"[,\n]+", source) if value.strip()]






def clear_legacy_cookies(response):
    if COOKIE_DOMAIN:
        response.delete_cookie("wg-easy", domain=COOKIE_DOMAIN, path="/")
    response.delete_cookie("wg-easy", path="/")


@app.post("/admin/logout", responses=HTTP_RESPONSES)
def admin_logout(request: Request):
    auth_store.logout(request.cookies.get(auth.COOKIE, ''))
    response = RedirectResponse(ADMIN_LOGIN_PATH, 303)
    response.delete_cookie(auth.COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    clear_legacy_cookies(response)
    return response


@app.get("/healthz", responses=HTTP_RESPONSES)
def health():
    return {"ok": True}




















def wg_session():
    transport = httpx.AsyncHTTPTransport(uds=os.getenv('AWG_SOCKET', '/awg-control/control.sock'))
    return httpx.AsyncClient(base_url='http://controller', transport=transport, timeout=20)


@app.get(CABINET_PATH, responses=HTTP_RESPONSES)
def cabinet(request: Request, phone: str = ""):
    is_admin = admin_ok(request)
    if not phone:
        phone = session_phone(request)
    require_permission(request, "devices.view", account_for_phone(phone))
    with db() as con:
        user = con.execute(USER_BY_PHONE, (phone,)).fetchone()
        devices = con.execute("SELECT * FROM devices WHERE phone=? ORDER BY id", (phone,)).fetchall()
    if not user:
        raise HTTPException(403)
    rows = device_routing_forms(devices, user, is_admin, request)
    actor = current_account(request)
    can_create = len(devices) < user['device_limit'] and identities.allowed(actor['account_id'], 'devices.create', user['account_id'])
    managed = account_navigation(request, user['account_id'])
    return page(f"Устройства: {user['name']}" if managed else "Мои устройства",
                render('cabinet.html', user=user, is_admin=is_admin, managed=managed, can_create=can_create,
                       can_route=identities.allowed(actor['account_id'], 'account.routing.view', user['account_id']),
                       count=len(devices), cards=rows), show_header=True)


@app.get("/admin/users/{phone}/devices", responses=HTTP_RESPONSES)
def admin_devices(request: Request, phone: str):
    require_admin(request)
    return cabinet(request, phone)


@app.post("/device", responses=HTTP_RESPONSES)
async def create_device(request: Request, name: str = Form(...), phone: str = Form("")):
    if admin_ok(request) and phone:
        account_for_phone(phone)
    else:
        phone = session_phone(request)
    require_permission(request, "devices.create", account_for_phone(phone))
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, "Укажите название устройства")
    with db() as con:
        con.execute(BEGIN_WRITE)
        user = con.execute(USER_BY_PHONE, (phone,)).fetchone()
        count = con.execute("SELECT count(*) FROM devices WHERE phone=?", (phone,)).fetchone()[0]
        if not user or (not user['enabled'] and not admin_ok(request)) or count >= user['device_limit']:
            raise HTTPException(403, 'Лимит устройств исчерпан или выдача запрещена')
        client_id = str(uuid.uuid4())
        con.execute("INSERT INTO devices(phone,name,client_id,created_at,account_id,operation) VALUES(?,?,?,?,?,'create')",
                    (phone, name, client_id, int(time.time()), user["account_id"]))
    await process_device_operations()
    return device_redirect(request, phone)


async def process_device_operations():
    async with device_lock:
        with db() as con:
            rows = con.execute("SELECT * FROM devices WHERE operation!='applied'").fetchall()
        for row in rows:
            try:
                await apply_device_operation(row)
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                continue  # Durable intent is retried; never log credentials or API bodies.
        if time.monotonic() - getattr(app.state, 'reconciled_at', 0) >= 15:
            try:
                await reconcile_native_clients()
                app.state.reconciled_at = time.monotonic()
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                pass


async def reconcile_native_clients():
    async with wg_session() as client:
        response = await client.get('/clients')
        response.raise_for_status()
    records = response.json()
    if not isinstance(records, list):
        raise ValueError('Invalid controller snapshot')
    mapping = {str(row['id']): row for row in records}
    with db() as con:
        dirty = False
        for device in con.execute('SELECT id,client_id,vpn_ip FROM devices').fetchall():
            peer = mapping.get(device['client_id'])
            if peer is None:
                continue
            address = str(ipaddress.IPv4Address(peer['ipv4Address']))
            enabled = int(peer.get('effective_enabled', peer.get('enabled', True)))
            con.execute('UPDATE devices SET vpn_ip=?,native_enabled=? WHERE id=?', (address, enabled, device['id']))
            dirty |= address != device['vpn_ip']
        if dirty:
            changed(con)


async def apply_device_operation(row):
    async with wg_session() as client:
        path = f"/clients/{row['client_id']}"
        response = await (client.put(path, json={'name': row['name']}) if row['operation'] == 'create' else client.delete(path))
        response.raise_for_status()
        result = response.json()
        if not result['applied']:
            return
        with db() as con:
            if row['operation'] == 'delete':
                con.execute("DELETE FROM devices WHERE id=? AND operation='delete'", (row['id'],))
            else:
                con.execute("UPDATE devices SET vpn_ip=?,operation='applied' WHERE id=? AND operation='create'", (result['ipv4Address'], row['id']))
            changed(con)


@app.on_event('startup')
async def start_device_worker():
    async def worker():
        while True:
            try:
                await process_device_operations()
            except sqlite3.Error:
                pass  # Keep the durable queue alive during transient database contention.
            await asyncio.sleep(2)
    app.state.device_worker = asyncio.create_task(worker())


@app.on_event('shutdown')
async def stop_device_worker():
    app.state.device_worker.cancel()
    await asyncio.gather(app.state.device_worker, return_exceptions=True)


def owned_device(request, device_id, action='devices.view'):
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Устройство не найдено")
    require_permission(request, action, row['account_id'])
    return row


def device_redirect(request, phone):
    account_id = account_for_phone(phone)
    own_account = current_account(request)['account_id'] == account_id
    return RedirectResponse(CABINET_PATH if own_account else f"/accounts/{account_id}", 303)


@app.post("/device/{device_id}/rename", responses=HTTP_RESPONSES)
def rename_device(request: Request, device_id: int, name: str = Form(...)):
    row = owned_device(request, device_id, RENAME_DEVICE)
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, NAME_REQUIRED)
    with db() as con:
        con.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
    return device_redirect(request, row["phone"])


def assignment_author(administrator):
    return 'admin' if administrator else 'user'


def validate_exit_assignment(con, phone, administrator, exit_id):
    permission = con.execute("SELECT can_change_ru_exit FROM users WHERE phone=?", (phone,)).fetchone()
    if not administrator and not permission[0]:
        raise HTTPException(403, "Смена альтернативного выхода запрещена администратором")
    if exit_id and not con.execute("SELECT 1 FROM ru_exits WHERE id=?", (exit_id,)).fetchone():
        raise HTTPException(400, "Альтернативный выход не найден")


def save_exit_assignment(con, device_id, exit_id, administrator):
    con.execute("UPDATE devices SET ru_exit_id=?,assigned_by=? WHERE id=?",
                (exit_id or None, assignment_author(administrator) if exit_id else None, device_id))
    changed(con)


@app.post("/device/{device_id}/update", responses=HTTP_RESPONSES)
def update_device(request: Request, device_id: int, name: str = Form(...), ru_exit_id: int | None = Form(None)):
    row = owned_device(request, device_id, RENAME_DEVICE if ru_exit_id is None else DEVICE_EXIT)
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, NAME_REQUIRED)
    if name != row['name']:
        require_permission(request, RENAME_DEVICE, row['account_id'])
    administrator = admin_ok(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if ru_exit_id is not None:
            require_permission(request, DEVICE_EXIT, row['account_id'])
            validate_exit_assignment(con, row['phone'], True, ru_exit_id)
            current = con.execute('SELECT ru_exit_id FROM devices WHERE id=?', (device_id,)).fetchone()
            # Saving a name must not claim an unchanged administrator assignment.
            if current[0] != (ru_exit_id or None):
                save_exit_assignment(con, device_id, ru_exit_id, administrator)
        con.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
    return device_redirect(request, row['phone'])


@app.post("/device/{device_id}/ru-exit", responses=HTTP_RESPONSES)
def assign_exit(request: Request, device_id: int, ru_exit_id: int = Form(0)):
    row = owned_device(request, device_id, DEVICE_EXIT)
    administrator = admin_ok(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        validate_exit_assignment(con, row['phone'], True, ru_exit_id)
        save_exit_assignment(con, device_id, ru_exit_id, administrator)
    return device_redirect(request, row["phone"])


@app.post("/device/{device_id}/delete", responses=HTTP_RESPONSES)
async def delete_device(request: Request, device_id: int):
    row = owned_device(request, device_id, 'devices.delete')
    with db() as con:
        con.execute("UPDATE devices SET operation='delete' WHERE id=?", (device_id,))
    await process_device_operations()
    return device_redirect(request, row["phone"])


@app.get("/device/{device_id}/config", responses=HTTP_RESPONSES)
async def config(request: Request, device_id: int):
    row = owned_device(request, device_id, DEVICE_CONFIG)
    if row['operation'] != 'applied':
        raise HTTPException(409, 'Изменения устройства ещё применяются')
    async with wg_session() as client:
        response = await client.get(f"/clients/{row['client_id']}/configuration")
        response.raise_for_status()
        data = response.content
    filename = f"{latin_slug(row['name'], f'device-{device_id}')}.conf"
    disposition = f'attachment; filename="{filename}"'
    return Response(data, media_type="application/x-wireguard-profile", headers={"Content-Disposition": disposition, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def device_connection(request, device_id):
    row = owned_device(request, device_id, DEVICE_CONFIG)
    if row['operation'] != 'applied':
        raise HTTPException(409, 'Изменения устройства ещё применяются')
    async with wg_session() as client:
        response = await client.get(f"/clients/{row['client_id']}/configuration")
        response.raise_for_status()
        return connection_url(response.text, row['name'])


@app.get("/device/{device_id}/connect", responses=HTTP_RESPONSES)
async def connect(request: Request, device_id: int):
    return JSONResponse({'url': await device_connection(request, device_id)}, headers={'Cache-Control': 'no-store'})


@app.get("/device/{device_id}/qr", responses=HTTP_RESPONSES)
async def qr(request: Request, device_id: int):
    url = await device_connection(request, device_id)
    try:
        # The in-app QR reader accepts compressed Base64 data without the URI scheme.
        image = qrcode.make(url.removeprefix('vpn://'))
    except qrcode.exceptions.DataOverflowError:
        raise HTTPException(400, 'Настройки не помещаются в QR-код. Используйте кнопку «Установить».') from None
    out = io.BytesIO(); image.save(out, format="PNG")
    return Response(out.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})


@app.get("/download/amneziawg/windows", responses=HTTP_RESPONSES)
async def download_amneziawg_windows(request: Request):
    session_phone(request)
    releases_url = "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest"
    try:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "aas-portal"}
        async with httpx.AsyncClient(timeout=10, headers=headers) as client:
            response = await client.get("https://api.github.com/repos/amnezia-vpn/amneziawg-windows-client/releases/latest")
            response.raise_for_status()
        asset = next(item for item in response.json()["assets"] if re.fullmatch(r"amneziawg-amd64-(?!windows7).*\.msi", item["name"]))
        return RedirectResponse(asset["browser_download_url"], 302, headers={"Cache-Control": "no-store"})
    except (httpx.HTTPError, KeyError, StopIteration, TypeError):
        return RedirectResponse(releases_url, 302, headers={"Cache-Control": "no-store"})






@app.post("/admin/settings/dial-numbers", responses=HTTP_RESPONSES)
def admin_dial_numbers(request: Request, numbers: list[str] = Form(...)):
    require_admin(request, 'settings.edit')
    normalized = [phone_normalize(value) for value in numbers if value.strip()]
    if not 1 <= len(normalized) <= 20:
        raise HTTPException(400, "Укажите от 1 до 20 номеров")
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES('dial_numbers',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("\n".join(dict.fromkeys(normalized)),))
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index','0') ON CONFLICT(key) DO UPDATE SET value='0'")
    audit_change(request, 'settings.dial-numbers')
    return RedirectResponse(ADMIN_PATH, 303)




@app.exception_handler(RequestValidationError)
def validation_error(request: Request, exc: RequestValidationError):
    # Never return validation inputs: upload/config fields may contain private keys.
    messages = {"missing": "Обязательное поле", "int_parsing": "Введите целое число", "int_type": "Введите целое число", "string_type": "Введите текст"}
    errors = [{"loc": x["loc"], "msg": messages.get(x["type"], x["msg"])} for x in exc.errors()]
    if request.headers.get('X-Requested-With') == 'fetch':
        return JSONResponse({'detail': errors}, 422)
    request.state.field_errors = {str(item['loc'][-1]): item['msg'] for item in errors}
    return friendly_http_error(request, HTTPException(422, '; '.join(f"{'.'.join(map(str, x['loc'][1:]))}: {x['msg']}" for x in errors)))


@app.exception_handler(httpx.HTTPError)
def upstream_error(request: Request, exc):
    return friendly_http_error(request, HTTPException(502, 'Сервис VPN временно недоступен'))


def navigation_model(actor):
    key = actor['account_id']
    with identities.transaction() as con:
        targets = [row[0] for row in con.execute('SELECT id FROM accounts')]
        accounts_visible = any(identity.allowed(con, key, 'accounts.view', target) for target in targets)
    links = [(CABINET_PATH, 'Мои устройства')]
    if accounts_visible:
        links.append((ADMIN_PATH, 'Пользователи'))
    for path, label, permission in [(RU_EXITS_PATH, 'Альтернативные выходы', VIEW_EXITS), (ROUTING_PATH, 'Маршрутизация', GLOBAL_ROUTING)]:
        if identities.allowed(key, permission):
            links.append((path, label))
    if identities.owner(key):
        links.extend([('/admin/roles', 'Роли и доступ'), ('/admin/login-methods', 'Способы входа')])
    return links


def admin_nav(active=ADMIN_PATH):
    request = request_context.get()
    if request:
        request.state.active_section = active


def account_navigation(request, account_id):
    """Resource ownership determines the section, independently of actor privileges."""
    managed = current_account(request)['account_id'] != account_id
    admin_nav(ADMIN_PATH if managed else CABINET_PATH)
    return managed


def routing_status():
    try:
        status = json.loads(ROUTER_STATUS.read_text())
        if time.time() - status.get('updated_at', 0) > 45:
            return {'state': 'stale', 'message': 'Контроллер не отвечает'}
        return status
    except (OSError, ValueError):
        return {'state': 'pending', 'message': 'Нет данных о маршрутизации'}


def status_text(status):
    with db() as con:
        revision = int(con.execute("SELECT value FROM settings WHERE key='routing_revision'").fetchone()[0])
    if status.get('applied_revision') != revision and status.get('state') == 'applied':
        return 'Настройки сохранены. Ожидается применение на VPN-сервере.'
    return {'applied': 'Настройки применены на VPN-сервере.',
            'error': 'Не удалось применить изменения. VPN использует предыдущие настройки.',
            'pending': 'Не удалось получить состояние VPN-сервера. Применение маршрутов пока не подтверждено.',
            'stale': 'Данные о маршрутизации устарели: VPN-сервер не обновлял состояние более 45 секунд.'}.get(
                status.get('state'), 'Настройки сохранены. Ожидается применение на VPN-сервере.')


def device_actions(device, request=None):
    actor = current_account(request) if request else None
    def allowed(action):
        return actor is None or identities.allowed(actor['account_id'], action, device['account_id'])
    return render('components/device_actions.html', device=device, config=allowed(DEVICE_CONFIG),
                  routing=bool(request) and allowed('device.routing.view'), delete=allowed('devices.delete'))


def device_routing_forms(devices, user, administrator, request=None):
    with db() as con:
        exits = con.execute('SELECT id,name FROM ru_exits ORDER BY id').fetchall()
        default = user['ru_exit_id'] or int(con.execute(DEFAULT_EXIT_QUERY).fetchone()[0])
    names = {x['id']: x['name'] for x in exits}
    status = routing_status()
    cards = [{'device': device, 'state': device_state_labels(device, names, default, status), 'actions': device_actions(device, request), 'form': permitted_device_form(device, exits, user, administrator, request)} for device in devices]
    return render('components/devices.html', cards=cards, status=status_text(status))


def permitted_device_form(device, exits, user, administrator, request):
    can_rename = True
    can_exit = administrator or user['can_change_ru_exit']
    if request:
        actor = current_account(request)
        can_rename = identities.allowed(actor['account_id'], RENAME_DEVICE, device['account_id'])
        can_exit = identities.allowed(actor['account_id'], DEVICE_EXIT, device['account_id'])
    return device_edit_form(device, exits, can_exit, can_rename, device_actions(device, request)) if can_rename or can_exit else ''


def device_edit_form(device, exits, can_change_exit, can_rename=True, actions=''):
    return render('components/device_form.html', form_action=f"/device/{device['id']}/update", device=device, exits=exits,
                  can_change_exit=can_change_exit, can_rename=can_rename, actions=actions)


def exit_health_label(status, node_id):
    state = status.get('exits', {}).get(str(node_id), {})
    if status.get('state') == 'stale':
        return 'Данные о доступности устарели'
    if status.get('state') == 'pending' or not state:
        return 'Доступность неизвестна'
    return 'Доступен' if state.get('healthy') else UNAVAILABLE_LABEL


def device_state_labels(device, names, default, status):
    actual = status.get('devices', {}).get(str(device['id']), {})
    unknown = status.get('state') in {'stale', 'pending'}
    assigned = names.get(device['ru_exit_id'], 'По умолчанию: ' + names.get(default, '—'))
    effective = 'Неизвестно' if unknown else names.get(actual.get('effective'), UNAVAILABLE_LABEL)
    fallback = ' · резервный режим' if not unknown and actual.get('fallback') else ''
    return f'Назначен: {assigned} · Используется: {effective}{fallback}'


@app.get(RU_EXITS_PATH, responses=HTTP_RESPONSES)
def ru_exits_page(request: Request):
    require_admin(request, VIEW_EXITS)
    with db() as con:
        exits = con.execute('SELECT id,name,legacy,config_file FROM ru_exits ORDER BY id').fetchall()
        default = int(con.execute(DEFAULT_EXIT_QUERY).fetchone()[0])
    status = routing_status()
    admin_nav(RU_EXITS_PATH)
    actor = current_account(request)
    can_edit = identities.allowed(actor['account_id'], EDIT_EXITS)
    can_default = identities.allowed(actor['account_id'], DEFAULT_EXIT_ACTION)
    can_private = identities.allowed(actor['account_id'], 'exits.private')
    nodes = []
    for row in exits:
        node = dict(row)
        config = stored_config_text(RU_CONFIG_DIR, node['config_file']) if can_private else ''
        node.update(health=exit_health_label(status, node['id']), config=config,
                    editor=render('components/exit_form.html', node=node, config=config,
                                  can_default=can_default, default=default) if can_edit else '')
        nodes.append(node)
    return page('Альтернативные выходы', render('exits.html', nodes=nodes, default=default, can_edit=can_edit,
                can_default=can_default, routing_status=status_text(status),
                new_editor=render('components/exit_form.html', node=None, config='', can_default=False, default=default)), show_header=True)


async def uploaded_endpoint(config_text, config_upload):
    if config_upload and config_upload.filename:
        if config_text.strip():
            raise HTTPException(400, 'Выберите файл или текст конфига')
        try:
            config_text = (await config_upload.read(65537)).decode('utf-8-sig')
        except UnicodeError:
            raise HTTPException(400, 'Конфиг должен быть текстом UTF-8') from None
    endpoint = None
    if config_text.strip():
        try:
            endpoint = parse_wireguard(config_text)
        except ValueError as error:
            raise HTTPException(400, str(error)) from None
    return endpoint, config_text


def updated_exit_config(old, endpoint, text):
    filename = old['config_file'] if old else None
    legacy = old['legacy'] if old else 0
    if not endpoint:
        return filename, legacy
    if filename and stored_config_text(RU_CONFIG_DIR, filename) == text:
        return filename, legacy
    filename = secrets.token_hex(16) + '.json'
    store_config(RU_CONFIG_DIR, filename, endpoint, text)
    return filename, 0


@app.post(RU_EXITS_PATH, responses=HTTP_RESPONSES)
@app.post('/admin/ru-exits/{exit_id}', responses=HTTP_RESPONSES)
async def save_ru_exit(request: Request, exit_id: int = 0, name: str = Form(...), config_text: str = Form(''), config_upload: UploadFile = File(None)):
    require_admin(request, EDIT_EXITS)
    name = name.strip()[:80]
    if not name:
        raise HTTPException(400, NAME_REQUIRED)
    endpoint, config_text = await uploaded_endpoint(config_text, config_upload)
    with db() as con:
        con.execute(BEGIN_WRITE)
        old = con.execute('SELECT * FROM ru_exits WHERE id=?', (exit_id,)).fetchone() if exit_id else None
        if exit_id and not old:
            raise HTTPException(404, 'Альтернативный выход не найден')
        if not old and not endpoint:
            raise HTTPException(400, 'Загрузите или вставьте WireGuard-конфиг')
        if not old and con.execute('SELECT count(*) FROM ru_exits').fetchone()[0] >= 64:
            raise HTTPException(400, 'Достигнут лимит 64 выходов')
        filename, legacy = updated_exit_config(old, endpoint, config_text)
        if old:
            con.execute('UPDATE ru_exits SET name=?,config_file=?,legacy=? WHERE id=?', (name, filename, legacy, exit_id))
        else:
            exit_id = con.execute('INSERT INTO ru_exits(name,config_file) VALUES(?,?)', (name, filename)).lastrowid
        changed(con)
    audit_change(request, 'exits.save', exit_id)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.post('/admin/ru-exits/{exit_id}/default', responses=HTTP_RESPONSES)
def default_ru_exit(request: Request, exit_id: int):
    require_admin(request, DEFAULT_EXIT_ACTION)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if not con.execute('SELECT 1 FROM ru_exits WHERE id=?', (exit_id,)).fetchone():
            raise HTTPException(404, 'Альтернативный выход не найден')
        con.execute("UPDATE settings SET value=? WHERE key='ru_default'", (str(exit_id),))
        changed(con)
    audit_change(request, DEFAULT_EXIT_ACTION, exit_id)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.post('/admin/ru-exits/{exit_id}/delete', responses=HTTP_RESPONSES)
def delete_ru_exit(request: Request, exit_id: int):
    require_admin(request, EDIT_EXITS)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if con.execute("SELECT 1 FROM settings WHERE key='ru_default' AND value=?", (str(exit_id),)).fetchone() or con.execute('SELECT 1 FROM devices WHERE ru_exit_id=?', (exit_id,)).fetchone() or con.execute('SELECT 1 FROM users WHERE ru_exit_id=?', (exit_id,)).fetchone():
            raise HTTPException(409, 'Сначала снимите назначения и выберите другой выход по умолчанию')
        con.execute('DELETE FROM ru_exits WHERE id=?', (exit_id,))
        changed(con)
    audit_change(request, 'exits.delete', exit_id)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.get(ROUTING_PATH, responses=HTTP_RESPONSES)
def routing_page(request: Request):
    require_admin(request, GLOBAL_ROUTING)
    with db() as con:
        rules = con.execute('SELECT * FROM routing_rules ORDER BY value').fetchall()
    from access_pages import rules_text
    admin_nav(ROUTING_PATH)
    editor = render('components/routing_editor.html', path=ROUTING_PATH, values={target: rules_text(rules, target) for target in ('ru', 'direct')},
                    editable=True, can_exit=False, exits=[], selected_exit=None)
    return page('Маршрутизация', render('routing.html', level='Глобальные правила', owner='', status=status_text(routing_status()),
                crumbs=[], editor=editor, inheritance=[], chain='', actual=''), show_header=True)


@app.post(ROUTING_PATH, responses=HTTP_RESPONSES)
def save_routing(request: Request, ru: str = Form(''), direct: str = Form('')):
    require_admin(request, GLOBAL_ROUTING)
    rules = set()
    try:
        for target, value in [('ru', ru), ('direct', direct)]:
            if len(value) > 65536:
                raise ValueError('Слишком большой список правил')
            for line in value.splitlines():
                if line.strip():
                    kind, normalized = normalize_rule(line)
                    rules.add((target, kind, normalized))
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    with db() as con:
        con.execute('DELETE FROM routing_rules')
        con.executemany('INSERT INTO routing_rules(target,kind,value) VALUES(?,?,?)', sorted(rules))
        changed(con)
    audit_change(request, GLOBAL_ROUTING)
    return RedirectResponse(ROUTING_PATH, 303)



@app.get('/routing/status', responses=HTTP_RESPONSES)
def live_routing_status(request: Request, admin_view: bool = False):
    if admin_view:
        require_admin(request)
    administrator = admin_ok(request)
    phone = None if administrator else session_phone(request)
    status = routing_status()
    with db() as con:
        names = {r['id']: r['name'] for r in con.execute('SELECT id,name FROM ru_exits')}
        default = int(con.execute(DEFAULT_EXIT_QUERY).fetchone()[0])
        devices = con.execute('''SELECT d.id,d.ru_exit_id,d.account_id,u.ru_exit_id account_default
            FROM devices d LEFT JOIN users u ON u.account_id=d.account_id''' +
            ('' if administrator else ' WHERE d.phone=?'), () if administrator else (phone,)).fetchall()
    actor = current_account(request)
    devices = [device for device in devices if identities.allowed(actor['account_id'], 'devices.view', device['account_id'])]
    device_states = {str(device['id']): device_state_labels(device, names, device['account_default'] or default, status) for device in devices}
    exits = {str(node_id): exit_health_label(status, node_id) for node_id in names} if identities.allowed(actor['account_id'], VIEW_EXITS) else {}
    return JSONResponse({'message': status_text(status), 'devices': device_states, 'exits': exits})


import admin_auth
import unowned
import sys
admin_auth.register(sys.modules[__name__])
unowned.register(sys.modules[__name__])


def account_for_device(device_id):
    with db() as con:
        return con.execute('SELECT account_id FROM devices WHERE id=?', (device_id,)).fetchone()[0]

import access_pages
import security_pages


access_pages.register(sys.modules[__name__])
security_pages.register(sys.modules[__name__])
