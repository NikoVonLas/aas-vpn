import base64
import html
import io
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

import httpx
import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer

app = FastAPI(docs_url=None, redoc_url=None)
DB = os.getenv("PORTAL_DB", "/data/portal.db")
ZVONOK = "https://zvonok.com/manager/cabapi_external/api/v1/phones"
WG_AUTH_SNAPSHOT = os.getenv("WG_AUTH_SNAPSHOT", "/data/wg-auth.json")
COOKIE_DOMAIN = os.environ["COOKIE_DOMAIN"]
password_hasher = PasswordHasher()


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
            wg_client_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS auth_cache(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), user_id INTEGER NOT NULL,
            username TEXT NOT NULL, password_hash TEXT NOT NULL, totp_key TEXT,
            totp_verified INTEGER NOT NULL, enabled INTEGER NOT NULL,
            session_password TEXT NOT NULL, session_timeout INTEGER NOT NULL,
            synced_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        con.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('session_secret',?)", (secrets.token_hex(32),))
    sync_auth_cache()


def sync_auth_cache():
    """Refresh the standalone cache from the isolated synchronizer snapshot."""
    try:
        with open(WG_AUTH_SNAPSHOT, encoding="utf-8") as stream:
            snapshot = json.load(stream)
        with db() as con:
            con.execute("""INSERT INTO auth_cache(singleton,user_id,username,password_hash,totp_key,totp_verified,enabled,session_password,session_timeout,synced_at)
              VALUES(1,?,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET
              user_id=excluded.user_id,username=excluded.username,password_hash=excluded.password_hash,
              totp_key=excluded.totp_key,totp_verified=excluded.totp_verified,enabled=excluded.enabled,
              session_password=excluded.session_password,session_timeout=excluded.session_timeout,synced_at=excluded.synced_at""",
              (snapshot["user_id"], snapshot["username"], snapshot["password_hash"], snapshot["totp_key"], snapshot["totp_verified"], snapshot["enabled"], snapshot["session_password"], snapshot["session_timeout"], snapshot["synced_at"]))
        return True
    except (OSError, ValueError, KeyError):
        return False


def auth_cache(refresh=False):
    if refresh:
        sync_auth_cache()
    with db() as con:
        row = con.execute("SELECT * FROM auth_cache WHERE singleton=1").fetchone()
    if not row:
        raise HTTPException(503, "Авторизация ещё не синхронизирована с WG Easy")
    return row


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def iron_key(secret, salt):
    return hashlib.pbkdf2_hmac("sha1", secret.encode(), salt.encode(), 1, dklen=32)


def iron_seal(payload, secret, ttl=0):
    enc_salt, mac_salt, iv = secrets.token_hex(32), secrets.token_hex(32), os.urandom(16)
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    encryptor = Cipher(algorithms.AES(iron_key(secret, enc_salt)), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    expiration = str(int(time.time() * 1000) + ttl * 1000) if ttl else ""
    base = f"Fe26.2**{enc_salt}*{b64url(iv)}*{b64url(encrypted)}*{expiration}"
    digest = hmac.new(iron_key(secret, mac_salt), base.encode(), hashlib.sha256).digest()
    return f"{base}*{mac_salt}*{b64url(digest)}"


def iron_unseal(value, secret):
    parts = value.split("*")
    if len(parts) != 8 or parts[0] != "Fe26.2":
        raise ValueError("bad seal")
    _, _, enc_salt, iv64, encrypted64, expiration, mac_salt, supplied = parts
    base = "*".join(parts[:6])
    expected = b64url(hmac.new(iron_key(secret, mac_salt), base.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, supplied):
        raise ValueError("bad hmac")
    if expiration and int(expiration) <= int(time.time() * 1000) - 60_000:
        raise ValueError("expired")
    decryptor = Cipher(algorithms.AES(iron_key(secret, enc_salt)), modes.CBC(b64url_decode(iv64))).decryptor()
    padded = decryptor.update(b64url_decode(encrypted64)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return json.loads((unpadder.update(padded) + unpadder.finalize()).decode())


def make_wg_cookie(user_id, remember=False):
    cached = auth_cache(refresh=True)
    payload = {"id": str(uuid.uuid4()), "createdAt": int(time.time() * 1000), "data": {"userId": user_id}}
    return iron_seal(payload, cached["session_password"], cached["session_timeout"] if remember else 0)


def page(title, body):
    return HTMLResponse(f"""<!doctype html><html lang=ru><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>
<style>body{{font:16px system-ui;max-width:620px;margin:40px auto;padding:0 18px;background:#101418;color:#eef}}
.card{{background:#1a2027;padding:24px;border-radius:18px}}input,button{{box-sizing:border-box;width:100%;padding:13px;margin:7px 0;border-radius:10px;border:1px solid #455;background:#111820;color:#fff}}
button,.btn{{background:#2478ff;border:0;cursor:pointer;text-decoration:none;display:inline-block;text-align:center;padding:13px;box-sizing:border-box;border-radius:10px;color:white}}small{{color:#aab}} table{{width:100%}}td{{padding:6px}}</style>
<main><h1>{html.escape(title)}</h1><div class=card>{body}</div></main></html>""")


def phone_signer():
    with db() as con:
        secret = con.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()[0]
    return URLSafeTimedSerializer(secret, salt="aas-portal")


def phone_normalize(value):
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits[0] in "78":
        digits = "7" + digits[1:]
    if not 10 <= len(digits) <= 15:
        raise HTTPException(400, "Неверный номер")
    return "+" + digits


def session_phone(request):
    raw = request.cookies.get("aas_session", "")
    try:
        return phone_signer().loads(raw, max_age=30 * 24 * 3600)["phone"]
    except BadSignature:
        raise HTTPException(401, "Войдите повторно")


def admin_ok(request):
    raw = request.cookies.get("wg-easy", "")
    if not raw:
        return False
    cached = auth_cache(refresh=True)
    try:
        session = iron_unseal(raw, cached["session_password"])
        return cached["enabled"] == 1 and session.get("data", {}).get("userId") == cached["user_id"]
    except (ValueError, KeyError, TypeError):
        cached = auth_cache(refresh=True)
        try:
            session = iron_unseal(raw, cached["session_password"])
            return cached["enabled"] == 1 and session.get("data", {}).get("userId") == cached["user_id"]
        except (ValueError, KeyError, TypeError):
            return False
        return False


def require_admin(request):
    if not admin_ok(request):
        raise HTTPException(303, headers={"Location": "/admin/login"})


def next_dial_number():
    numbers = [phone_normalize(value) for value in os.getenv("ZVONOK_DIAL_NUMBERS", "").split(",") if value.strip()]
    if not numbers:
        return ""
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT value FROM settings WHERE key='dial_number_index'").fetchone()
        index = int(row[0]) if row else 0
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str((index + 1) % len(numbers)),))
    return numbers[index % len(numbers)]


@app.get("/admin/login")
def admin_login_form():
    return page("Вход администратора", "<p><small>Используйте учётную запись WG Easy.</small></p><form method=post><input name=username autocomplete=username placeholder='Логин' required><input name=password type=password autocomplete=current-password placeholder='Пароль' required><input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code placeholder='Код 2FA'><label><input style='width:auto' type=checkbox name=remember value=1> Запомнить меня</label><button>Войти</button></form>")


@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...), totp: str = Form(""), remember: str = Form("")):
    cached = auth_cache(refresh=True)
    user_ok = secrets.compare_digest(username, cached["username"])
    try:
        password_ok = password_hasher.verify(cached["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        password_ok = False
    totp_ok = True
    if cached["totp_verified"]:
        totp_ok = bool(cached["totp_key"] and pyotp.TOTP(cached["totp_key"]).verify(totp, valid_window=1))
    if not (cached["enabled"] and user_ok and password_ok and totp_ok):
        raise HTTPException(401, "Неверный логин, пароль или код 2FA")
    response = RedirectResponse("/admin", 303)
    max_age = cached["session_timeout"] if remember else None
    response.set_cookie("wg-easy", make_wg_cookie(cached["user_id"], bool(remember)), domain=COOKIE_DOMAIN, path="/", httponly=True, secure=True, samesite="lax", max_age=max_age)
    return response


@app.post("/admin/logout")
def admin_logout():
    response = RedirectResponse("/admin/login", 303)
    response.delete_cookie("wg-easy", domain=COOKIE_DOMAIN, path="/")
    return response


@app.get("/healthz")
def health():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return page("Получить VPN", "<p>Введите номер, который владелец сервера добавил в список.</p><form method=post action=/start><input name=phone type=tel autocomplete=tel placeholder='+7 999 123-45-67' required><button>Продолжить</button></form>")


@app.post("/start")
async def start(phone: str = Form(...)):
    phone = phone_normalize(phone)
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE phone=? AND enabled=1", (phone,)).fetchone()
        recent = con.execute("SELECT count(*) FROM verifications WHERE phone=? AND created_at>?", (phone, int(time.time()) - 600)).fetchone()[0]
    if not user:
        raise HTTPException(403, "Этот номер не добавлен владельцем")
    if recent >= 3:
        raise HTTPException(429, "Слишком много попыток. Подождите 10 минут")
    token = secrets.token_urlsafe(24)
    data = {"public_key": os.environ["ZVONOK_PUBLIC_KEY"], "campaign_id": os.environ["ZVONOK_CAMPAIGN_ID"], "phone": phone}
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(f"{ZVONOK}/confirm/", data=data)
        response.raise_for_status()
        result = response.json()
    call_id = str(result.get("call_id") or result.get("id") or "")
    dial = next_dial_number() or str(result.get("confirm_phone") or result.get("phone_to_call") or result.get("verification_phone") or result.get("call_phone") or "")
    with db() as con:
        con.execute("INSERT INTO verifications(token,phone,call_id,dial_phone,created_at) VALUES(?,?,?,?,?)", (token, phone, call_id, dial, int(time.time())))
    return RedirectResponse(f"/verify/{token}", 303)


async def zvonok_status(row):
    params = {"public_key": os.environ["ZVONOK_PUBLIC_KEY"], "campaign_id": os.environ["ZVONOK_CAMPAIGN_ID"], "phone": row["phone"], "expand": 1}
    endpoint = "calls_by_phone/"
    if row["call_id"]:
        params.pop("campaign_id"); params.pop("phone")
        params["call_id"] = row["call_id"]
        endpoint = "call_by_id/"
    async with httpx.AsyncClient(timeout=15) as client:
        result = (await client.get(f"{ZVONOK}/{endpoint}", params=params)).json()
    success = {x.strip().lower() for x in os.getenv("ZVONOK_SUCCESS_STATUSES", "processed,success,confirmed").split(",")}
    def values(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("call_status", "status", "status_name"):
                    yield str(item).lower()
                yield from values(item)
        elif isinstance(value, list):
            for item in value:
                yield from values(item)
    return any(value in success for value in values(result))


@app.get("/verify/{token}")
async def verify(token: str, check: int = 0):
    with db() as con:
        row = con.execute("SELECT * FROM verifications WHERE token=?", (token,)).fetchone()
    if not row or time.time() - row["created_at"] > 600:
        raise HTTPException(410, "Попытка устарела")
    if check and await zvonok_status(row):
        with db() as con:
            con.execute("UPDATE verifications SET verified_at=? WHERE token=?", (int(time.time()), token))
        response = RedirectResponse("/cabinet", 303)
        response.set_cookie("aas_session", phone_signer().dumps({"phone": row["phone"]}), httponly=True, secure=True, samesite="lax", max_age=2592000)
        return response
    dial = html.escape(row["dial_phone"] or "номер, указанный в кампании Zvonok")
    return page("Подтверждение", f"<p>Позвоните со своего телефона на:</p><h2>{dial}</h2><p><small>Отвечать никто не будет. После звонка нажмите кнопку.</small></p><a class=btn href='/verify/{token}?check=1'>Я позвонил — проверить</a>")


async def wg_session():
    client = httpx.AsyncClient(base_url=os.environ["AWG_API_URL"], timeout=20)
    cached = auth_cache(refresh=True)
    client.cookies.set("wg-easy", make_wg_cookie(cached["user_id"]), path="/")
    return client


@app.get("/cabinet")
def cabinet(request: Request):
    phone = session_phone(request)
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE phone=? AND enabled=1", (phone,)).fetchone()
        devices = con.execute("SELECT * FROM devices WHERE phone=? ORDER BY id", (phone,)).fetchall()
    if not user:
        raise HTTPException(403)
    rows = "".join(f"<tr><td>{html.escape(x['name'])}</td><td><a class=btn href='/device/{x['id']}/qr'>QR</a> <a class=btn href='/device/{x['id']}/config'>Файл</a></td></tr>" for x in devices)
    create = "" if len(devices) >= user["device_limit"] else "<form method=post action=/device><input name=name maxlength=40 placeholder='Например, iPhone' required><button>Добавить устройство</button></form>"
    return page(f"Привет, {user['name']}", f"<p>Устройств: {len(devices)} из {user['device_limit']}</p><table>{rows}</table>{create}")


@app.post("/device")
async def create_device(request: Request, name: str = Form(...)):
    phone = session_phone(request)
    name = name.strip()[:40]
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE phone=? AND enabled=1", (phone,)).fetchone()
        count = con.execute("SELECT count(*) FROM devices WHERE phone=?", (phone,)).fetchone()[0]
    if not user or count >= user["device_limit"]:
        raise HTTPException(403, "Лимит устройств исчерпан")
    wg_name = f"portal-{phone[-4:]}-{secrets.token_hex(3)}-{name}"
    async with await wg_session() as client:
        response = await client.post("/api/client", json={"name": wg_name, "expiresAt": None})
        response.raise_for_status()
        clients = (await client.get("/api/client")).json()
    created = next(x for x in clients if x["name"] == wg_name)
    with db() as con:
        con.execute("INSERT INTO devices(phone,name,wg_client_id,created_at) VALUES(?,?,?,?)", (phone, name, str(created["id"]), int(time.time())))
    return RedirectResponse("/cabinet", 303)


def owned_device(request, device_id):
    phone = session_phone(request)
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=? AND phone=?", (device_id, phone)).fetchone()
    if not row:
        raise HTTPException(404)
    return row


@app.get("/device/{device_id}/config")
async def config(request: Request, device_id: int):
    row = owned_device(request, device_id)
    async with await wg_session() as client:
        data = (await client.get(f"/api/client/{row['wg_client_id']}/configuration")).content
    return Response(data, media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="vpn-{device_id}.conf"', "Cache-Control": "no-store"})


@app.get("/device/{device_id}/qr")
async def qr(request: Request, device_id: int):
    row = owned_device(request, device_id)
    async with await wg_session() as client:
        config = (await client.get(f"/api/client/{row['wg_client_id']}/configuration")).text
    image = qrcode.make(config)
    out = io.BytesIO(); image.save(out, format="PNG")
    return Response(out.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})


@app.get("/admin")
def admin(request: Request):
    require_admin(request)
    with db() as con:
        users = con.execute("SELECT * FROM users ORDER BY name").fetchall()
    rows = "".join(f"<tr><td>{html.escape(x['name'])}<br><small>{html.escape(x['phone'])}</small></td><td>{x['device_limit']}</td><td><form method=post action='/admin/toggle/{html.escape(x['phone'])}'><button>{'Отключить' if x['enabled'] else 'Включить'}</button></form></td></tr>" for x in users)
    return page("Доступ к VPN", f"<form method=post><input name=name placeholder='Имя' required><input name=phone type=tel placeholder='+79991234567' required><input name=device_limit type=number min=1 max=20 value=2 required><button>Добавить или обновить</button></form><table>{rows}</table>")


@app.post("/admin")
def admin_save(request: Request, name: str = Form(...), phone: str = Form(...), device_limit: int = Form(...)):
    require_admin(request)
    phone = phone_normalize(phone)
    if not 1 <= device_limit <= 20:
        raise HTTPException(400)
    with db() as con:
        con.execute("INSERT INTO users(phone,name,device_limit,enabled,created_at) VALUES(?,?,?,1,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name,device_limit=excluded.device_limit,enabled=1", (phone, name.strip()[:80], device_limit, int(time.time())))
    return RedirectResponse("/admin", 303)


@app.post("/admin/toggle/{phone}")
def admin_toggle(request: Request, phone: str):
    require_admin(request)
    phone = phone_normalize(phone)
    with db() as con:
        con.execute("UPDATE users SET enabled=1-enabled WHERE phone=?", (phone,))
    return RedirectResponse("/admin", 303)
