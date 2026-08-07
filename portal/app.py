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
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/assets", StaticFiles(directory="static"), name="assets")
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
        raise HTTPException(503, "Сервис авторизации временно недоступен")
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


def page(title, body, show_header=False, phone_widget=False):
    heading = f"<div class=topbar><div class=brand><span class=logo>W</span><span>AAS VPN · WG Easy</span></div></div><h1>{html.escape(title)}</h1>" if show_header else ""
    phone_head = '<link rel=stylesheet href=/assets/css/intlTelInput.min.css>' if phone_widget else ""
    phone_script = """<script src=/assets/js/intlTelInputWithUtils.min.js></script><script>
const phoneInput=document.getElementById('phone-input');
const phoneValue=document.getElementById('phone-value');
const phoneForm=document.getElementById('phone-form');
const regionNames=new Intl.DisplayNames(['ru'],{type:'region'});
const localizedCountries=Object.fromEntries(window.intlTelInput.getCountryData().map(({iso2})=>[iso2,regionNames.of(iso2.toUpperCase())]));
const iti=window.intlTelInput(phoneInput,{initialCountry:'ru',nationalMode:true,formatAsYouType:true,strictMode:true,localizedCountries,i18n:{
selectedCountryAriaLabel:'Изменить страну, выбрана ${countryName} (${dialCode})',noCountrySelected:'Выберите страну',countryListAriaLabel:'Список стран',searchPlaceholder:'Поиск',clearSearchAriaLabel:'Очистить поиск',searchEmptyState:'Ничего не найдено',searchSummaryAria:(count)=>`Найдено: ${count}`
}});
phoneForm.addEventListener('submit',()=>{const normalized=iti.getNumber();phoneValue.value=normalized||phoneInput.value;});
</script>""" if phone_widget else ""
    return HTMLResponse(f"""<!doctype html><html lang=ru><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title or 'Вход')}</title>{phone_head}
<style>
:root{{--bg:#f5f5f5;--card:#fff;--text:#262626;--muted:#737373;--line:#e5e5e5;--input:#fff;--red:#b91c1c;--red-hover:#991b1b;--soft:#f5f5f5}}
*{{box-sizing:border-box}} body{{font:15px Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;max-width:920px;margin:0 auto;padding:38px 18px 70px;background:var(--bg);color:var(--text)}}
h1{{font-size:30px;margin:0 0 22px;font-weight:650}} h2{{font-size:17px;margin:0 0 16px}} p{{line-height:1.55}} small,.muted{{color:var(--muted)}}
.card{{background:var(--card);padding:22px;border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 3px #0000000d;margin-bottom:16px}}
.grid{{display:grid;grid-template-columns:2fr 2fr 1fr auto;gap:10px;align-items:end}} .stack{{display:grid;gap:10px}} .section-head{{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}}
label{{display:grid;gap:6px;font-size:13px;color:var(--muted)}} input,textarea,select{{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #d4d4d4;background:var(--input);color:var(--text);font:inherit;outline:none}}
input:focus,textarea:focus{{border-color:var(--red);box-shadow:0 0 0 3px #b91c1c1a}} textarea{{resize:vertical;min-height:92px}}
button,.btn{{border:0;border-radius:8px;background:var(--red);color:#fff;font:inherit;font-size:14px;font-weight:600;padding:10px 14px;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;white-space:nowrap}}
button:hover,.btn:hover{{background:var(--red-hover)}} .secondary{{background:#e5e5e5;color:#262626}} .secondary:hover{{background:#d4d4d4}} .danger-soft{{background:#fee2e2;color:#991b1b}} .danger-soft:hover{{background:#fecaca}}
.users{{display:grid;gap:10px}} .user{{display:grid;grid-template-columns:2fr 1.5fr 100px auto;gap:10px;align-items:end;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}}
.actions{{display:flex;gap:7px}} .actions button{{padding:9px 11px}} .badge{{display:inline-flex;padding:4px 8px;border-radius:999px;font-size:12px;background:#dcfce7;color:#166534}} .badge.off{{background:#fee2e2;color:#991b1b}}
.label-row{{display:flex;align-items:center;justify-content:space-between;gap:6px;white-space:nowrap}} .device-count{{display:inline-flex;align-items:center;justify-content:center;min-width:28px;padding:2px 6px;border-radius:999px;background:#e5e5e5;color:#525252;font-size:11px;font-weight:650;line-height:16px}}
.topbar{{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px}} .brand{{display:flex;gap:10px;align-items:center;font-size:14px;color:var(--muted)}} .logo{{width:32px;height:32px;border-radius:50%;background:var(--red);display:grid;place-items:center;color:#fff;font-weight:800}}
.iti{{width:100%;--iti-country-selector-bg:var(--card);--iti-border-color:var(--line);--iti-hover-color:#b91c1c14;--iti-icon-color:var(--muted)}}
.iti input{{width:100%}} .iti__selected-country,.iti__selected-country-primary{{border-radius:7px 0 0 7px}} .iti__selected-country-primary{{padding-left:12px;padding-right:12px}}
.iti__selected-dial-code{{margin-left:6px;margin-right:5px}} .iti__country-selector{{background:var(--card);color:var(--text);border:1px solid var(--line)!important;border-radius:8px;box-shadow:0 8px 24px #0003;overflow:hidden}}
.iti__country-list{{background:var(--card);color:var(--text)}} .iti__country.iti__highlight{{background:#b91c1c14}} .iti__search-input{{background:var(--input);color:var(--text);border-radius:0}}
@media(max-width:720px){{body{{padding-top:24px}} .grid,.user{{grid-template-columns:1fr}} .actions{{display:grid;grid-template-columns:1fr 1fr}} .actions button{{width:100%}}}}
@media(prefers-color-scheme:dark){{:root{{--bg:#171717;--card:#262626;--text:#f5f5f5;--muted:#a3a3a3;--line:#404040;--input:#171717;--soft:#303030}} .secondary{{background:#404040;color:#f5f5f5}} .secondary:hover{{background:#525252}} .device-count{{background:#404040;color:#d4d4d4}}}}
</style>
<main>{heading}{body}</main>{phone_script}</html>""")


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
    numbers = dial_numbers()
    if not numbers:
        return ""
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT value FROM settings WHERE key='dial_number_index'").fetchone()
        index = int(row[0]) if row else 0
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str((index + 1) % len(numbers)),))
    return numbers[index % len(numbers)]


def dial_numbers():
    with db() as con:
        row = con.execute("SELECT value FROM settings WHERE key='dial_numbers'").fetchone()
    source = row[0] if row else os.getenv("ZVONOK_DIAL_NUMBERS", "")
    return [phone_normalize(value) for value in re.split(r"[,\n]+", source) if value.strip()]


@app.get("/admin/login")
def admin_login_form():
    return page("Вход", "<section class=card><p class=muted>Используйте учётную запись администратора.</p><form class=stack method=post><label>Логин<input name=username autocomplete=username required></label><label>Пароль<input name=password type=password autocomplete=current-password required></label><label>Код 2FA<input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code></label><label style='display:flex;grid-template-columns:auto 1fr;align-items:center'><input style='width:auto' type=checkbox name=remember value=1> Запомнить меня</label><button>Войти</button></form></section>")


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
    return page("", "<section class=card><form id=phone-form class=stack method=post action=/start><input id=phone-input type=tel autocomplete=tel inputmode=tel aria-label='Номер телефона' placeholder='Номер телефона' required><input id=phone-value name=phone type=hidden><button>Продолжить</button></form></section>", phone_widget=True)


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
    return page("Подтверждение", f"<section class=card><p>Позвоните со своего телефона на:</p><h2>{dial}</h2><p class=muted>Отвечать никто не будет. После звонка нажмите кнопку.</p><a class=btn href='/verify/{token}?check=1'>Я позвонил — проверить</a></section>")


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
    return page(f"Привет, {user['name']}", f"<p>Устройств: {len(devices)} из {user['device_limit']}</p><table>{rows}</table>{create}", show_header=True)


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
        users = con.execute("SELECT u.*,count(d.id) device_count FROM users u LEFT JOIN devices d ON d.phone=u.phone GROUP BY u.phone ORDER BY u.name").fetchall()
    rows = "".join(f"""<form class=user method=post action=/admin/user>
      <input type=hidden name=original_phone value='{html.escape(x['phone'])}'>
      <label>Имя<input name=name maxlength=80 value='{html.escape(x['name'])}' required></label>
      <label>Телефон<input name=phone type=tel value='{html.escape(x['phone'])}' required></label>
      <label><span class=label-row><span>Лимит</span><span class=device-count title='Выдано конфигураций'>{x['device_count']}/{x['device_limit']}</span></span><input name=device_limit type=number min=1 max=20 value='{x['device_limit']}' required></label>
      <div class=actions><button>Сохранить</button><button class='secondary{' danger-soft' if x['enabled'] else ''}' formaction='/admin/toggle/{html.escape(x['phone'])}'>{'Запретить выдачу' if x['enabled'] else 'Разрешить выдачу'}</button></div>
    </form>""" for x in users)
    numbers = "\n".join(dial_numbers())
    body = f"""
    <section class=card><div class=section-head><div><h2>Добавить человека</h2><div class=muted>Номер должен совпадать с номером входящего звонка.</div></div></div>
      <form class=grid method=post action=/admin/user><label>Имя<input name=name placeholder='Например, Мама' required></label><label>Телефон<input name=phone type=tel placeholder='+7 999 123-45-67' required></label><label>Устройств<input name=device_limit type=number min=1 max=20 value=2 required></label><button>Добавить</button></form>
    </section>
    <section class=card><div class=section-head><div><h2>Разрешённые пользователи</h2><div class=muted>{len(users)} пользователей · изменения сохраняются отдельно для каждой строки</div></div></div><div class=users>{rows or '<div class=muted>Список пока пуст.</div>'}</div></section>
    <section class=card><div class=section-head><div><h2>Номера подтверждения Zvonok</h2><div class=muted>Выдаются последовательно по кругу.</div></div></div><form class=stack method=post action=/admin/settings/dial-numbers><label>По одному номеру в строке<textarea name=numbers required>{html.escape(numbers)}</textarea></label><div><button>Сохранить номера</button></div></form></section>
    <form method=post action=/admin/logout><button class='secondary'>Выйти</button></form>"""
    return page("Управление доступом", body, show_header=True)


@app.post("/admin/user")
@app.post("/admin")
def admin_save(request: Request, name: str = Form(...), phone: str = Form(...), device_limit: int = Form(...), original_phone: str = Form("")):
    require_admin(request)
    phone = phone_normalize(phone)
    original_phone = phone_normalize(original_phone) if original_phone else ""
    if not 1 <= device_limit <= 20:
        raise HTTPException(400)
    with db() as con:
        if original_phone and original_phone != phone:
            if con.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
                raise HTTPException(409, "Новый номер уже используется")
            con.execute("UPDATE users SET phone=? WHERE phone=?", (phone, original_phone))
            con.execute("UPDATE devices SET phone=? WHERE phone=?", (phone, original_phone))
            con.execute("UPDATE verifications SET phone=? WHERE phone=?", (phone, original_phone))
        con.execute("INSERT INTO users(phone,name,device_limit,enabled,created_at) VALUES(?,?,?,1,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name,device_limit=excluded.device_limit", (phone, name.strip()[:80], device_limit, int(time.time())))
    return RedirectResponse("/admin", 303)


@app.post("/admin/settings/dial-numbers")
def admin_dial_numbers(request: Request, numbers: str = Form(...)):
    require_admin(request)
    normalized = [phone_normalize(value) for value in re.split(r"[,\n]+", numbers) if value.strip()]
    if not 1 <= len(normalized) <= 20:
        raise HTTPException(400, "Укажите от 1 до 20 номеров")
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES('dial_numbers',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("\n".join(dict.fromkeys(normalized)),))
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index','0') ON CONFLICT(key) DO UPDATE SET value='0'")
    return RedirectResponse("/admin", 303)


@app.post("/admin/toggle/{phone}")
def admin_toggle(request: Request, phone: str):
    require_admin(request)
    phone = phone_normalize(phone)
    with db() as con:
        con.execute("UPDATE users SET enabled=1-enabled WHERE phone=?", (phone,))
    return RedirectResponse("/admin", 303)
