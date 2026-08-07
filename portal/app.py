import html
import io
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager

import httpx
import pyotp
import qrcode
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer

app = FastAPI(docs_url=None, redoc_url=None)
DB = os.getenv("PORTAL_DB", "/data/portal.db")
signer = URLSafeTimedSerializer(os.environ["PORTAL_SESSION_SECRET"], salt="aas-portal")
ZVONOK = "https://zvonok.com/manager/cabapi_external/api/v1/phones"


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
        """)


def page(title, body):
    return HTMLResponse(f"""<!doctype html><html lang=ru><meta charset=utf-8>
<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title>
<style>body{{font:16px system-ui;max-width:620px;margin:40px auto;padding:0 18px;background:#101418;color:#eef}}
.card{{background:#1a2027;padding:24px;border-radius:18px}}input,button{{box-sizing:border-box;width:100%;padding:13px;margin:7px 0;border-radius:10px;border:1px solid #455;background:#111820;color:#fff}}
button,.btn{{background:#2478ff;border:0;cursor:pointer;text-decoration:none;display:inline-block;text-align:center;padding:13px;box-sizing:border-box;border-radius:10px;color:white}}small{{color:#aab}} table{{width:100%}}td{{padding:6px}}</style>
<main><h1>{html.escape(title)}</h1><div class=card>{body}</div></main></html>""")


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
        return signer.loads(raw, max_age=30 * 24 * 3600)["phone"]
    except BadSignature:
        raise HTTPException(401, "Войдите повторно")


def admin_ok(request):
    raw = request.cookies.get("aas_admin", "")
    try:
        return signer.loads(raw, max_age=12 * 3600).get("admin") is True
    except BadSignature:
        return False


def require_admin(request):
    if not admin_ok(request):
        raise HTTPException(401, "Сначала войдите в /admin/login")


@app.get("/admin/login")
def admin_login_form():
    return page("Вход администратора", "<form method=post><input name=username autocomplete=username placeholder='Логин' required><input name=password type=password autocomplete=current-password placeholder='Пароль' required><input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code placeholder='Код 2FA' required><button>Войти</button></form>")


@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...), totp: str = Form(...)):
    user_ok = secrets.compare_digest(username, os.getenv("PORTAL_ADMIN_USER", "admin"))
    password_ok = secrets.compare_digest(password, os.environ["PORTAL_ADMIN_PASSWORD"])
    secret = os.environ["PORTAL_ADMIN_TOTP_SECRET"].replace(" ", "")
    totp_ok = pyotp.TOTP(secret).verify(totp, valid_window=1)
    if not (user_ok and password_ok and totp_ok):
        raise HTTPException(401, "Неверный логин, пароль или код 2FA")
    response = RedirectResponse("/admin", 303)
    response.set_cookie("aas_admin", signer.dumps({"admin": True}), httponly=True, secure=True, samesite="strict", max_age=43200)
    return response


@app.post("/admin/logout")
def admin_logout():
    response = RedirectResponse("/admin/login", 303)
    response.delete_cookie("aas_admin")
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
    dial = str(result.get("confirm_phone") or result.get("phone_to_call") or result.get("verification_phone") or result.get("call_phone") or "")
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
        response.set_cookie("aas_session", signer.dumps({"phone": row["phone"]}), httponly=True, secure=True, samesite="lax", max_age=2592000)
        return response
    dial = html.escape(row["dial_phone"] or "номер, указанный в кампании Zvonok")
    return page("Подтверждение", f"<p>Позвоните со своего телефона на:</p><h2>{dial}</h2><p><small>Отвечать никто не будет. После звонка нажмите кнопку.</small></p><a class=btn href='/verify/{token}?check=1'>Я позвонил — проверить</a>")


async def wg_session():
    payload = {"username": os.environ["AWG_ADMIN_USERNAME"], "password": os.environ["AWG_ADMIN_PASSWORD"], "remember": False}
    totp = os.getenv("AWG_ADMIN_TOTP_SECRET")
    if totp:
        payload["totpCode"] = pyotp.TOTP(totp.replace(" ", "")).now()
    client = httpx.AsyncClient(base_url=os.environ["AWG_API_URL"], timeout=20)
    response = await client.post("/api/session", json=payload)
    response.raise_for_status()
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
