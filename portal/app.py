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
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
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
const regionNames=typeof Intl.DisplayNames==='function'?new Intl.DisplayNames(['ru'],{type:'region'}):null;
const countryCodes='ad ae af ag ai al am ao ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug us uy uz va vc ve vg vi vn vu wf ws xk ye yt za zm zw'.split(' ');
const localizedCountries=Object.fromEntries(countryCodes.map(iso2=>{
  if(iso2==='xk')return [iso2,'Косово'];
  try{return [iso2,regionNames?.of(iso2.toUpperCase())||iso2.toUpperCase()]}catch{return [iso2,iso2.toUpperCase()]}
}));
const phoneWidgets=new WeakMap();
function initPhone(input){
  if(phoneWidgets.has(input))return;
  const iti=window.intlTelInput(input,{initialCountry:'ru',nationalMode:true,separateDialCode:true,formatAsYouType:true,strictMode:true,localizedCountries,i18n:{
selectedCountryAriaLabel:'Изменить страну, выбрана ${countryName} (${dialCode})',noCountrySelected:'Выберите страну',countryListAriaLabel:'Список стран',searchPlaceholder:'Поиск',clearSearchAriaLabel:'Очистить поиск',searchEmptyState:'Ничего не найдено',searchSummaryAria:(count)=>`Найдено: ${count}`
  }});
  phoneWidgets.set(input,iti);
  input.form?.addEventListener('submit',()=>{const normalized=iti.getNumber();if(input.dataset.target){document.getElementById(input.dataset.target).value=normalized||input.value}else{input.value=normalized||input.value}});
}
document.querySelectorAll('.phone-input').forEach(initPhone);
document.addEventListener('click',event=>{if(event.target.id==='add-dial-number'){
  const row=document.createElement('div');row.className='dial-number-row';
  row.innerHTML='<input class="phone-input" name="numbers" type="tel" autocomplete="off" inputmode="tel" placeholder="999 123-45-67" required><button type="button" class="secondary remove-number" aria-label="Удалить номер">Удалить</button>';
  document.getElementById('dial-numbers').append(row);initPhone(row.querySelector('input'));
}});
document.addEventListener('click',event=>{if(event.target.classList.contains('remove-number'))event.target.closest('.dial-number-row').remove()});
let adminSaving=false;
document.addEventListener('submit',async event=>{
  const form=event.target;
  const action=new URL(event.submitter?.formAction||form.action,location.href);
  if(adminSaving||action.origin!==location.origin||(!action.pathname.startsWith('/admin/')&&action.pathname!=='/admin')||action.pathname==='/admin/login'||action.pathname==='/admin/logout')return;
  event.preventDefault();adminSaving=true;
  const submitter=event.submitter;submitter?.setAttribute('disabled','');
  try{
    const response=await fetch(action,{method:(form.method||'post').toUpperCase(),body:new FormData(form)});
    if(!response.ok)throw new Error((await response.text())||`Ошибка ${response.status}`);
    const pageResponse=await fetch('/admin',{headers:{Accept:'text/html'}});
    if(!pageResponse.ok)throw new Error('Не удалось обновить данные');
    const documentNew=new DOMParser().parseFromString(await pageResponse.text(),'text/html');
    document.querySelector('main').replaceWith(documentNew.querySelector('main'));
    document.querySelectorAll('.phone-input').forEach(initPhone);
  }catch(error){alert(error.message)}finally{adminSaving=false;submitter?.removeAttribute('disabled')}
});
</script>""" if phone_widget else ""
    share_script = """<script>
const shareFiles=new WeakMap();
const shareProbe=typeof File==='function'?new File([''], 'settings.conf', {type:'text/plain'}):null;
if(navigator.share&&navigator.canShare&&shareProbe&&navigator.canShare({files:[shareProbe]})){
  document.querySelectorAll('.share-button').forEach(async button=>{
    try{
      const id=button.dataset.deviceId;
      const [configResponse,qrResponse]=await Promise.all([fetch(`/device/${id}/config`),fetch(`/device/${id}/qr`)]);
      if(!configResponse.ok||!qrResponse.ok)return;
      const configFile=new File([await configResponse.blob()],'settings.conf',{type:'text/plain'});
      const qrFile=new File([await qrResponse.blob()],'qr-code.png',{type:'image/png'});
      const both=[configFile,qrFile];
      shareFiles.set(button,navigator.canShare({files:both})?both:[configFile]);
      button.style.display='inline-flex';
    }catch{}
  });
}
document.addEventListener('click',event=>{
  const button=event.target.closest('.share-button');if(!button)return;
  const files=shareFiles.get(button);if(!files)return;
  button.disabled=true;
  navigator.share({title:button.dataset.deviceName,text:'Настройки подключения',files})
    .catch(error=>{if(error.name!=='AbortError')alert(error.message)})
    .finally(()=>button.disabled=false);
});
</script>"""
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
.dial-number-row{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px}} #dial-numbers{{display:grid;gap:10px}} .dial-save{{display:flex;justify-content:flex-end}}
.device-form{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:end;margin-top:16px}}
.device-actions{{display:flex;align-items:center;gap:7px;flex-wrap:wrap}} .device-actions form{{display:inline;margin:0}} .share-button{{display:none}}
.devices{{display:grid;gap:10px}} .device-card{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:12px;align-items:center;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--soft)}} .device-name{{font-weight:600;overflow-wrap:anywhere}}
.guide summary{{cursor:pointer;font-size:17px;font-weight:650;list-style-position:inside}} .guide[open] summary{{margin-bottom:18px}} .guide h3{{font-size:15px;margin:16px 0 8px}} .guide ol{{margin:0;padding:0;list-style-position:inside}} .guide li{{margin:0 0 8px;line-height:1.5}}
@media(min-width:721px) and (max-width:1920px){{
  .grid{{grid-template-columns:2fr 2fr 1fr}} .grid>button{{grid-column:1/-1;justify-self:end}}
  .user{{grid-template-columns:2fr 1.5fr 100px}} .user>.actions{{grid-column:1/-1;justify-content:flex-end}}
}}
@media(max-width:720px){{body{{padding-top:24px}} .grid,.user,.device-form,.device-card{{grid-template-columns:1fr}} .actions{{display:grid;grid-template-columns:1fr 1fr}} .actions button,.dial-save button,.device-form button{{width:100%}} .device-actions{{display:grid;grid-template-columns:1fr 1fr}} .device-actions>*{{width:100%}} .device-actions .btn,.device-actions button{{width:100%}}}}
@media(prefers-color-scheme:dark){{:root{{--bg:#171717;--card:#262626;--text:#f5f5f5;--muted:#a3a3a3;--line:#404040;--input:#171717;--soft:#303030}} .secondary{{background:#404040;color:#f5f5f5}} .secondary:hover{{background:#525252}} .device-count{{background:#404040;color:#d4d4d4}}}}
</style>
<main>{heading}{body}</main>{phone_script}{share_script}</html>""")


def phone_signer():
    with db() as con:
        secret = con.execute("SELECT value FROM settings WHERE key='session_secret'").fetchone()[0]
    return URLSafeTimedSerializer(secret, salt="aas-portal")


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
    return page("Вход", "<section class=card><p class=muted>Используйте учётную запись администратора.</p><form class=stack method=post><label>Логин<input name=username autocomplete=username placeholder=admin required></label><label>Пароль<input name=password type=password autocomplete=current-password placeholder='••••••••' required></label><label>Код 2FA<input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code placeholder=123456></label><label style='display:flex;grid-template-columns:auto 1fr;align-items:center'><input style='width:auto' type=checkbox name=remember value=1> Запомнить меня</label><button>Войти</button></form></section>")


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
    return page("", "<section class=card><form class=stack method=post action=/start><input class=phone-input data-target=phone-value type=tel autocomplete=tel inputmode=tel aria-label='Номер телефона' placeholder='999 123-45-67' required><input id=phone-value name=phone type=hidden><button>Продолжить</button></form></section>", phone_widget=True)


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
    public_key = os.getenv("ZVONOK_PUBLIC_KEY", "").strip()
    if not public_key:
        raise HTTPException(503, "Сервис подтверждения временно недоступен")
    token = secrets.token_urlsafe(24)
    data = {"public_key": public_key, "campaign_id": os.environ["ZVONOK_CAMPAIGN_ID"], "phone": phone}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(f"{ZVONOK}/confirm/", data=data)
            response.raise_for_status()
            result = response.json()
    except (httpx.HTTPStatusError, httpx.RequestError, ValueError):
        raise HTTPException(503, "Сервис подтверждения временно недоступен") from None
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
    success = {x.strip().lower() for x in os.getenv("ZVONOK_SUCCESS_STATUSES", "processed,success,confirmed,pincode_ok").split(",")}
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
async def verify(token: str):
    with db() as con:
        row = con.execute("SELECT * FROM verifications WHERE token=?", (token,)).fetchone()
    if not row or time.time() - row["created_at"] > 600:
        raise HTTPException(410, "Попытка устарела")
    dial = html.escape(row["dial_phone"] or "номер, указанный в кампании Zvonok")
    return page("Подтверждение", f"""<section class=card><p>Позвоните со своего телефона на:</p><h2>{dial}</h2><p class=muted>Робот ответит на звонок. После ответа звонок можно завершить — страница продолжит автоматически.</p><div id=call-status class=muted>Ожидаем подтверждение звонка…</div></section><script>
const statusNode=document.getElementById('call-status');
async function pollCall(){{
  try{{
    const response=await fetch('/verify/{token}/status',{{cache:'no-store'}});
    const result=await response.json();
    if(result.verified){{statusNode.textContent='Звонок подтверждён';location.replace('/cabinet');return}}
    statusNode.textContent='Ожидаем подтверждение звонка…';
  }}catch{{statusNode.textContent='Проверяем звонок…'}}
  setTimeout(pollCall,4000);
}}
setTimeout(pollCall,1500);
</script>""")


@app.get("/verify/{token}/status")
async def verify_status(token: str):
    with db() as con:
        row = con.execute("SELECT * FROM verifications WHERE token=?", (token,)).fetchone()
    if not row or time.time() - row["created_at"] > 600:
        raise HTTPException(410, "Попытка устарела")
    confirmed = bool(row["verified_at"])
    if not confirmed:
        try:
            confirmed = await zvonok_status(row)
        except (httpx.HTTPError, ValueError):
            confirmed = False
    if confirmed and not row["verified_at"]:
        with db() as con:
            con.execute("UPDATE verifications SET verified_at=? WHERE token=?", (int(time.time()), token))
    response = JSONResponse({"verified": confirmed}, headers={"Cache-Control": "no-store"})
    if confirmed:
        response.set_cookie("aas_session", phone_signer().dumps({"phone": row["phone"]}), httponly=True, secure=True, samesite="lax", max_age=2592000)
    return response


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
    rows = "".join(f"""<div class=device-card><div class=device-name>{html.escape(x['name'])}</div><div class=device-actions><a class=btn href='/device/{x['id']}/qr'>QR</a><a class=btn href='/device/{x['id']}/config'>Файл</a><button type=button class='secondary share-button' data-device-id='{x['id']}' data-device-name='{html.escape(x['name'], quote=True)}'>Поделиться</button><form method=post action='/device/{x['id']}/delete' onsubmit="return confirm('Удалить это устройство? Его настройки сразу перестанут работать.')"><button class=danger-soft>Удалить</button></form></div></div>""" for x in devices)
    create = "" if len(devices) >= user["device_limit"] else "<form class=device-form method=post action=/device><label>Название устройства<input name=name maxlength=40 placeholder='Вася Пупкин' required></label><button>Добавить устройство</button></form>"
    guide = """<details class='card guide'><summary>Как подключиться</summary><h3>1. Сначала на этом сайте</h3><ol><li>В поле <b>«Название устройства»</b> напишите любое понятное название, например <b>Вася Пупкин</b>.</li><li>Нажмите <b>«Добавить устройство»</b>. Ниже появятся кнопки QR и Файл.</li></ol><p class=muted>Название нужно только для удобства — можно написать что угодно.</p><h3>2. Затем в приложении</h3><ol><li>Установите <b>AmneziaWG</b> на телефон или компьютер, который хотите подключить.</li><li>Если сайт открыт на другом экране — нажмите <b>QR</b> и отсканируйте код через AmneziaWG.</li><li>Если сайт открыт на подключаемом устройстве — нажмите <b>Файл</b>, затем откройте скачанный файл через AmneziaWG.</li></ol></details>"""
    return page(f"Привет, {user['name']}", f"{guide}{create}<p>Устройств: {len(devices)} из {user['device_limit']}</p><div class=devices>{rows or '<div class=muted>Устройств пока нет.</div>'}</div>", show_header=True)


@app.post("/device")
async def create_device(request: Request, name: str = Form(...)):
    phone = session_phone(request)
    name = name.strip()[:40]
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE phone=? AND enabled=1", (phone,)).fetchone()
        count = con.execute("SELECT count(*) FROM devices WHERE phone=?", (phone,)).fetchone()[0]
    if not user or count >= user["device_limit"]:
        raise HTTPException(403, "Лимит устройств исчерпан")
    wg_base_name = f"{latin_slug(user['name'], 'user')}-{latin_slug(name, 'device')}"
    async with await wg_session() as client:
        clients = (await client.get("/api/client")).json()
        existing_names = {client["name"] for client in clients}
        wg_name = wg_base_name
        suffix = 2
        while wg_name in existing_names:
            wg_name = f"{wg_base_name[:61]}-{suffix}"
            suffix += 1
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


@app.post("/device/{device_id}/delete")
async def delete_device(request: Request, device_id: int):
    row = owned_device(request, device_id)
    async with await wg_session() as client:
        response = await client.delete(f"/api/client/{row['wg_client_id']}")
        if response.status_code != 404:
            response.raise_for_status()
    with db() as con:
        con.execute("DELETE FROM devices WHERE id=? AND phone=?", (device_id, row["phone"]))
    return RedirectResponse("/cabinet", 303)


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
      <label>Телефон<input class=phone-input name=phone type=tel autocomplete=off inputmode=tel value='{html.escape(x['phone'])}' required></label>
      <label><span class=label-row><span>Лимит</span><span class=device-count title='Выдано конфигураций'>{x['device_count']}/{x['device_limit']}</span></span><input name=device_limit type=number min=1 max=20 value='{x['device_limit']}' required></label>
      <div class=actions><button>Сохранить</button><button class='secondary{' danger-soft' if x['enabled'] else ''}' formaction='/admin/toggle/{html.escape(x['phone'])}'>{'Запретить выдачу' if x['enabled'] else 'Разрешить выдачу'}</button></div>
    </form>""" for x in users)
    number_fields = "".join(f"""<div class=dial-number-row><input class=phone-input name=numbers type=tel autocomplete=off inputmode=tel value='{html.escape(number)}' required><button type=button class='secondary remove-number'>Удалить</button></div>""" for number in dial_numbers())
    body = f"""
    <section class=card><div class=section-head><div><h2>Добавить человека</h2><div class=muted>Номер должен совпадать с номером входящего звонка.</div></div></div>
      <form class=grid method=post action=/admin/user><label>Имя<input name=name placeholder='Вася Пупкин' required></label><label>Телефон<input class=phone-input name=phone type=tel autocomplete=off inputmode=tel placeholder='999 123-45-67' required></label><label>Устройств<input name=device_limit type=number min=1 max=20 value=2 required></label><button>Добавить</button></form>
    </section>
    <section class=card><div class=section-head><div><h2>Разрешённые пользователи</h2><div class=muted>{len(users)} пользователей · изменения сохраняются отдельно для каждой строки</div></div></div><div class=users>{rows or '<div class=muted>Список пока пуст.</div>'}</div></section>
    <section class=card><div class=section-head><div><h2>Номера подтверждения Zvonok</h2><div class=muted>Выдаются последовательно по кругу.</div></div><button id=add-dial-number type=button class=secondary>Добавить номер</button></div><form class=stack method=post action=/admin/settings/dial-numbers><div id=dial-numbers>{number_fields}</div><div class=dial-save><button>Сохранить номера</button></div></form></section>
    <form method=post action=/admin/logout><button class='secondary'>Выйти</button></form>"""
    return page("Управление доступом", body, show_header=True, phone_widget=True)


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
def admin_dial_numbers(request: Request, numbers: list[str] = Form(...)):
    require_admin(request)
    normalized = [phone_normalize(value) for value in numbers if value.strip()]
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
