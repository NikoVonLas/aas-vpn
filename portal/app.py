import asyncio
import html
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
from datetime import datetime

import httpx
import auth
import qrcode
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.exceptions import RequestValidationError
from pathlib import Path
from routing import migrate, changed, parse_wireguard, normalize_rule, atomic_json, stored_config_text, store_config
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer

ADMIN_LOGIN_PATH = '/admin/login'
ADMINISTRATORS_PATH = '/admin/administrators'
ADMIN_PATH = '/admin'
CABINET_PATH = '/cabinet'
WG_CLIENT_PATH = '/clients'
USER_BY_PHONE = 'SELECT * FROM users WHERE phone=?'
ACTIVE_USER_BY_PHONE = 'SELECT * FROM users WHERE phone=? AND enabled=1'

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
ZVONOK = "https://zvonok.com/manager/cabapi_external/api/v1/phones"
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "")
auth_store = auth.Auth(os.getenv("AUTH_DB", str(Path(DB).with_name("auth.db"))))
password_hasher = auth.HASHER
RU_CONFIG_DIR = Path(os.getenv("RU_CONFIG_DIR", "/ru-configs"))
ROUTER_STATUS = Path(os.getenv("ROUTER_STATUS", "/routing-status/status.json"))
device_lock = asyncio.Lock()


async def validate_csrf(request, token):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not request.headers.get("content-length", "0").isdigit():
            return JSONResponse({"detail": "Некорректный размер запроса"}, 400)
        if int(request.headers.get("content-length", "0")) > 131072:
            return JSONResponse({"detail": "Форма слишком большая"}, 413)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Запрос с другого сайта запрещён"}, 403)
        # Double-submit token, host-only secure cookie; protect login/logout too.
        if len(await request.body()) > 131072:
            return JSONResponse({"detail": "Форма слишком большая"}, 413)
        form = await request.form()
        supplied = request.headers.get("X-CSRF-Token") or form.get("csrf_token", "")
        if not isinstance(supplied, str) or not request.cookies.get("__Host-aas_csrf") or not secrets.compare_digest(supplied, token):
            return JSONResponse({"detail": "Обновите страницу и повторите действие (CSRF)"}, 403)
        # BaseHTTPMiddleware must leave the original body available to FastAPI.
    return None


@app.middleware("http")
async def csrf_and_privacy(request, call_next):
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.url.path not in {'/admin/login', '/admin/logout'} and Path(DB).with_name('maintenance').exists():
        return JSONResponse({'detail': 'Сервис обновляется. Повторите действие через несколько минут'}, 503, headers={'Retry-After': '30'})
    token = request.cookies.get("__Host-aas_csrf") or secrets.token_urlsafe(32)
    error = await validate_csrf(request, token)
    if error is not None:
        return error
    response = await call_next(request)
    if response.headers.get("content-type", "").startswith("text/html"):
        data = b"".join([chunk async for chunk in response.body_iterator]).decode()
        field = f'<input type="hidden" name="csrf_token" value="{html.escape(token)}">'
        data = re.sub(r"(<form\b[^>]*>)", lambda m: m[0] + field, data, flags=re.I)
        cookies = response.headers.getlist("set-cookie")
        response = HTMLResponse(data, status_code=response.status_code,
                                headers={k: v for k, v in response.headers.items() if k.lower() not in {"content-length", "set-cookie"}})
        for cookie in cookies:
            response.headers.append("set-cookie", cookie)

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
    Path(DB).with_name('wg-auth.json').unlink(missing_ok=True)
    RU_CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def page(title, body, show_header=False, phone_widget=False):
    heading = f"<div class=topbar><div class=brand><span class=logo>A+</span><span>AAS VPN</span></div></div><h1>{html.escape(title)}</h1>" if show_header else ""
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
  const formatPasted=()=>{const normalized=iti.getNumber();if(normalized)iti.setNumber(normalized)};
  input.addEventListener('paste',()=>setTimeout(formatPasted,0));
  input.addEventListener('input',event=>{
    if(event.inputType==='insertFromPaste'||event.inputType==='insertReplacementText'){
      requestAnimationFrame(formatPasted);
    }
  });
  input.form?.addEventListener('submit',()=>{const normalized=iti.getNumber();if(input.dataset.target){document.getElementById(input.dataset.target).value=normalized||input.value}else{input.value=normalized||input.value}});
}
document.querySelectorAll('.phone-input').forEach(initPhone);
document.addEventListener('click',event=>{if(event.target.id==='add-dial-number'){
  const row=document.createElement('div');row.className='dial-number-row';
  row.innerHTML='<input class="phone-input" name="numbers" type="tel" autocomplete="off" inputmode="tel" placeholder="999 123-45-67" required><button type="button" class="secondary remove-number" aria-label="Удалить номер">Удалить</button>';
  document.getElementById('dial-numbers').append(row);initPhone(row.querySelector('input'));
}});
document.addEventListener('click',event=>{if(event.target.classList.contains('remove-number'))event.target.closest('.dial-number-row').remove()});
function formError(detail,status){
  if(typeof detail==='string')return detail;
  if(Array.isArray(detail)){
    const fields={name:'Имя',phone:'Телефон',device_limit:'Лимит устройств',numbers:'Номера',ru_exit_id:'RU-выход'};
    const messages=detail.filter(x=>x&&typeof x.msg==='string').map(x=>{
      const field=Array.isArray(x.loc)?x.loc.filter(v=>v!=='body').join('.'):'';
      return `${fields[field]||field}: ${x.msg}`;
    });
    if(messages.length)return messages.join('\\n');
  }
  return `Ошибка HTTP ${status}`;
}
let adminSaving=false;
document.addEventListener('submit',async event=>{
  const form=event.target;
  const action=new URL(event.submitter?.hasAttribute('formaction')?event.submitter.formAction:form.action,location.href);
  if(adminSaving||action.origin!==location.origin||(!action.pathname.startsWith('/admin/')&&action.pathname!=='/admin')||action.pathname==='/admin/login'||action.pathname==='/admin/logout')return;
  event.preventDefault();adminSaving=true;
  const submitter=event.submitter;submitter?.setAttribute('disabled','');
  try{
    const response=await fetch(action,{method:(form.method||'post').toUpperCase(),body:new FormData(form),headers:{'X-Requested-With':'fetch'}});
    if(response.redirected&&new URL(response.url).pathname==='/admin/login'){location.assign('/admin/login');return}
    if(!response.ok){const error=await response.json().catch(()=>null);throw new Error(formError(error?.detail,response.status))}
    const pageResponse=await fetch(location.pathname,{headers:{Accept:'text/html'}});
    if(pageResponse.redirected&&new URL(pageResponse.url).pathname==='/admin/login'){location.assign('/admin/login');return}
    if(!pageResponse.ok)throw new Error('Не удалось обновить данные');
    const documentNew=new DOMParser().parseFromString(await pageResponse.text(),'text/html');
    document.querySelector('main').replaceWith(documentNew.querySelector('main'));
    document.querySelectorAll('.phone-input').forEach(initPhone);
  }catch(error){alert(error.message)}finally{adminSaving=false;submitter?.removeAttribute('disabled')}
});
</script>""" if phone_widget else ""
    share_script = """<script>
const qrDialog=document.getElementById('qr-dialog');
const qrImage=document.getElementById('qr-image');
document.addEventListener('click',event=>{
  const button=event.target.closest('.qr-button');if(!button)return;
  if(qrDialog?.showModal){qrImage.src=button.dataset.qrUrl;qrDialog.showModal()}
  else{window.open(button.dataset.qrUrl,'_blank','noopener')}
});
qrDialog?.addEventListener('click',event=>{if(event.target===qrDialog)qrDialog.close()});
document.addEventListener('click',event=>{
  const button=event.target.closest('.delete-device');if(!button)return;
  const dialog=document.getElementById('delete-dialog');
  const form=document.getElementById('delete-form');
  form.action=button.dataset.deleteUrl;
  document.getElementById('delete-device-name').textContent=button.dataset.deviceName;
  if(dialog?.showModal)dialog.showModal();else if(confirm('Удалить это устройство?'))form.requestSubmit();
});
const shareFiles=new WeakMap();
const shareProbe=typeof File==='function'?new File([''], 'qr-code.png', {type:'image/png'}):null;
if(navigator.share&&navigator.canShare&&shareProbe&&navigator.canShare({files:[shareProbe]})){
  document.querySelectorAll('.share-button').forEach(async button=>{
    try{
      const id=button.dataset.deviceId;
      const qrResponse=await fetch(`/device/${id}/qr`);
      if(!qrResponse.ok)return;
      const qrFile=new File([await qrResponse.blob()],'qr-code.png',{type:'image/png'});
      shareFiles.set(button,[qrFile]);
      button.style.display='inline-flex';
    }catch{}
  });
}
document.addEventListener('click',event=>{
  const button=event.target.closest('.share-button');if(!button)return;
  const files=shareFiles.get(button);if(!files)return;
  button.disabled=true;
  navigator.share({files})
    .catch(error=>{if(error.name!=='AbortError')alert(error.message)})
    .finally(()=>button.disabled=false);
});
</script>"""
    return HTMLResponse(f"""<!doctype html><html lang=ru><meta charset=utf-8>
<script src=/assets/js/routing-status.js defer></script>
<script src=/assets/js/config-editor.js defer></script>
<meta name=viewport content='width=device-width,initial-scale=1'><title>{html.escape(title or 'Вход')}</title>{phone_head}
<link rel=stylesheet href=/assets/css/portal.css>
<main>{heading}{body}</main><dialog id=qr-dialog class=qr-dialog><img id=qr-image alt='QR-код подключения'><button type=button onclick="this.closest('dialog').close()">Закрыть</button></dialog><dialog id=delete-dialog class=confirm-dialog><form id=delete-form method=post><h2>Удалить устройство?</h2><p>Настройки <b id=delete-device-name></b> сразу перестанут работать.</p><div class=confirm-actions><button type=button class=secondary onclick="this.closest('dialog').close()">Отмена</button><button class=danger-soft>Удалить</button></div></form></dialog>{phone_script}{share_script}</html>""")


def phone_signer():
    return URLSafeTimedSerializer(auth_store.setting('phone_secret'), salt='aas-portal')


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
        phone = phone_signer().loads(raw, max_age=30 * 24 * 3600)["phone"]
    except BadSignature:
        raise HTTPException(303, headers={"Location": "/"})
    with db() as con:
        active = con.execute("SELECT 1 FROM users WHERE phone=? AND enabled=1", (phone,)).fetchone()
    if not active:
        raise HTTPException(303, headers={"Location": "/"})
    return phone


def admin_ok(request):
    row = auth_store.session(request.cookies.get(auth.COOKIE, ''))
    return bool(row and not row['must_change'])


def require_admin(request):
    row = auth_store.session(request.cookies.get(auth.COOKIE, ''))
    if not row:
        raise HTTPException(303, headers={"Location": ADMIN_LOGIN_PATH})
    if row['must_change']:
        raise HTTPException(303, headers={"Location": ADMINISTRATORS_PATH})


@app.exception_handler(HTTPException)
def friendly_http_error(request: Request, exc: HTTPException):
    location = (exc.headers or {}).get("Location")
    if 300 <= exc.status_code < 400 and location:
        return RedirectResponse(location, status_code=exc.status_code)
    detail = str(exc.detail or "Не удалось выполнить запрос")
    if request.url.path.endswith("/status") or request.headers.get("X-Requested-With") == "fetch":
        return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=exc.headers)
    if request.url.path.startswith(ADMIN_PATH):
        back_url, back_text = ADMIN_LOGIN_PATH, "Вернуться ко входу"
    elif request.url.path.startswith("/device") or request.url.path == CABINET_PATH:
        back_url, back_text = CABINET_PATH, "Вернуться в кабинет"
    else:
        back_url, back_text = "/", "Вернуться на главную"
    body = f"<section class=card><h1>Не получилось</h1><p>{html.escape(detail)}</p><a class=btn href='{back_url}'>{back_text}</a></section>"
    response = page("Ошибка", body)
    response.status_code = exc.status_code
    return response


@app.exception_handler(404)
def not_found_page(request: Request, exc):
    body = """<section class='card not-found'><div class=glitch data-text=404>404</div><h1>Страница не найдена</h1><p class=muted>Такого адреса нет или страница была перемещена.</p><a class=btn href=/>На главную</a></section>"""
    response = page("404", body)
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


@app.get(ADMIN_LOGIN_PATH, responses=HTTP_RESPONSES)
def admin_login_form():
    return page("Вход", "<section class=card><p class=muted>Используйте учётную запись администратора.</p><form class=stack method=post><label>Логин<input name=username autocomplete=username placeholder=admin required></label><label>Пароль<input name=password type=password autocomplete=current-password placeholder='••••••••' required></label><label>Код 2FA<input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code placeholder=123456></label><label class=check-label><input type=checkbox name=remember value=1> Запомнить меня</label><button>Войти</button></form></section>")


@app.post(ADMIN_LOGIN_PATH, responses=HTTP_RESPONSES)
def admin_login(request: Request, username: str = Form(...), password: str = Form(...), totp: str = Form(""), remember: str = Form("")):
    try:
        token, ttl = auth_store.login(username, password, totp, request.client.host, bool(remember))
    except ValueError as exc:
        raise HTTPException(401, str(exc)) from None
    session = auth_store.session(token)
    response = RedirectResponse(ADMINISTRATORS_PATH if session['must_change'] else ADMIN_PATH, 303)
    response.set_cookie(auth.COOKIE, token, path="/", httponly=True, secure=True, samesite="lax", max_age=ttl if remember else None)
    clear_legacy_cookies(response)
    return response


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


@app.get("/", response_class=HTMLResponse, responses=HTTP_RESPONSES)
def index():
    return page("", "<section class=card><form class=stack method=post action=/start><input class=phone-input data-target=phone-value type=tel autocomplete=tel inputmode=tel aria-label='Номер телефона' placeholder='999 123-45-67' required><input id=phone-value name=phone type=hidden><button>Продолжить</button></form></section>", phone_widget=True)


@app.post("/start", responses=HTTP_RESPONSES)
async def start(phone: str = Form(...)):
    phone = phone_normalize(phone)
    with db() as con:
        user = con.execute(ACTIVE_USER_BY_PHONE, (phone,)).fetchone()
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


def matching_call(result, row):
    candidates = []
    for call in call_records(result):
        if not isinstance(call, dict):
            continue
        activity = call_activity(call)
        if activity is not None and row["created_at"] - 5 <= activity <= row["created_at"] + 600:
            candidates.append((activity, call))
    if not candidates:
        return None
    _, result = min(candidates, key=lambda item: item[0])
    call_id = str(result.get("call_id") or result.get("id") or "")
    if call_id:
        with db() as con:
            con.execute("UPDATE verifications SET call_id=? WHERE token=? AND (call_id IS NULL OR call_id='')", (call_id, row["token"]))
    return result


def call_status_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("call_status", "status", "status_name"):
                yield str(item).lower()
            yield from call_status_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from call_status_values(item)


async def zvonok_status(row):
    params = {"public_key": os.environ["ZVONOK_PUBLIC_KEY"], "campaign_id": os.environ["ZVONOK_CAMPAIGN_ID"], "phone": row["phone"], "expand": 1}
    endpoint = "calls_by_phone/"
    if row["call_id"]:
        params.pop("campaign_id")
        params.pop("phone")
        params["call_id"] = row["call_id"]
        endpoint = "call_by_id/"
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(f"{ZVONOK}/{endpoint}", params=params)
        response.raise_for_status()
        result = response.json()
    if not row["call_id"]:
        result = matching_call(result, row)
    success = {x.strip().lower() for x in os.getenv("ZVONOK_SUCCESS_STATUSES", "processed,success,confirmed,pincode_ok").split(",")}
    return any(value in success for value in call_status_values(result))


@app.get("/verify/{token}", responses=HTTP_RESPONSES)
def verify(token: str):
    with db() as con:
        row = con.execute("SELECT * FROM verifications WHERE token=?", (token,)).fetchone()
    if not row or time.time() - row["created_at"] > 600:
        raise HTTPException(410, "Попытка устарела")
    dial_raw = row["dial_phone"] or ""
    if dial_raw:
        dial = html.escape(dial_raw)
        dial_href = html.escape(re.sub(r"[^+\d]", "", dial_raw), quote=True)
        dial_control = f"<p>Нажмите на номер, чтобы позвонить:</p><a class=btn href='tel:{dial_href}'>{dial}</a>"
    else:
        dial_control = "<p>Позвоните на номер, указанный в кампании Zvonok.</p>"
    return page("Подтверждение", f"""<section class=card>{dial_control}<p class=muted>Робот ответит на звонок. После ответа звонок можно завершить — страница продолжит автоматически.</p><div id=call-status class=muted>Ожидаем подтверждение звонка…</div></section><script>
const statusNode=document.getElementById('call-status');
async function pollCall(){{
  try{{
    const response=await fetch(location.pathname + '/status',{{cache:'no-store'}});
    const result=await response.json();
    if(result.verified){{statusNode.textContent='Звонок подтверждён';location.replace('/cabinet');return}}
    statusNode.textContent='Ожидаем подтверждение звонка…';
  }}catch{{statusNode.textContent='Проверяем звонок…'}}
  setTimeout(pollCall,4000);
}}
setTimeout(pollCall,1500);
</script>""")


@app.get("/verify/{token}/status", responses=HTTP_RESPONSES)
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


def wg_session():
    transport = httpx.AsyncHTTPTransport(uds=os.getenv('AWG_SOCKET', '/awg-control/control.sock'))
    return httpx.AsyncClient(base_url='http://controller', transport=transport, timeout=20)


@app.get(CABINET_PATH, responses=HTTP_RESPONSES)
def cabinet(request: Request, phone: str = ""):
    is_admin = admin_ok(request)
    if phone:
        require_admin(request)
    else:
        phone = session_phone(request)
    with db() as con:
        user = con.execute(USER_BY_PHONE, (phone,)).fetchone()
        devices = con.execute("SELECT * FROM devices WHERE phone=? ORDER BY id", (phone,)).fetchall()
    if not user:
        raise HTTPException(403)
    rows = device_routing_forms(devices, user, is_admin)
    create = "" if len(devices) >= user["device_limit"] else "<form class=device-form method=post action=/device><label>Название устройства<input name=name maxlength=40 placeholder='Телефон' required></label><button>Добавить устройство</button></form>"
    if is_admin:
        create = create.replace("action=/device>", f"action=/device><input type=hidden name=phone value=\"{html.escape(phone)}\">")
    guide = """<details class='card guide'><summary>Как подключиться</summary><h3>Скачать AmneziaWG</h3><div class=app-links><a href='https://play.google.com/store/apps/details?id=org.amnezia.awg' target=_blank rel=noopener>Android</a><a href='https://apps.apple.com/app/amneziawg/id6478942365' target=_blank rel=noopener>iPhone / iPad</a><a href='https://apps.apple.com/app/amneziawg/id6478942365' target=_blank rel=noopener>macOS</a><a href='https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest' target=_blank rel=noopener>Windows</a></div><h3>На сайте</h3><ul><li>Под этой инструкцией найдите поле <b>«Название устройства»</b>.</li><li>Напишите любое понятное название, например <b>Телефон</b>, и нажмите <b>«Добавить устройство»</b>.</li><li>Ниже появится карточка устройства с кнопками.</li></ul><h3>Если сайт открыт на телефоне или компьютере, на который нужно установить VPN</h3><ul><li>Установите <b>AmneziaWG</b> по подходящей ссылке выше.</li><li>В карточке устройства на этом сайте нажмите <b>«Файл»</b>.</li><li>Откройте AmneziaWG и нажмите кнопку добавления подключения.</li><li>Выберите импорт из файла, найдите скачанный файл настроек и откройте его.</li><li>Либо нажмите <b>«Поделиться QR»</b>, отправьте картинку на другое устройство и следуйте инструкции ниже.</li></ul><h3>Если сайт или отправленный QR открыт на другом устройстве</h3><ul><li>Установите и откройте <b>AmneziaWG</b> на подключаемом устройстве.</li><li>Нажмите в приложении кнопку добавления подключения и выберите сканирование QR-кода.</li><li>На другом устройстве откройте полученную картинку. Если там открыт сайт, нажмите <b>«QR»</b> в карточке устройства.</li><li>Отсканируйте появившийся код.</li></ul></details>"""
    guide = guide.replace("https://apps.apple.com/app/amneziawg/id6478942365' target=_blank rel=noopener>macOS", "macappstore://apps.apple.com/app/id6478942365'>macOS")
    guide = guide.replace("https://github.com/amnezia-vpn/amneziawg-windows-client/releases/latest' target=_blank rel=noopener>Windows", "/download/amneziawg/windows'>Windows")
    return page(f"Устройства: {user['name']}" if is_admin else f"Привет, {user['name']}", f"{admin_nav() if is_admin else ''}{guide}{create}<p>Устройств: {len(devices)} из {user['device_limit']}</p><div class=devices>{rows or '<div class=muted>Устройств пока нет.</div>'}</div>", show_header=True)


@app.get("/admin/users/{phone}/devices", responses=HTTP_RESPONSES)
def admin_devices(request: Request, phone: str):
    require_admin(request)
    return cabinet(request, phone)


@app.post("/device", responses=HTTP_RESPONSES)
async def create_device(request: Request, name: str = Form(...), phone: str = Form("")):
    if admin_ok(request) and phone:
        phone = phone_normalize(phone)
    else:
        phone = session_phone(request)
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
        con.execute("INSERT INTO devices(phone,name,client_id,created_at,operation) VALUES(?,?,?,?,'create')",
                    (phone, name, client_id, int(time.time())))
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


def owned_device(request, device_id):
    administrator = admin_ok(request)
    phone = None if administrator else session_phone(request)
    with db() as con:
        row = con.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
    if not row or (not administrator and row["phone"] != phone):
        raise HTTPException(404, "Устройство не найдено")
    return row


def device_redirect(request, phone):
    return RedirectResponse(f"/admin/users/{phone}/devices" if admin_ok(request) else CABINET_PATH, 303)


@app.post("/device/{device_id}/rename", responses=HTTP_RESPONSES)
def rename_device(request: Request, device_id: int, name: str = Form(...)):
    row = owned_device(request, device_id)
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
        raise HTTPException(403, "Смена RU-выхода запрещена администратором")
    if exit_id and not con.execute("SELECT 1 FROM ru_exits WHERE id=?", (exit_id,)).fetchone():
        raise HTTPException(400, "RU-выход не найден")


def save_exit_assignment(con, device_id, exit_id, administrator):
    con.execute("UPDATE devices SET ru_exit_id=?,assigned_by=? WHERE id=?",
                (exit_id or None, assignment_author(administrator) if exit_id else None, device_id))
    changed(con)


@app.post("/device/{device_id}/update", responses=HTTP_RESPONSES)
def update_device(request: Request, device_id: int, name: str = Form(...), ru_exit_id: int | None = Form(None)):
    row = owned_device(request, device_id)
    name = name.strip()[:40]
    if not name:
        raise HTTPException(400, NAME_REQUIRED)
    administrator = admin_ok(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if ru_exit_id is not None:
            validate_exit_assignment(con, row['phone'], administrator, ru_exit_id)
            current = con.execute('SELECT ru_exit_id FROM devices WHERE id=?', (device_id,)).fetchone()
            # Saving a name must not claim an unchanged administrator assignment.
            if current[0] != (ru_exit_id or None):
                save_exit_assignment(con, device_id, ru_exit_id, administrator)
        con.execute("UPDATE devices SET name=? WHERE id=?", (name, device_id))
    return device_redirect(request, row['phone'])


@app.post("/device/{device_id}/ru-exit", responses=HTTP_RESPONSES)
def assign_exit(request: Request, device_id: int, ru_exit_id: int = Form(0)):
    row = owned_device(request, device_id)
    administrator = admin_ok(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        validate_exit_assignment(con, row['phone'], administrator, ru_exit_id)
        save_exit_assignment(con, device_id, ru_exit_id, administrator)
    return device_redirect(request, row["phone"])


@app.post("/device/{device_id}/delete", responses=HTTP_RESPONSES)
async def delete_device(request: Request, device_id: int):
    row = owned_device(request, device_id)
    with db() as con:
        con.execute("UPDATE devices SET operation='delete' WHERE id=?", (device_id,))
    await process_device_operations()
    return device_redirect(request, row["phone"])


@app.get("/device/{device_id}/config", responses=HTTP_RESPONSES)
async def config(request: Request, device_id: int):
    row = owned_device(request, device_id)
    if row['operation'] != 'applied':
        raise HTTPException(409, 'Изменения устройства ещё применяются')
    async with wg_session() as client:
        response = await client.get(f"/clients/{row['client_id']}/configuration")
        response.raise_for_status()
        data = response.content
    filename = f"{latin_slug(row['name'], f'device-{device_id}')}.conf"
    disposition = f'attachment; filename="{filename}"'
    return Response(data, media_type="application/x-wireguard-profile", headers={"Content-Disposition": disposition, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/device/{device_id}/qr", responses=HTTP_RESPONSES)
async def qr(request: Request, device_id: int):
    row = owned_device(request, device_id)
    if row['operation'] != 'applied':
        raise HTTPException(409, 'Изменения устройства ещё применяются')
    async with wg_session() as client:
        response = await client.get(f"/clients/{row['client_id']}/configuration")
        response.raise_for_status()
        config = response.text
    image = qrcode.make(config)
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


@app.get(ADMIN_PATH, responses=HTTP_RESPONSES)
def admin(request: Request):
    require_admin(request)
    with db() as con:
        users = con.execute("SELECT u.*,count(d.id) device_count FROM users u LEFT JOIN devices d ON d.phone=u.phone GROUP BY u.phone ORDER BY u.name").fetchall()
    issued_total = sum(user["device_count"] for user in users)
    allowed_total = sum(user["device_limit"] for user in users)
    rows = "".join(f"""<form class=user method=post action=/admin/user>
      <input type=hidden name=original_phone value='{html.escape(x['phone'])}'>
      <label>Имя<input name=name maxlength=80 value='{html.escape(x['name'])}' required></label>
      <label>Телефон<input class=phone-input name=phone type=tel autocomplete=off inputmode=tel value='{html.escape(x['phone'])}' required></label>
      <label><span class=label-row><span>Лимит</span><span class=device-count title='Выдано конфигураций'>{x['device_count']}/{x['device_limit']}</span></span><input name=device_limit type=number min=1 max=20 value='{x['device_limit']}' required></label>
      <div class=user-footer><label class=check-label><input type=checkbox name=can_change_ru_exit value=1 {'checked' if x['can_change_ru_exit'] else ''}> Смена RU-выхода</label><div class=actions><a class='btn secondary' href='/admin/users/{html.escape(x['phone'])}/devices'>Устройства</a>
      <button class='secondary{' danger-soft' if x['enabled'] else ''}' formaction='/admin/toggle/{html.escape(x['phone'])}'>{'Запретить выдачу' if x['enabled'] else 'Разрешить выдачу'}</button><button>Сохранить</button></div></div>
    </form>""" for x in users)
    number_fields = "".join(f"""<div class=dial-number-row><input class=phone-input name=numbers type=tel autocomplete=off inputmode=tel value='{html.escape(number)}' required><button type=button class='secondary remove-number'>Удалить</button></div>""" for number in dial_numbers())
    body = f"""
    <section class=card><div class=section-head><div><h2>Добавить человека</h2><div class=muted>Номер должен совпадать с номером входящего звонка.</div></div></div>
      <form class=grid method=post action=/admin/user><label>Имя<input name=name placeholder='Вася Пупкин' required></label><label>Телефон<input class=phone-input name=phone type=tel autocomplete=off inputmode=tel placeholder='999 123-45-67' required></label><label>Устройств<input name=device_limit type=number min=1 max=20 value=2 required></label><button>Добавить</button></form>
    </section>
    <section class=card><div class=section-head><div><h2>Разрешённые пользователи</h2><div class=muted>{len(users)} пользователей · выдано {issued_total} из {allowed_total} конфигураций · изменения сохраняются отдельно для каждой строки</div></div></div><div class=users>{rows or '<div class=muted>Список пока пуст.</div>'}</div></section>
    <section class=card><div class=section-head><div><h2>Номера подтверждения Zvonok</h2><div class=muted>Выдаются последовательно по кругу.</div></div><button id=add-dial-number type=button class=secondary>Добавить номер</button></div><form class=stack method=post action=/admin/settings/dial-numbers><div id=dial-numbers>{number_fields}</div><div class=dial-save><button>Сохранить номера</button></div></form></section>
    <form method=post action=/admin/logout><button class='secondary'>Выйти</button></form>"""
    return page("Управление доступом", admin_nav() + body, show_header=True, phone_widget=True)


@app.post("/admin/user", responses=HTTP_RESPONSES)
@app.post(ADMIN_PATH, responses=HTTP_RESPONSES)
def admin_save(request: Request, name: str = Form(...), phone: str = Form(...), device_limit: int = Form(...), original_phone: str = Form(""), can_change_ru_exit: str = Form("")):
    require_admin(request)
    phone = phone_normalize(phone)
    original_phone = phone_normalize(original_phone) if original_phone else ""
    if not 1 <= device_limit <= 20:
        raise HTTPException(400)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if original_phone and original_phone != phone:
            if con.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
                raise HTTPException(409, "Новый номер уже используется")
            con.execute("UPDATE users SET phone=? WHERE phone=?", (phone, original_phone))
            con.execute("UPDATE devices SET phone=? WHERE phone=?", (phone, original_phone))
            con.execute("UPDATE verifications SET phone=? WHERE phone=?", (phone, original_phone))
        con.execute("INSERT INTO users(phone,name,device_limit,enabled,created_at) VALUES(?,?,?,1,?) ON CONFLICT(phone) DO UPDATE SET name=excluded.name,device_limit=excluded.device_limit", (phone, name.strip()[:80], device_limit, int(time.time())))
        con.execute("UPDATE users SET can_change_ru_exit=? WHERE phone=?", (int(can_change_ru_exit == "1"), phone))
        if can_change_ru_exit != "1":
            con.execute("UPDATE devices SET ru_exit_id=NULL,assigned_by=NULL WHERE phone=? AND assigned_by='user'", (phone,))
        changed(con)
    return RedirectResponse(ADMIN_PATH, 303)


@app.post("/admin/settings/dial-numbers", responses=HTTP_RESPONSES)
def admin_dial_numbers(request: Request, numbers: list[str] = Form(...)):
    require_admin(request)
    normalized = [phone_normalize(value) for value in numbers if value.strip()]
    if not 1 <= len(normalized) <= 20:
        raise HTTPException(400, "Укажите от 1 до 20 номеров")
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES('dial_numbers',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("\n".join(dict.fromkeys(normalized)),))
        con.execute("INSERT INTO settings(key,value) VALUES('dial_number_index','0') ON CONFLICT(key) DO UPDATE SET value='0'")
    return RedirectResponse(ADMIN_PATH, 303)


@app.post("/admin/toggle/{phone}", responses=HTTP_RESPONSES)
def admin_toggle(request: Request, phone: str):
    require_admin(request)
    phone = phone_normalize(phone)
    with db() as con:
        con.execute("UPDATE users SET enabled=1-enabled WHERE phone=?", (phone,))
    return RedirectResponse(ADMIN_PATH, 303)


@app.exception_handler(RequestValidationError)
def validation_error(request: Request, exc: RequestValidationError):
    # Never return validation inputs: upload/config fields may contain private keys.
    messages = {"missing": "Обязательное поле", "int_parsing": "Введите целое число", "int_type": "Введите целое число", "string_type": "Введите текст"}
    errors = [{"loc": x["loc"], "msg": messages.get(x["type"], x["msg"])} for x in exc.errors()]
    if request.headers.get('X-Requested-With') == 'fetch':
        return JSONResponse({'detail': errors}, 422)
    return friendly_http_error(request, HTTPException(422, '; '.join(f"{'.'.join(map(str, x['loc'][1:]))}: {x['msg']}" for x in errors)))


@app.exception_handler(httpx.HTTPError)
def upstream_error(request: Request, exc):
    return friendly_http_error(request, HTTPException(502, 'Сервис VPN временно недоступен'))


def admin_nav(active=ADMIN_PATH):
    links = [(ADMIN_PATH, 'Пользователи'), (RU_EXITS_PATH, 'RU-выходы'), (ROUTING_PATH, 'Маршрутизация'), (ADMINISTRATORS_PATH, 'Администраторы'), ('/admin/unowned', 'Без владельца')]
    return '<nav class="app-links admin-nav" aria-label="Администрирование">' + ''.join(
        f'<a href="{path}"' + (' aria-current="page"' if path == active else '') + f'>{label}</a>'
        for path, label in links) + '</nav>'


def routing_status():
    try:
        status = json.loads(ROUTER_STATUS.read_text())
        if time.time() - status.get('updated_at', 0) > 45:
            return {'state': 'stale', 'message': 'Контроллер не отвечает'}
        return status
    except (OSError, ValueError):
        return {'state': 'pending', 'message': 'Ожидание контроллера'}


def status_text(status):
    with db() as con:
        revision = int(con.execute("SELECT value FROM settings WHERE key='routing_revision'").fetchone()[0])
    if status.get('applied_revision') != revision and status.get('state') == 'applied':
        return 'Ожидает применения'
    return {'applied': 'Применено', 'error': 'Ошибка применения; сохранена рабочая конфигурация',
            'pending': 'Ожидание контроллера', 'stale': 'Контроллер не отвечает'}.get(status.get('state'), 'Ожидает применения')


def device_actions(device):
    device_id = device['id']
    if device['operation'] != 'applied':
        return '<p class=muted>Создание или удаление ожидает применения</p>'
    name = html.escape(device['name'], quote=True)
    return f"""<div class=device-actions>
      <button type=button class='secondary qr-button' data-qr-url='/device/{device_id}/qr'>QR</button>
      <a class='btn secondary' href='/device/{device_id}/config'>Файл</a>
      <button type=button class='secondary share-button' data-device-id='{device_id}' data-device-name='{name}'>Поделиться QR</button>
      <button type=button class='danger-soft delete-device' data-delete-url='/device/{device_id}/delete' data-device-name='{name}'>Удалить</button>
    </div>"""


def device_routing_forms(devices, user, administrator):
    with db() as con:
        exits = con.execute('SELECT id,name FROM ru_exits ORDER BY id').fetchall()
        default = int(con.execute(DEFAULT_EXIT_QUERY).fetchone()[0])
    names = {x['id']: x['name'] for x in exits}
    status = routing_status()
    result = f'<p class=muted data-routing-state>{html.escape(status_text(status))}</p>' if devices else ''
    for device in devices:
        selected = device['ru_exit_id']
        actual = status.get('devices', {}).get(str(device['id']), {})
        effective = names.get(actual.get('effective'), UNAVAILABLE_LABEL) if status.get('state') not in {'stale', 'pending'} else 'Неизвестно'
        assigned = names.get(selected, 'По умолчанию: ' + names.get(default, '—'))
        fallback = ' · резервный режим' if actual.get('fallback') else ''
        result += f"<section class='card device-card'><div class=device-head><h2>{html.escape(device['name'])}</h2>{device_actions(device)}</div><p data-device-state='{device['id']}'>Назначен: {html.escape(assigned)} · Используется: {html.escape(effective)}{fallback}</p>"
        if not device['vpn_ip']:
            result += '<p class=muted>Ожидает сопоставления VPN-IP</p>'
        if not device['native_enabled']:
            result += '<p class=muted>Устройство отключено или срок действия истёк</p>'
        result += device_edit_form(device, exits, administrator or user['can_change_ru_exit'])
        result += '</section>'
    return result


def device_edit_form(device, exits, can_change_exit):
    form = f"<form class='device-form {'device-edit' if can_change_exit else ''}' method=post action='/device/{device['id']}/update'><label>Название<input name=name maxlength=40 value='{html.escape(device['name'], quote=True)}' required></label>"
    if can_change_exit:
        options = '<option value="0">По умолчанию</option>' + ''.join(f"<option value='{node['id']}' {'selected' if node['id'] == device['ru_exit_id'] else ''}>{html.escape(node['name'])}</option>" for node in exits)
        form += f'<label>RU-выход<select name=ru_exit_id>{options}</select></label>'
    return form + '<button>Сохранить</button></form>'


def exit_health_label(status, node_id):
    state = status.get('exits', {}).get(str(node_id), {})
    if status.get('state') in {'pending', 'stale'} or not state:
        return 'Проверяется'
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
    require_admin(request)
    with db() as con:
        exits = con.execute('SELECT id,name,legacy,config_file FROM ru_exits ORDER BY id').fetchall()
        default = int(con.execute(DEFAULT_EXIT_QUERY).fetchone()[0])
    status = routing_status()
    body = admin_nav(RU_EXITS_PATH) + f'<p data-routing-state>{html.escape(status_text(status))}</p>'
    for node in exits:
        available = exit_health_label(status, node['id'])
        body += f"<section class=card><h2>{html.escape(node['name'])}{' · По умолчанию' if node['id'] == default else ''}</h2><p data-exit-state='{node['id']}'>{available}</p>"
        body += f"<form class=stack method=post enctype=multipart/form-data action='/admin/ru-exits/{node['id']}'><label>Название<input name=name maxlength=80 value='{html.escape(node['name'], quote=True)}' required></label>"
        config = html.escape(stored_config_text(RU_CONFIG_DIR, node['config_file']))
        body += f'<label>Заменить конфиг<input type=file name=config_upload accept=.conf></label><label>Конфиг<textarea name=config_text rows=8 autocomplete=off spellcheck=false placeholder="Загрузите файл или вставьте новый конфиг">{config}</textarea></label><p class="muted config-file-status" role=status>Редактируйте текст и нажмите «Сохранить». Настройки DNS применяются централизованно.</p>'
        body += f"<div class=exit-actions><button class=danger-soft formaction='/admin/ru-exits/{node['id']}/delete' formnovalidate>Удалить</button>"
        body += f"<button class=secondary formaction='/admin/ru-exits/{node['id']}/default' formnovalidate {'disabled' if node['id'] == default else ''}>По умолчанию</button><button>Сохранить</button></div></form></section>"
    body += '''<section class=card><h2>Добавить RU-выход</h2><form class=stack method=post enctype=multipart/form-data action=/admin/ru-exits><label>Название<input name=name maxlength=80 required></label><label>WireGuard .conf<input type=file name=config_upload accept=.conf></label><label>Конфиг<textarea name=config_text rows=8 autocomplete=off spellcheck=false></textarea></label><p class="muted config-file-status" role=status></p><p class=muted>Загрузите файл .conf или вставьте его текст. Настройки DNS применяются централизованно.</p><div class=form-submit><button>Добавить выход</button></div></form></section>'''
    return page('RU-выходы', body, show_header=True)


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
    require_admin(request)
    name = name.strip()[:80]
    if not name:
        raise HTTPException(400, NAME_REQUIRED)
    endpoint, config_text = await uploaded_endpoint(config_text, config_upload)
    with db() as con:
        con.execute(BEGIN_WRITE)
        old = con.execute('SELECT * FROM ru_exits WHERE id=?', (exit_id,)).fetchone() if exit_id else None
        if exit_id and not old:
            raise HTTPException(404, 'RU-выход не найден')
        if not old and not endpoint:
            raise HTTPException(400, 'Загрузите или вставьте WireGuard-конфиг')
        if not old and con.execute('SELECT count(*) FROM ru_exits').fetchone()[0] >= 64:
            raise HTTPException(400, 'Достигнут лимит 64 выходов')
        filename, legacy = updated_exit_config(old, endpoint, config_text)
        if old:
            con.execute('UPDATE ru_exits SET name=?,config_file=?,legacy=? WHERE id=?', (name, filename, legacy, exit_id))
        else:
            con.execute('INSERT INTO ru_exits(name,config_file) VALUES(?,?)', (name, filename))
        changed(con)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.post('/admin/ru-exits/{exit_id}/default', responses=HTTP_RESPONSES)
def default_ru_exit(request: Request, exit_id: int):
    require_admin(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if not con.execute('SELECT 1 FROM ru_exits WHERE id=?', (exit_id,)).fetchone():
            raise HTTPException(404, 'RU-выход не найден')
        con.execute("UPDATE settings SET value=? WHERE key='ru_default'", (str(exit_id),))
        changed(con)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.post('/admin/ru-exits/{exit_id}/delete', responses=HTTP_RESPONSES)
def delete_ru_exit(request: Request, exit_id: int):
    require_admin(request)
    with db() as con:
        con.execute(BEGIN_WRITE)
        if con.execute("SELECT 1 FROM settings WHERE key='ru_default' AND value=?", (str(exit_id),)).fetchone() or con.execute('SELECT 1 FROM devices WHERE ru_exit_id=?', (exit_id,)).fetchone():
            raise HTTPException(409, 'Сначала снимите назначения и выберите другой выход по умолчанию')
        con.execute('DELETE FROM ru_exits WHERE id=?', (exit_id,))
        changed(con)
    return RedirectResponse(RU_EXITS_PATH, 303)


@app.get(ROUTING_PATH, responses=HTTP_RESPONSES)
def routing_page(request: Request):
    require_admin(request)
    with db() as con:
        rules = con.execute('SELECT * FROM routing_rules ORDER BY value').fetchall()
    body = admin_nav(ROUTING_PATH) + f'<p data-routing-state>{html.escape(status_text(routing_status()))}</p><form class="stack routing-form" method=post action=/admin/routing>'
    for target, title in [('ru', 'Через RU'), ('direct', 'Через обычный выход')]:
        values = '\n'.join(('.' if x['kind'] == 'suffix' else '') + x['value'] for x in rules if x['target'] == target)
        body += f'<label class=card>{title}<textarea name={target} rows=12>{html.escape(values)}</textarea></label>'
    body += '<p class="muted routing-help">По одному правилу на строку: example.ru — точный домен; .example.ru — домен и поддомены; IPv4 или CIDR. Сначала проверяются домены от точного к общему, затем IP от узкой подсети к широкой. При равной точности побеждает обычный выход.</p><button>Сохранить правила</button></form>'
    return page('Маршрутизация', body, show_header=True)


@app.post(ROUTING_PATH, responses=HTTP_RESPONSES)
def save_routing(request: Request, ru: str = Form(''), direct: str = Form('')):
    require_admin(request)
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
        devices = con.execute('SELECT id,ru_exit_id FROM devices' + ('' if administrator else ' WHERE phone=?'), () if administrator else (phone,)).fetchall()
    device_states = {str(device['id']): device_state_labels(device, names, default, status) for device in devices}
    exits = {str(node_id): exit_health_label(status, node_id) for node_id in names} if administrator else {}
    return JSONResponse({'message': status_text(status), 'devices': device_states, 'exits': exits})


import admin_auth
import unowned
import sys
admin_auth.register(sys.modules[__name__])
unowned.register(sys.modules[__name__])
