"""Administrator management using the portal's shared page components."""
import html
import io
import time

from fastapi import Form, HTTPException, Request
from fastapi.responses import Response
import pyotp
import qrcode

PATH = '/admin/administrators'


def register(portal):
    app = portal.app
    store = portal.auth_store

    def current(request):
        row = store.session(request.cookies.get(portal.auth.COOKIE, ''))
        if not row:
            raise HTTPException(303, headers={'Location': portal.ADMIN_LOGIN_PATH})
        return row

    def reauth_fields():
        return "<label>Ваш текущий пароль<input name=password type=password autocomplete=current-password required></label><label>Ваш код 2FA<input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code></label>"

    def action_form(row, own):
        options = [('password', 'Изменить пароль'), ('totp-start', 'Настроить 2FA'), ('totp-disable', 'Отключить 2FA')] if own else [
            ('reset', 'Сбросить пароль'), ('toggle', 'Отключить' if row['enabled'] else 'Включить'), ('totp-reset', 'Сбросить 2FA')]
        if row['must_change'] and own:
            options = [('password', 'Изменить пароль')]
        select = ''.join(f'<option value="{value}">{label}</option>' for value, label in options)
        return f"""<form class=settings-form method=post action='{PATH}/{row['id']}'>
            <label>Действие<select name=action data-admin-action>{select}</select></label>
            <label data-admin-password>Новый пароль<input required name=new_password type=password minlength=12 maxlength=128 autocomplete=new-password></label>
            {reauth_fields()}<div class=form-actions><button>Сохранить</button></div></form>"""

    @app.get(PATH)
    def administrators(request: Request):
        actor = current(request)
        if actor['must_change']:
            rows = [actor]
            introduction = '<p role=status>Задайте свой пароль перед продолжением работы.</p>'
        else:
            with store.db() as con:
                rows = con.execute('SELECT * FROM admins ORDER BY id').fetchall()
            introduction = ''
        body = portal.admin_nav(PATH) + introduction
        for row in rows:
            own = row['id'] == actor['id']
            status = 'Включён' if row['enabled'] else 'Отключён'
            totp = '2FA включена' if row['totp_verified'] else '2FA не настроена'
            body += f"<section class=card><h2>{html.escape(row['username'])}{' · вы' if own else ''}</h2><p>{status} · {totp}</p>"
            body += action_form(row, own)
            if own and row['pending_totp'] and time.time() - (row['pending_at'] or 0) <= 600:
                body += f"""<p>Отсканируйте QR в приложении аутентификатора и введите полученный код.</p>
                    <img src='{PATH}/totp/qr' width=240 height=240 alt='QR настройки 2FA'>
                    <form class=device-form method=post action='{PATH}/totp/confirm'>
                    <label>Код 2FA<input name=totp inputmode=numeric pattern='[0-9]{{6}}' maxlength=6 required></label>
                    <button>Подтвердить</button></form>"""
            body += '</section>'
        if not actor['must_change']:
            body += f"""<section class=card><h2>Новый администратор</h2><form class=settings-form method=post action='{PATH}'>
                <label>Логин<input name=username maxlength=64 autocomplete=off required></label>
                <label>Временный пароль<input name=new_password type=password minlength=12 maxlength=128 autocomplete=new-password required></label>
                {reauth_fields()}<div class=form-actions><button>Добавить администратора</button></div></form></section>"""
        body += '<script src=/assets/js/admin-auth.js></script>'
        return portal.page('Администраторы', body, show_header=True)

    @app.post(PATH)
    def create(request: Request, username: str = Form(...), new_password: str = Form(...), password: str = Form(...), totp: str = Form('')):
        portal.require_admin(request)
        actor = current(request)
        try:
            store.throttle(actor['username'], request.client.host)
            with store.db() as con:
                store.verify(con, con.execute(portal.auth.ADMIN_QUERY, (actor['id'],)).fetchone(), password, totp)
            store.add(username, new_password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(PATH, 303)

    @app.get(PATH + '/totp/qr')
    def totp_qr(request: Request):
        actor = current(request)
        if actor['must_change'] or not actor['pending_totp'] or time.time() - (actor['pending_at'] or 0) > 600:
            raise HTTPException(404)
        uri = pyotp.TOTP(actor['pending_totp']).provisioning_uri(actor['username'], issuer_name='AAS VPN')
        buffer = io.BytesIO()
        qrcode.make(uri).save(buffer, format='PNG')
        return Response(buffer.getvalue(), media_type='image/png')

    @app.post(PATH + '/totp/confirm')
    def confirm(request: Request, totp: str = Form(...)):
        portal.require_admin(request)
        try:
            store.confirm_totp(current(request)['id'], totp)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(portal.ADMIN_LOGIN_PATH, 303)

    @app.post(PATH + '/{admin_id}')
    def change(request: Request, admin_id: int, action: str = Form(...), password: str = Form(...), totp: str = Form(''), new_password: str = Form('')):
        actor = current(request)
        if actor['must_change'] and (admin_id != actor['id'] or action != 'password'):
            raise HTTPException(403, 'Сначала измените временный пароль')
        try:
            store.throttle(actor['username'], request.client.host)
            store.change(actor['id'], admin_id, action, password, totp, new_password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(PATH, 303)
