"""Administrator management using the portal's shared page components."""
import html
import io
import time

from fastapi import Form, HTTPException, Request
from fastapi.responses import Response
import pyotp
import qrcode

PATH = '/admin/administrators'


class AdministratorPages:
    def __init__(self, portal):
        self.portal = portal
        self.store = portal.auth_store

    def current(self, request):
        return self.portal.require_owner(request)

    @staticmethod
    def reauth_fields():
        return "<label>Ваш текущий пароль<input name=password type=password autocomplete=current-password required></label><label>Ваш код 2FA<input name=totp inputmode=numeric pattern='[0-9]{6}' maxlength=6 autocomplete=one-time-code></label>"

    def action_form(self, row, own):
        if own:
            options = [('password', 'Изменить пароль'), ('totp-start', 'Настроить 2FA'), ('totp-disable', 'Отключить 2FA')]
        else:
            toggle = 'Отключить' if row['enabled'] else 'Включить'
            options = [('reset', 'Сбросить пароль'), ('toggle', toggle), ('totp-reset', 'Сбросить 2FA')]
        if row['must_change'] and own:
            options = [('password', 'Изменить пароль')]
        select = ''.join(f'<option value="{value}">{label}</option>' for value, label in options)
        return f"""<form class=settings-form method=post action='{PATH}/{row['id']}'>
            <label>Действие<select name=action data-admin-action>{select}</select></label>
            <label data-admin-password>Новый пароль<input required name=new_password type=password minlength=12 maxlength=128 autocomplete=new-password></label>
            {self.reauth_fields()}<div class=form-actions><button>Сохранить</button></div></form>"""

    def administrators(self, request: Request):
        portal = self.portal
        store = self.store
        actor = self.current(request)
        if actor['must_change']:
            rows = [actor]
            introduction = '<p role=status>Задайте свой пароль перед продолжением работы.</p>'
        else:
            with store.db() as con:
                rows = con.execute("SELECT c.* FROM admins c WHERE EXISTS (SELECT 1 FROM accounts a JOIN grants g ON g.account_id=a.id WHERE a.admin_id=c.id AND g.scope!='self') ORDER BY c.id").fetchall()
            introduction = ''
        body = portal.admin_nav(PATH) + introduction
        for row in rows:
            own = row['id'] == actor['id']
            status = 'Включён' if row['enabled'] else 'Отключён'
            totp = '2FA включена' if row['totp_verified'] else '2FA не настроена'
            body += f"<section class=card><h2>{html.escape(row['username'])}{' · вы' if own else ''}</h2><p>{status} · {totp}</p>"
            body += self.action_form(row, own)
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
                {self.reauth_fields()}<div class=form-actions><button>Добавить администратора</button></div></form></section>"""
        body += '<script src=/assets/js/admin-auth.js></script>'
        return portal.page('Администраторы', body, show_header=True)

    def create(self, request: Request, username: str = Form(...), new_password: str = Form(...), password: str = Form(...), totp: str = Form('')):
        portal = self.portal
        store = self.store
        portal.require_admin(request)
        actor = self.current(request)
        try:
            portal.require_owner(request, fresh=True)
            store.throttle(actor['username'], request.client.host)
            with store.db() as con:
                store.verify(con, con.execute(portal.auth.ADMIN_QUERY, (actor['id'],)).fetchone(), password, totp)
            store.add(username, new_password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(PATH, 303)

    def totp_qr(self, request: Request):
        actor = self.current(request)
        portal.require_owner(request, fresh=True)
        if actor['must_change'] or not actor['pending_totp'] or time.time() - (actor['pending_at'] or 0) > 600:
            raise HTTPException(404)
        uri = pyotp.TOTP(actor['pending_totp']).provisioning_uri(actor['username'], issuer_name='AAS VPN')
        buffer = io.BytesIO()
        qrcode.make(uri).save(buffer, format='PNG')
        return Response(buffer.getvalue(), media_type='image/png')

    def confirm(self, request: Request, totp: str = Form(...)):
        portal = self.portal
        store = self.store
        portal.require_admin(request)
        try:
            store.confirm_totp(self.current(request)['id'], totp)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(portal.ADMIN_LOGIN_PATH, 303)

    def change(self, request: Request, admin_id: int, action: str = Form(...), password: str = Form(...), totp: str = Form(''), new_password: str = Form('')):
        portal = self.portal
        store = self.store
        actor = self.current(request)
        if actor['must_change'] and (admin_id != actor['id'] or action != 'password'):
            raise HTTPException(403, 'Сначала измените временный пароль')
        try:
            store.throttle(actor['username'], request.client.host)
            store.change(actor['id'], admin_id, action, password, totp, new_password)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return portal.RedirectResponse(PATH, 303)


def register(portal):
    pages = AdministratorPages(portal)
    portal.app.add_api_route(PATH, pages.administrators, methods=['GET'])
    portal.app.add_api_route(PATH, pages.create, methods=['POST'])
    portal.app.add_api_route(PATH + '/totp/qr', pages.totp_qr, methods=['GET'])
    portal.app.add_api_route(PATH + '/totp/confirm', pages.confirm, methods=['POST'])
    portal.app.add_api_route(PATH + '/{admin_id}', pages.change, methods=['POST'])
