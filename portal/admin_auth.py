"""Administrator management using the portal's shared page components."""
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

    def administrators(self, request: Request):
        self.current(request)
        return self.portal.RedirectResponse('/admin', 303)

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
