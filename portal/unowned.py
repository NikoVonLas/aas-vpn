"""Administrator-only access to imported clients without a telephone owner."""
import html
import re

from fastapi import Form, HTTPException, Request

PATH = '/admin/unowned'


def register(portal):
    async def clients(request):
        portal.require_admin(request)
        async with portal.wg_session() as api:
            response = await api.get('/clients')
            response.raise_for_status()
        with portal.db() as con:
            owned = {row[0] for row in con.execute('SELECT client_id FROM devices')}
        return [row for row in response.json() if str(row['id']) not in owned]

    async def find(request, client_id):
        if not re.fullmatch(r'[a-zA-Z0-9-]{1,64}', client_id):
            raise HTTPException(404)
        row = next((row for row in await clients(request) if str(row['id']) == client_id), None)
        if not row:
            raise HTTPException(404)
        return row

    @portal.app.get(PATH)
    async def listing(request: Request):
        rows = await clients(request)
        with portal.db() as con:
            users = con.execute('SELECT phone,name FROM users ORDER BY name').fetchall()
        options = ''.join(f'<option value="{html.escape(user["phone"], quote=True)}">{html.escape(user["name"])}</option>' for user in users)
        body = portal.admin_nav(PATH)
        if not rows:
            body += '<section class=card><p>Все устройства назначены пользователям.</p></section>'
        for row in rows:
            client_id = str(row['id'])
            body += f'<section class=card><h2>{html.escape(row["name"])}</h2><p>{html.escape(row["ipv4Address"])}</p>'
            body += f"""<form class=device-form method=post action='{PATH}/{client_id}/assign'>
                <label>Пользователь<select name=phone required>{options}</select></label><button>Сохранить</button></form>
                <p class=muted>Назначение учитывает лимит устройств пользователя.</p></section>"""
        return portal.page('Без владельца', body, show_header=True)

    @portal.app.post(PATH + '/{client_id}/assign')
    async def assign(request: Request, client_id: str, phone: str = Form(...)):
        row = await find(request, client_id)
        with portal.db() as con:
            con.execute('BEGIN IMMEDIATE')
            user = con.execute(portal.USER_BY_PHONE, (phone,)).fetchone()
            count = con.execute('SELECT count(*) FROM devices WHERE phone=?', (phone,)).fetchone()[0]
            if not user or count >= user['device_limit']:
                raise HTTPException(403, 'Лимит устройств исчерпан')
            if con.execute('SELECT 1 FROM devices WHERE client_id=?', (client_id,)).fetchone():
                raise HTTPException(409, 'Устройство уже назначено')
            con.execute('INSERT INTO devices(phone,name,client_id,created_at,vpn_ip,operation) VALUES(?,?,?,?,?,?)',
                        (phone, row['name'], client_id, int(portal.time.time()), row['ipv4Address'], 'applied' if row['applied'] else 'create'))
            portal.changed(con)
        return portal.RedirectResponse(f'/admin/users/{phone}/devices', 303)
