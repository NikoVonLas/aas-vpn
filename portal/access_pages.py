"""Role, account and scoped routing pages built with shared portal components."""
import html
import json
import sqlite3
import time
import uuid
from fastapi import Form, HTTPException, Request
from fastapi.responses import RedirectResponse
import identity
from routing import changed, normalize_rule

def esc(value):
    return html.escape(str(value or ''), quote=True)

def choices(name, catalog, selected):
    return ''.join((f'''<label class=check-label><input type=checkbox name={name} value="{esc(key)}" {('checked' if key in selected else '')}> {esc(label)}</label>''' for (key, label) in catalog.items()))
METHODS = {'password': 'Логин и пароль', 'phone': 'Телефон', 'email': 'Почта', 'webauthn': 'Ключ / passkey', 'totp': 'TOTP'}

def parse_rules(ru, direct):
    rules = set()
    for (target, text) in [('ru', ru), ('direct', direct)]:
        if len(text) > 50000 or len(text.splitlines()) > 2000:
            raise ValueError('Слишком большой список правил')
        for line in text.splitlines():
            if line.strip():
                rules.add((target, *normalize_rule(line)))
    return sorted(rules)

def rules_text(rows, target):
    return '\n'.join((('.' if row['kind'] == 'suffix' else '') + row['value'] for row in rows if row['target'] == target))

class AccessPages:

    def __init__(self, portal):
        self.p = portal

    def permission_error(self, request: Request, exc):
        return self.p.friendly_http_error(request, HTTPException(403, str(exc)))

    def value_error(self, request: Request, exc):
        return self.p.friendly_http_error(request, HTTPException(400, str(exc)))

    def conflict(self, request: Request, exc):
        return self.p.friendly_http_error(request, HTTPException(409, 'Данные уже используются или объект недоступен'))

    def roles(self, request: Request):
        self.p.require_owner(request)
        with self.p.auth_store.db() as con:
            rows = con.execute('SELECT * FROM roles ORDER BY protected DESC,name').fetchall()
            grants = con.execute('SELECT g.* FROM grants g JOIN accounts a ON a.id=g.account_id JOIN roles r ON r.id=g.role_id LEFT JOIN admins c ON c.id=a.admin_id ORDER BY COALESCE(c.username,a.phone,a.id),r.name,g.scope').fetchall()
            accounts = con.execute('SELECT a.id,a.phone,c.username FROM accounts a LEFT JOIN admins c ON c.id=a.admin_id').fetchall()
            targets = {g['id']: [r[0] for r in con.execute('SELECT account_id FROM grant_targets WHERE grant_id=?', (g['id'],))] for g in grants}
        names = {r['id']: r['name'] for r in rows}
        account_names = {a['id']: a['username'] or a['phone'] or a['id'] for a in accounts}
        body = self.p.admin_nav('/admin/roles') + '<p class=muted>Права и способы входа всех ролей складываются. Отзыв права сохраняет маршруты и назначения.</p>'
        for row in [*rows, {'id': '', 'name': '', 'permissions': '[]', 'primary_methods': '["password"]', 'secondary_methods': '["totp","webauthn"]', 'require_2fa': 0, 'protected': 0}]:
            body += f"<section class=card><details {('open' if not row['id'] else '')}><summary>{esc(row['name']) or 'Новая роль'}</summary>"
            body += f'''<form class=stack method=post action=/admin/roles/save><input type=hidden name=role_id value="{esc(row['id'])}">'''
            body += f'''<label>Название<input name=name maxlength=80 value="{esc(row['name'])}" required></label>'''
            body += '<details><summary>Права</summary>' + choices('permissions', identity.ACTIONS, json.loads(row['permissions'])) + '</details>'
            body += '<fieldset><legend>Основные способы входа</legend>' + choices('primary', {k: METHODS[k] for k in sorted(identity.PRIMARY)}, json.loads(row['primary_methods'])) + '</fieldset>'
            body += '<fieldset><legend>Вторые способы</legend>' + choices('secondary', METHODS, json.loads(row['secondary_methods'])) + '</fieldset>'
            body += f"<label class=check-label><input type=checkbox name=required value=1 {('checked' if row['require_2fa'] else '')}> Обязательная 2FA</label><div class=form-actions>"
            if row['id']:
                body += '<button class=secondary name=copy value=1>Создать копию</button>'
            body += '<button>Сохранить</button>'
            body += '</div></form></details></section>'
        account_options = ''.join((f'<option value="{esc(key)}">{esc(name)}</option>' for (key, name) in account_names.items()))
        role_options = ''.join((f'<option value="{esc(key)}">{esc(name)}</option>' for (key, name) in names.items()))
        body += f"<section class=card><h2>Назначения</h2><form class=stack method=post action=/admin/roles/assign><label>Аккаунт<select name=account_id>{account_options}</select></label><label>Роль<select name=role_id>{role_options}</select></label><label>Область<select name=scope><option value=self>Свой аккаунт</option><option value=selected>Выбранные аккаунты</option><option value=global>Глобально</option></select></label><fieldset><legend>Выбранные аккаунты (только для этой области)</legend>{choices('targets', account_names, [])}</fieldset><button>Добавить назначение</button></form></section>"
        for g in grants:
            scope = {'self': 'Свой аккаунт', 'selected': 'Выбранные аккаунты', 'global': 'Глобально'}[g['scope']]
            selected = ', '.join((account_names.get(key, key) for key in targets[g['id']]))
            body += f'''<section class=card><p>{esc(account_names[g['account_id']])} · {esc(names[g['role_id']])} · {scope} {esc(selected)}</p><form method=post action=/admin/roles/assign><input type=hidden name=account_id value="{g['account_id']}"><input type=hidden name=remove value="{g['id']}"><button class=danger-soft>Отозвать назначение</button></form></section>'''
        return self.p.page('Роли и доступ', body, show_header=True)

    def save_role(self, request: Request, name: str=Form(...), role_id: str=Form(''), permissions: list[str]=Form([]), primary: list[str]=Form([]), secondary: list[str]=Form([]), required: str=Form(''), copy_role: str=Form('', alias='copy')):
        actor = self.p.require_owner(request, fresh=True)
        self.p.identities.save_role(actor['account_id'], '' if copy_role else role_id, name + (' — копия' if copy_role else ''), permissions, primary, secondary, bool(required))
        return RedirectResponse('/admin/roles', 303)

    def assign(self, request: Request, account_id: str=Form(...), role_id: str=Form(''), scope: str=Form('self'), targets: list[str]=Form([]), remove: str=Form('')):
        actor = self.p.require_owner(request, fresh=True)
        self.p.identities.assign(actor['account_id'], account_id, role_id, scope, targets, remove)
        return RedirectResponse('/admin/roles', 303)

    def account_page(self, request: Request, account_id: str):
        self.p.require_permission(request, 'devices.view', account_id)
        with self.p.db() as con:
            user = con.execute('SELECT phone FROM users WHERE account_id=?', (account_id,)).fetchone()
        if not user:
            raise HTTPException(404)
        return self.p.cabinet(request, user['phone'])

    def routing_model(self, request, scope, key, write=False):
        action = f"{scope}.routing.{('edit' if write else 'view')}"
        if scope == 'device':
            resource = self.p.owned_device(request, int(key), action)
        else:
            self.p.require_permission(request, action, key)
            with self.p.db() as con:
                resource = con.execute('SELECT * FROM users WHERE account_id=?', (key,)).fetchone()
        if not resource:
            raise HTTPException(404)
        return resource

    def routing_form(self, request, scope, key):
        resource = self.routing_model(request, scope, key)
        actor = self.p.current_account(request)
        with self.p.db() as con:
            rows = con.execute('SELECT * FROM scoped_routing_rules WHERE scope=? AND owner_id=?', (scope, str(key))).fetchall()
            global_rules = con.execute('SELECT * FROM routing_rules').fetchall()
            inherited = con.execute("SELECT * FROM scoped_routing_rules WHERE scope='account' AND owner_id=?", (resource['account_id'],)).fetchall() if scope == 'device' else []
            exits = con.execute('SELECT id,name FROM ru_exits').fetchall()
            default = con.execute("SELECT value FROM settings WHERE key='ru_default'").fetchone()[0]
            account_default = con.execute('SELECT ru_exit_id FROM users WHERE account_id=?', (resource['account_id'],)).fetchone()[0]
        path = f'/device/{key}/routing' if scope == 'device' else f'/accounts/{key}/routing'
        editable = self.p.identities.allowed(actor['account_id'], f'{scope}.routing.edit', resource['account_id'])
        body = self.p.admin_nav('/admin/routing') if self.p.admin_ok(request) else '<p><a href=/cabinet>Устройства</a> · <a href=/security>Безопасность профиля</a></p>'
        body += f'''<section class=card><h2>{esc(resource['name'])}</h2><p>Приоритет: устройство → аккаунт → глобальные правила.</p><p data-routing-state>{esc(self.p.status_text(self.p.routing_status()))}</p><form class=stack method=post action="{path}">'''
        for (target, label) in [('ru', 'Через RU'), ('direct', 'Основной VPS')]:
            body += f"<label>{label}<textarea name={target} rows=8 {('readonly' if not editable else '')}>{esc(rules_text(rows, target))}</textarea></label>"
        can_exit = scope == 'account' and self.p.identities.allowed(actor['account_id'], 'account.exit', resource['account_id'])
        if can_exit:
            options = '<option value=0>Глобальный дефолт</option>' + ''.join((f"<option value={node['id']} {('selected' if node['id'] == resource['ru_exit_id'] else '')}>{esc(node['name'])}</option>" for node in exits))
            body += f'<label>RU-выход аккаунта<select name=ru_exit_id>{options}</select></label>'
        if editable or can_exit:
            body += '<button>Сохранить</button>'
        body += '</form></section>'
        names = {str(node['id']): node['name'] for node in exits}
        body += f"<section class=card><h2>Наследование</h2><p>RU-дефолт аккаунта: {esc(names.get(str(account_default), 'Глобальный'))} · Глобальный: {esc(names.get(default, '—'))}</p>"
        for (label, source) in [('Аккаунт', inherited), ('Глобальные', global_rules)]:
            body += f'<details><summary>{label}</summary>'
            for (target, caption) in [('ru', 'Через RU'), ('direct', 'Основной VPS')]:
                body += f"<h3>{caption}</h3><pre>{esc(rules_text(source, target)) or 'Пусто'}</pre>"
            body += '</details>'
        return self.p.page('Маршрутизация', body + '</section>', show_header=True)

    def device_routes(self, request: Request, device_id: int):
        return self.routing_form(request, 'device', device_id)

    def account_routes(self, request: Request, account_id: str):
        return self.routing_form(request, 'account', account_id)

    def save_routes(self, request, scope, key, ru, direct, exit_id):
        resource = self.routing_model(request, scope, key)
        rules = parse_rules(ru, direct)
        if exit_id is not None:
            self.p.require_permission(request, 'account.exit', resource['account_id'])
        with self.p.db() as con:
            con.execute('BEGIN IMMEDIATE')
            existing = sorted(tuple(row) for row in con.execute('SELECT target,kind,value FROM scoped_routing_rules WHERE scope=? AND owner_id=?', (scope, str(key))))
            if rules != existing or exit_id is None:
                self.p.require_permission(request, f'{scope}.routing.edit', resource['account_id'])
            if exit_id and (not con.execute('SELECT 1 FROM ru_exits WHERE id=?', (exit_id,)).fetchone()):
                raise ValueError('RU-выход не найден')
            con.execute('DELETE FROM scoped_routing_rules WHERE scope=? AND owner_id=?', (scope, str(key)))
            con.executemany('INSERT INTO scoped_routing_rules VALUES(?,?,?,?,?)', [(scope, str(key), *rule) for rule in rules])
            if exit_id is not None:
                con.execute('UPDATE users SET ru_exit_id=? WHERE account_id=?', (exit_id or None, key))
            changed(con)
        return RedirectResponse(f'/device/{key}/routing' if scope == 'device' else f'/accounts/{key}/routing', 303)

    def save_device_routes(self, request: Request, device_id: int, ru: str=Form(''), direct: str=Form('')):
        return self.save_routes(request, 'device', device_id, ru, direct, None)

    def save_account_routes(self, request: Request, account_id: str, ru: str=Form(''), direct: str=Form(''), ru_exit_id: int | None=Form(None)):
        return self.save_routes(request, 'account', account_id, ru, direct, ru_exit_id)

    def accounts(self, request: Request):
        actor = self.p.current_account(request)
        with self.p.identities.transaction() as con:
            rows = con.execute('SELECT u.*,a.phone login_phone,c.username,\n                (SELECT count(*) FROM portal.devices d WHERE d.account_id=u.account_id) device_count\n                FROM portal.users u JOIN accounts a ON a.id=u.account_id LEFT JOIN admins c ON c.id=a.admin_id ORDER BY u.name').fetchall()
        rows = [r for r in rows if self.p.identities.allowed(actor['account_id'], 'accounts.view', r['account_id'])]
        body = self.p.admin_nav() + f"<p>{len(rows)} аккаунтов · устройств: {sum((r['device_count'] for r in rows))}</p>"
        is_owner = self.p.identities.owner(actor['account_id'])
        if self.p.identities.allowed(actor['account_id'], 'accounts.create'):
            body += '<section class=card><h2>Новый аккаунт</h2><form class=settings-form method=post action=/admin/accounts><label>Имя<input name=name maxlength=80 required></label><label>Логин<input name=username maxlength=64 required></label><label>Временный пароль<input name=password type=password minlength=12 maxlength=128 required autocomplete=new-password></label><label>Лимит устройств<input name=device_limit type=number min=1 max=20 value=2 required></label><button>Добавить аккаунт</button></form></section>'
        for row in rows:
            key = row['account_id']
            body += f"<section class=card><h2>{esc(row['name'])}</h2><p>{esc(row['username'] or row['login_phone'])} · {row['device_count']}/{row['device_limit']} устройств</p><form class=settings-form method=post action=/accounts/{key}/save>"
            for (field, caption, action) in [('name', 'Имя', 'accounts.edit'), ('device_limit', 'Лимит устройств', 'accounts.limits')]:
                if self.p.identities.allowed(actor['account_id'], action, key):
                    body += f'<label>{caption}<input name={field} value="{esc(row[field])}" required></label>'
            if self.p.identities.allowed(actor['account_id'], 'accounts.state', key):
                body += f"<label class=check-label><input type=checkbox name=enabled value=1 {('checked' if row['enabled'] else '')}> Аккаунт включён</label><input type=hidden name=state_present value=1>"
            body += '<div class=form-actions>'
            if self.p.identities.allowed(actor['account_id'], 'devices.view', key):
                body += f'<a class="btn secondary" href=/accounts/{key}>Устройства</a>'
            if self.p.identities.allowed(actor['account_id'], 'account.routing.view', key):
                body += f'<a class="btn secondary" href=/accounts/{key}/routing>Маршрутизация</a>'
            if any((self.p.identities.allowed(actor['account_id'], action, key) for action in ('accounts.edit', 'accounts.limits', 'accounts.state'))):
                body += '<button>Сохранить</button>'
            body += '</div></form>'
            if is_owner:
                body += f'<form method=post action=/admin/accounts/{key}/recovery><button class=secondary>Выдать одноразовое восстановление</button></form>'
            body += '</section>'
        body += '<form method=post action=/admin/logout><button class=secondary>Выйти</button></form>'
        return self.p.page('Аккаунты', body, show_header=True, phone_widget=True)

    def create_account(self, request: Request, name: str=Form(...), username: str=Form(...), password: str=Form(...), device_limit: int=Form(2)):
        actor = self.p.require_permission(request, 'accounts.create')
        self.p.auth_store.validate_password(password)
        if not name.strip() or not username.strip() or len(username) > 64 or (not 1 <= device_limit <= 20):
            raise ValueError('Проверьте имя, логин и лимит')
        key = str(uuid.uuid4())
        with self.p.identities.transaction() as con:
            credential = con.execute('INSERT INTO admins(username,password_hash,must_change) VALUES(?,?,1)', (username.strip(), self.p.password_hasher.hash(password))).lastrowid
            con.execute('INSERT INTO accounts(id,admin_id) VALUES(?,?)', (key, credential))
            identity.grant(con, key, 'user')
            con.execute('INSERT INTO portal.users(phone,account_id,name,device_limit,created_at) VALUES(?,?,?,?,?)', (key, key, name.strip()[:80], device_limit, int(time.time())))
            identity.audit(con, actor['account_id'], 'accounts.create', key)
        return RedirectResponse('/admin', 303)

    def save_account(self, request: Request, account_id: str, name: str | None=Form(None), device_limit: int | None=Form(None), enabled: str=Form(''), state_present: str=Form('')):
        actor = self.p.current_account(request)
        for (present, action) in [(name is not None, 'accounts.edit'), (device_limit is not None, 'accounts.limits'), (bool(state_present), 'accounts.state')]:
            if present:
                self.p.require_permission(request, action, account_id)
        if name is not None and (not name.strip()) or (device_limit is not None and (not 1 <= device_limit <= 20)):
            raise ValueError('Проверьте имя и лимит')
        with self.p.identities.transaction() as con:
            target = con.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not target:
                raise HTTPException(404)
            privileged = con.execute("SELECT 1 FROM grants WHERE account_id=? AND scope!='self'", (account_id,)).fetchone()
            if privileged and (not identity.owner(con, actor['account_id'])):
                raise PermissionError('Только владелец управляет административными аккаунтами')
            if name is not None:
                con.execute('UPDATE portal.users SET name=? WHERE account_id=?', (name.strip()[:80], account_id))
            if device_limit is not None:
                con.execute('UPDATE portal.users SET device_limit=? WHERE account_id=?', (device_limit, account_id))
            if state_present:
                con.execute('UPDATE portal.users SET enabled=? WHERE account_id=?', (int(bool(enabled)), account_id))
                con.execute('UPDATE accounts SET enabled=? WHERE id=?', (int(bool(enabled)), account_id))
                identity.ensure_owner(con)
                if target['enabled'] != int(bool(enabled)):
                    con.execute('DELETE FROM identity_sessions WHERE account_id=?', (account_id,))
            identity.audit(con, actor['account_id'], 'accounts.save', account_id)
        return RedirectResponse('/admin', 303)

def register(portal):
    pages = AccessPages(portal)
    portal.app.add_exception_handler(PermissionError, pages.permission_error)
    portal.app.add_exception_handler(ValueError, pages.value_error)
    portal.app.add_exception_handler(sqlite3.IntegrityError, pages.conflict)
    portal.app.add_api_route('/admin/roles', pages.roles, methods=['GET'])
    portal.app.add_api_route('/admin/roles/save', pages.save_role, methods=['POST'])
    portal.app.add_api_route('/admin/roles/assign', pages.assign, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}', pages.account_page, methods=['GET'])
    portal.app.add_api_route('/device/{device_id}/routing', pages.device_routes, methods=['GET'])
    portal.app.add_api_route('/accounts/{account_id}/routing', pages.account_routes, methods=['GET'])
    portal.app.add_api_route('/device/{device_id}/routing', pages.save_device_routes, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/routing', pages.save_account_routes, methods=['POST'])
    portal.app.add_api_route('/admin', pages.accounts, methods=['GET'])
    portal.app.add_api_route('/admin/accounts', pages.create_account, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/save', pages.save_account, methods=['POST'])
