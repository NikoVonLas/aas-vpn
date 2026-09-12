"""Role, account and scoped routing pages built with shared portal components."""
import json
import sqlite3
import time
import uuid
from fastapi import Form, HTTPException, Request
from fastapi.responses import RedirectResponse
import identity
from routing import changed, normalize_rule
from views import render
from urllib.parse import urlencode

ROLES_PATH = '/admin/roles'
CREATE_ACCOUNT = 'accounts.create'
EDIT_ACCOUNT = 'accounts.edit'
ACCOUNT_LIMITS = 'accounts.limits'
ACCOUNT_STATE = 'accounts.state'
ACCOUNTS_PATH = '/admin'
ROUTING_LABEL = 'Маршрутизация'
DEVICES_LABEL = 'Устройства'
ACCOUNT_EXIT = 'account.exit'


METHODS = {method.value: label for method, label in (
    (identity.LoginMethod.PASSWORD, 'Логин и пароль'),
    (identity.LoginMethod.PHONE, 'Телефон'),
    (identity.LoginMethod.EMAIL, 'Почта'),
    (identity.LoginMethod.WEBAUTHN, 'Ключ / passkey'),
    (identity.LoginMethod.TOTP, 'Приложение-аутентификатор (TOTP)'),
)}

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

    def conflict(self, request: Request, _exc):
        return self.p.friendly_http_error(request, HTTPException(409, 'Данные уже используются или объект недоступен'))

    def roles(self, request: Request, edit: str=''):
        self.p.require_owner(request)
        self.p.admin_nav(ROLES_PATH)
        with self.p.auth_store.db() as con:
            rows = [self.role_model(row) for row in con.execute('SELECT * FROM roles ORDER BY protected DESC,name')]
            disabled = [METHODS[key] for key in sorted(identity.SECONDARY - identity.enabled_methods(con))]
        for row in rows:
            row['editor'] = self.role_editor(request, row, disabled)
        new = {'id': '', 'name': '', 'permissions': [], 'primary_methods': ['password'], 'secondary_methods': ['totp', 'webauthn'], 'require_2fa': 0, 'protected': 0}
        return self.p.page('Роли и доступ', render('roles.html', roles=rows, opened=edit,
                           new_editor=self.role_editor(request, new, disabled)), show_header=True)

    def role_model(self, row):
        result = dict(row)
        for field in ('permissions', 'primary_methods', 'secondary_methods'):
            result[field] = json.loads(result[field])
        result['primary_labels'] = [METHODS[key] for key in result['primary_methods']]
        return result

    def edit_role(self, request: Request, role_id: str=''):
        self.p.require_owner(request)
        role_id = 'administrator' if role_id == 'owner' else role_id
        if role_id:
            with self.p.auth_store.db() as con:
                if not con.execute('SELECT 1 FROM roles WHERE id=?', (role_id,)).fetchone():
                    raise HTTPException(404)
        return self.roles(request, edit=role_id or 'new')

    def role_editor(self, request, role, disabled):
        groups = {name: {} for name in ('Аккаунты', DEVICES_LABEL, ROUTING_LABEL, 'Инфраструктура')}
        for key, label in identity.ACTIONS.items():
            group = 'Инфраструктура'
            if key.startswith('accounts.'):
                group = 'Аккаунты'
            elif key.startswith('devices.'):
                group = DEVICES_LABEL
            elif 'routing' in key or key in {ACCOUNT_EXIT, 'device.exit'}:
                group = ROUTING_LABEL
            groups[group][key] = label
        submitted = getattr(request.state, 'form_draft', {}).get('role_id', [''])[0]
        action = '/admin/roles/save' if submitted == role['id'] else '/admin/roles/other'
        return render('components/role_form.html', form_action=action, role=role, groups=groups,
                      primary={key: METHODS[key] for key in sorted(identity.PRIMARY)}, methods=METHODS, disabled_methods=disabled)

    def save_role(self, request: Request, name: str=Form(...), role_id: str=Form(''), permissions: list[str]=Form([]), primary: list[str]=Form([]), secondary: list[str]=Form([]), required: str=Form(''), copy_role: str=Form('', alias='copy')):
        actor = self.p.require_owner(request, fresh=True)
        key = self.p.identities.save_role(actor['account_id'], '' if copy_role else role_id, name + (' — копия' if copy_role else ''), permissions, primary, secondary, bool(required))
        return RedirectResponse(f'{ROLES_PATH}/{key}/edit', 303)

    def assign(self, request: Request, account_id: str=Form(...), role_id: str=Form(''), scope: str=Form('self'), targets: list[str]=Form([]), remove: str=Form('')):
        actor = self.p.require_owner(request, fresh=True)
        with self.p.auth_store.db() as con:
            if not con.execute('SELECT 1 FROM accounts WHERE id=?', (account_id,)).fetchone():
                raise HTTPException(404)
        self.p.identities.assign(actor['account_id'], account_id, role_id, scope, targets, remove)
        return RedirectResponse(f'/accounts/{account_id}/edit', 303)

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
            account = con.execute('SELECT name,ru_exit_id FROM users WHERE account_id=?', (resource['account_id'],)).fetchone()
            account_default = account['ru_exit_id']
        path = f'/device/{key}/routing' if scope == 'device' else f'/accounts/{key}/routing'
        editable = self.p.identities.allowed(actor['account_id'], f'{scope}.routing.edit', resource['account_id'])
        managed = self.p.account_navigation(request, resource['account_id'])
        can_exit = scope == 'account' and self.p.identities.allowed(actor['account_id'], ACCOUNT_EXIT, resource['account_id'])
        values = lambda source: {target: rules_text(source, target) for target in ('ru', 'direct')}
        editor = render('components/routing_editor.html', path=path, values=values(rows), editable=editable,
                        can_exit=can_exit, exits=exits, selected_exit=resource['ru_exit_id'])
        names = {str(node['id']): node['name'] for node in exits}
        chain = 'Альтернативный выход аккаунта: ' + names.get(str(account_default), 'Глобальный выход') + ' → Глобальный: ' + names.get(default, '—')
        status = self.p.routing_status()
        actual = self.p.device_state_labels(resource, {int(k): v for k, v in names.items()}, account_default or int(default), status) if scope == 'device' else ''
        inherited_sources = [('Аккаунт', values(inherited))] if scope == 'device' else []
        inherited_sources.append(('Глобальные правила', values(global_rules)))
        crumbs = [('Пользователи', ACCOUNTS_PATH), (account['name'], f"/accounts/{resource['account_id']}/edit")] if managed else [('Мои устройства', '/cabinet')]
        if scope == 'device' and managed:
            crumbs.append((DEVICES_LABEL, f"/accounts/{resource['account_id']}"))
        crumbs.append((ROUTING_LABEL, ''))
        return self.p.page(ROUTING_LABEL, render('routing.html', level='Устройство' if scope == 'device' else 'Аккаунт',
                           owner=resource['name'], status=self.p.status_text(status), editor=editor,
                           crumbs=crumbs, chain=chain, actual=actual, inheritance=inherited_sources), show_header=True)

    def device_routes(self, request: Request, device_id: int):
        return self.routing_form(request, 'device', device_id)

    def account_routes(self, request: Request, account_id: str):
        return self.routing_form(request, 'account', account_id)

    def save_routes(self, request, scope, key, ru, direct, exit_id):
        resource = self.routing_model(request, scope, key)
        rules = parse_rules(ru, direct)
        if exit_id is not None:
            self.p.require_permission(request, ACCOUNT_EXIT, resource['account_id'])
        with self.p.db() as con:
            con.execute('BEGIN IMMEDIATE')
            existing = sorted(tuple(row) for row in con.execute('SELECT target,kind,value FROM scoped_routing_rules WHERE scope=? AND owner_id=?', (scope, str(key))))
            if rules != existing or exit_id is None:
                self.p.require_permission(request, f'{scope}.routing.edit', resource['account_id'])
            if exit_id and (not con.execute('SELECT 1 FROM ru_exits WHERE id=?', (exit_id,)).fetchone()):
                raise ValueError('Альтернативный выход не найден')
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

    def account_rows(self, actor):
        with self.p.identities.transaction() as con:
            rows = con.execute('''SELECT u.*,a.phone login_phone,a.email,c.username,
                (SELECT count(*) FROM portal.devices d WHERE d.account_id=u.account_id) device_count
                FROM portal.users u JOIN accounts a ON a.id=u.account_id
                LEFT JOIN admins c ON c.id=a.admin_id ORDER BY u.name,u.account_id''').fetchall()
            grants = con.execute('SELECT g.account_id,r.id,r.name FROM grants g JOIN roles r ON r.id=g.role_id').fetchall()
            rows = [dict(row) for row in rows if identity.allowed(con, actor['account_id'], 'accounts.view', row['account_id'])]
        for row in rows:
            row['role_ids'] = {g['id'] for g in grants if g['account_id'] == row['account_id']}
            row['roles'] = sorted({g['name'] for g in grants if g['account_id'] == row['account_id']})
        return rows, grants

    def accounts(self, request: Request, q: str='', state: str='', role: str='', page: int=1, edit: str=''):
        actor = self.p.current_account(request)
        self.p.admin_nav()
        rows, grants = self.account_rows(actor)
        visible = {row['account_id'] for row in rows}
        role_options = {g['id']: g['name'] for g in grants if g['account_id'] in visible}
        query = q.strip()[:254]
        rows = [row for row in rows if (not query or query.casefold() in ' '.join(str(row[key] or '') for key in ('name', 'username', 'login_phone', 'email')).casefold())
                and (not role or role in row['role_ids'])
                and (state not in {'enabled', 'disabled'} or bool(row['enabled']) == (state == 'enabled'))]
        total = len(rows)
        pages = max(1, (total + 24) // 25)
        current = min(max(1, page), pages)
        links = [(number, '/admin?' + urlencode({'q': query, 'state': state, 'role': role, 'page': number})) for number in range(1, pages + 1)]
        shown = rows[(current-1)*25:current*25]
        access = self.account_access_model() if self.p.identities.owner(actor['account_id']) else None
        for row in shown:
            row['editor'] = self.account_editor(actor, row, access)
        return self.p.page('Пользователи', render('accounts.html', rows=shown, total=total, opened=edit,
                           new_editor=self.new_account_editor() if self.p.identities.allowed(actor['account_id'], CREATE_ACCOUNT) else '',
                           device_count=sum(row['device_count'] for row in rows), query=query, state=state, selected_role=role,
                           role_options=role_options, current_page=current, pages=pages, page_links=links,
                           can_create=self.p.identities.allowed(actor['account_id'], CREATE_ACCOUNT)), show_header=True)

    def new_account_editor(self):
        with self.p.auth_store.db() as con:
            methods = set(json.loads(con.execute("SELECT primary_methods FROM roles WHERE id='user'").fetchone()[0])) & identity.enabled_methods(con)
        return render('components/account_form.html', form_action='/admin/accounts', row=None,
                      permissions={}, access=None, can_save=True, create_methods=methods)

    def new_account(self, request: Request):
        self.p.require_permission(request, CREATE_ACCOUNT)
        return self.accounts(request, edit='new')

    def edit_account(self, request: Request, account_id: str):
        actor = self.p.require_permission(request, 'accounts.view', account_id)
        rows, _ = self.account_rows(actor)
        index = next((index for index, row in enumerate(rows) if row['account_id'] == account_id), None)
        if index is None:
            raise HTTPException(404)
        return self.accounts(request, page=index // 25 + 1, edit=account_id)

    def account_editor(self, actor, row, access):
        account_id = row['account_id']
        permissions = {action: self.p.identities.allowed(actor['account_id'], action, account_id)
                       for action in (EDIT_ACCOUNT, ACCOUNT_LIMITS, ACCOUNT_STATE, 'devices.view', 'account.routing.view')}
        return render('components/account_form.html', form_action=f'/accounts/{account_id}/save', row=row, permissions=permissions,
                      access=self.account_roles(account_id, access) if access else None,
                      can_save=bool(access) or any(permissions[action] for action in (EDIT_ACCOUNT, ACCOUNT_LIMITS)))

    def account_access_model(self):
        with self.p.auth_store.db() as con:
            roles = {r['id']: r['name'] for r in con.execute('SELECT id,name FROM roles ORDER BY protected DESC,name')}
            grants = {}
            for row in con.execute('SELECT account_id,role_id FROM grants'):
                grants.setdefault(row['account_id'], set()).add(row['role_id'])
        return roles, grants

    def account_roles(self, key, access):
        roles, grants = access
        return render('components/account_roles.html', form_action=f'/accounts/{key}/save',
                      account_id=key, roles=roles, selected=grants.get(key, set()))

    def assign_account(self, request: Request, account_id: str, role_id: str=Form(''), scope: str=Form('self'), targets: list[str]=Form([]), remove: str=Form('')):
        return self.assign(request, account_id, role_id, scope, targets, remove)

    def create_account(self, request: Request, name: str=Form(...), username: str=Form(''), password: str=Form(''), device_limit: int=Form(2), phone: str=Form('')):
        actor = self.p.require_permission(request, CREATE_ACCOUNT)
        if not name.strip() or len(username) > 64 or (not 1 <= device_limit <= 20):
            raise ValueError('Проверьте имя, логин и лимит')
        key = str(uuid.uuid4())
        with self.p.identities.transaction() as con:
            credential, number = self.new_account_credentials(con, username, password, phone)
            con.execute('INSERT INTO accounts(id,admin_id,phone) VALUES(?,?,?)', (key, credential, number))
            identity.grant(con, key, 'user', role_based=True)
            con.execute('INSERT INTO portal.users(phone,account_id,name,device_limit,created_at) VALUES(?,?,?,?,?)', (key, key, name.strip()[:80], device_limit, int(time.time())))
            identity.ensure_login_paths(con)
            identity.audit(con, actor['account_id'], CREATE_ACCOUNT, key)
        return RedirectResponse(f'/accounts/{key}/edit', 303)

    def new_account_credentials(self, con, username, password, phone):
        methods = set(json.loads(con.execute("SELECT primary_methods FROM roles WHERE id='user'").fetchone()[0])) & identity.enabled_methods(con)
        credential = None
        number = self.p.phone_normalize(phone) if phone.strip() else None
        if number and 'phone' not in methods:
            raise ValueError('Телефонный вход не разрешён для пользователей')
        if username or password:
            if 'password' not in methods or not username.strip():
                raise ValueError('Логин и пароль не разрешены или логин не заполнен')
            self.p.auth_store.validate_password(password)
            credential = con.execute('INSERT INTO admins(username,password_hash,must_change) VALUES(?,?,1)',
                                     (username.strip(), self.p.password_hasher.hash(password))).lastrowid
        if not credential and not number:
            raise ValueError('Укажите разрешённый способ входа: телефон или логин и пароль')
        return credential, number

    def save_account(self, request: Request, account_id: str, name: str | None=Form(None), device_limit: int | None=Form(None), enabled: str=Form(''), state_present: str=Form(''), roles: list[str]=Form([]), roles_present: str=Form('')):
        actor = self.p.require_owner(request) if roles_present or roles else self.p.current_account(request)
        self.validate_account_changes(request, account_id, name, device_limit, state_present)
        with self.p.identities.transaction() as con:
            target = con.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not target:
                raise HTTPException(404)
            if identity.privileged(con, account_id) and (not identity.owner(con, actor['account_id'])):
                raise PermissionError('Только администратор управляет административными аккаунтами')
            if name is not None:
                con.execute('UPDATE portal.users SET name=? WHERE account_id=?', (name.strip()[:80], account_id))
            if device_limit is not None:
                con.execute('UPDATE portal.users SET device_limit=? WHERE account_id=?', (device_limit, account_id))
            if state_present:
                self.save_account_state(con, target, bool(enabled))
            if roles_present or roles:
                self.save_account_roles(con, actor, account_id, roles)
            identity.audit(con, actor['account_id'], 'accounts.save', account_id)
        return RedirectResponse(f'/accounts/{account_id}/edit', 303)

    def validate_account_changes(self, request, account_id, name, device_limit, state_present):
        for (present, action) in [(name is not None, EDIT_ACCOUNT), (device_limit is not None, ACCOUNT_LIMITS), (bool(state_present), ACCOUNT_STATE)]:
            if present:
                self.p.require_permission(request, action, account_id)
        if name is not None and (not name.strip()) or (device_limit is not None and (not 1 <= device_limit <= 20)):
            raise ValueError('Проверьте имя и лимит')

    def save_account_state(self, con, target, enabled):
        account_id = target['id']
        con.execute('UPDATE portal.users SET enabled=? WHERE account_id=?', (int(enabled), account_id))
        con.execute('UPDATE accounts SET enabled=? WHERE id=?', (int(enabled), account_id))
        con.execute('UPDATE admins SET enabled=? WHERE id=?', (int(enabled), target['admin_id']))
        identity.ensure_owner(con)
        if enabled:
            identity.ensure_login_paths(con)
        if bool(target['enabled']) != enabled:
            con.execute('DELETE FROM identity_sessions WHERE account_id=?', (account_id,))

    def set_account_state(self, request: Request, account_id: str, enabled: str=Form(...)):
        actor = self.p.current_account(request)
        self.p.require_permission(request, ACCOUNT_STATE, account_id)
        if enabled not in {'0', '1'}:
            raise ValueError('Неизвестное состояние аккаунта')
        with self.p.identities.transaction() as con:
            target = con.execute('SELECT * FROM accounts WHERE id=?', (account_id,)).fetchone()
            if not target:
                raise HTTPException(404)
            if identity.privileged(con, account_id) and not identity.owner(con, actor['account_id']):
                raise PermissionError('Только администратор управляет административными аккаунтами')
            self.save_account_state(con, target, enabled == '1')
            identity.audit(con, actor['account_id'], 'accounts.state', account_id)
        return RedirectResponse(f'/accounts/{account_id}/edit', 303)

    def save_account_roles(self, con, actor, account_id, roles):
        current = {r['role_id'] for r in con.execute('SELECT role_id FROM grants WHERE account_id=?', (account_id,))}
        if set(roles) != current:
            self.p.require_fresh(actor)
        identity.replace_roles(con, actor['account_id'], account_id, roles)

def register(portal):
    pages = AccessPages(portal)
    portal.app.add_exception_handler(PermissionError, pages.permission_error)
    portal.app.add_exception_handler(ValueError, pages.value_error)
    portal.app.add_exception_handler(sqlite3.IntegrityError, pages.conflict)
    portal.app.add_api_route(ROLES_PATH, pages.roles, methods=['GET'])
    portal.app.add_api_route('/admin/roles/save', pages.save_role, methods=['POST'])
    portal.app.add_api_route('/admin/roles/assign', pages.assign, methods=['POST'])
    portal.app.add_api_route('/accounts/new', pages.new_account, methods=['GET'])
    portal.app.add_api_route('/accounts/{account_id}/edit', pages.edit_account, methods=['GET'])
    portal.app.add_api_route('/admin/roles/new', pages.edit_role, methods=['GET'])
    portal.app.add_api_route('/admin/roles/{role_id}/edit', pages.edit_role, methods=['GET'])
    portal.app.add_api_route('/accounts/{account_id}', pages.account_page, methods=['GET'])
    portal.app.add_api_route('/device/{device_id}/routing', pages.device_routes, methods=['GET'])
    portal.app.add_api_route('/accounts/{account_id}/routing', pages.account_routes, methods=['GET'])
    portal.app.add_api_route('/device/{device_id}/routing', pages.save_device_routes, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/routing', pages.save_account_routes, methods=['POST'])
    portal.app.add_api_route(ACCOUNTS_PATH, pages.accounts, methods=['GET'])
    portal.app.add_api_route('/admin/accounts', pages.create_account, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/roles', pages.assign_account, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/save', pages.save_account, methods=['POST'])
    portal.app.add_api_route('/accounts/{account_id}/state', pages.set_account_state, methods=['POST'])
