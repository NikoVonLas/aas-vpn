"""Presentation regressions: scope, atomicity, escaping and safe return paths."""
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from conftest import admin_login, phone_login, post
from test_identity import accounts, give
from views import environment, local_path, render


def test_every_page_template_has_a_visual_coverage_decision():
    root = Path(__file__).resolve().parents[1]
    registry = json.loads((root / 'tests/ui/screens.json').read_text())
    covered = set(registry['existing']) | set(registry['shared'])
    covered.update(template for state in registry['states'] for template in state.get('templates', []))
    pages = {path.name for path in (root / 'portal/templates').glob('*.html')}
    assert pages == covered
    for name in environment.list_templates():
        environment.get_template(name)


@pytest.mark.parametrize('value', ['//example.test/path', 'https://example.test', '/\\example.test', '/\n/path', 'relative', '///example.test'])
def test_return_path_rejects_external_or_ambiguous_urls(value):
    assert local_path(value) == '/cabinet'


def test_autoescape_data_and_attribute_boundaries():
    result = render('components/device_form.html', device=dict(id=1, name='\"><script>alert(1)</script>', ru_exit_id=None), exits=[], can_change_exit=True, can_rename=True)
    assert '<script>' not in result
    assert '&lt;script&gt;' in result
    assert '&#34;' in result


def test_account_editor_is_scoped_and_search_cannot_leak_other_accounts(portal):
    app, client = portal
    owner, first, second = accounts(app)
    give(app, first, 'observer', 'selected', [second])
    phone_login(app, client)
    page = client.get('/admin?q=admin').text
    assert 'Аккаунты не найдены' in page
    assert '/accounts/' + owner + '/edit' not in page
    assert client.get('/accounts/' + owner + '/edit').status_code == 404
    assert client.get('/accounts/' + second + '/edit').status_code == 200
    assert 'RU-выходы' not in client.get('/admin').text
    assert 'Способы входа' not in client.get('/admin').text


def test_account_filter_pagination_and_invalid_save_are_atomic(portal):
    app, client = portal
    admin_login(app, client)
    key = accounts(app)[1]
    with app.identities.transaction() as con:
        for index in range(30):
            new = f'fixture-{index}'
            con.execute('INSERT INTO accounts(id,phone) VALUES(?,?)', (new, f'+79990100{index:03}'))
            con.execute('INSERT INTO portal.users(phone,account_id,name,device_limit,enabled,created_at) VALUES(?,?,?,2,1,0)', (new, new, f'Find {index:02}'))
    first = client.get('/admin?q=Find&page=1').text
    second = client.get('/admin?q=Find&page=2').text
    assert first.count('class="list-group-item list-group-item-action account-row"') == 25
    assert second.count('class="list-group-item list-group-item-action account-row"') == 5
    assert 'Find 25' not in first
    assert 'Find 25' in second
    assert 'Find 00' not in client.get('/admin?q=Find&state=disabled').text
    assert post(client, '/accounts/' + key + '/save', {'name': 'Not saved', 'device_limit': '0'}).status_code == 400
    with app.db() as con:
        assert con.execute('SELECT name FROM users WHERE account_id=?', (key,)).fetchone()[0] == 'Первый'


def test_form_has_one_csrf_and_protected_role_values_survive_post(portal):
    app, client = portal
    admin_login(app, client)
    key = accounts(app)[1]
    page = client.get('/accounts/' + key + '/edit').text
    assert 'form="recovery-form"' in page
    role = client.get('/admin/roles/owner/edit').text
    assert 'readonly' in role
    assert 'disabled' in role
    assert 'name="permissions" value="accounts.view"' in role
    # Ordinary and secondary form actions receive a token, without regex insertion.
    import re
    forms = re.findall(r'<form\b.*?</form>', page, re.S)
    assert all(form.count('name="csrf_token"') == 1 for form in forms)


def test_fresh_login_returns_to_editor_without_replaying_mutation(portal):
    app, client = portal
    admin_login(app, client)
    key = accounts(app)[1]
    edit = '/accounts/' + key + '/edit'
    with app.auth_store.db() as con:
        con.execute('UPDATE identity_sessions SET confirmed=0')
    response = post(client, '/admin/accounts/' + key + '/recovery', headers={'referer': 'https://portal.example.test' + edit})
    assert response.headers['location'] == '/security/confirm'
    response = post(client, '/login', {'identifier': 'admin', 'password': 'test-password'})
    assert response.headers['location'] == edit + '?resume=1'
    with app.auth_store.db() as con:
        assert not con.execute('SELECT 1 FROM recovery_codes').fetchone()


def test_restricted_session_only_shows_required_confirmation(portal):
    app, client = portal
    with app.auth_store.db() as con:
        con.execute("UPDATE admins SET totp_key='JBSWY3DPEHPK3PXP',totp_verified=1 WHERE id=1")
        con.execute("UPDATE roles SET require_2fa=1 WHERE id='owner'")
    post(client, '/login', {'identifier': 'admin', 'password': 'test-password'})
    body = client.get('/security').text
    assert 'Завершите подтверждение входа' in body
    assert 'action="/security/second"' in body
    assert 'action="/security/password"' not in body
    assert 'action="/security/mfa"' not in body
    assert 'Сессии' not in body


def test_vendored_bootstrap_matches_pinned_integrity():
    import base64
    import hashlib
    static = Path(__file__).resolve().parents[1] / 'portal/static'
    package = json.loads((static / 'vendor.json').read_text())['bootstrap']
    assert package['version'] == '5.3.8'
    for path, expected in package['files'].items():
        actual = 'sha384-' + base64.b64encode(hashlib.sha384((static / path).read_bytes()).digest()).decode()
        assert actual == expected['sha384']


def test_field_validation_keeps_public_values_without_partial_save(portal):
    app, client = portal
    admin_login(app, client)
    key = accounts(app)[1]
    response = post(client, '/accounts/' + key + '/save', {'name': 'Черновик', 'device_limit': 'not-a-number'})
    assert response.status_code == 422
    assert 'value="Черновик"' in response.text
    assert 'aria-invalid="true"' in response.text
    assert 'Введите целое число' in response.text
    with app.db() as con:
        assert con.execute('SELECT name FROM users WHERE account_id=?', (key,)).fetchone()[0] == 'Первый'


def test_invalid_device_draft_only_changes_the_submitted_form(portal):
    app, client = portal
    admin_login(app, client)
    with app.db() as con:
        owner = con.execute('SELECT phone,account_id FROM devices WHERE id=1').fetchone()
        con.execute('INSERT INTO devices(phone,account_id,name,client_id,created_at,vpn_ip) VALUES(?,?,?,?,0,?)',
                    (owner['phone'], owner['account_id'], 'Соседняя карточка', '43', '10.8.0.4'))
    response = post(client, '/device/1/update', {'name': 'Черновик устройства', 'ru_exit_id': 'invalid'})
    assert response.status_code == 422
    assert response.text.count('value="Черновик устройства"') == 1
    assert 'value="Соседняя карточка"' in response.text
    with app.db() as con:
        assert con.execute('SELECT name FROM devices WHERE id=1').fetchone()[0] == 'phone1'


def test_privileges_do_not_change_personal_device_navigation(portal):
    import re
    app, client = portal
    _, first, second = accounts(app)
    give(app, first, 'observer', 'selected', [second])
    phone_login(app, client)
    personal = ['/cabinet', '/accounts/' + first, '/accounts/' + first + '/routing', '/device/1/routing']
    managed = ['/accounts/' + second, '/accounts/' + second + '/routing', '/device/2/routing']
    for path in personal + managed:
        response = client.get(path)
        assert response.status_code == 200
        active = re.findall(r'<a[^>]*aria-current="page"[^>]*>([^<]+)</a>', response.text)
        assert active == ['Мои устройства' if path in personal else 'Пользователи']
    assert post(client, '/device/1/update', {'name': 'phone1'}).headers['location'] == '/cabinet'
