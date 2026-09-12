"""Autoescaped HTML components and request-local presentation context."""
from contextvars import ContextVar
from itertools import count
from pathlib import Path
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

DRAFT_FIELDS = {'name', 'username', 'identifier', 'phone', 'device_limit', 'enabled', 'state_present', 'ru_exit_id', 'role_id', 'roles', 'roles_present', 'permissions', 'primary', 'secondary', 'required', 'ru', 'direct'}

request_context = ContextVar('presentation_request', default=None)
environment = Environment(loader=FileSystemLoader(Path(__file__).with_name('templates')),
                          autoescape=select_autoescape(['html']), undefined=StrictUndefined)


def local_path(value, fallback='/cabinet'):
    """Accept local GET destinations only, never protocol-relative URLs."""
    if not isinstance(value, str) or any(ord(c) < 32 for c in value) or '\\' in value:
        return fallback
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not value.startswith('/') or value.startswith('//'):
        return fallback
    return parsed.path + ('?' + parsed.query if parsed.query else '')


def render(template, *, form_action='', **values):
    request = request_context.get()
    if request and not hasattr(request.state, 'field_ids'):
        request.state.field_ids = count()
    ids = request.state.field_ids if request else count()
    token = getattr(request.state, 'csrf_token', '') if request else ''
    draft = getattr(request.state, 'form_draft', {}) if request else {}
    errors = getattr(request.state, 'field_errors', {}) if request else {}
    failed = getattr(request.state, 'form_failed', False) if request else False
    if form_action and (request is None or request.url.path != form_action):
        failed = False
        errors = {}
    def form_value(name, default=''):
        return draft[name][0] if failed and name in draft and draft[name] else default
    def form_checked(name, value, default=False):
        return str(value) in draft.get(name, []) if failed and name in DRAFT_FIELDS else default
    return Markup(environment.get_template(template).render(csrf_token=token, failed=failed, form_value=form_value,
                  form_checked=form_checked, field_id=lambda: 'phone-field-' + str(next(ids)), field_errors=errors, form_error=getattr(request.state, 'form_error', '') if request else '', **values))


def component_catalog(portal):
    """Registered by the local preview fixture, never exposed on production."""
    editor = render('components/device_form.html', device={'id': 1, 'name': 'Рабочий ноутбук', 'ru_exit_id': None},
                    exits=[{'id': 1, 'name': 'Домашний Keenetic'}], can_change_exit=True, can_rename=True)
    return portal.page('Компоненты', render('catalog.html', editor=editor), show_header=True)
