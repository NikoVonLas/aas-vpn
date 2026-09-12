// Native POST preserves the response and the clicked button's action.
document.addEventListener('submit', event => {
  const form = event.target;
  if (event.defaultPrevented || form.method !== 'post') return;
  if (form.dataset.submitting) { event.preventDefault(); return; }
  form.dataset.submitting = 'true';
  form.setAttribute('aria-busy', 'true');
  // Do not disable successful controls: name/value and formaction must survive.
  form.querySelectorAll('button[type=submit]').forEach(button => button.setAttribute('aria-disabled', 'true'));
});
window.addEventListener('pageshow', () => document.querySelectorAll('form[data-submitting]').forEach(form => {
  delete form.dataset.submitting;
  form.removeAttribute('aria-busy');
  form.querySelectorAll('[aria-disabled]').forEach(button => button.removeAttribute('aria-disabled'));
}));
const loginForm = document.querySelector('[data-login-methods]');
if (loginForm) {
  const methods = new Set(loginForm.dataset.loginMethods.split(','));
  const hint = document.getElementById('login-hint');
  const initial = hint.textContent;
  const update = () => {
    const identifier = loginForm.elements.identifier.value.trim();
    if (loginForm.elements.password?.value) hint.textContent = 'Вход с паролем.';
    else if ((identifier.startsWith('+') || loginForm.elements.identifier.type === 'tel') && methods.has('phone')) hint.textContent = 'Следующий шаг — подтверждение звонком.';
    else if (identifier.includes('@') && methods.has('email')) hint.textContent = 'Отправим код и ссылку на почту.';
    else hint.textContent = initial;
  };
  loginForm.addEventListener('input', update);
  loginForm.addEventListener('change', update);
  window.addEventListener('pageshow', update);
}
// A per-tab, ten-minute draft allowlist. No passwords, codes or private config.
const draftNames = new Set(['name', 'username', 'phone', 'device_limit', 'enabled', 'state_present', 'ru_exit_id', 'role_id', 'roles', 'roles_present', 'permissions', 'primary', 'secondary', 'required', 'ru', 'direct']);
const draftForms = document.querySelectorAll('form[id^=account-form-], .routing-form, form[action="/admin/roles/save"], .device-edit');
const resume = new URL(location.href).searchParams.has('resume');
for (const form of draftForms) {
  const storageKey = 'aas-draft:' + new URL(form.action).pathname + ':' + (form.dataset.draftId || '');
  try {
    const raw = sessionStorage.getItem(storageKey);
    const draft = raw ? JSON.parse(raw) : null;
    if (resume && draft && Date.now() - draft.at < 600000) {
      const editor = form.closest('.entity-editor');
      if (editor) editor.open = true;
      for (const input of form.elements) {
        if (!draftNames.has(input.name) || !(input.name in draft.values)) continue;
        const values = draft.values[input.name];
        if (input.type === 'checkbox') input.checked = values.includes(input.value);
        else input.value = values[0] ?? '';
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }
    sessionStorage.removeItem(storageKey);
    const saveDraft = () => {
      const values = {};
      const data = new FormData(form);
      for (const input of form.elements) {
        if (!draftNames.has(input.name) || input.type === 'password') continue;
        values[input.name] ??= [];
        if (input.type !== 'checkbox' || input.checked) values[input.name].push(input.type === 'tel' ? String(data.get(input.name) ?? input.value) : input.value);
      }
      sessionStorage.setItem(storageKey, JSON.stringify({ at: Date.now(), values }));
    };
    form.addEventListener('input', saveDraft);
    form.addEventListener('change', saveDraft);
  } catch { /* Storage can be disabled; ordinary forms remain usable. */ }
}
const identifier = document.querySelector('form[action="/login"] [name=identifier]');
if (identifier) {
  identifier.autocomplete = ['tel', 'email'].includes(identifier.type) ? identifier.type : 'username';
  identifier.setAttribute('aria-describedby', identifier.hasAttribute('aria-invalid') ? 'identifier-help login-hint' : 'login-hint');
  identifier.autocapitalize = 'none';
  identifier.spellcheck = false;
}
document.querySelector('form[action="/admin/logout"]')?.addEventListener('submit', () => {
  try { Object.keys(sessionStorage).filter(key => key.startsWith('aas-draft:')).forEach(key => sessionStorage.removeItem(key)); } catch { /* Optional storage. */ }
});

for (const element of document.querySelectorAll('[data-bs-toggle=tooltip]')) {
  bootstrap.Tooltip.getOrCreateInstance(element, { trigger: 'hover focus', container: 'body' });
}
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  document.querySelectorAll('[data-bs-toggle=tooltip]').forEach(element => bootstrap.Tooltip.getInstance(element)?.hide());
});

for (const field of document.querySelectorAll('[data-multiselect]')) {
  const update = () => {
    const selected = [...field.querySelectorAll('input:checked')].map(input => input.closest('label').textContent.trim());
    field.querySelector('[data-selection]').textContent = selected.join(', ') || 'Выберите роли';
  };
  field.addEventListener('change', update);
  field.addEventListener('shown.bs.dropdown', () => field.querySelector('input:not(:disabled)')?.focus());
  field.addEventListener('keydown', event => {
    if (!['ArrowDown', 'ArrowUp'].includes(event.key) || !field.querySelector('.dropdown-menu.show')) return;
    event.preventDefault();
    event.stopPropagation();
    const inputs = [...field.querySelectorAll('input:not(:disabled)')];
    const step = event.key === 'ArrowDown' ? 1 : -1;
    inputs[(inputs.indexOf(document.activeElement) + step + inputs.length) % inputs.length]?.focus();
  });
  update();
}
