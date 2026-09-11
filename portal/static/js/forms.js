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
for (const form of document.querySelectorAll('[data-role-assignment]')) {
  const targets = form.querySelector('[data-targets]');
  const scope = form.elements.scope;
  const count = targets.querySelector('[data-selected-count]');
  const update = () => {
    targets.hidden = scope.value !== 'selected';
    targets.querySelectorAll('[name=targets]').forEach(input => { input.disabled = targets.hidden; });
    count.textContent = 'Выбрано: ' + targets.querySelectorAll('[name=targets]:checked').length;
  };
  scope.addEventListener('change', update);
  targets.addEventListener('change', update);
  targets.querySelector('[type=search]').addEventListener('input', event => {
    const query = event.target.value.toLocaleLowerCase('ru');
    targets.querySelectorAll('.check-label').forEach(label => { label.hidden = !label.textContent.toLocaleLowerCase('ru').includes(query); });
  });
  update();
}
const loginForm = document.querySelector('[data-login-methods]');
if (loginForm) {
  const methods = new Set(loginForm.dataset.loginMethods.split(','));
  const hint = document.getElementById('login-hint');
  const initial = hint.textContent;
  const update = () => {
    const identifier = loginForm.elements.identifier.value.trim();
    if (loginForm.elements.password?.value) hint.textContent = 'Вход с паролем.';
    else if (identifier.startsWith('+') && methods.has('phone')) hint.textContent = 'Следующий шаг — подтверждение звонком.';
    else if (identifier.includes('@') && methods.has('email')) hint.textContent = 'Отправим код и ссылку на почту.';
    else hint.textContent = initial;
  };
  loginForm.addEventListener('input', update);
  loginForm.addEventListener('change', update);
  window.addEventListener('pageshow', update);
}
// A per-tab, ten-minute draft allowlist. No passwords, codes or private config.
const draftNames = new Set(['name', 'username', 'phone', 'device_limit', 'enabled', 'state_present', 'ru_exit_id', 'role_id', 'scope', 'targets', 'permissions', 'primary', 'secondary', 'required', 'ru', 'direct']);
const draftForms = document.querySelectorAll('form[id^=account-form-], form[data-role-assignment], .routing-form, form[action="/admin/roles/save"], .device-edit');
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
      for (const input of form.elements) {
        if (!draftNames.has(input.name) || input.type === 'password') continue;
        values[input.name] ??= [];
        if (input.type !== 'checkbox' || input.checked) values[input.name].push(input.value);
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
