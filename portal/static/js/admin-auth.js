document.addEventListener('change', event => {
  if (!event.target.matches('[data-admin-action]')) return;
  const field = event.target.form.querySelector('[data-admin-password]');
  const needsPassword = ['password', 'reset'].includes(event.target.value);
  field.hidden = !needsPassword;
  field.querySelector('input').required = needsPassword;
  if (!needsPassword) field.querySelector('input').value = '';
});
