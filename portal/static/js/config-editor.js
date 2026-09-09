// Read imports locally so the administrator can edit them before saving.
document.addEventListener('change', async event => {
  const input = event.target;
  if (!input.matches('input[type=file][name=config_upload]')) return;
  const file = input.files[0];
  if (!file) return;
  const form = input.form;
  const editor = form.elements.config_text;
  const status = form.querySelector('.config-file-status');
  const buttons = [...form.querySelectorAll('button')].map(button => [button, button.disabled]);
  input.disabled = true;
  buttons.forEach(([button]) => { button.disabled = true; });
  try {
    if (file.size > 65536) throw new Error('Размер конфига не должен превышать 64 КБ.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    editor.value = text;
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    status.textContent = `Загружен ${file.name}. Текст можно изменить перед сохранением.`;
  } catch (error) {
    status.textContent = error instanceof TypeError ? 'Конфиг должен быть текстом UTF-8.' : 'Не удалось прочитать файл. Проверьте формат и размер (до 64 КБ).';
  } finally {
    // Submit only the edited text, never a stale copy of the uploaded file.
    input.value = '';
    input.disabled = false;
    buttons.forEach(([button, disabled]) => { button.disabled = disabled; });
  }
});
