(() => {
  const dialog = document.getElementById('connect-dialog');
  const status = document.getElementById('connect-status');
  const link = document.getElementById('connect-link');
  const ready = document.getElementById('connect-ready');
  const copy = document.getElementById('connect-copy');
  const retry = document.getElementById('connect-retry');
  const manual = document.getElementById('connect-manual');
  const key = document.getElementById('connect-key');
  let controller;
  let source;
  async function prepare() {
    controller?.abort();
    const pending = new AbortController();
    controller = pending;
    ready.hidden = copy.hidden = retry.hidden = manual.hidden = true;
    link.removeAttribute('href');
    key.value = '';
    status.textContent = 'Подготовка подключения…';
    try {
      const response = await fetch(source.dataset.connectUrl, {
        signal: pending.signal, cache: 'no-store', redirect: 'error',
        headers: { 'X-Requested-With': 'fetch' }
      });
      if (!response.ok) throw new Error('Connection unavailable');
      const data = await response.json();
      if (pending.signal.aborted) return;
      if (typeof data.url !== 'string' || !/^vpn:\/\/[A-Za-z0-9_-]+$/.test(data.url)) throw new Error('Invalid connection');
      link.href = data.url;
      ready.hidden = copy.hidden = false;
      status.textContent = 'Подключение готово.';
      link.click();
    } catch {
      if (pending.signal.aborted) return;
      status.textContent = 'Не удалось загрузить подключение. Повторите попытку. Если вход истёк, войдите на сайт снова.';
      retry.hidden = false;
    }
  }
  document.addEventListener('click', event => {
    const button = event.target.closest('.connect-device');
    if (!button) return;
    source = button;
    document.getElementById('connect-title').textContent = 'AmneziaVPN: ' + button.dataset.deviceName;
    bootstrap.Modal.getOrCreateInstance(dialog).show();
    prepare();
  });
  retry.addEventListener('click', prepare);
  copy.addEventListener('click', async () => {
    const active = controller;
    try {
      await navigator.clipboard.writeText(link.getAttribute('href'));
      if (active.signal.aborted) return;
      status.textContent = 'Ключ скопирован. Откройте AmneziaVPN, нажмите «+» и вставьте ключ.';
    } catch {
      if (active.signal.aborted) return;
      key.value = link.getAttribute('href');
      manual.hidden = false;
      key.focus();
      key.select();
      status.textContent = 'Скопируйте выделенный ключ и вставьте его в AmneziaVPN.';
    }
  });
  dialog.addEventListener('hide.bs.modal', () => {
    controller?.abort();
    link.removeAttribute('href');
    key.value = '';
  });
  dialog.addEventListener('hidden.bs.modal', () => source?.focus());
})();
