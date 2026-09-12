const callForm = document.querySelector('[data-phone-confirm]');
if (callForm) {
  const status = callForm.querySelector('[data-call-status]');
  const retry = document.querySelector('[data-call-retry]');
  const expires = Number(callForm.dataset.expires) * 1000;
  let stopped = false;
  let timer;
  let controller;
  const expire = () => {
    stopped = true;
    status.textContent = 'Время подтверждения истекло. Начните заново.';
    retry.hidden = false;
  };
  const handleResponse = (response, data) => {
    if (response.status === 410) { expire(); return; }
    if (response.ok && data.location) {
      const target = new URL(data.location, location.origin);
      if (target.origin !== location.origin) throw new Error('Invalid destination');
      stopped = true;
      location.assign(target.href);
    } else if (response.status >= 400 && response.status < 500) {
      stopped = true;
      status.textContent = data.detail || 'Подтверждение недоступно. Начните заново.';
      retry.hidden = false;
    } else {
      status.textContent = response.ok ? 'Ждём звонка…' : 'Проверка звонка временно недоступна. Повторяем автоматически.';
    }
  };
  const poll = async () => {
    if (stopped) return;
    if (Date.now() >= expires) { expire(); return; }
    if (document.hidden) { timer = setTimeout(poll, 3000); return; }
    controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(callForm.dataset.statusUrl, {
        method: 'POST', body: new FormData(callForm), credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch' }, signal: controller.signal,
      });
      const data = await response.json();
      handleResponse(response, data);
    } catch {
      if (!stopped) status.textContent = 'Не удалось проверить звонок. Повторяем автоматически.';
    } finally {
      clearTimeout(timeout);
      if (!stopped) timer = setTimeout(poll, 3000);
    }
  };
  window.addEventListener('pagehide', () => {
    stopped = true;
    clearTimeout(timer);
    controller?.abort();
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted) { stopped = false; poll(); }
  });
  await poll();
}
