// Refresh live status without replacing forms or discarding unsaved edits.
const deviceTraffic = new Map();

function formatRate(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 Б/с';
  const units = ['Б/с', 'КБ/с', 'МБ/с', 'ГБ/с'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  const digits = unit && value < 100 ? 1 : 0;
  return value.toLocaleString('ru-RU', {minimumFractionDigits: digits, maximumFractionDigits: digits}) + ' ' + units[unit];
}

function updateDeviceState(node, state) {
  const connection = node.querySelector('[data-device-connection]');
  const download = node.querySelector('[data-device-download]');
  const upload = node.querySelector('[data-device-upload]');
  if (!connection || !download || !upload || !state || typeof state !== 'object') return;
  const id = node.dataset.deviceState;
  const connected = state.connected === true;
  const known = connected || state.connected === false;
  connection.textContent = connected ? 'Подключён' : (known ? 'Не подключён' : 'Нет данных');
  node.dataset.connected = connected ? 'true' : (known ? 'false' : 'unknown');
  const current = {connected, download: Number(state.download), upload: Number(state.upload), at: Number(state.observed_at)};
  const previous = deviceTraffic.get(id);
  if (!known) {
    download.textContent = upload.textContent = '—';
  } else if (connected && previous?.connected && current.at > previous.at &&
             current.download >= previous.download && current.upload >= previous.upload) {
    const seconds = current.at - previous.at;
    download.textContent = formatRate((current.download - previous.download) / seconds);
    upload.textContent = formatRate((current.upload - previous.upload) / seconds);
  } else {
    download.textContent = upload.textContent = '0 Б/с';
  }
  if (Number.isFinite(current.download) && Number.isFinite(current.upload) && Number.isFinite(current.at)) {
    deviceTraffic.set(id, current);
  }
  node.dataset.liveReady = 'true';
}

async function refreshRoutingStatus() {
  if (!document.querySelector('[data-routing-state]') || document.hidden) return;
  try {
    const response = await fetch('/routing/status?admin_view=' + location.pathname.startsWith('/admin'), {cache: 'no-store'});
    if (response.redirected) { location.assign(response.url); return; }
    if (!response.ok) return;
    const state = await response.json();
    document.querySelectorAll('[data-routing-state]').forEach(node => { node.textContent = state.message; });
    document.querySelectorAll('[data-device-state]').forEach(node => {
      updateDeviceState(node, state.devices[node.dataset.deviceState]);
    });
    document.querySelectorAll('[data-exit-state]').forEach(node => {
      if (state.exits[node.dataset.exitState]) node.textContent = state.exits[node.dataset.exitState];
    });
  } catch { /* Keep the last displayed status; retry on the next interval. */ }
}
refreshRoutingStatus();
setInterval(refreshRoutingStatus, 3000);
