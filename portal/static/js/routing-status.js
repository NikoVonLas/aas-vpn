// Refresh status labels without replacing forms or discarding unsaved edits.
async function refreshRoutingStatus() {
  if (!document.querySelector('[data-routing-state]') || document.hidden) return;
  try {
    const response = await fetch('/routing/status?admin_view=' + location.pathname.startsWith('/admin'), {cache: 'no-store'});
    if (response.redirected) { location.assign(response.url); return; }
    if (!response.ok) return;
    const state = await response.json();
    document.querySelectorAll('[data-routing-state]').forEach(node => { node.textContent = state.message; });
    document.querySelectorAll('[data-device-state]').forEach(node => {
      if (state.devices[node.dataset.deviceState]) node.textContent = state.devices[node.dataset.deviceState];
    });
    document.querySelectorAll('[data-exit-state]').forEach(node => {
      if (state.exits[node.dataset.exitState]) node.textContent = state.exits[node.dataset.exitState];
    });
  } catch { /* Keep the last displayed status; retry on the next interval. */ }
}
setInterval(refreshRoutingStatus, 10000);
