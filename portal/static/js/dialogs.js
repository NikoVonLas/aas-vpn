document.addEventListener('click', event => {
  const button = event.target.closest('.qr-button, .delete-device');
  if (!button) return;
  const qr = button.classList.contains('qr-button');
  const dialog = document.getElementById(qr ? 'qr-dialog' : 'delete-dialog');
  if (qr) {
    document.getElementById('qr-title').textContent = 'QR: ' + button.dataset.deviceName;
    document.getElementById('qr-image').src = button.dataset.qrUrl;
  } else {
    document.getElementById('delete-form').action = button.dataset.deleteUrl;
    document.getElementById('delete-device-name').textContent = button.dataset.deviceName;
  }
  dialog.addEventListener('hidden.bs.modal', () => button.focus(), { once: true });
  bootstrap.Modal.getOrCreateInstance(dialog).show();
});
