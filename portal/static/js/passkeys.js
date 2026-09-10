'use strict';
const decode = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.codePointAt(0));
const encode = value => btoa(String.fromCodePoint(...new Uint8Array(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
document.querySelectorAll('form[data-passkey]').forEach(form => {
  const keyButton = form.querySelector('[data-passkey-submit]');
  const trigger = keyButton?.type === 'button' ? keyButton : form;
  trigger.addEventListener(trigger === form ? 'submit' : 'click', async event => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const button = keyButton || event.submitter || form.querySelector('button');
    button.disabled = true;
    let status = form.querySelector('[role=status]');
    if (!status) { status = document.createElement('p'); status.setAttribute('role', 'status'); form.append(status); }
    try {
      const data = new FormData(form);
      data.delete('password');
      data.set('purpose', form.dataset.passkey);
      const send = async (url, body) => {
        const response = await fetch(url, { method: 'POST', body, headers: { 'X-Requested-With': 'fetch' } });
        const result = await response.json();
        if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Не удалось подтвердить ключ');
        return result;
      };
      const started = await send('/security/passkeys/start', data);
      const options = started.options;
      options.challenge = decode(options.challenge);
      if (options.user) options.user.id = decode(options.user.id);
      for (const field of ['allowCredentials', 'excludeCredentials']) {
        if (options[field]) options[field].forEach(item => { item.id = decode(item.id); });
      }
      const key = await navigator.credentials[form.dataset.passkey === 'enroll' ? 'create' : 'get']({ publicKey: options });
      const response = {};
      for (const field of ['clientDataJSON', 'authenticatorData', 'signature', 'attestationObject', 'userHandle']) {
        if (key.response[field]) response[field] = encode(key.response[field]);
      }
      const proof = new FormData();
      proof.set('csrf_token', data.get('csrf_token'));
      proof.set('key', started.key);
      proof.set('credential', JSON.stringify({ id: key.id, rawId: encode(key.rawId), type: key.type, response, clientExtensionResults: key.getClientExtensionResults() }));
      const result = await send('/security/passkeys/finish', proof);
      location.assign(result.location);
    } catch (error) {
      status.textContent = error.name === 'NotAllowedError' ? 'Подтверждение отменено. Можно повторить.' : error.message;
    } finally { button.disabled = false; }
  });
});
