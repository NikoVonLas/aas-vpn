const { test, expect } = require('@playwright/test');

async function login(page) {
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/admin/login');
  await page.locator('[name=identifier]').fill('admin');
  await page.locator('[name=password]').fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  if (new URL(page.url()).pathname === '/security') await page.goto('/fixture/complete-login');
  await expect(page).toHaveURL(/\/admin$/);
}

for (const [name, path, active] of [
  ['users', '/admin', 'Пользователи'],
  ['exits', '/admin/ru-exits', 'Альтернативные выходы'],
  ['routing', '/admin/routing', 'Маршрутизация'],
  ['roles', '/admin/roles', 'Роли и доступ'],
  ['login-methods', '/admin/login-methods', 'Способы входа'],
  ['devices', '/admin/users/+79990000001/devices', 'Пользователи'],
]) {
  test(`${name} layout`, async ({ page }) => {
    await login(page);
    await page.goto(path);
    await page.evaluate(() => document.fonts.ready);
    await expect(page.getByRole('link', { name: 'Без владельца', exact: true })).toHaveCount(0);
    await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    if (page.viewportSize().width < 768) await page.getByRole('button', { name: /^Меню/ }).click();
    const current = page.locator('[aria-current=page]');
    await expect(current).toHaveText(active);
    await expect(current).toHaveCSS('background-color', 'rgb(185, 28, 28)');
  });
}

for (const [name, path] of [['login', '/admin/login'], ['not-found', '/missing-page']]) {
  test(`${name} layout`, async ({ page }) => {
    await page.goto(path);
    await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true });
  });
}

test('account saves name, limit and state together', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').last().click();
  const form = page.locator('.account-list > details[open] form[id^=account-form-]');
  const response = page.waitForResponse(r => /\/accounts\/[^/]+\/save$/.test(r.url()) && r.request().method() === 'POST');
  await form.getByRole('button', { name: 'Сохранить', exact: true }).click();
  expect((await response).status()).toBe(303);
  await expect(page).toHaveURL(/\/accounts\/[^/]+\/edit$/);
});

test('logout after native save uses its own action', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').first().click();
  const row = page.locator('.account-list > details[open] form[id^=account-form-]');
  const response = page.waitForResponse(r => /\/accounts\/[^/]+\/save$/.test(r.url()) && r.request().method() === 'POST');
  await row.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await response;
  await expect(page.locator('form[action^="/accounts/"][action$="/save"]').first().getByRole('button', { name: 'Сохранить', exact: true })).toBeEnabled();
  const logout = page.waitForRequest(r => r.url().endsWith('/admin/logout') && r.method() === 'POST');
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await logout;
  await expect(page).toHaveURL(/\/admin\/login$/);
  await page.goto('/admin');
  await expect(page).toHaveURL(/\/$/);
});

test('RU file import is editable and save is the last action', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').first().click();
  await expect(page.locator('.account-list > details[open] form[id^=account-form-] button').last()).toHaveText('Сохранить');
  await page.goto('/admin/ru-exits');
  const legacy = page.locator('form[action="/admin/ru-exits/1"]');
  await page.locator('#exit-1 > summary').click();
  await expect(legacy.locator('textarea')).toHaveValue(/\[Interface\]/);
  await expect(legacy.locator('.exit-actions button')).toHaveText(['Удалить', 'По умолчанию', 'Сохранить']);
  const boxes = await legacy.locator('.exit-actions button').evaluateAll(buttons => buttons.map(button => button.getBoundingClientRect().top));
  expect(new Set(boxes).size).toBe(1);
  const form = page.locator('form[action="/admin/ru-exits"]');
  await page.locator('#exit-new > summary').click();
  const key = Buffer.alloc(32, 1).toString('base64');
  const imported = `[Interface]\nPrivateKey = ${key}\nAddress = 10.55.0.2/32\n[Peer]\nPublicKey = ${key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.10:51820\n`;
  await form.locator('[name=config_upload]').setInputFiles({ name: 'test.conf', mimeType: 'text/plain', buffer: Buffer.from(imported) });
  await expect(form.locator('textarea')).toHaveValue(imported);
  await expect(form.getByRole('status')).toContainText('Текст можно изменить');
  const edited = imported.replace('10.55.0.2', '10.55.0.3');
  await form.locator('textarea').fill(edited);
  await form.locator('[name=name]').fill('Проверка импорта');
  const sent = page.waitForRequest(request => request.url().endsWith('/admin/ru-exits') && request.method() === 'POST');
  await form.getByRole('button', { name: 'Добавить выход', exact: true }).click();
  expect((await sent).postData()).toContain('10.55.0.3/32');
  const card = page.locator('details.entity-editor').filter({ has: page.getByRole('heading', { name: 'Проверка импорта', exact: true }) });
  await expect(card).toBeVisible();
  await page.reload();
  await expect(card.locator('textarea')).toHaveValue(edited);
  await card.locator('summary').click();
  const revised = edited.replace('10.55.0.3', '10.55.0.4');
  await card.locator('textarea').fill(revised);
  await card.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await expect(card.locator('textarea')).toHaveValue(revised);
  await page.reload();
  await expect(card.locator('textarea')).toHaveValue(revised);
  await card.locator('summary').click();
  await card.getByRole('button', { name: 'Удалить', exact: true }).click();
  await expect(card).toHaveCount(0);
});

test('device has one save action for both fields', async ({ page }) => {
  await login(page);
  await page.goto('/admin/users/+79990000001/devices');
  const form = page.locator('.device-card form').first();
  const name = form.locator('[name=name]');
  const exit = form.locator('select');
  const save = form.getByRole('button', { name: 'Сохранить', exact: true });
  await expect(form.locator('.btn-primary')).toHaveCount(1);
  const controls = await form.locator('input[name=name],select,button.btn-primary').evaluateAll(elements => elements.map(element => {
    const rect = element.getBoundingClientRect();
    return { x: rect.x, top: rect.top, bottom: rect.bottom, height: rect.height };
  }));
  if (page.viewportSize().width > 720) {
    expect(controls[0].bottom).toBe(controls[1].bottom);
    expect(controls[1].bottom).toBeLessThan(controls[2].top);
    expect(controls[0].x).toBeLessThan(controls[1].x);
    const actions = await form.locator('.device-actions').boundingBox();
    expect(actions.x).toBeLessThan(controls[2].x);
    expect(Math.abs(actions.y - controls[2].top)).toBeLessThan(2);
  } else {
    expect(controls[0].bottom).toBeLessThan(controls[1].top);
    expect(controls[1].bottom).toBeLessThan(controls[2].top);
  }
  await expect(exit).toHaveCSS('padding-right', '40px');
  await expect(exit).toHaveCSS('background-position', 'calc(100% - 12px) 50%');
  await exit.selectOption('2');
  await exit.focus();
  await expect(form).toHaveScreenshot('device-form-focus.png');
  await name.fill('Совместное сохранение');
  await exit.selectOption('2');
  const sent = page.waitForRequest(request => request.url().endsWith('/device/1/update') && request.method() === 'POST');
  await save.click();
  const values = new URLSearchParams((await sent).postData());
  expect(values.get('name')).toBe('Совместное сохранение');
  expect(values.get('ru_exit_id')).toBe('2');
  await page.reload();
  await expect(name).toHaveValue('Совместное сохранение');
  await expect(exit).toHaveValue('2');
  await name.fill('Рабочий ноутбук');
  await exit.selectOption('0');
  await save.click();
  await expect(name).toHaveValue('Рабочий ноутбук');
});

for (const [phone, allowed] of [['+79990000001', true], ['+79990000002', false]]) {
  test(`cabinet layout with exit permission ${allowed}`, async ({ page }) => {
    await page.goto('/fixture/phone-login/' + phone);
    await expect(page).toHaveURL(/\/cabinet$/);
    await expect(page).toHaveScreenshot(`cabinet-${allowed ? 'exit' : 'name'}.png`, { fullPage: true });
    const form = page.locator('.device-card form').first();
    await expect(form.locator('.btn-primary')).toHaveText('Сохранить');
    await expect(form.locator('select')).toHaveCount(allowed ? 1 : 0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test('roles are assigned and revoked inside a user card', async ({ page }) => {
  await login(page);
  await page.goto('/admin/administrators');
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByRole('link', { name: 'Администраторы', exact: true })).toHaveCount(0);
  await page.locator('.account-row').filter({ hasText: 'Александр Константинопольский' }).click();
  const card = page.locator('.account-list > details[open]');
  await card.locator('.account-roles > summary').click();
  const form = card.locator('.account-roles > form.stack');
  await form.getByRole('combobox', { name: 'Роль', exact: true }).selectOption('administrator');
  await expect(form.getByRole('combobox', { name: 'Область', exact: true })).toHaveValue('global');
  await expect(form.locator('[name=scope] option[value=self]')).toHaveJSProperty('disabled', true);
  await form.getByRole('combobox', { name: 'Роль', exact: true }).selectOption('user');
  await form.getByRole('combobox', { name: 'Область', exact: true }).selectOption('selected');
  await expect(form.locator('[data-targets]')).toBeVisible();
  await form.getByRole('checkbox', { name: /^Мария ·/ }).check();
  await expect(card).toHaveScreenshot('user-role-assignment.png');
  await form.getByRole('button', { name: 'Добавить роль', exact: true }).click();
  await expect(page).toHaveURL(/\/accounts\/[^/]+\/edit$/);
  await expect(card.locator('.account-roles > summary')).toContainText('Пользователь');
  await card.locator('.account-roles > summary').click();
  const grant = card.locator('form').filter({ hasText: 'Пользователь · Выбранные аккаунты Мария' });
  await grant.getByRole('button', { name: 'Отозвать назначение', exact: true }).click();
  await expect(card.locator('form').filter({ hasText: 'Пользователь · Выбранные аккаунты Мария' })).toHaveCount(0);
  await page.goto('/admin/roles');
  await expect(page.getByRole('button', { name: 'Добавить роль', exact: true })).toHaveCount(0);
  await expect(page.locator('form[action="/admin/roles/assign"]')).toHaveCount(0);
});


test('profile layout', async ({ page }) => {
  await login(page);
  await page.goto('/security');
  await page.locator('section').filter({ has: page.getByRole('heading', { name: 'Сессии', exact: true }) }).locator('p').evaluateAll(nodes => nodes.forEach(node => { node.textContent = 'Текущая сессия'; }));
  await expect(page).toHaveScreenshot('security.png', { fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.locator('[aria-current=page]')).toHaveText('Безопасность профиля');
});

test('scoped routing layout and transactional save', async ({ page }) => {
  await login(page);
  await page.goto('/device/1/routing');
  await expect(page).toHaveScreenshot('device-routing.png', { fullPage: true });
  await page.locator('[name=ru]').fill('.example.test');
  await page.locator('[name=direct]').fill('192.0.2.0/24');
  await page.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await page.reload();
  await expect(page.locator('[name=ru]')).toHaveValue('.example.test');
  await page.locator('[name=ru]').fill('');
  await page.locator('[name=direct]').fill('');
  await page.getByRole('button', { name: 'Сохранить', exact: true }).click();
});

test('virtual FIDO2 registration, authentication, replay and deletion', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }
  });
  await login(page);
  await page.goto('/security');
  const enroll = page.locator('form[data-passkey=enroll]');
  await enroll.locator('[name=name]').fill('Тестовый ключ FIDO2');
  const registration = page.waitForResponse(r => r.url().endsWith('/security/passkeys/finish'));
  await enroll.getByRole('button').click();
  expect((await registration).status()).toBe(200);
  await expect(page.getByText('Тестовый ключ FIDO2 · ещё не использовался', { exact: true })).toBeVisible();
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);
  // Use the key as a second method after a password; primary policy remains password.
  const start = await page.locator('[name=csrf_token]').first().inputValue();
  const begun = await page.request.post('/security/passkeys/start', { form: { csrf_token: start, purpose: 'second' } });
  expect(begun.status()).toBe(200);
  const challenge = await begun.json();
  const proof = await page.evaluate(async options => {
    const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const encode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    options.challenge = decode(options.challenge);
    options.allowCredentials.forEach(c => { c.id = decode(c.id); });
    const key = await navigator.credentials.get({ publicKey: options });
    return { id: key.id, rawId: encode(key.rawId), type: key.type, response: { clientDataJSON: encode(key.response.clientDataJSON), authenticatorData: encode(key.response.authenticatorData), signature: encode(key.response.signature), userHandle: encode(key.response.userHandle) } };
  }, challenge.options);
  const payload = { csrf_token: start, key: challenge.key, credential: JSON.stringify(proof) };
  const invalidProofs = [];
  for (const [field, value] of [['challenge', 'wrong-challenge'], ['origin', 'https://other.example.test']]) {
    const invalid = structuredClone(proof);
    const clientData = JSON.parse(Buffer.from(invalid.response.clientDataJSON, 'base64url'));
    clientData[field] = value;
    invalid.response.clientDataJSON = Buffer.from(JSON.stringify(clientData)).toString('base64url');
    invalidProofs.push(invalid);
  }
  for (const field of ['rp', 'uv']) {
    const invalid = structuredClone(proof);
    const data = Buffer.from(invalid.response.authenticatorData, 'base64url');
    if (field === 'rp') data[0] ^= 1;
    else data[32] &= ~4;
    invalid.response.authenticatorData = data.toString('base64url');
    invalidProofs.push(invalid);
  }
  const wrongAccount = structuredClone(proof);
  wrongAccount.response.userHandle = Buffer.from('another-account').toString('base64url');
  invalidProofs.push(wrongAccount);
  for (const invalid of invalidProofs) {
    const rejected = await page.request.post('/security/passkeys/finish', { form: { ...payload, credential: JSON.stringify(invalid) } });
    expect(rejected.status()).toBe(400);
  }
  const accepted = await page.request.post('/security/passkeys/finish', { form: payload });
  expect(accepted.status()).toBe(200);
  const replay = await page.request.post('/security/passkeys/finish', { form: payload });
  expect(replay.status()).toBe(400);
  await page.goto('/admin/roles/administrator/edit');
  const owner = page.locator('form[action="/admin/roles/save"]').filter({ has: page.locator('[name=role_id][value=administrator]') });
  await owner.locator('[name=primary][value=webauthn]').check();
  await expect(owner.locator('input[type=checkbox][name=required]')).toBeChecked();
  await owner.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await page.goto('/');
  await page.locator('[name=password]').fill('unused-password');
  const keyRequest = page.waitForRequest(r => r.url().endsWith('/security/passkeys/start'));
  await page.locator('[name=identifier]').fill('admin');
  await page.getByRole('button', { name: 'Войти с ключом / passkey', exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
  expect((await keyRequest).postData()).not.toContain('unused-password');
  // A UV-verified key satisfies mandatory MFA as the primary method.
  try {
    await page.request.get('/fixture/login-options/webauthn');
    await page.goto('/');
    await expect(page.locator('[name=password]')).toHaveCount(0);
    await page.getByLabel('Аккаунт', { exact: true }).fill('admin');
    await page.getByLabel('Аккаунт', { exact: true }).press('Enter');
    await expect(page).toHaveURL(/\/admin$/);
  } finally {
    await page.request.get('/fixture/login-options/restore');
  }
  await login(page);
  await page.goto('/security');
  await page.getByRole('button', { name: 'Удалить ключ', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await page.goto('/fixture/state/required');
  await page.getByRole('button', { name: 'Удалить ключ', exact: true }).click();
  await expect(page).toHaveURL(/\/$/);
  await page.request.get('/fixture/state/reset');
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
});


test('one login form serves every entry URL', async ({ page }) => {
  for (const path of ['/', '/admin/login', '/?method=phone', '/?method=webauthn']) {
    await page.goto(path);
    const form = page.locator('form[action="/login"]');
    await expect(form).toHaveCount(1);
    await expect(page.getByRole('navigation', { name: 'Способ входа' })).toHaveCount(0);
    await expect(form.getByLabel('Логин или телефон')).toBeVisible();
    await expect(form.getByLabel('Пароль', { exact: true })).not.toHaveAttribute('required');
    await expect(form.getByRole('button')).toHaveText(['Войти']);
  }
});

test('Enter in the common form starts the mandatory administrator confirmation', async ({ page }) => {
  await page.request.get('/fixture/state/reset');
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/');
  await page.getByLabel('Логин или телефон').fill('admin');
  await page.getByLabel('Пароль', { exact: true }).fill('visual-test-password');
  await page.getByLabel('Пароль', { exact: true }).press('Enter');
  await expect(page).toHaveURL(/\/security$/);
  await expect(page.getByRole('heading', { name: 'Приложение-аутентификатор (TOTP)', exact: true })).toBeVisible();
});


test('login fields and actions follow all method combinations', async ({ page }) => {
  const catalog = ['password', 'phone', 'email', 'webauthn'];
  try {
    for (let mask = 1; mask < 16; mask++) {
      const methods = catalog.filter((_, index) => mask & (1 << index));
      await page.request.get('/fixture/login-options/' + methods.join(','));
      await page.goto('/');
      const form = page.locator('form[action="/login"]');
      await expect(form).toHaveCount(1);
      await expect(form.locator('[name=password]')).toHaveCount(methods.includes('password') ? 1 : 0);
      await expect(form.locator('[data-passkey-submit]')).toHaveCount(methods.includes('webauthn') ? 1 : 0);
      let primaryAction = 'Продолжить';
      if (methods.includes('password')) primaryAction = 'Войти';
      else if (methods.length === 1 && methods[0] === 'webauthn') primaryAction = 'Войти с ключом / passkey';
      await expect(form.getByRole('button').last()).toHaveText(primaryAction);
      await expect(page).toHaveScreenshot('login-options-' + methods.join('-') + '.png', { fullPage: true });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    }
  } finally {
    await page.request.get('/fixture/login-options/restore');
  }
});
