const { test, expect } = require('@playwright/test');

async function login(page) {
  await page.goto('/admin/login');
  await page.locator('[name=username]').fill('admin');
  await page.locator('[name=password]').fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
}

for (const [name, path, active] of [
  ['users', '/admin', 'Пользователи'],
  ['exits', '/admin/ru-exits', 'RU-выходы'],
  ['routing', '/admin/routing', 'Маршрутизация'],
  ['administrators', '/admin/administrators', 'Администраторы'],
  ['unowned', '/admin/unowned', 'Без владельца'],
  ['devices', '/admin/users/+79990000001/devices', 'Пользователи'],
]) {
  test(`${name} layout`, async ({ page }) => {
    await login(page);
    await page.goto(path);
    await page.evaluate(() => document.fonts.ready);
    await expect(page).toHaveScreenshot(`${name}.png`, { fullPage: true });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const current = page.locator('nav [aria-current=page]');
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

test('button with formaction keeps its own endpoint', async ({ page }) => {
  await login(page);
  const row = page.locator('form.user').last();
  const request = page.waitForRequest(r => r.url().includes('/admin/toggle/') && r.method() === 'POST');
  await row.getByRole('button', { name: 'Запретить выдачу', exact: true }).click();
  await request;
  await expect(page.locator('form.user').last().getByRole('button', { name: 'Разрешить выдачу', exact: true })).toBeVisible();
  await page.locator('form.user').last().getByRole('button', { name: 'Разрешить выдачу', exact: true }).click();
  await expect(page.locator('form.user').last().getByRole('button', { name: 'Запретить выдачу', exact: true })).toBeVisible();
});

test('logout after AJAX save uses its own action', async ({ page }) => {
  await login(page);
  const row = page.locator('form.user').first();
  const response = page.waitForResponse(r => r.url().endsWith('/admin/user') && r.request().method() === 'POST');
  await row.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await response;
  await expect(page.locator('form.user').first().getByRole('button', { name: 'Сохранить', exact: true })).toBeEnabled();
  const logout = page.waitForRequest(r => r.url().endsWith('/admin/logout') && r.method() === 'POST');
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await logout;
  await expect(page).toHaveURL(/\/admin\/login$/);
  await page.goto('/admin');
  await expect(page).toHaveURL(/\/admin\/login$/);
});

test('RU file import is editable and save is the last action', async ({ page }) => {
  await login(page);
  await expect(page.locator('form.user').first().getByRole('button').last()).toHaveText('Сохранить');
  await page.goto('/admin/ru-exits');
  const legacy = page.locator('form[action="/admin/ru-exits/1"]');
  await expect(legacy.locator('textarea')).toHaveValue(/\[Interface\]/);
  await expect(legacy.locator('.exit-actions button')).toHaveText(['Удалить', 'По умолчанию', 'Сохранить']);
  const boxes = await legacy.locator('.exit-actions button').evaluateAll(buttons => buttons.map(button => button.getBoundingClientRect().top));
  expect(new Set(boxes).size).toBe(1);
  const form = page.locator('form[action="/admin/ru-exits"]');
  const key = Buffer.alloc(32, 1).toString('base64');
  const imported = `[Interface]\nPrivateKey = ${key}\nAddress = 10.55.0.2/32\n[Peer]\nPublicKey = ${key}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.10:51820\n`;
  await form.locator('[name=config_upload]').setInputFiles({ name: 'test.conf', mimeType: 'text/plain', buffer: Buffer.from(imported) });
  await expect(form.locator('textarea')).toHaveValue(imported);
  await expect(form.locator('[role=status]')).toContainText('Текст можно изменить');
  const edited = imported.replace('10.55.0.2', '10.55.0.3');
  await form.locator('textarea').fill(edited);
  await form.locator('[name=name]').fill('Проверка импорта');
  const sent = page.waitForRequest(request => request.url().endsWith('/admin/ru-exits') && request.method() === 'POST');
  await form.getByRole('button', { name: 'Добавить выход', exact: true }).click();
  expect((await sent).postData()).toContain('10.55.0.3/32');
  const card = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Проверка импорта', exact: true }) });
  await expect(card).toBeVisible();
  await page.reload();
  await expect(card.locator('textarea')).toHaveValue(edited);
  const revised = edited.replace('10.55.0.3', '10.55.0.4');
  await card.locator('textarea').fill(revised);
  await card.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await expect(card.locator('textarea')).toHaveValue(revised);
  await page.reload();
  await expect(card.locator('textarea')).toHaveValue(revised);
  await card.getByRole('button', { name: 'Удалить', exact: true }).click();
  await expect(card).toHaveCount(0);
});

test('country hover stays inside the phone field and dropdown opens', async ({ page }) => {
  await login(page);
  const phone = page.locator('.iti').first();
  const country = phone.locator('.iti__selected-country');
  await country.hover();
  const bounds = await phone.evaluate(element => {
    const input = element.querySelector('input[type=tel]').getBoundingClientRect();
    const button = element.querySelector('.iti__selected-country').getBoundingClientRect();
    return { top: button.top - input.top, bottom: input.bottom - button.bottom };
  });
  expect(bounds.top).toBeGreaterThanOrEqual(0);
  expect(bounds.bottom).toBeGreaterThanOrEqual(0);
  await expect(phone).toHaveScreenshot('phone-hover.png');
  await country.click();
  await expect(page.locator('.iti__country-list:visible')).toBeVisible();
});

test('device has one save action for both fields', async ({ page }) => {
  await login(page);
  await page.goto('/admin/users/+79990000001/devices');
  const form = page.locator('.device-card form').first();
  const name = form.locator('[name=name]');
  const exit = form.locator('select');
  const save = form.getByRole('button', { name: 'Сохранить', exact: true });
  await expect(form.getByRole('button')).toHaveCount(1);
  const controls = await form.locator('input[name=name],select,button').evaluateAll(elements => elements.map(element => {
    const rect = element.getBoundingClientRect();
    return { x: rect.x, top: rect.top, bottom: rect.bottom, height: rect.height };
  }));
  if (page.viewportSize().width > 720) {
    expect(new Set(controls.map(rect => rect.bottom)).size).toBe(1);
    expect(controls[0].x).toBeLessThan(controls[1].x);
    expect(controls[1].x).toBeLessThan(controls[2].x);
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
    await expect(form.getByRole('button')).toHaveText('Сохранить');
    await expect(form.locator('select')).toHaveCount(allowed ? 1 : 0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test('administrator forms share controls and hide unused password', async ({ page }) => {
  await login(page);
  await page.goto('/admin/administrators');
  const ownForm = page.locator('form.settings-form').first();
  await expect(ownForm.getByRole('button', { name: 'Сохранить', exact: true })).toHaveCount(1);
  await ownForm.locator('[data-admin-action]').selectOption('totp-start');
  await expect(ownForm.locator('[data-admin-password]')).toBeHidden();
  await ownForm.locator('[data-admin-action]').selectOption('password');
  await expect(ownForm.locator('[data-admin-password]')).toBeVisible();
  const widths = await page.locator('.admin-nav a').evaluateAll(links => links.map(link => link.scrollWidth <= link.clientWidth));
  expect(widths.every(Boolean)).toBe(true);
});
