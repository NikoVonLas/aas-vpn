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

test('login layout', async ({ page }) => {
  await page.goto('/admin/login');
  await expect(page).toHaveScreenshot('login.png', { fullPage: true });
});

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
  await expect(legacy.locator('textarea')).toBeVisible();
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
  await card.getByRole('button', { name: 'Удалить', exact: true }).click();
  await expect(card).toHaveCount(0);
});
