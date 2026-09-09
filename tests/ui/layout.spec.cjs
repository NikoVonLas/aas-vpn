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
