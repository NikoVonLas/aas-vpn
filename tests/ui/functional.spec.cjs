const { test, expect } = require('@playwright/test');
async function login(page) {
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/');
  await page.getByLabel('Логин или телефон').fill('admin');
  await page.getByLabel('Пароль', { exact: true }).fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page).toHaveURL(/\/admin$/);
}

test('recovery response is visible and code can only be consumed once', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').filter({ hasText: 'Мария' }).click();
  const account = new URL(page.url()).pathname.split('/')[2];
  await page.getByRole('button', { name: 'Восстановление', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Одноразовое восстановление' })).toBeVisible();
  const code = await page.locator('pre').textContent();
  expect(code.length).toBeGreaterThan(30);
  await page.goto('/login/recovery');
  await page.getByLabel('ID аккаунта').fill(account);
  await page.getByLabel('Одноразовый код владельца').fill(code);
  await page.getByRole('button', { name: 'Продолжить' }).click();
  await expect(page).toHaveURL(/\/security$/);
  await expect(page.getByRole('heading', { name: 'Сессии', exact: true })).toHaveCount(0);
  await page.goto('/login/recovery');
  await page.getByLabel('ID аккаунта').fill(account);
  await page.getByLabel('Одноразовый код владельца').fill(code);
  await page.getByRole('button', { name: 'Продолжить' }).click();
  await expect(page.getByRole('alert')).toHaveText('Код восстановления недоступен');
});

test('modal keyboard focus returns to the initiating device', async ({ page }) => {
  await login(page);
  await page.goto('/device/1/routing');
  await page.goto('/admin/users/+79990000001/devices');
  const button = page.getByRole('button', { name: 'QR', exact: true }).first();
  await button.click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveAccessibleName('QR: Рабочий ноутбук');
  await page.keyboard.press('Escape');
  await expect(button).toBeFocused();
  const remove = page.getByRole('button', { name: 'Удалить', exact: true }).first();
  await remove.click();
  await page.getByRole('button', { name: 'Отмена', exact: true }).click();
  await expect(remove).toBeFocused();
});

test('login error preserves identifier and auto-detection explains next step', async ({ page }) => {
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/');
  await page.getByLabel('Логин или телефон').fill('+79990000001');
  await expect(page.locator('#login-hint')).toContainText('звонком');
  await page.getByLabel('Логин или телефон').fill('admin');
  await page.getByLabel('Пароль', { exact: true }).fill('invalid-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page.locator('[name=identifier]')).toHaveValue('admin');
  await expect(page.locator('[name=identifier]')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('[name=password]')).toHaveValue('');
});

test('role draft resumes after confirmation without repeating POST', async ({ page }) => {
  await login(page);
  await page.goto('/admin/roles/observer/edit');
  await page.getByLabel('Название', { exact: true }).fill('Черновик роли');
  await page.request.get('/fixture/state/reauth');
  await page.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await expect(page).toHaveURL(/\/security\/confirm$/);
  await page.getByRole('link', { name: 'Перейти ко входу' }).click();
  await page.locator('[name=identifier]').fill('admin');
  await page.locator('[name=password]').fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page).toHaveURL(/\/admin\/roles\/observer\/edit\?resume=1$/);
  await expect(page.getByLabel('Название', { exact: true })).toHaveValue('Черновик роли');
  await page.goto('/admin/roles');
  await expect(page.getByRole('heading', { name: 'Наблюдатель', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Черновик роли', exact: true })).toHaveCount(0);
});

test('theme tokens meet text and focus contrast', async ({ page }) => {
  await page.goto('/fixture/components');
  const colors = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    return Object.fromEntries(['--muted', '--bg', '--card', '--focus', '--red'].map(name => [name, root.getPropertyValue(name).trim()]));
  });
  function luminance(hex) {
    if (hex.length === 4) hex = '#' + [...hex.slice(1)].map(x => x + x).join('');
    const components = hex.slice(1).match(/../g).map(x => Number.parseInt(x, 16) / 255).map(x => x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4);
    return components[0] * 0.2126 + components[1] * 0.7152 + components[2] * 0.0722;
  }
  const contrast = (a, b) => (Math.max(luminance(a), luminance(b)) + 0.05) / (Math.min(luminance(a), luminance(b)) + 0.05);
  expect(contrast(colors['--muted'], colors['--bg'])).toBeGreaterThanOrEqual(4.5);
  expect(contrast(colors['--muted'], colors['--card'])).toBeGreaterThanOrEqual(4.5);
  expect(contrast(colors['--focus'], colors['--card'])).toBeGreaterThanOrEqual(3);
  expect(contrast('#ffffff', colors['--red'])).toBeGreaterThanOrEqual(4.5);
});
