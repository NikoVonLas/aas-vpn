const { test, expect } = require('@playwright/test');
const registry = require('./screens.json');
async function login(page) {
  await page.request.get('/fixture/state/reset');
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/');
  await page.locator('[name=identifier]').fill('admin');
  await page.locator('[name=password]').fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  if (new URL(page.url()).pathname === '/security') await page.goto('/fixture/complete-login');
  await expect(page).toHaveURL(/\/admin$/);
}
async function stable(page) {
  await page.locator('form[action="/security/sessions/revoke"] p').evaluateAll(nodes => nodes.forEach(node => { node.textContent = 'Текущая сессия'; }));
  await page.evaluate(() => document.fonts.ready);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}
test.afterEach(async ({ page }) => { await page.request.get('/fixture/state/reset'); });
for (const state of registry.states) {
  test(`screen ${state.name}`, async ({ page }) => {
    await login(page);
    let path = state.path;
    if (path.startsWith('account-')) {
      await page.locator('.account-row').filter({ hasText: 'Александр Константинопольский' }).click();
      const account = (await page.locator('.account-list > details[open]').getAttribute('id')).slice('account-'.length);
      path = '/accounts/' + account + '/edit';
      if (state.path === 'account-routing') path = path.replace('/edit', '/routing');
    }
    if (state.state) await page.request.get('/fixture/state/' + state.state);
    await page.goto(path);
    if (state.name !== 'expired') await expect(page.getByRole('heading', { level: 1 })).not.toHaveText('Не получилось');
    if (state.open) await page.locator('summary:visible').filter({ hasText: state.open }).first().click();
    if (state.tooltip) {
      await page.locator(state.tooltip).hover();
      await expect(page.getByRole('tooltip')).toHaveText('Отключено глобально');
    }
    await stable(page);
    await expect(page).toHaveScreenshot(state.name + '.png', { fullPage: true });
  });
}
for (const name of ['qr', 'delete']) {
  test(`screen ${name} dialog`, async ({ page }) => {
    await login(page);
    await page.goto('/admin/users/+79990000001/devices');
    await page.getByRole('button', { name: name === 'qr' ? 'QR' : 'Удалить', exact: true }).first().click();
    if (name === 'qr') await expect(page.locator('#qr-image')).toHaveJSProperty('complete', true);
    await expect(page).toHaveScreenshot(name + '-dialog.png');
  });
}
test('screen recovery result and backup codes', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').filter({ hasText: 'Мария' }).click();
  await page.locator('.account-list > details[open]').getByRole('button', { name: 'Восстановление', exact: true }).click();
  await page.locator('pre').evaluate(node => { node.textContent = 'Тестовый одноразовый код восстановления'; });
  await page.getByText(/^ID аккаунта:/).evaluate(node => { node.textContent = 'ID аккаунта: test-account'; });
  await expect(page).toHaveScreenshot('recovery-result.png', { fullPage: true });
  await page.goto('/security');
  await page.getByRole('button', { name: 'Выпустить резервные коды' }).click();
  await page.locator('pre').evaluate(node => { node.textContent = Array.from({length: 10}, (_, i) => 'test-backup-code-' + i).join('\n'); });
  await expect(page).toHaveScreenshot('backup-codes.png', { fullPage: true });
});
test('screen login without methods and auto-detection', async ({ page }) => {
  try {
    await page.request.get('/fixture/login-options/none');
    await page.goto('/');
    await expect(page).toHaveScreenshot('login-unavailable.png', { fullPage: true });
  } finally { await page.request.get('/fixture/login-options/restore'); }
  await page.goto('/');
  await page.locator('[name=identifier]').fill('+79990000001');
  await expect(page).toHaveScreenshot('login-detected-phone.png', { fullPage: true });
  await page.locator('[name=password]').fill('autofilled-password');
  await expect(page.locator('#login-hint')).toHaveText('Вход с паролем.');
  await expect(page).toHaveScreenshot('login-filled-password.png', { fullPage: true });
});
test('screen restricted navigation and maintenance error', async ({ page }) => {
  await page.goto('/fixture/phone-login/+79990000002');
  await page.goto('/admin/ru-exits');
  await expect(page).toHaveScreenshot('permission-error.png', { fullPage: true });
  await login(page);
  await page.goto('/admin/users/+79990000001/devices');
  await page.request.get('/fixture/state/maintenance');
  await page.locator('.device-card').first().getByRole('button', { name: 'Сохранить' }).click();
  await expect(page.getByRole('alert')).toContainText('Сервис обновляется');
  await expect(page).toHaveScreenshot('maintenance.png', { fullPage: true });
});
test('screen menu and increased text', async ({ page }) => {
  await login(page);
  if (page.viewportSize().width < 768) await page.getByRole('button', { name: /^Меню/ }).click();
  await expect(page).toHaveScreenshot('navigation-open.png', { fullPage: true });
  await page.addStyleTag({ content: 'body{font-size:30px}h1{font-size:52px}h2{font-size:34px}.btn,.form-control,.form-select,label,.app-links a{font-size:26px}.form-control,.form-select{height:auto!important;min-height:60px}' });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('screen login and account field errors', async ({ page }) => {
  await login(page);
  await page.goto('/');
  await page.locator('[name=identifier]').fill('admin');
  await page.locator('[name=password]').fill('wrong-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page).toHaveScreenshot('login-error.png', { fullPage: true });
  await page.goto('/accounts/new');
  await page.locator('#account-new [name=name]').fill('Новый пользователь');
  await page.locator('#account-new [name=phone]').fill('+79990000001');
  await page.getByRole('button', { name: 'Добавить аккаунт' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('#account-new [name=name]')).toHaveValue('Новый пользователь');
  await expect(page.locator('#account-new [name=phone]')).toHaveValue('+79990000001');
  await expect(page).toHaveScreenshot('account-error.png', { fullPage: true });
  await page.goto('/admin/users/+79990000001/devices');
  const device = page.locator('form[action="/device/1/update"]');
  await device.locator('[name=name]').fill('   ');
  await device.getByRole('button', { name: 'Сохранить', exact: true }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('form[action="/device/2/update"] [name=name]')).toHaveValue('Телефон с длинным названием устройства');
  await expect(page).toHaveScreenshot('device-error.png', { fullPage: true });
});
