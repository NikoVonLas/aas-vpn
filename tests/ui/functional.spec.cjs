const { test, expect } = require('@playwright/test');
async function login(page) {
  await page.request.get('/fixture/reset-sessions');
  await page.goto('/');
  await page.getByLabel('Логин или телефон').fill('admin');
  await page.getByLabel('Пароль', { exact: true }).fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  if (new URL(page.url()).pathname === '/security') await page.goto('/fixture/complete-login');
  await expect(page).toHaveURL(/\/admin$/);
}

test('recovery response is visible and code can only be consumed once', async ({ page }) => {
  await login(page);
  await page.locator('.account-row').filter({ hasText: 'Мария' }).click();
  const account = (await page.locator('.account-list > details[open]').getAttribute('id')).slice('account-'.length);
  await page.locator('.account-list > details[open]').getByRole('button', { name: 'Восстановление', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Одноразовое восстановление' })).toBeVisible();
  const code = await page.locator('pre').textContent();
  expect(code.length).toBeGreaterThan(30);
  await page.goto('/login/recovery');
  await page.getByLabel('ID аккаунта').fill(account);
  await page.getByLabel('Одноразовый код администратора').fill(code);
  await page.getByRole('button', { name: 'Продолжить' }).click();
  await expect(page).toHaveURL(/\/security$/);
  await expect(page.getByRole('heading', { name: 'Сессии', exact: true })).toHaveCount(0);
  await page.goto('/login/recovery');
  await page.getByLabel('ID аккаунта').fill(account);
  await page.getByLabel('Одноразовый код администратора').fill(code);
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
  await page.goto('/admin/roles/user/edit');
  await page.locator('#role-user').getByLabel('Название', { exact: true }).fill('Черновик роли');
  await page.request.get('/fixture/state/reauth');
  await page.locator('#role-user').getByRole('button', { name: 'Сохранить', exact: true }).click();
  await expect(page).toHaveURL(/\/security\/confirm$/);
  await page.getByRole('link', { name: 'Перейти ко входу' }).click();
  await page.locator('[name=identifier]').fill('admin');
  await page.locator('[name=password]').fill('visual-test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  if (new URL(page.url()).pathname === '/security') await page.goto('/fixture/complete-login');
  await expect(page).toHaveURL(/\/admin\/roles\/user\/edit\?resume=1$/);
  await expect(page.locator('#role-user').getByLabel('Название', { exact: true })).toHaveValue('Черновик роли');
  await page.goto('/admin/roles');
  await expect(page.getByRole('heading', { name: 'Пользователь', exact: true })).toBeVisible();
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

async function openNavigation(page) {
  const menu = page.getByRole('button', { name: /^Меню/ });
  if (await menu.isVisible()) await menu.click();
}

test('navigation links select their destination and keep the same content width', async ({ page }) => {
  await login(page);
  const dimensions = [];
  for (const [label, path, heading] of [
    ['Мои устройства', '/cabinet', 'Мои устройства'],
    ['Пользователи', '/admin', 'Пользователи'],
    ['Альтернативные выходы', '/admin/ru-exits', 'Альтернативные выходы'],
    ['Маршрутизация', '/admin/routing', 'Маршрутизация'],
    ['Роли и доступ', '/admin/roles', 'Роли и доступ'],
    ['Способы входа', '/admin/login-methods', 'Способы входа'],
    ['Безопасность профиля', '/security', 'Безопасность профиля'],
  ]) {
    await openNavigation(page);
    await page.getByRole('link', { name: label, exact: true }).click();
    expect(new URL(page.url()).pathname).toBe(path);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(heading);
    const active = page.locator('[aria-current=page]');
    await expect(active).toHaveCount(1);
    if (path === '/security') await expect(active).toHaveAccessibleName(label);
    else await expect(active).toHaveText(label);
    await expect(active).toHaveCSS('background-color', 'rgb(185, 28, 28)');
    dimensions.push(await page.locator('main').evaluate(node => ({ width: node.getBoundingClientRect().width, left: node.getBoundingClientRect().left })));
  }
  for (const dimension of dimensions) expect(dimension).toEqual(dimensions[0]);
  await page.getByRole('link', { name: 'Безопасность профиля', exact: true }).click();
  await expect(page.locator('[aria-current=page]')).toHaveText('Безопасность профиля');
  await openNavigation(page);
  await page.locator('.admin-nav').getByRole('link', { name: 'Пользователи', exact: true }).click();
  await page.locator('.account-row').filter({ hasText: 'Александр Константинопольский' }).click();
  const editor = await page.locator('main').evaluate(node => ({ width: node.getBoundingClientRect().width, left: node.getBoundingClientRect().left }));
  expect(editor).toEqual(dimensions[0]);
  await expect(page.locator('[aria-current=page]')).toHaveText('Пользователи');
  await page.locator('.account-list > details[open]').getByRole('link', { name: 'Устройства', exact: true }).click();
  await expect(page.locator('[aria-current=page]')).toHaveText('Пользователи');
});

test('all entity lists use the same keyboard-operated disclosure', async ({ page }) => {
  await login(page);
  for (const [path, selector] of [['/admin', '.account-list > details'], ['/admin/roles', '#role-user'], ['/admin/ru-exits', '#exit-1'], ['/admin/login-methods', '#method-totp']]) {
    await page.goto(path);
    const editor = page.locator(selector).first();
    const summary = editor.locator(':scope > summary');
    await expect(editor).not.toHaveAttribute('open', '');
    await summary.focus();
    await page.keyboard.press('Enter');
    await expect(editor).toHaveAttribute('open', '');
    expect(new URL(page.url()).pathname).toBe(path);
    await expect(editor.locator('.editor-body')).toBeVisible();
    await summary.click();
    await expect(editor.locator('.editor-body')).toBeHidden();
  }
});

test('built-in global switches persist and rejected changes preserve other cards', async ({ page }) => {
  await page.request.get('/fixture/state/reset');
  await login(page);
  await page.request.get('/fixture/state/optional-mfa');
  try {
    for (const method of ['totp', 'webauthn']) {
      await page.goto('/admin/login-methods');
      const card = page.locator('#method-' + method);
      await card.locator('summary').click();
      await card.getByRole('checkbox', { name: 'Разрешить для всего сервиса' }).uncheck();
      await card.getByRole('button', { name: 'Сохранить', exact: true }).click();
      await expect(card.locator('.badge')).toHaveText('Выключен');
    }
    const password = page.locator('#method-password');
    await password.locator('summary').click();
    await password.getByRole('checkbox').uncheck();
    await password.getByRole('button', { name: 'Сохранить', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('способа входа');
    await expect(password).toHaveAttribute('open', '');
    await expect(password.locator('.badge')).toHaveText('Включён');
    await expect(page.locator('#method-totp .badge')).toHaveText('Выключен');
    await page.goto('/security');
    await expect(page.getByRole('heading', { name: 'Приложение-аутентификатор (TOTP)', exact: true })).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Ключи и passkeys', exact: true })).toHaveCount(0);
  } finally { await page.request.get('/fixture/state/reset'); }
});


test('role permissions and profile forms are visible with consistent actions', async ({ page }) => {
  await page.request.get('/fixture/state/reset');
  await login(page);
  await page.goto('/admin/roles');
  await expect(page.locator('details[id^=role-]')).toHaveCount(3);
  const role = page.locator('#role-administrator');
  await role.locator('summary').click();
  await expect(role.getByRole('group', { name: 'Аккаунты', exact: true })).toBeVisible();
  await expect(role.getByRole('group', { name: 'Основные способы входа', exact: true })).toBeVisible();
  await expect(role.getByRole('group', { name: 'Второй фактор', exact: true })).toBeVisible();
  await expect(role.locator('details')).toHaveCount(0);
  await expect(role.getByRole('checkbox', { name: 'Обязательная 2FA', exact: true })).toBeChecked();
  await expect(role.getByRole('checkbox', { name: 'Обязательная 2FA', exact: true })).toBeDisabled();
  await page.getByRole('link', { name: 'Безопасность профиля', exact: true }).click();
  await expect(page.locator('main details')).toHaveCount(0);
  await expect(page.locator('.admin-nav a[href="/security"]')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Подтвердить вход заново' })).toHaveCount(0);
  await expect(page.locator('.profile-link')).toHaveAttribute('aria-current', 'page');
});
