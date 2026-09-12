const { test, expect } = require('@playwright/test');

test('OIDC alongside the automatic login form', async ({ page }) => {
  try {
    await page.request.get('/fixture/login-options/password,phone,oidc');
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Войти через OpenID Connect', exact: true })).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Логин или телефон', exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(page).toHaveScreenshot('oidc-mixed-login.png', { fullPage: true });
  } finally { await page.request.get('/fixture/login-options/restore'); }
});
