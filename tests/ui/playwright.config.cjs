const { defineConfig } = require('@playwright/test');
const baseURL = `https://localhost:${process.env.AAS_UI_PORT || '8765'}`;

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.cjs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL, ignoreHTTPSErrors: true, locale: 'ru-RU', reducedMotion: 'reduce', trace: 'retain-on-failure' },
  expect: { toHaveScreenshot: { animations: 'disabled', maxDiffPixelRatio: 0.002 } },
  projects: [
    { name: 'firefox', testMatch: 'functional.spec.cjs', use: { browserName: 'firefox', viewport: { width: 390, height: 844 } } },
    { name: 'webkit', testMatch: 'functional.spec.cjs', use: { browserName: 'webkit', viewport: { width: 390, height: 844 } } },
    { name: 'phone-small', use: { viewport: { width: 360, height: 800 }, colorScheme: 'light' } },
    { name: 'phone', use: { viewport: { width: 390, height: 844 }, colorScheme: 'light' } },
    { name: 'tablet', use: { viewport: { width: 768, height: 1024 }, colorScheme: 'light' } },
    { name: 'desktop', use: { viewport: { width: 1440, height: 1000 }, colorScheme: 'light' } },
    { name: 'phone-small-dark', use: { viewport: { width: 360, height: 800 }, colorScheme: 'dark' } },
    { name: 'tablet-dark', use: { viewport: { width: 768, height: 1024 }, colorScheme: 'dark' } },
    { name: 'desktop-dark', use: { viewport: { width: 1440, height: 1000 }, colorScheme: 'dark' } },
    { name: 'phone-dark', use: { viewport: { width: 390, height: 844 }, colorScheme: 'dark' } },
  ],
  webServer: {
    command: `${process.env.PYTHON || 'python3'} server.py`,
    url: `${baseURL}/healthz`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 30000,
  },
});
