const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.cjs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { baseURL: 'http://localhost:8765', locale: 'ru-RU', reducedMotion: 'reduce', trace: 'retain-on-failure' },
  expect: { toHaveScreenshot: { animations: 'disabled', maxDiffPixelRatio: 0.002 } },
  projects: [
    { name: 'phone-small', use: { viewport: { width: 360, height: 800 }, colorScheme: 'light' } },
    { name: 'phone', use: { viewport: { width: 390, height: 844 }, colorScheme: 'light' } },
    { name: 'tablet', use: { viewport: { width: 768, height: 1024 }, colorScheme: 'light' } },
    { name: 'desktop', use: { viewport: { width: 1440, height: 1000 }, colorScheme: 'light' } },
    { name: 'phone-dark', use: { viewport: { width: 390, height: 844 }, colorScheme: 'dark' } },
  ],
  webServer: {
    command: `${process.env.PYTHON || 'python3'} server.py`,
    url: 'http://localhost:8765/healthz',
    reuseExistingServer: false,
    timeout: 30000,
  },
});
