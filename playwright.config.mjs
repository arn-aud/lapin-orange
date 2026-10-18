import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: { ...devices['Desktop Chrome'], trace: 'retain-on-failure' },
  webServer: {
    command: "GATE_PASSPHRASE='lapin test phrase' node build.mjs && node tests/serve.mjs",
    url: 'http://localhost:4173/',
    reuseExistingServer: !process.env.CI,
  },
});
