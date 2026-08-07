import { defineConfig, devices } from '@playwright/test'

const baseURL = process.env.BINARYSCAN_LIVE_E2E_BASE_URL

if (!baseURL) {
  throw new Error(
    'BINARYSCAN_LIVE_E2E_BASE_URL is required; run scripts/e2e-live-report.sh',
  )
}

export default defineConfig({
  testDir: './e2e-live',
  outputDir: './test-results-live',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: [
    ['line'],
    ['html', { outputFolder: 'playwright-report-live', open: 'never' }],
  ],
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL,
    locale: 'zh-CN',
    timezoneId: 'Asia/Shanghai',
    colorScheme: 'light',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium-live-mysql',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
})
