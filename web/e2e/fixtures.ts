import {
  expect,
  test as base,
  type Page,
  type TestInfo,
} from '@playwright/test'

interface UiDiagnostics {
  consoleErrors: string[]
  pageErrors: string[]
}

export const test = base.extend<{ uiDiagnostics: UiDiagnostics }>({
  uiDiagnostics: [
    async ({ page }, use) => {
      const diagnostics: UiDiagnostics = {
        consoleErrors: [],
        pageErrors: [],
      }

      page.on('console', (message) => {
        if (message.type() === 'error') diagnostics.consoleErrors.push(message.text())
      })
      page.on('pageerror', (error) => {
        diagnostics.pageErrors.push(error.message)
      })

      await use(diagnostics)

      expect(
        diagnostics.consoleErrors,
        '页面不应产生 console.error',
      ).toEqual([])
      expect(diagnostics.pageErrors, '页面不应产生未处理异常').toEqual([])
    },
    { auto: true },
  ],
})

export { expect }

export async function expectNoPageOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }))

  expect(
    Math.max(overflow.document, overflow.body),
    `页面宽度 ${Math.max(overflow.document, overflow.body)} 不应超过视口 ${overflow.viewport}`,
  ).toBeLessThanOrEqual(overflow.viewport + 1)
}

export async function logoutFromDemo(page: Page): Promise<void> {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '系统概览' })).toBeVisible()
  const logout = page.getByRole('button', { name: '退出登录' })
  if (!(await logout.isVisible())) {
    await page.getByRole('button', { name: '打开主导航' }).click()
  }
  await logout.click()
  await expect(page).toHaveURL(/\/login$/)
}

export async function loginAs(
  page: Page,
  username: string,
  password = 'preview-password',
): Promise<void> {
  await page.getByLabel('用户名').fill(username)
  await page.getByLabel('密码').fill(password)
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page.getByRole('heading', { name: '系统概览' })).toBeVisible()
}

export function taskUrl(taskId: string): string {
  return `/tasks/${taskId}`
}

export function testLabel(testInfo: TestInfo): string {
  return `${testInfo.project.name}: ${testInfo.title}`
}
