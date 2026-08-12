import { expect, test, type Page } from '@playwright/test'

const username = process.env.BINARYSCAN_LIVE_E2E_USERNAME
const password = process.env.BINARYSCAN_LIVE_E2E_PASSWORD
const taskId = process.env.BINARYSCAN_LIVE_C_ANALYSIS_TASK_ID

test.skip(
  !username || !password || !taskId,
  'Live C analysis credentials and task ID are required',
)

async function login(page: Page, target: string): Promise<void> {
  await page.goto(target)
  await expect(page).toHaveURL(/\/login(?:\?|$)/)
  await page.getByLabel('用户名').fill(username!)
  await page.getByLabel('密码').fill(password!)
  await page.getByRole('button', { name: '登录' }).click()
  await page.waitForURL((url) => url.pathname === target)
}

test('C analysis finding opens its saved source snippet', async ({ page }) => {
  const target = `/tasks/${taskId}`
  await login(page, target)

  await page.getByRole('tab', { name: '检测结果' }).click()
  await page.getByRole('tab', { name: 'C 源码检测' }).click()
  const action = page.getByRole('button', { name: /查看 .+ 的代码片段/ }).first()
  await expect(action).toBeVisible()
  await action.click()

  const drawer = page.getByRole('dialog', { name: 'C 源码检测详情' })
  await expect(drawer).toBeVisible()
  await expect(drawer.getByText('检测片段', { exact: true })).toBeVisible()
  await expect(drawer.locator('.snippet-line').first()).toBeVisible()
})
