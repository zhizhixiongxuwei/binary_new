import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

import { expect, test, type Page } from '@playwright/test'

const username = process.env.BINARYSCAN_LIVE_E2E_USERNAME
const password = process.env.BINARYSCAN_LIVE_E2E_PASSWORD
const ghidraTaskId = process.env.BINARYSCAN_LIVE_GHIDRA_TASK_ID
const trivyTaskId = process.env.BINARYSCAN_LIVE_TRIVY_TASK_ID
const screenshotDirectory = process.env.BINARYSCAN_LIVE_E2E_SCREENSHOT_DIR
const enabled = Boolean(username && password && ghidraTaskId && trivyTaskId)

test.skip(!enabled, 'Live analyzer task IDs and credentials are required.')
test.setTimeout(60_000)

async function login(page: Page, taskId: string): Promise<void> {
  const target = `/tasks/${taskId}`
  await page.goto(target)
  await expect(page).toHaveURL(/\/login(?:\?|$)/)
  await page.getByLabel('用户名').fill(username!)
  await page.getByLabel('密码').fill(password!)
  await page.getByRole('button', { name: '登录' }).click()
  await expect(page).toHaveURL(new RegExp(`${target}$`))
}

async function expectLayout(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { name: '任务命令' })).toBeVisible()
  await expect(page.getByRole('heading', { name: '执行日志' })).toBeVisible()
  await expect(page.getByText('实时事件已连接')).toBeVisible()
  expect(
    await page.locator('.task-detail').evaluate((element) =>
      element.firstElementChild?.classList.contains('task-actions'),
    ),
  ).toBe(true)
  expect(
    await page.evaluate(() =>
      document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true)
}

async function saveScreenshot(page: Page, name: string): Promise<void> {
  if (!screenshotDirectory) return
  mkdirSync(screenshotDirectory, { recursive: true })
  await page.screenshot({
    path: join(screenshotDirectory, name),
    fullPage: true,
  })
}

test('真实 Ghidra 结构化日志与顶部任务命令区可见', async ({ page }) => {
  await login(page, ghidraTaskId!)
  await expectLayout(page)

  const log = page.getByRole('log')
  await expect(log.getByText('反编译请求已排队')).toBeVisible()
  await expect(log.getByText('Ghidra 正在准备输入')).toBeVisible()
  await expect(log.getByText('Ghidra JVM 正在启动')).toBeVisible()
  await expect(log.getByText('Ghidra 正在反编译').last()).toBeVisible()
  await expect(log.getByText('Ghidra 反编译已完成')).toBeVisible()
  await expect(log).not.toContainText('BINARYSCAN_GHIDRA_PROGRESS')
  await expect(log).not.toContainText('run_id')

  await saveScreenshot(page, 'task-progress-ghidra-desktop.png')
})

test('真实 Trivy 结构化日志在移动端无横向溢出', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await login(page, trivyTaskId!)
  await expectLayout(page)

  const log = page.getByRole('log')
  await expect(log.getByText('正在校验镜像归档')).toBeVisible()
  await expect(log.getByText('离线漏洞库已就绪')).toBeVisible()
  await expect(log.getByText('Trivy 正在检测镜像')).toBeVisible()
  await expect(log.getByText('镜像目标检测完成')).toBeVisible()
  await expect(log.getByText('Trivy 镜像检测已完成')).toBeVisible()
  await expect(log).not.toContainText('/data/task-work/')
  await expect(log).not.toContainText('raw_report')

  for (const name of ['取消', '重检', '延期 30 天', '删除']) {
    await expect(page.getByRole('button', { name })).toBeVisible()
  }
  await saveScreenshot(page, 'task-progress-trivy-mobile.png')
})
