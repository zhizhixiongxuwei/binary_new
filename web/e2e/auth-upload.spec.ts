import {
  expect,
  expectNoPageOverflow,
  loginAs,
  logoutFromDemo,
  test,
} from './fixtures'

test('登录、退出和只读角色路由门禁 @mobile', async ({ page }) => {
  await logoutFromDemo(page)

  const submit = page.getByRole('button', { name: '登录' })
  await expect(submit).toBeDisabled()
  await loginAs(page, 'demo-reader')

  await expect(page.getByText('只读用户', { exact: true })).toBeAttached()
  await expect(page.getByRole('link', { name: '新建任务' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: '系统维护' })).toHaveCount(0)

  await page.evaluate(() => {
    window.history.pushState({}, '', '/system')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole('heading', { name: '系统概览' })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('登录限速倒计时结束后自动恢复提交 @mobile', async ({ page }) => {
  await logoutFromDemo(page)

  await page.getByLabel('用户名').fill('demo-rate-limited')
  await page.getByLabel('密码').fill('preview-password')
  const submit = page.getByRole('button', { name: '登录' })
  await submit.click()

  const cooldown = page.locator('#login-rate-limit-status')
  await expect(cooldown).toContainText('登录尝试过于频繁')
  await expect(cooldown).toContainText('为保护系统，请稍后再试')
  await expect(page.getByLabel('3 秒后可再次登录')).toBeVisible()
  await expect(submit).toBeDisabled()
  await expectNoPageOverflow(page)

  await expect(submit).toBeEnabled({ timeout: 5_000 })
  await expect(cooldown).toHaveCount(0)
  await expectNoPageOverflow(page)
})

test('浏览器选择文件后完成分片上传并创建可浏览任务 @mobile', async ({
  page,
}) => {
  await page.goto('/tasks/new')
  await expect(page.getByRole('heading', { name: '新建任务' })).toBeVisible()

  await page.getByLabel('选择待检测文件').setInputFiles({
    name: 'playwright-sample.exe',
    mimeType: 'application/vnd.microsoft.portable-executable',
    buffer: Buffer.from('MZ-playwright-demo-binary'),
  })

  const queue = page.getByRole('list', { name: '上传队列' })
  await expect(queue.getByText('playwright-sample.exe')).toBeVisible()
  await expect(queue.getByText('等待上传')).toBeVisible()
  await page.getByRole('button', { name: '开始上传' }).click()
  await expect(queue.getByText('任务已创建')).toBeVisible()
  await expect(
    queue.getByLabel('playwright-sample.exe 上传进度 100%'),
  ).toBeVisible()

  await queue.getByRole('button', { name: '查看任务', exact: true }).click()
  await expect(page.getByRole('heading', { name: '任务详情' })).toBeVisible()
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await expect(page.getByText('playwright-sample.exe', { exact: true }).first()).toBeVisible()
  await page
    .getByRole('button', { name: '查看 playwright-sample.exe 的节点详情' })
    .click()
  await expect(page.getByText('纯前端示例任务，不会持久化或执行真实检测')).toBeVisible()
  await expectNoPageOverflow(page)
})
