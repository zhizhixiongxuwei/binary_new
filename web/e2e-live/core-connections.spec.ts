import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'

import {
  expect,
  test,
  type APIResponse,
  type Page,
} from '@playwright/test'

interface Envelope<T> {
  data: T
  meta: { requestId: string }
}

interface CreatedTask {
  id: string
}

interface TaskDetail {
  id: string
  status: string
  input_type: string
  sha256: string
  size_bytes: number
}

const username = process.env.BINARYSCAN_LIVE_E2E_USERNAME
const password = process.env.BINARYSCAN_LIVE_E2E_PASSWORD
const resultPath = process.env.BINARYSCAN_LIVE_E2E_RESULT

if (!username || !password || !resultPath) {
  throw new Error(
    'Live connection variables are required; run scripts/e2e-live-report.sh',
  )
}

test.setTimeout(60_000)

function isResponse(
  response: APIResponse,
  method: string,
  pathname: string,
): boolean {
  const url = new URL(response.url())
  return response.request().method() === method && url.pathname === pathname
}

async function data<T>(response: APIResponse): Promise<T> {
  expect(response.ok(), await response.text()).toBe(true)
  const payload = (await response.json()) as Envelope<T>
  expect(payload.meta.requestId).toMatch(/^[a-f0-9-]+$/)
  return payload.data
}

async function login(page: Page, target = '/'): Promise<void> {
  await page.goto(target)
  await expect(page).toHaveURL(/\/login(?:\?|$)/)
  await expect(
    page.getByRole('heading', {
      level: 1,
      name: '库博二进制代码静态分析工具系统V1.0',
    }),
  ).toBeVisible()
  await expect(page).toHaveTitle('库博二进制代码静态分析工具系统V1.0')

  await page.getByLabel('用户名').fill(username)
  await page.getByLabel('密码').fill(password)
  const loginResponse = page.waitForResponse((response) =>
    isResponse(response, 'POST', '/api/v1/auth/login'),
  )
  await page.getByRole('button', { name: '登录' }).click()
  expect((await loginResponse).status()).toBe(200)

  await expect(page).toHaveURL(
    target === '/' ? /\/$/ : new RegExp(`${target.replace('/', '\\/')}$`),
  )
  await expect(
    page.locator('.brand').getAttribute('aria-label'),
  ).resolves.toBe('库博二进制代码静态分析工具系统V1.0')
}

test('真实登录、首页、系统管理 API 与退出链路可用', async ({ page }) => {
  await login(page)
  await expect(page.getByRole('heading', { name: '系统概览' })).toBeVisible()
  await expect(
    page.locator('.metrics').getByText('最近任务', { exact: true }),
  ).toBeVisible()

  const systemResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', '/api/v1/admin/system'),
  )
  const usersResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', '/api/v1/admin/users'),
  )
  const auditResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', '/api/v1/admin/audit-logs'),
  )
  const databaseResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', '/api/v1/admin/offline-dbs'),
  )
  await page.getByRole('link', { name: '系统维护' }).click()

  for (const response of await Promise.all([
    systemResponse,
    usersResponse,
    auditResponse,
    databaseResponse,
  ])) {
    expect(response.status(), await response.text()).toBe(200)
  }
  await expect(page.getByRole('heading', { name: '系统维护' })).toBeVisible()
  await expect(page.getByText('服务状态', { exact: true })).toBeVisible()
  await expect(page.getByText('UI PREVIEW')).toHaveCount(0)

  const logoutResponse = page.waitForResponse((response) =>
    isResponse(response, 'POST', '/api/v1/auth/logout'),
  )
  await page.getByRole('button', { name: '退出登录' }).click()
  expect((await logoutResponse).status()).toBe(204)
  await expect(page).toHaveURL(/\/login$/)

  const me = await page.request.get('/api/v1/me')
  expect(me.status()).toBe(401)
})

test('浏览器真实分片上传、任务执行、文件树与结果 API 全链路可用', async ({
  page,
}) => {
  await login(page, '/tasks/new')
  await expect(page.getByRole('heading', { name: '新建任务' })).toBeVisible()

  const filename = 'live-browser-connection.bin'
  const sample = Buffer.from(
    'Kubor live browser upload, API, worker, database and report connection.\n',
  )
  const expectedSHA256 = createHash('sha256').update(sample).digest('hex')

  await page.getByLabel('选择待检测文件').setInputFiles({
    name: filename,
    mimeType: 'application/octet-stream',
    buffer: sample,
  })

  const createUploadResponse = page.waitForResponse((response) =>
    isResponse(response, 'POST', '/api/v1/uploads'),
  )
  const uploadPartResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'PUT' &&
      /^\/api\/v1\/uploads\/[a-f0-9-]+\/parts\/1$/.test(url.pathname)
    )
  })
  const completeUploadResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'POST' &&
      /^\/api\/v1\/uploads\/[a-f0-9-]+\/complete$/.test(url.pathname)
    )
  })
  const createTaskResponse = page.waitForResponse((response) =>
    isResponse(response, 'POST', '/api/v1/tasks'),
  )

  await page.getByRole('button', { name: '开始上传' }).click()
  const [createdUpload, uploadedPart, completedUpload, taskResponse] =
    await Promise.all([
      createUploadResponse,
      uploadPartResponse,
      completeUploadResponse,
      createTaskResponse,
    ])
  expect(createdUpload.status()).toBe(201)
  expect(uploadedPart.status()).toBe(204)
  expect(completedUpload.status()).toBe(200)
  expect(taskResponse.status()).toBe(201)
  const createdTask = await data<CreatedTask>(taskResponse)
  expect(createdTask.id).toMatch(
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
  )

  const queue = page.getByRole('list', { name: '上传队列' })
  await expect(queue.getByText('任务已创建')).toBeVisible()
  await expect(queue.getByLabel(`${filename} 上传进度 100%`)).toBeVisible()

  let terminalTask: TaskDetail | undefined
  await expect
    .poll(
      async () => {
        const response = await page.request.get(
          `/api/v1/tasks/${createdTask.id}`,
        )
        terminalTask = await data<TaskDetail>(response)
        return terminalTask.status
      },
      { timeout: 30_000, intervals: [250, 500, 1_000] },
    )
    .toBe('SUCCEEDED')

  expect(terminalTask).toMatchObject({
    id: createdTask.id,
    sha256: expectedSHA256,
    size_bytes: sample.byteLength,
  })
  expect(terminalTask?.input_type).toBeTruthy()

  const listResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', '/api/v1/tasks'),
  )
  await page.getByRole('link', { name: '检测任务' }).click()
  expect((await listResponse).status()).toBe(200)
  await expect(page.getByRole('button', { name: `查看任务：${filename}` })).toBeVisible()
  await page.getByRole('button', { name: `查看任务：${filename}` }).click()

  await expect(page).toHaveURL(new RegExp(`/tasks/${createdTask.id}$`))
  await expect(page.getByLabel('执行状态：已完成')).toBeVisible()
  await expect(page.getByText(expectedSHA256, { exact: true })).toBeVisible()
  await expect(
    page.getByRole('button', { name: `查看 ${filename} 的节点详情` }),
  ).toBeVisible()

  const decompileResponse = page.waitForResponse((response) =>
    isResponse(
      response,
      'GET',
      `/api/v1/tasks/${createdTask.id}/decompile-results`,
    ),
  )
  await page.getByRole('tab', { name: '反编译' }).click()
  expect((await decompileResponse).status()).toBe(200)
  await expect(page.getByText('暂无反编译结果')).toBeVisible()

  const vulnerabilityResponse = page.waitForResponse((response) =>
    isResponse(
      response,
      'GET',
      `/api/v1/tasks/${createdTask.id}/vulnerabilities`,
    ),
  )
  await page.getByRole('tab', { name: '容器漏洞' }).click()
  expect((await vulnerabilityResponse).status()).toBe(200)
  await expect(page.getByText('未发现容器漏洞')).toBeVisible()

  const reportsResponse = page.waitForResponse((response) =>
    isResponse(response, 'GET', `/api/v1/tasks/${createdTask.id}/reports`),
  )
  await page.getByRole('tab', { name: '报告' }).click()
  expect((await reportsResponse).status()).toBe(200)

  for (const format of ['JSON', 'HTML'] as const) {
    const reportResponse = page.waitForResponse((response) =>
      isResponse(
        response,
        'POST',
        `/api/v1/tasks/${createdTask.id}/reports`,
      ),
    )
    const row = page.getByRole('region', { name: `${format} 报告` })
    await row.getByRole('button', { name: `生成 ${format} 报告` }).click()
    expect((await reportResponse).status()).toBe(201)
    await expect(row).toContainText('已完成')
    await expect(row.getByRole('button', { name: `下载 ${format} 报告` })).toBeVisible()
  }
  await expect(page.getByText('2/2 已完成')).toBeVisible()

  writeFileSync(
    resultPath,
    `${JSON.stringify({
      task_id: createdTask.id,
      size_bytes: sample.byteLength,
      sha256: expectedSHA256,
    })}\n`,
    { encoding: 'utf8', mode: 0o600 },
  )
})
