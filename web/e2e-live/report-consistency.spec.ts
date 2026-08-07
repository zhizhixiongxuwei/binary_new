import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

import { expect, test, type APIResponse, type Download, type Locator } from '@playwright/test'

interface DatabaseTaskSnapshot {
  id: string
  name: string
  input_type: string
  status: string
  risk_level: string
  progress_basis_points: number
  creator_id: string
  creator_name: string
  original_filename: string
  size_bytes: number
  sha256: string
  sample_relation: string
}

interface BrowserTask {
  id: string
  name: string
  input_type: string
  status: string
  risk_level: string
  progress: number
  progress_indeterminate: boolean
  creator_id: string
  creator_name: string
  original_filename: string
  size_bytes: number
  sha256: string
}

interface ReportSnapshot {
  id: string
  task_id: string
  format: 'json' | 'html'
  schema_version: string
  status: string
  sha256: string
  size_bytes: number
}

interface DatabaseSnapshot {
  provenance: {
    source: string
    schema_version: number
    analyzer_run_count: number
  }
  task: DatabaseTaskSnapshot
  reports: ReportSnapshot[]
}

interface Envelope<T> {
  data: T
  meta: { requestId: string }
}

interface ReportList {
  items: ReportSnapshot[]
  sample_relation: string
}

interface JsonReport {
  schemaVersion: string
  reportId: string
  task: {
    id: string
    name: string
    status: string
    riskLevel: string
    rootFormat: string
    progressBasisPoints: number
  }
  input: {
    filename: string
    sizeBytes: number
    sha256: string
  }
  analyzerRuns: unknown[]
}

const snapshotPath = process.env.BINARYSCAN_LIVE_E2E_SNAPSHOT
const username = process.env.BINARYSCAN_LIVE_E2E_USERNAME
const password = process.env.BINARYSCAN_LIVE_E2E_PASSWORD

if (!snapshotPath || !username || !password) {
  throw new Error(
    'Live E2E fixture variables are required; run scripts/e2e-live-report.sh',
  )
}

const snapshot = JSON.parse(
  readFileSync(snapshotPath, 'utf8'),
) as DatabaseSnapshot

function report(format: ReportSnapshot['format']): ReportSnapshot {
  const value = snapshot.reports.find((candidate) => candidate.format === format)
  if (!value) throw new Error(`database snapshot is missing ${format} report`)
  return value
}

function sha256(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex')
}

async function responseData<T>(response: APIResponse): Promise<T> {
  expect(response.ok(), await response.text()).toBe(true)
  const payload = (await response.json()) as Envelope<T>
  expect(payload.meta.requestId).toMatch(/^[a-f0-9-]+$/)
  return payload.data
}

async function downloadedBytes(download: Download): Promise<Buffer> {
  const failure = await download.failure()
  expect(failure).toBeNull()
  const path = await download.path()
  expect(path).not.toBeNull()
  return readFileSync(path!)
}

async function assertReportBytes(
  response: APIResponse,
  download: Download,
  expected: ReportSnapshot,
): Promise<Buffer> {
  expect(response.ok()).toBe(true)
  expect(response.headers()['x-checksum-sha256']).toBe(expected.sha256)
  expect(Number(response.headers()['content-length'])).toBe(expected.size_bytes)

  const apiBytes = await response.body()
  const browserBytes = await downloadedBytes(download)
  expect(browserBytes.equals(apiBytes)).toBe(true)
  expect(browserBytes.byteLength).toBe(expected.size_bytes)
  expect(sha256(browserBytes)).toBe(expected.sha256)
  return browserBytes
}

async function downloadFromRow(
  row: Locator,
  accessibleName: string,
): Promise<Download> {
  const page = row.page()
  const download = page.waitForEvent('download')
  await row.getByRole('button', { name: accessibleName }).click()
  return download
}

test('真实页面、API、MySQL 与 JSON/HTML 报告关键字段一致', async ({ page }) => {
  expect(snapshot.provenance.source).toBe('mysql-query')
  expect(Number.isInteger(snapshot.provenance.schema_version)).toBe(true)
  expect(snapshot.provenance.schema_version).toBeGreaterThan(0)
  expect(snapshot.provenance.analyzer_run_count).toBe(0)

  const ready = await page.request.get('/api/v1/health/ready')
  expect(ready.status()).toBe(200)
  await expect(ready.json()).resolves.toMatchObject({
    data: { dependencies: { mysql: { status: 'ready' } } },
  })

  await page.goto(`/tasks/${snapshot.task.id}`)
  await expect(page).toHaveURL(/\/login\?.*redirect=/)
  await page.getByLabel('用户名').fill(username)
  await page.getByLabel('密码').fill(password)

  const taskResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      response.url().endsWith(`/api/v1/tasks/${snapshot.task.id}`),
  )
  await page.getByRole('button', { name: '登录' }).click()
  const browserTask = await responseData<BrowserTask>(await taskResponsePromise)

  await expect(page).toHaveURL(new RegExp(`/tasks/${snapshot.task.id}$`))
  await expect(page.getByRole('heading', { name: '任务详情' })).toBeVisible()
  await expect(page.getByText(snapshot.task.original_filename, { exact: true })).toBeVisible()
  await expect(page.getByText(snapshot.task.id, { exact: true }).first()).toBeVisible()
  await expect(page.getByText(snapshot.task.sha256, { exact: true })).toBeVisible()
  await expect(page.getByLabel('执行状态：已完成')).toBeVisible()
  await expect(page.getByLabel('风险等级：高危')).toBeVisible()
  const expectedProgress = snapshot.task.progress_basis_points / 100
  await expect(
    page.getByRole('progressbar', { name: `任务进度 ${expectedProgress}%` }),
  ).toHaveAttribute('aria-valuenow', String(expectedProgress))

  expect(browserTask).toMatchObject({
    id: snapshot.task.id,
    name: snapshot.task.name,
    input_type: snapshot.task.input_type,
    status: snapshot.task.status,
    risk_level: snapshot.task.risk_level,
    progress: expectedProgress,
    progress_indeterminate: false,
    creator_id: snapshot.task.creator_id,
    creator_name: snapshot.task.creator_name,
    original_filename: snapshot.task.original_filename,
    size_bytes: snapshot.task.size_bytes,
    sha256: snapshot.task.sha256,
  })

  const reportsResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'GET' &&
      response.url().endsWith(`/api/v1/tasks/${snapshot.task.id}/reports`),
  )
  await page.getByRole('tab', { name: '报告' }).click()
  const browserReports = await responseData<ReportList>(await reportsResponsePromise)
  expect(browserReports.sample_relation).toBe(snapshot.task.sample_relation)
  expect(browserReports.items).toHaveLength(2)

  for (const expected of snapshot.reports) {
    expect(browserReports.items).toContainEqual(expect.objectContaining(expected))
    const row = page.getByRole('region', {
      name: expected.format === 'json' ? 'JSON 报告' : 'HTML 报告',
    })
    await expect(row).toContainText(expected.sha256)
    await expect(row).toContainText(expected.schema_version)
    await expect(row).toContainText('已完成')
  }
  await expect(page.getByText('2/2 已完成')).toBeVisible()
  await expect(page.getByText('样本保留中')).toHaveCount(2)

  const json = report('json')
  const jsonRow = page.getByRole('region', { name: 'JSON 报告' })
  const jsonDownload = await downloadFromRow(jsonRow, '下载 JSON 报告')
  expect(jsonDownload.suggestedFilename()).toBe(
    `binaryscan-${snapshot.task.id}-report.json`,
  )
  const jsonAPI = await page.request.get(
    `/api/v1/tasks/${snapshot.task.id}/reports/${json.id}/download`,
  )
  const jsonBytes = await assertReportBytes(jsonAPI, jsonDownload, json)
  const jsonDocument = JSON.parse(jsonBytes.toString('utf8')) as JsonReport
  expect(jsonDocument).toMatchObject({
    schemaVersion: json.schema_version,
    reportId: json.id,
    task: {
      id: snapshot.task.id,
      name: snapshot.task.name,
      status: snapshot.task.status,
      riskLevel: snapshot.task.risk_level,
      rootFormat: snapshot.task.input_type,
      progressBasisPoints: snapshot.task.progress_basis_points,
    },
    input: {
      filename: snapshot.task.original_filename,
      sizeBytes: snapshot.task.size_bytes,
      sha256: snapshot.task.sha256,
    },
    analyzerRuns: [],
  })

  const html = report('html')
  const htmlRow = page.getByRole('region', { name: 'HTML 报告' })
  const htmlDownload = await downloadFromRow(htmlRow, '下载 HTML 报告')
  expect(htmlDownload.suggestedFilename()).toBe(
    `binaryscan-${snapshot.task.id}-report.html`,
  )
  const htmlAPI = await page.request.get(
    `/api/v1/tasks/${snapshot.task.id}/reports/${html.id}/download`,
  )
  const htmlBytes = await assertReportBytes(htmlAPI, htmlDownload, html)
  const htmlDocument = htmlBytes.toString('utf8')
  expect(htmlDocument).toContain('data-report-contract="binaryscan-report/v1"')
  expect(htmlDocument).toContain(`data-task-id="${snapshot.task.id}"`)
  expect(htmlDocument).toContain(`data-report-id="${html.id}"`)
  expect(htmlDocument).toContain(
    `<td data-report-field="task-name">${snapshot.task.name}</td>`,
  )
  expect(htmlDocument).toContain(
    `<td data-report-field="input-filename">${snapshot.task.original_filename}</td>`,
  )
  expect(htmlDocument).toContain(snapshot.task.sha256)
  expect(htmlDocument).toContain('<td colspan="5">无分析器记录</td>')
})
