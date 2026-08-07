import { readFileSync } from 'node:fs'

import { expect, test, type Page } from '@playwright/test'

interface GhidraAcceptance {
  task_id: string
  job_id: string
  node_id: string
  sample_sha256: string
  format: string
  architecture: string
  result_count: number
  completed_result_count: number
  total_source_bytes: number
  engine: string
  engine_version: string
  monaco_source_api_verified: boolean
}

interface DecompileResult {
  id: string
  file_node_id: string
  language: string
  engine_name: string
  engine_version: string
  status: string
}

interface DecompilePageEnvelope {
  data: {
    items: DecompileResult[]
    next_cursor?: string
  }
}

interface FilePageEnvelope {
  data: {
    items: Array<{
      id: string
      format: string
      architecture: string
      sha256: string
    }>
  }
}

interface SourceEnvelope {
  data: {
    content: string
    complete: boolean
    size_bytes: number
  }
}

const username = process.env.BINARYSCAN_LIVE_E2E_USERNAME
const password = process.env.BINARYSCAN_LIVE_E2E_PASSWORD
const acceptancePath = process.env.BINARYSCAN_LIVE_GHIDRA_RESULT

test.skip(
  !username || !password || !acceptancePath,
  'BINARYSCAN_LIVE_E2E_USERNAME, BINARYSCAN_LIVE_E2E_PASSWORD and BINARYSCAN_LIVE_GHIDRA_RESULT are required',
)

function loadAcceptance(): GhidraAcceptance {
  const value = JSON.parse(
    readFileSync(acceptancePath!, 'utf8'),
  ) as GhidraAcceptance
  expect(value.task_id).toMatch(
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,
  )
  expect(value.result_count).toBeGreaterThan(0)
  expect(value.completed_result_count).toBe(value.result_count)
  expect(value.total_source_bytes).toBeGreaterThan(0)
  expect(value.format).toBe('macho-thin')
  expect(value.architecture).toBe('x86_64')
  expect(value.engine).toBe('ghidra')
  expect(value.engine_version).toBe('12.1.2')
  expect(value.monaco_source_api_verified).toBe(true)
  return value
}

async function assertAllResultPages(
  page: Page,
  acceptance: GhidraAcceptance,
): Promise<void> {
  const ids = new Set<string>()
  let cursor = ''
  let pageCount = 0
  do {
    const query = new URLSearchParams({ page_size: '200' })
    if (cursor) query.set('cursor', cursor)
    const body = await browserData<DecompilePageEnvelope>(
      page,
      `/api/v1/tasks/${acceptance.task_id}/decompile-results?${query}`,
    )
    expect(body.data.items.length).toBeGreaterThan(0)
    expect(body.data.items.length).toBeLessThanOrEqual(200)
    for (const item of body.data.items) {
      expect(item).toMatchObject({
        file_node_id: acceptance.node_id,
        language: 'c',
        engine_name: acceptance.engine,
        engine_version: acceptance.engine_version,
        status: 'complete',
      })
      expect(ids.has(item.id)).toBe(false)
      ids.add(item.id)
    }
    cursor = body.data.next_cursor ?? ''
    pageCount += 1
    expect(pageCount).toBeLessThan(100)
  } while (cursor)

  expect(ids.size).toBe(acceptance.result_count)
  expect(pageCount).toBeGreaterThan(1)
}

async function login(page: Page, target: string): Promise<void> {
  await page.goto(target)
  await expect(page).toHaveURL(/\/login(?:\?|$)/)
  await page.getByLabel('用户名').fill(username!)
  await page.getByLabel('密码').fill(password!)
  const loginResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'POST' &&
      url.pathname === '/api/v1/auth/login'
    )
  })
  await page.getByRole('button', { name: '登录' }).click()
  expect((await loginResponse).status()).toBe(200)
  await page.waitForURL((url) => url.pathname === target)
}

async function browserData<T>(page: Page, path: string): Promise<T> {
  const result = await page.evaluate(async (target) => {
    const response = await fetch(target, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    return { status: response.status, text: await response.text() }
  }, path)
  expect(result.status, result.text).toBe(200)
  return JSON.parse(result.text) as T
}

test('真实 Ghidra 伪 C 由 Monaco 只读编辑器展示', async ({ page }, testInfo) => {
  const acceptance = loadAcceptance()
  const target = `/tasks/${acceptance.task_id}`
  await login(page, target)

  const files = await browserData<FilePageEnvelope>(
    page,
    `/api/v1/tasks/${acceptance.task_id}/files?page_size=200`,
  )
  expect(files.data.items).toContainEqual(
    expect.objectContaining({
      id: acceptance.node_id,
      format: acceptance.format,
      architecture: acceptance.architecture,
      sha256: acceptance.sample_sha256,
    }),
  )
  const decompileCommand = page.locator('button[data-action="decompile-file"]')
  await expect(decompileCommand).toBeVisible()
  await expect(decompileCommand).toBeEnabled()
  await expect(decompileCommand).toContainText('发起反编译')
  await assertAllResultPages(page, acceptance)

  const resultResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'GET' &&
      url.pathname === `/api/v1/tasks/${acceptance.task_id}/decompile-results`
    )
  })
  const sourceResponse = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      response.request().method() === 'GET' &&
      new RegExp(
        `^/api/v1/tasks/${acceptance.task_id}/decompile-results/[a-f0-9-]+/source$`,
      ).test(url.pathname)
    )
  })

  await page.getByRole('tab', { name: '反编译' }).click()
  const firstPageResponse = await resultResponse
  expect(firstPageResponse.status()).toBe(200)
  const firstPage = (await firstPageResponse.json()) as DecompilePageEnvelope
  expect(firstPage.data.items.length).toBeGreaterThan(0)
  expect(firstPage.data.items.length).toBeLessThan(acceptance.result_count)
  expect(firstPage.data.next_cursor).toBeTruthy()
  const source = await sourceResponse
  expect(source.status()).toBe(200)
  const sourceBody = (await source.json()) as SourceEnvelope
  expect(sourceBody.data.complete).toBe(true)
  expect(sourceBody.data.size_bytes).toBeGreaterThan(0)
  expect(sourceBody.data.content.trim().length).toBeGreaterThan(0)

  await expect(page.getByText('伪 C', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('ghidra 12.1.2 · complete')).toBeVisible()
  await expect(page.getByRole('tree', { name: '反编译符号' })).toBeVisible()
  expect(await page.getByRole('treeitem').count()).toBeGreaterThan(0)
  await expect(page.getByRole('button', { name: '加载更多符号' })).toBeVisible()
  await expect(
    page.getByText('Monaco 只读编辑器已就绪', { exact: true }),
  ).toBeVisible()
  await expect(
    page.locator('.read-only-editor[data-editor-state="ready"] .monaco-editor'),
  ).toBeVisible()
  const renderedSource = await page.locator('.monaco-editor .view-lines').textContent()
  expect(renderedSource).toMatch(/\S/)

  await page.screenshot({
    path: testInfo.outputPath('ghidra-monaco-live.png'),
    fullPage: true,
  })
})
