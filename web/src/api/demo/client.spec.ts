import { afterEach, describe, expect, it, vi } from 'vitest'

import { configureApiClient, resetApiClient } from '@/api/client'
import { createDemoApiClient } from '@/api/demo/client'
import {
  DEMO_OPERATOR,
  DEMO_READER,
  DEMO_TASK_IDS,
} from '@/api/demo/fixtures'
import { useChunkUpload } from '@/composables/useChunkUpload'

describe('standalone demo API', () => {
  afterEach(() => {
    resetApiClient()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('serves deterministic task pages without using fetch', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo API must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const firstPage = await demoApi.listTasks({ page_size: 2 })
    expect(firstPage.next_cursor).toBe('demo-offset-2')
    const nextCursor = firstPage.next_cursor
    if (!nextCursor) throw new Error('demo task cursor missing')
    const secondPage = await demoApi.listTasks({
      cursor: nextCursor,
      page_size: 2,
    })

    expect(firstPage.items).toHaveLength(2)
    expect(secondPage.items).toHaveLength(2)
    expect(secondPage.items[0]?.id).not.toBe(firstPage.items[0]?.id)
    expect(firstPage.items.map((task) => task.status)).toEqual([
      'SCANNING',
      'PARTIAL_SUCCEEDED',
    ])
    expect(
      firstPage.items.every(
        (task) =>
          Object.prototype.hasOwnProperty.call(task, 'sample_deleted_at') &&
          task.sample_deleted_at === null,
      ),
    ).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('filters demo tasks by creator, exact tag, and inclusive creation dates', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const creator = await demoApi.listTasks({
      page_size: 20,
      creator: '界面预览管',
    })
    const exactTag = await demoApi.listTasks({
      page_size: 20,
      tag: 'firmware',
    })
    const mismatchedTagCase = await demoApi.listTasks({
      page_size: 20,
      tag: 'FIRMWARE',
    })
    const dateRange = await demoApi.listTasks({
      page_size: 20,
      created_from: '2026-07-29',
      created_to: '2026-07-30',
    })
    const oneDay = await demoApi.listTasks({
      page_size: 20,
      created_from: '2026-07-29',
      created_to: '2026-07-29',
    })

    expect(creator.items).toHaveLength(6)
    expect(exactTag.items.map((task) => task.name)).toEqual([
      'gateway-firmware.tar',
    ])
    expect(mismatchedTagCase.items).toHaveLength(0)
    expect(dateRange.items).toHaveLength(5)
    expect(oneDay.items).toHaveLength(3)
    expect(
      oneDay.items.every((task) => task.created_at.startsWith('2026-07-29')),
    ).toBe(true)
  })

  it('paginates one branch and returns metadata with a string parent identifier', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const root = await demoApi.listTaskFiles(DEMO_TASK_IDS.firmware, {
      page_size: 1,
    })
    expect(root.items).toHaveLength(1)
    expect(root.next_cursor).toBeUndefined()

    const firstChildren = await demoApi.listTaskFiles(DEMO_TASK_IDS.firmware, {
      parent_id: root.items[0]!.id,
      page_size: 2,
    })
    expect(firstChildren.items).toHaveLength(2)
    expect(firstChildren.next_cursor).toBe('demo-offset-2')
    const nextCursor = firstChildren.next_cursor
    if (!nextCursor) throw new Error('expected the first child page to have a cursor')

    const remainingChildren = await demoApi.listTaskFiles(DEMO_TASK_IDS.firmware, {
      parent_id: root.items[0]!.id,
      cursor: nextCursor,
      page_size: 2,
    })
    expect(remainingChildren.items).toHaveLength(2)

    const detail = await demoApi.getTaskFile(
      DEMO_TASK_IDS.firmware,
      firstChildren.items[0]!.id,
    )
    expect(typeof detail.id).toBe('string')
    expect(detail.source_parent).toEqual({
      id: root.items[0]!.id,
      logical_path: '/gateway-firmware.tar',
    })
    expect(detail.source_container).toEqual({
      id: root.items[0]!.id,
      logical_path: '/gateway-firmware.tar',
      format: 'tar',
    })
    expect(detail.metadata_json).toMatchObject({ entry_count: 5 })
  })

  it('keeps file decompile submission explicitly read-only without HTTP', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo decompile must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(
      demoApi.createFileDecompileRequest(
        DEMO_TASK_IDS.firmware,
        '18446744073709551005',
        { engine_target: 'auto', options: {} },
        'demo-decompile-intent',
      ),
    ).rejects.toMatchObject({
      status: 501,
      code: 'DEMO_READ_ONLY',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('keeps decompile job status explicitly read-only without HTTP', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo decompile status must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(
      demoApi.getFileDecompileRequest(
        DEMO_TASK_IDS.firmware,
        '323e4567-e89b-42d3-a456-426614174002',
      ),
    ).rejects.toMatchObject({
      status: 501,
      code: 'DEMO_READ_ONLY',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('keeps bulk decompile source export explicitly read-only without HTTP', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo source export must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(
      demoApi.downloadDecompileSources(DEMO_TASK_IDS.executable, true),
    ).rejects.toMatchObject({
      status: 501,
      code: 'DEMO_READ_ONLY',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('supports an explicit demo logout and administrator login', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(demoApi.getMe()).resolves.toMatchObject({
      role: 'administrator',
      username: 'demo-admin',
    })
    await demoApi.logout()
    await expect(demoApi.getMe()).rejects.toMatchObject({
      status: 401,
      code: 'UNAUTHENTICATED',
    })
    await expect(
      demoApi.login({ username: 'preview', password: 'preview' }),
    ).resolves.toMatchObject({
      role: 'administrator',
      must_change_password: false,
    })
  })

  it('selects deterministic operator and reader profiles by demo username', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await demoApi.logout()
    await expect(
      demoApi.login({ username: DEMO_READER.username, password: 'preview' }),
    ).resolves.toEqual(DEMO_READER)
    await demoApi.logout()
    await expect(
      demoApi.login({ username: DEMO_OPERATOR.username, password: 'preview' }),
    ).resolves.toEqual(DEMO_OPERATOR)
  })

  it('provides a deterministic login cooldown without using transport state', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(
      demoApi.login({
        username: 'demo-rate-limited',
        password: 'never-persisted',
      }),
    ).rejects.toMatchObject({
      status: 429,
      code: 'login_rate_limited',
      retryAfterSeconds: 3,
    })
  })

  it('completes the pure frontend upload and creates a browsable preview task', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo upload must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })
    const upload = await demoApi.createUpload(
      {
        filename: 'local-sample.exe',
        size: 4,
        content_type: 'application/octet-stream',
      },
      'demo-upload-create',
    )

    await demoApi.uploadPart(upload.id, {
      part_number: 1,
      start: 0,
      end: 3,
      total: 4,
      sha256: 'a'.repeat(64),
      chunk: new Blob(['demo']),
    })
    await expect(demoApi.completeUpload(upload.id)).resolves.toMatchObject({
      status: 'completed',
      size_bytes: 4,
    })

    const created = await demoApi.createTask(
      { upload_id: upload.id, name: 'local-sample.exe' },
      'demo-idempotency-key',
    )
    expect(typeof created.id).toBe('string')
    await expect(demoApi.getTask(created.id)).resolves.toMatchObject({
      name: 'local-sample.exe',
      status: 'QUEUED',
    })
    const files = await demoApi.listTaskFiles(created.id)
    expect(files.items[0]).toMatchObject({
      display_name: 'local-sample.exe',
      extraction_status: 'queued',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('replays upload creation by key and rejects a changed request', async () => {
    const demoApi = createDemoApiClient({ delayMs: 0 })
    const input = {
      filename: 'idempotent.bin',
      size: 4,
      content_type: 'application/octet-stream',
    }
    const created = await demoApi.createUpload(input, 'stable-upload-key')
    await demoApi.uploadPart(created.id, {
      part_number: 1,
      start: 0,
      end: 3,
      total: 4,
      sha256: 'a'.repeat(64),
      chunk: new Blob(['demo']),
    })
    await demoApi.completeUpload(created.id)

    await expect(
      demoApi.createUpload(input, 'stable-upload-key'),
    ).resolves.toEqual(created)
    await expect(
      demoApi.createUpload(
        { ...input, filename: 'different.bin' },
        'stable-upload-key',
      ),
    ).rejects.toMatchObject({
      status: 409,
      code: 'idempotency_conflict',
    })
  })

  it('keeps lifecycle actions deterministic and entirely in memory', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo task actions must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const cancelled = await demoApi.cancelTask(
      DEMO_TASK_IDS.executable,
      'cancel-intent',
    )
    const repeatedCancel = await demoApi.cancelTask(
      DEMO_TASK_IDS.executable,
      'cancel-intent',
    )
    const retried = await demoApi.retryTask(
      DEMO_TASK_IDS.damagedImage,
      'retry-intent',
    )
    const deleting = await demoApi.deleteTask(DEMO_TASK_IDS.firmware)

    expect(cancelled.status).toBe('CANCEL_REQUESTED')
    expect(repeatedCancel).toEqual(cancelled)
    expect(retried).toMatchObject({
      status: 'QUEUED',
      progress: 0,
      current_stage: 'QUEUED',
    })
    expect(retried.error_code).toBeUndefined()
    expect(retried.error_message).toBeUndefined()
    expect(deleting.status).toBe('DELETING')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('implements the report transport contract without changing the fixed demo preview', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo reports must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const created = await demoApi.createTaskReport(
      DEMO_TASK_IDS.executable,
      { format: 'json' },
      'demo-report-intent',
    )
    const repeated = await demoApi.createTaskReport(
      DEMO_TASK_IDS.executable,
      { format: 'json' },
      'demo-report-intent',
    )
    const listed = await demoApi.listTaskReports(DEMO_TASK_IDS.executable)
    const download = await demoApi.downloadTaskReport(
      DEMO_TASK_IDS.executable,
      created.id,
      'json',
    )

    expect(created).toMatchObject({
      task_id: DEMO_TASK_IDS.executable,
      format: 'json',
      status: 'complete',
    })
    expect(repeated).toEqual(created)
    expect(listed.items).toEqual([created])
    expect(listed.sample_relation).toBe('retained')
    expect(download.kind).toBe('blob')
    if (download.kind !== 'blob') {
      throw new Error('demo report downloads must use the Blob transport')
    }
    expect(download.filename).toBe('binaryscan-report.json')
    expect(download.blob).toBeInstanceOf(Blob)
    expect(download.blob.size).toBeGreaterThan(0)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('previews maintenance reads but rejects account mutations explicitly', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo maintenance must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })

    const system = await demoApi.getSystemStatus()
    const users = await demoApi.listAdminUsers({ page_size: 1 })
    const audit = await demoApi.listAuditLogs({
      action: 'auth.login',
      page_size: 10,
    })

    expect(system.storage_mounts).toHaveLength(2)
		expect(system.trivy_database_bundle?.status).toBe('stale')
    expect(users.items).toHaveLength(1)
    expect(users.next_cursor).toBe('demo-offset-1')
    expect(audit.items).toHaveLength(1)
    expect(audit.items[0]?.actor?.username).toBe('demo-admin')
    await expect(
      demoApi.createAdminUser({
        username: 'new-reader',
        display_name: '新用户',
        role: 'reader',
        temporary_password: 'temporary-pass-123',
      }),
    ).rejects.toMatchObject({
      status: 501,
      code: 'DEMO_READ_ONLY',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('extends demo retention with compare-and-set semantics without HTTP', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo retention must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })
    const before = await demoApi.getTask(DEMO_TASK_IDS.firmware)
    const expected = before.sample_expires_at
    if (!expected) throw new Error('demo fixture must have an expiry')
    const next = new Date(expected)
    next.setUTCDate(next.getUTCDate() + 15)

    const extended = await demoApi.extendTaskRetention(
      DEMO_TASK_IDS.firmware,
      {
        expected_sample_expires_at: expected,
        sample_expires_at: next.toISOString(),
      },
    )

    expect(extended.sample_expires_at).toBe(next.toISOString())
    await expect(
      demoApi.extendTaskRetention(DEMO_TASK_IDS.firmware, {
        expected_sample_expires_at: expected,
        sample_expires_at: next.toISOString(),
      }),
    ).rejects.toMatchObject({
      status: 409,
      code: 'RETENTION_CONFLICT',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('rejects demo retries after retention expiry like the live API', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-09-01T00:00:00Z'))
    const demoApi = createDemoApiClient({ delayMs: 0 })

    await expect(
      demoApi.retryTask(DEMO_TASK_IDS.damagedImage, 'expired-retry'),
    ).rejects.toMatchObject({
      status: 409,
      code: 'task_sample_unavailable',
    })
  })

  it('cancels an unfinished demo upload without reaching HTTP', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo upload deletion must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    const demoApi = createDemoApiClient({ delayMs: 0 })
    const upload = await demoApi.createUpload(
      {
        filename: 'cancel-me.tar',
        size: 12,
        content_type: 'application/x-tar',
      },
      'demo-upload-cancel',
    )

    await expect(demoApi.deleteUpload(upload.id)).resolves.toBeUndefined()
    await expect(demoApi.getUpload(upload.id)).rejects.toMatchObject({
      status: 404,
      code: 'UPLOAD_NOT_FOUND',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('drives the existing upload composable end to end through the demo boundary', async () => {
    const fetchMock = vi.fn(() => {
      throw new Error('demo upload workflow must not call fetch')
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('crypto', {
      randomUUID: vi
        .fn()
        .mockReturnValueOnce('demo-local-id')
        .mockReturnValueOnce('demo-task-intent'),
      subtle: {
        digest: vi.fn().mockResolvedValue(Uint8Array.from([0xca, 0xfe]).buffer),
      },
    })
    configureApiClient(createDemoApiClient({ delayMs: 0 }))
    const uploads = useChunkUpload()
    const file = new File(['standalone preview'], 'standalone.exe')
    vi.spyOn(file, 'slice').mockReturnValue({
      arrayBuffer: vi.fn().mockResolvedValue(new ArrayBuffer(18)),
    } as unknown as Blob)
    uploads.addFiles([file])

    await uploads.startAll()

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'completed',
      progress: 100,
      uploadedBytes: 18,
    })
    expect(uploads.queue.value[0]?.taskId).toMatch(
      /^90000000-0000-4000-8000-\d{12}$/,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
