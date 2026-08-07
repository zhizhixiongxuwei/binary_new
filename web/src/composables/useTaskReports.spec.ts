import { flushPromises } from '@vue/test-utils'
import {
  effectScope,
  nextTick,
  shallowRef,
  type EffectScope,
} from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  DecompileResult,
  ReportDownload,
  ReportFormat,
  TaskReport,
  TaskReportList,
  TaskStatus,
  UserRole,
} from '@/api/types'
import { useTaskReports } from '@/composables/useTaskReports'

const activeScopes: EffectScope[] = []

function inScope<T>(factory: () => T): T {
  const scope = effectScope()
  const value = scope.run(factory)
  if (value === undefined) throw new Error('effect scope did not return a value')
  activeScopes.push(scope)
  return value
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function report(
  format: ReportFormat,
  overrides: Partial<TaskReport> = {},
): TaskReport {
  return {
    id: `report-${format}`,
    task_id: 'task-reports',
    format,
    schema_version: '1.1.0',
    status: 'complete',
    sha256: format === 'json' ? 'a'.repeat(64) : 'b'.repeat(64),
    size_bytes: format === 'json' ? 1_024 : 2_048,
    error_code: null,
    error_message: null,
    created_at: '2026-07-30T01:00:00Z',
    completed_at: '2026-07-30T01:00:01Z',
    ...overrides,
  }
}

function decompileResult(
  overrides: Partial<DecompileResult> = {},
): DecompileResult {
  return {
    id: '223e4567-e89b-42d3-a456-426614174001',
    file_node_id: '42',
    symbol_key: 'FUN_140001000',
    symbol_kind: 'function',
    display_name: 'main',
    group_name: 'gocloc',
    location: '0x100001000',
    signature: 'int main(void)',
    detail: 'Ghidra output',
    language: 'c',
    engine_name: 'ghidra',
    engine_version: '12.1.2',
    status: 'complete',
    size_bytes: 128,
    diagnostics: {},
    created_at: '2026-08-04T01:00:00Z',
    completed_at: '2026-08-04T01:00:01Z',
    ...overrides,
  }
}

describe('useTaskReports', () => {
  beforeEach(() => {
    vi.spyOn(api, 'listDecompileResults').mockResolvedValue({ items: [] })
  })

  afterEach(() => {
    for (const scope of activeScopes.splice(0)) scope.stop()
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('moves from loading to an actionable empty state', async () => {
    const pending = deferred<TaskReportList>()
    const listReports = vi
      .spyOn(api, 'listTaskReports')
      .mockReturnValue(pending.promise)
    const role = shallowRef<UserRole | null>('operator')
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: role,
      }),
    )

    expect(results.loading.value).toBe(true)
    expect(results.state.value).toMatchObject({
      status: 'loading',
      title: '正在读取任务报告',
    })
    expect(listReports).toHaveBeenCalledWith('task-reports')

    pending.resolve({ items: [] })
    await flushPromises()

    expect(results.state.value).toMatchObject({
      status: 'empty',
      title: '尚未生成任务报告',
    })
    expect(results.canGenerate.value).toBe(true)

    role.value = 'reader'
    await nextTick()
    expect(results.state.value.description).toBe(
      '当前角色只能查看和下载已有报告，不能生成新报告。',
    )
  })

  it('probes one current result without coupling probe failures to report state', async () => {
    vi.mocked(api.listDecompileResults).mockResolvedValue({
      items: [decompileResult()],
    })
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [report('html')],
    })
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    expect(api.listDecompileResults).toHaveBeenCalledWith('task-reports', {
      page_size: 1,
    })
    expect(results.hasDecompileSources.value).toBe(true)
    expect(results.state.value.status).toBe('ready')

    vi.mocked(api.listDecompileResults).mockRejectedValueOnce(
      new ApiError('结果不存在', 404, { code: 'result_not_found' }),
    )
    results.refresh()
    await flushPromises()

    expect(results.hasDecompileSources.value).toBe(false)
    expect(results.state.value.status).toBe('ready')
    expect(results.actionError.value).toBe('')
  })

  it('lets readers inspect and download reports but never submit generation', async () => {
    const json = report('json')
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [json],
      sample_relation: 'deleted',
    })
    const createReport = vi.spyOn(api, 'createTaskReport')
    const role = shallowRef<UserRole | null>('reader')
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: role,
      }),
    )
    await flushPromises()

    expect(results.state.value).toEqual({ status: 'ready' })
    expect(results.reports.value).toEqual([json])
    expect(results.sampleRelation.value).toBe('deleted')
    expect(results.canGenerate.value).toBe(false)

    await results.generate('html')
    expect(createReport).not.toHaveBeenCalled()
    expect(results.actionError.value).toContain('只能查看和下载')

    role.value = 'administrator'
    await nextTick()
    expect(results.canGenerate.value).toBe(true)
  })

  it('keeps report generation read-only until an eligible task is terminal', async () => {
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [] })
    const createReport = vi.spyOn(api, 'createTaskReport')
    const taskStatus = shallowRef<TaskStatus>('SCANNING')
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus,
        userRole: 'administrator',
      }),
    )
    await flushPromises()

    expect(results.canGenerate.value).toBe(false)
    expect(results.generationHint.value).toContain('任务完成')
    await results.generate('json')
    expect(createReport).not.toHaveBeenCalled()
    expect(results.actionError.value).toContain('当前仅可查看已有报告')

    taskStatus.value = 'SUCCEEDED'
    await nextTick()
    expect(results.canGenerate.value).toBe(true)
  })

  it('submits each report format once and reuses its idempotency key after an error', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('report-intent'),
    })
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [
        report('json', {
          status: 'failed',
          sha256: null,
          size_bytes: null,
          completed_at: null,
          error_code: 'REPORT_FAILED',
          error_message: '模板渲染失败',
        }),
      ],
    })
    const retryRequest = deferred<TaskReport>()
    const createReport = vi
      .spyOn(api, 'createTaskReport')
      .mockRejectedValueOnce(
        new ApiError('报告服务繁忙', 503, { code: 'REPORT_BUSY' }),
      )
      .mockReturnValueOnce(retryRequest.promise)
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'operator',
      }),
    )
    await flushPromises()

    await results.generate('json')
    expect(results.actionError.value).toContain('报告服务繁忙')

    const retry = results.generate('json')
    void results.generate('json')
    expect(createReport).toHaveBeenCalledTimes(2)
    expect(createReport).toHaveBeenNthCalledWith(
      1,
      'task-reports',
      { format: 'json' },
      'report-intent',
    )
    expect(createReport).toHaveBeenNthCalledWith(
      2,
      'task-reports',
      { format: 'json' },
      'report-intent',
    )
    expect(results.generatingFormats.value).toEqual(['json'])

    retryRequest.resolve(report('json'))
    await retry

    expect(results.generatingFormats.value).toEqual([])
    expect(results.reports.value[0]).toMatchObject({
      format: 'json',
      status: 'complete',
    })
    expect(results.actionError.value).toBe('')
  })

  it('ignores list and generation results from a previous task', async () => {
    const oldList = deferred<TaskReportList>()
    const currentList = deferred<TaskReportList>()
    const taskId = shallowRef('task-old')
    vi.spyOn(api, 'listTaskReports')
      .mockReturnValueOnce(oldList.promise)
      .mockReturnValueOnce(currentList.promise)
    const results = inScope(() =>
      useTaskReports({
        taskId,
        taskStatus: 'SUCCEEDED',
        userRole: 'administrator',
      }),
    )

    taskId.value = 'task-current'
    await nextTick()
    currentList.resolve({
      items: [report('html', { task_id: 'task-current' })],
    })
    await flushPromises()

    oldList.resolve({
      items: [report('json', { task_id: 'task-old' })],
    })
    await flushPromises()

    expect(results.reports.value).toEqual([
      report('html', { task_id: 'task-current' }),
    ])
  })

  it('does not apply a completed generation after the task changes', async () => {
    const generation = deferred<TaskReport>()
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'createTaskReport').mockReturnValue(generation.promise)
    const taskId = shallowRef('task-reports')
    const results = inScope(() =>
      useTaskReports({
        taskId,
        taskStatus: 'SUCCEEDED',
        userRole: 'administrator',
      }),
    )
    await flushPromises()

    const pending = results.generate('json')
    taskId.value = 'task-current'
    await nextTick()
    generation.resolve(report('json'))
    await pending
    await flushPromises()

    expect(results.reports.value).toEqual([])
    expect(results.generatingFormats.value).toEqual([])
  })

  it('downloads a complete report with an object URL and always revokes it', async () => {
    vi.useFakeTimers()
    const json = report('json')
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [json] })
    vi.spyOn(api, 'downloadTaskReport').mockResolvedValue({
      kind: 'blob',
      blob: new Blob(['report']),
      filename: 'verified-report.json',
    })
    const createObjectURL = vi.fn().mockReturnValue('blob:report-download')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL })
    const append = vi.spyOn(document.body, 'append')
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    await results.download(json)

    expect(api.downloadTaskReport).toHaveBeenCalledWith(
      'task-reports',
      'report-json',
      'json',
      'identity',
    )
    expect(createObjectURL).toHaveBeenCalledOnce()
    const appendedAnchor = append.mock.calls[0]?.[0]
    expect(appendedAnchor).toBeInstanceOf(HTMLAnchorElement)
    expect((appendedAnchor as HTMLAnchorElement).download).toBe(
      'verified-report.json',
    )
    expect((appendedAnchor as HTMLAnchorElement).href).toBe(
      'blob:report-download',
    )
    expect(revokeObjectURL).not.toHaveBeenCalled()
    vi.advanceTimersByTime(29_999)
    expect(revokeObjectURL).not.toHaveBeenCalled()
    vi.advanceTimersByTime(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:report-download')
    expect(results.downloadingReportId.value).toBe('')
  })

  it('exports a task-current source archive with pending and isolated error states', async () => {
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [report('html')],
    })
    vi.mocked(api.listDecompileResults).mockResolvedValue({
      items: [decompileResult()],
    })
    const pending = deferred<ReportDownload>()
    const downloadSources = vi
      .spyOn(api, 'downloadDecompileSources')
      .mockReturnValueOnce(pending.promise)
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    results.exportSources(true)
    expect(results.exportingSources.value).toBe(true)
    expect(downloadSources).toHaveBeenCalledWith('task-reports', true)

    pending.resolve({
      kind: 'url',
      url: '/api/v1/tasks/task-reports/decompile-sources.zip?combined=true',
    })
    await flushPromises()

    expect(results.exportingSources.value).toBe(false)
    expect(results.actionError.value).toBe('')
    expect(click).toHaveBeenCalledOnce()

    downloadSources.mockRejectedValueOnce(new Error('归档空间不足'))
    results.exportSources(false)
    await flushPromises()

    expect(results.exportingSources.value).toBe(false)
    expect(results.actionError.value).toContain('导出反编译源码包失败')
    expect(results.actionError.value).toContain('归档空间不足')
  })

  it('uses a same-origin native URL without buffering the production report', async () => {
    const json = report('json')
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [json] })
    vi.spyOn(api, 'downloadTaskReport').mockResolvedValue({
      kind: 'url',
      url: '/api/v1/tasks/task-reports/reports/report-json/download',
    })
    const append = vi.spyOn(document.body, 'append')
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    await results.download(json)

    const appendedAnchor = append.mock.calls[0]?.[0] as HTMLAnchorElement
    expect(appendedAnchor.href).toBe(
      `${window.location.origin}/api/v1/tasks/task-reports/reports/report-json/download`,
    )
    expect(appendedAnchor.hasAttribute('download')).toBe(true)
    expect(appendedAnchor.download).toBe('')
    expect(results.actionError.value).toBe('')
  })

  it('requests the gzip representation for JSON without accepting it for HTML', async () => {
    const json = report('json')
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [json],
      sample_relation: 'retained',
    })
    vi.spyOn(api, 'downloadTaskReport').mockResolvedValue({
      kind: 'url',
      url: '/api/v1/tasks/task-reports/reports/report-json/download?encoding=gzip',
    })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    await results.download(json, 'gzip')

    expect(api.downloadTaskReport).toHaveBeenCalledWith(
      'task-reports',
      'report-json',
      'json',
      'gzip',
    )
    await results.download(report('html'), 'gzip')
    expect(api.downloadTaskReport).toHaveBeenCalledTimes(1)
    expect(results.actionError.value).toContain('只有 JSON 报告支持 gzip')
  })

  it('polls pending reports until settled and stops after completion', async () => {
    vi.useFakeTimers()
    const listReports = vi
      .spyOn(api, 'listTaskReports')
      .mockResolvedValueOnce({
        items: [report('json', { status: 'queued' })],
      })
      .mockResolvedValueOnce({
        items: [report('json', { status: 'generating' })],
      })
      .mockResolvedValueOnce({
        items: [report('json', { status: 'complete' })],
      })
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    expect(listReports).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(2_000)
    expect(listReports).toHaveBeenCalledTimes(2)
    expect(results.reports.value[0]?.status).toBe('generating')
    await vi.advanceTimersByTimeAsync(2_000)
    expect(listReports).toHaveBeenCalledTimes(3)
    expect(results.reports.value[0]?.status).toBe('complete')
    await vi.advanceTimersByTimeAsync(10_000)
    expect(listReports).toHaveBeenCalledTimes(3)
  })

  it('cancels the previous task poll when the task changes', async () => {
    vi.useFakeTimers()
    const taskId = shallowRef('task-reports')
    const listReports = vi
      .spyOn(api, 'listTaskReports')
      .mockResolvedValueOnce({
        items: [report('json', { status: 'queued' })],
      })
      .mockResolvedValueOnce({ items: [] })
    const results = inScope(() =>
      useTaskReports({
        taskId,
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    taskId.value = 'task-next'
    await nextTick()
    await flushPromises()
    expect(listReports).toHaveBeenNthCalledWith(2, 'task-next')
    expect(results.reports.value).toEqual([])

    await vi.advanceTimersByTimeAsync(10_000)
    expect(listReports).toHaveBeenCalledTimes(2)
  })

  it('bounds polling for a report that never leaves the pending state', async () => {
    vi.useFakeTimers()
    const listReports = vi.spyOn(api, 'listTaskReports').mockResolvedValue({
      items: [report('json', { status: 'generating' })],
    })
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    await vi.advanceTimersByTimeAsync(60_000)
    expect(listReports).toHaveBeenCalledTimes(31)
    expect(results.actionError.value).toContain('手动刷新')

    await vi.advanceTimersByTimeAsync(60_000)
    expect(listReports).toHaveBeenCalledTimes(31)
  })

  it('clears pending polls and releases a started Blob download URL on disposal', async () => {
    vi.useFakeTimers()
    const json = report('json', { status: 'queued' })
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [json] })
    vi.spyOn(api, 'downloadTaskReport').mockResolvedValue({
      kind: 'blob',
      blob: new Blob(['report']),
      filename: 'verified-report.json',
    })
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockReturnValue('blob:scope-download'),
      revokeObjectURL,
    })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()
    await results.download(report('json'))

    const scope = activeScopes.pop()
    scope?.stop()
    expect(revokeObjectURL).toHaveBeenCalledOnce()
    expect(api.listTaskReports).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:scope-download')
  })

  it('retains an allocated download URL for 30 seconds when the task changes during the click', async () => {
    vi.useFakeTimers()
    const json = report('json')
    const taskId = shallowRef('task-reports')
    vi.spyOn(api, 'listTaskReports')
      .mockResolvedValueOnce({ items: [json] })
      .mockResolvedValueOnce({ items: [] })
    vi.spyOn(api, 'downloadTaskReport').mockResolvedValue({
      kind: 'blob',
      blob: new Blob(['report']),
      filename: 'verified-report.json',
    })
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockImplementation(() => {
        taskId.value = 'task-next'
        return 'blob:task-switch'
      }),
      revokeObjectURL,
    })
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const results = inScope(() =>
      useTaskReports({
        taskId,
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    await results.download(json)
    await flushPromises()

    expect(results.reports.value).toEqual([])
    expect(revokeObjectURL).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(29_999)
    expect(revokeObjectURL).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:task-switch')
  })

  it('surfaces list and download errors without exposing a stale download', async () => {
    const listReports = vi
      .spyOn(api, 'listTaskReports')
      .mockRejectedValueOnce(
        new ApiError('报告索引不可用', 503, {
          code: 'REPORT_INDEX_UNAVAILABLE',
        }),
      )
      .mockResolvedValueOnce({ items: [report('html')] })
    const results = inScope(() =>
      useTaskReports({
        taskId: 'task-reports',
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      }),
    )
    await flushPromises()

    expect(results.state.value).toEqual({
      status: 'error',
      title: '报告结果读取失败',
      description: '报告索引不可用',
      errorCode: 'REPORT_INDEX_UNAVAILABLE',
    })

    results.refresh()
    await flushPromises()
    expect(listReports).toHaveBeenCalledTimes(2)

    vi.spyOn(api, 'downloadTaskReport').mockRejectedValue(
      new ApiError('报告文件校验失败', 409, {
        code: 'REPORT_HASH_MISMATCH',
      }),
    )
    await results.download(report('html'))

    expect(results.actionError.value).toContain('报告文件校验失败')
    expect(results.downloadingReportId.value).toBe('')
  })
})
