import {
  computed,
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import {
  api,
  ApiError,
} from '@/api/client'
import type {
  ReportDownloadEncoding,
  ReportFormat,
  TaskReport,
  TaskReportSampleRelation,
  TaskStatus,
  UserRole,
} from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'
import { useReportDownload } from '@/composables/useReportDownload'
import { createIdempotencyKey } from '@/utils/idempotency'

interface UseTaskReportsOptions {
  taskId: MaybeRefOrGetter<string>
  taskStatus: MaybeRefOrGetter<TaskStatus | null>
  userRole: MaybeRefOrGetter<UserRole | null>
  enabled?: MaybeRefOrGetter<boolean>
}

const REPORT_POLL_INTERVAL_MS = 2_000
const MAX_REPORT_POLL_ATTEMPTS = 30
const REPORTABLE_TASK_STATUSES = new Set<TaskStatus>([
  'SUCCEEDED',
  'PARTIAL_SUCCEEDED',
  'FAILED',
  'CANCELLED',
])
const READABLE_DECOMPILE_STATUSES = new Set([
  'complete',
  'partial',
  'bytecode_only',
])

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError || error instanceof Error) return error.message
  return fallback
}

function replaceFormat(
  reports: readonly TaskReport[],
  report: TaskReport,
): readonly TaskReport[] {
  return [
    ...reports.filter((candidate) => candidate.format !== report.format),
    report,
  ].sort((left, right) => left.format.localeCompare(right.format))
}

export function useTaskReports(options: UseTaskReportsOptions) {
  const reports = shallowRef<readonly TaskReport[]>([])
  const loading = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const operationError = shallowRef('')
  const generatingFormats = shallowRef<readonly ReportFormat[]>([])
  const sampleRelation = shallowRef<TaskReportSampleRelation | 'unknown'>(
    'unknown',
  )
  const hasDecompileSources = shallowRef(false)
  const idempotencyKeys = new Map<string, string>()
  const reportDownload = useReportDownload({
    taskId: options.taskId,
    ...(options.enabled === undefined ? {} : { enabled: options.enabled }),
  })
  let scopeGeneration = 0
  let listGeneration = 0
  let decompileProbeGeneration = 0
  let listInFlight = false
  let pollAttempts = 0
  let pollTimer: ReturnType<typeof globalThis.setTimeout> | null = null

  const roleCanGenerate = computed(() => {
    const role = toValue(options.userRole)
    return role === 'administrator' || role === 'operator'
  })
  const taskIsReportable = computed(() => {
    const status = toValue(options.taskStatus)
    return status !== null && REPORTABLE_TASK_STATUSES.has(status)
  })
  const canGenerate = computed(
    () => roleCanGenerate.value && taskIsReportable.value,
  )
  const actionError = computed(
    () => reportDownload.error.value || operationError.value,
  )
  const downloadingReportId = computed(
    () => reportDownload.pendingKey.value.split(':', 1)[0] ?? '',
  )
  const exportingSources = computed(() =>
    reportDownload.pendingKey.value.startsWith('decompile-sources:'),
  )
  const generationHint = computed(() => {
    if (!roleCanGenerate.value) {
      return '当前角色只能查看和下载已有报告，不能生成新报告。'
    }
    if (!taskIsReportable.value) {
      return '任务完成、部分完成、失败或取消后才能生成报告；当前仅可查看已有报告。'
    }
    return '确认按需反编译和镜像检测结束后再生成；JSON 与 HTML 独立取快照。'
  })
  const state = computed<TaskResultState>(() => {
    if (loading.value) {
      return {
        status: 'loading',
        title: '正在读取任务报告',
        description: '正在加载 JSON 和 HTML 报告的生成状态。',
      }
    }
    if (error.value) {
      return {
        status: 'error',
        title: '报告结果读取失败',
        description: error.value,
        ...(errorCode.value ? { errorCode: errorCode.value } : {}),
      }
    }
    if (reports.value.length === 0) {
      return {
        status: 'empty',
        title: '尚未生成任务报告',
        description: canGenerate.value
          ? '可以按需生成 JSON 或离线 HTML 报告。'
          : generationHint.value,
      }
    }
    return { status: 'ready' }
  })

  function isEnabled(): boolean {
    return (
      options.enabled === undefined ||
      toValue(options.enabled)
    )
  }

  function hasPendingReport(): boolean {
    return reports.value.some(
      (report) =>
        report.status === 'queued' || report.status === 'generating',
    )
  }

  function clearPollTimer(): void {
    if (pollTimer === null) return
    globalThis.clearTimeout(pollTimer)
    pollTimer = null
  }

  function schedulePoll(): void {
    clearPollTimer()
    const taskId = toValue(options.taskId)
    if (!taskId || !isEnabled() || !hasPendingReport()) {
      pollAttempts = 0
      return
    }
    if (pollAttempts >= MAX_REPORT_POLL_ATTEMPTS) {
      if (!operationError.value) {
        operationError.value = '报告仍在生成，请稍后手动刷新状态。'
      }
      return
    }

    const currentScope = scopeGeneration
    pollTimer = globalThis.setTimeout(() => {
      pollTimer = null
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      pollAttempts += 1
      void load(true)
    }, REPORT_POLL_INTERVAL_MS)
  }

  async function load(background = false): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || !isEnabled() || listInFlight) return

    const requestGeneration = ++listGeneration
    const currentScope = scopeGeneration
    listInFlight = true
    if (!background) {
      loading.value = true
      error.value = ''
      errorCode.value = ''
      operationError.value = ''
    }

    try {
      const result = await api.listTaskReports(taskId)
      if (
        requestGeneration !== listGeneration ||
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      reports.value = result.items
      sampleRelation.value = result.sample_relation ?? 'unknown'
      if (!hasPendingReport()) pollAttempts = 0
    } catch (caught) {
      if (
        requestGeneration !== listGeneration ||
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      if (background) {
        operationError.value = `报告状态刷新失败：${errorMessage(
          caught,
          '未知错误',
        )}`
      } else {
        error.value = errorMessage(caught, '报告结果读取失败')
        errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
        reports.value = []
        sampleRelation.value = 'unknown'
      }
    } finally {
      if (currentScope === scopeGeneration) {
        listInFlight = false
        if (requestGeneration === listGeneration && !background) {
          loading.value = false
        }
        schedulePoll()
      }
    }
  }

  async function probeDecompileSources(): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || !isEnabled()) return
    const generation = ++decompileProbeGeneration
    const currentScope = scopeGeneration
    try {
      const page = await api.listDecompileResults(taskId, { page_size: 1 })
      if (
        generation !== decompileProbeGeneration ||
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      hasDecompileSources.value = page.items.some((item) =>
        READABLE_DECOMPILE_STATUSES.has(item.status),
      )
    } catch {
      if (
        generation === decompileProbeGeneration &&
        currentScope === scopeGeneration &&
        taskId === toValue(options.taskId)
      ) {
        hasDecompileSources.value = false
      }
    }
  }

  function reportFor(format: ReportFormat): TaskReport | undefined {
    return reports.value.find((report) => report.format === format)
  }

  function operationKey(taskId: string, format: ReportFormat): string {
    return `${taskId}:${format}`
  }

  function idempotencyKey(taskId: string, format: ReportFormat): string {
    const key = operationKey(taskId, format)
    const existing = idempotencyKeys.get(key)
    if (existing) return existing

    const created = createIdempotencyKey()
    idempotencyKeys.set(key, created)
    return created
  }

  async function generate(format: ReportFormat): Promise<void> {
    const taskId = toValue(options.taskId)
    const existing = reportFor(format)
    if (!taskId || !isEnabled() || generatingFormats.value.includes(format)) {
      return
    }
    if (!canGenerate.value) {
      operationError.value = generationHint.value
      return
    }
    if (existing && existing.status !== 'failed') return

    const currentScope = scopeGeneration
    const intentKey = operationKey(taskId, format)
    generatingFormats.value = [...generatingFormats.value, format]
    reportDownload.clearError()
    operationError.value = ''

    try {
      const report = await api.createTaskReport(
        taskId,
        { format },
        idempotencyKey(taskId, format),
      )
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      listGeneration += 1
      loading.value = false
      error.value = ''
      errorCode.value = ''
      reports.value = replaceFormat(reports.value, report)
      idempotencyKeys.delete(intentKey)
      pollAttempts = 0
      schedulePoll()
    } catch (caught) {
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId)
      ) {
        return
      }
      operationError.value = `生成 ${format.toUpperCase()} 报告失败：${errorMessage(
        caught,
        '未知错误',
      )}`
    } finally {
      if (currentScope === scopeGeneration) {
        generatingFormats.value = generatingFormats.value.filter(
          (candidate) => candidate !== format,
        )
      }
    }
  }

  function exportSources(includeCombined: boolean): void {
    void reportDownload.downloadSources(includeCombined)
  }

  async function download(
    report: TaskReport,
    encoding: ReportDownloadEncoding = 'identity',
  ): Promise<void> {
    operationError.value = ''
    await reportDownload.download(report, encoding)
  }

  function refresh(): void {
    pollAttempts = 0
    clearPollTimer()
    void load()
    void probeDecompileSources()
  }

  watch(
    [
      () => toValue(options.taskId),
      () => isEnabled(),
    ],
    ([taskId, enabled]) => {
      scopeGeneration += 1
      listGeneration += 1
      decompileProbeGeneration += 1
      listInFlight = false
      pollAttempts = 0
      clearPollTimer()
      reports.value = []
      loading.value = false
      error.value = ''
      errorCode.value = ''
      operationError.value = ''
      generatingFormats.value = []
      sampleRelation.value = 'unknown'
      hasDecompileSources.value = false
      idempotencyKeys.clear()
      if (taskId && enabled) {
        void load()
        void probeDecompileSources()
      }
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    scopeGeneration += 1
    listGeneration += 1
    decompileProbeGeneration += 1
    listInFlight = false
    clearPollTimer()
    idempotencyKeys.clear()
  })

  return {
    reports: readonly(reports),
    loading: readonly(loading),
    actionError,
    sampleRelation: readonly(sampleRelation),
    hasDecompileSources: readonly(hasDecompileSources),
    generatingFormats: readonly(generatingFormats),
    downloadingReportKey: reportDownload.pendingKey,
    downloadingReportId,
    exportingSources,
    canGenerate,
    taskIsReportable,
    generationHint,
    state,
    generate,
    download,
    exportSources,
    refresh,
  }
}
