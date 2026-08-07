import type { JsonValue, TaskEventMessage } from '@/api/types'

export type TaskExecutionLogTone = 'neutral' | 'info' | 'warning' | 'error'
export type TaskWorkflowKind = 'decompile' | 'image-scan' | 'task'

export interface TaskExecutionLogEntry {
  key: string
  sequence: number
  title: string
  detailLabel: string | null
  stageLabel: string | null
  progressLabel: string | null
  severityLabel: string
  tone: TaskExecutionLogTone
  createdAt: string
  workflow: TaskWorkflowKind
  phase: string | null
  current: number | null
  total: number | null
}

interface SafeEventSummary {
  title: string
  detailLabel: string | null
}

type JsonRecord = Readonly<Record<string, JsonValue>>

const taskEventTitles: Readonly<Record<string, string>> = {
  'task.created': '任务已创建',
  'task.status_changed': '执行状态已更新',
  'task.progress': '任务进度已更新',
  'task.metadata_changed': '文件识别信息已更新',
  'task.retention_changed': '样本保留期已更新',
  'task.sample_deleted': '原始样本已清理',
  'task.deletion_cleanup_started': '删除清理已开始',
  'task.deletion_cleanup_completed': '删除清理已完成',
  'task.deletion_cleanup_failed': '删除清理失败',
  'decompile.queued': '反编译请求已排队',
  'image_scan.queued': '镜像漏洞检测已排队',
}

const stageLabels: Readonly<Record<string, string>> = {
  UPLOAD: '上传',
  UPLOADING: '上传',
  VALIDATE: '校验',
  VALIDATING: '校验',
  IDENTIFY: '识别',
  IDENTIFYING: '识别',
  EXTRACT: '解包',
  EXTRACTING: '解包',
  INDEX: '索引',
  INDEXING: '索引',
  SCAN: '分析扫描',
  SCANNING: '分析扫描',
  REPORT: '报告',
  REPORTING: '报告',
  QUEUED: '等待执行',
  CANCEL_REQUESTED: '正在取消',
  DELETING: '正在删除',
  DELETED: '已删除',
  COMPLETE: '已完成',
  COMPLETED: '已完成',
}

const severityModels: Readonly<
  Record<string, { label: string; tone: TaskExecutionLogTone }>
> = {
  debug: { label: '调试', tone: 'neutral' },
  info: { label: '信息', tone: 'info' },
  warning: { label: '警告', tone: 'warning' },
  error: { label: '错误', tone: 'error' },
}
const defaultSeverity = { label: '信息', tone: 'info' } as const
const decompileAnalyzerModels: Readonly<
  Record<string, { label: string; counterLabel: string }>
> = {
  ghidra: { label: 'Ghidra', counterLabel: '函数' },
  vineflower: { label: 'Java 反编译器', counterLabel: '类' },
  jadx: { label: 'JADX', counterLabel: '类' },
  'python-bytecode': { label: 'Python 字节码分析器', counterLabel: '模块' },
}
const safeToken = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}$/
const safeErrorCode = /^[a-z0-9][a-z0-9_.-]{0,63}$/

function payloadRecord(value: JsonValue): JsonRecord | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  return value as JsonRecord
}

function safeCounter(payload: JsonRecord, key: string): number | null {
  const value = payload[key]
  return typeof value === 'number'
    && Number.isSafeInteger(value)
    && value >= 0
    && value <= 10_000_000
    ? value
    : null
}

function safeSeconds(payload: JsonRecord): number | null {
  const value = safeCounter(payload, 'elapsed_seconds')
  return value !== null && value <= 7 * 24 * 60 * 60 ? value : null
}

function safePayloadToken(
  payload: JsonRecord,
  key: string,
  pattern = safeToken,
): string | null {
  const value = payload[key]
  return typeof value === 'string' && pattern.test(value) ? value : null
}

function countDetail(
  label: string,
  current: number | null,
  total: number | null,
): string | null {
  if (current === null || total === null || current > total) return null
  return `${label} ${current} / ${total}`
}

function appendElapsed(detail: string | null, seconds: number | null): string | null {
  if (seconds === null) return detail
  const elapsed = `已运行 ${seconds} 秒`
  return detail ? `${detail} · ${elapsed}` : elapsed
}

function decompileSummary(
  eventType: string,
  payload: JsonRecord,
): SafeEventSummary | null {
  const analyzer = safePayloadToken(payload, 'analyzer')
  const analyzerModel = analyzer ? decompileAnalyzerModels[analyzer] : null
  if (!analyzerModel) return null
  const { label: analyzerLabel, counterLabel } = analyzerModel
  const phase = safePayloadToken(payload, 'phase')
  const current = safeCounter(payload, 'current')
  const total = safeCounter(payload, 'total')

  if (eventType === 'decompile.progress') {
    if (phase === 'preparing') {
      return { title: `${analyzerLabel} 正在准备输入`, detailLabel: null }
    }
    if (phase === 'starting') {
      return {
        title: analyzer === 'ghidra'
          ? 'Ghidra JVM 正在启动'
          : `${analyzerLabel} 正在启动`,
        detailLabel: null,
      }
    }
    if (phase === 'running') {
      return {
        title: `${analyzerLabel} 正在反编译`,
        detailLabel: appendElapsed(
          countDetail(counterLabel, current, total),
          safeSeconds(payload),
        ),
      }
    }
    if (phase === 'publishing') {
      return {
        title: '正在保存反编译结果',
        detailLabel: countDetail(counterLabel, current, total),
      }
    }
    return null
  }
  if (eventType === 'decompile.completed' && phase === 'completed') {
    const partial = safePayloadToken(payload, 'completeness') === 'partial'
    return {
      title: partial
        ? `${analyzerLabel} 反编译部分完成`
        : `${analyzerLabel} 反编译已完成`,
      detailLabel: partial
        ? countDetail(counterLabel, current, total) ?? '已保存上限内的反编译结果'
        : countDetail(counterLabel, current, total),
    }
  }
  if (eventType === 'decompile.failed' && phase === 'failed') {
    const errorCode = safePayloadToken(payload, 'error_code', safeErrorCode)
    return {
      title: `${analyzerLabel} 反编译失败`,
      detailLabel: errorCode ? `错误码 ${errorCode}` : null,
    }
  }
  return null
}

function trivyCountDetail(
  payload: JsonRecord,
  suffix: string | null = null,
): string | null {
  const target = countDetail(
    '目标',
    safeCounter(payload, 'current'),
    safeCounter(payload, 'total'),
  )
  if (!suffix) return target
  return target ? `${target} · ${suffix}` : suffix
}

function findingDetail(payload: JsonRecord): string {
  return `${safeCounter(payload, 'finding_count') ?? 0} 条发现`
}

function trivySummary(
  eventType: string,
  payload: JsonRecord,
): SafeEventSummary | null {
  if (safePayloadToken(payload, 'analyzer') !== 'trivy') return null
  const phase = safePayloadToken(payload, 'phase')

  if (eventType === 'trivy.progress') {
    if (phase === 'verifying') {
      return { title: '正在校验镜像归档', detailLabel: null }
    }
    if (phase === 'database_ready') {
      const versions = [
        safePayloadToken(payload, 'database_version')
          ? `漏洞库 ${safePayloadToken(payload, 'database_version')}`
          : null,
        safePayloadToken(payload, 'java_database_version')
          ? `Java 库 ${safePayloadToken(payload, 'java_database_version')}`
          : null,
      ].filter((value): value is string => value !== null)
      return {
        title: '离线漏洞库已就绪',
        detailLabel: versions.length > 0 ? versions.join(' · ') : null,
      }
    }
    if (phase === 'targets_ready') {
      const total = safeCounter(payload, 'total')
      return {
        title: '镜像检测目标已就绪',
        detailLabel: total === null ? null : `共 ${total} 个目标`,
      }
    }
    if (phase === 'scanning') {
      return {
        title: 'Trivy 正在检测镜像',
        detailLabel: appendElapsed(
          trivyCountDetail(payload),
          safeSeconds(payload),
        ),
      }
    }
    if (phase === 'publishing') {
      return {
        title: '正在保存漏洞结果',
        detailLabel: findingDetail(payload),
      }
    }
    return null
  }
  if (eventType === 'trivy.target_completed' && phase === 'target_completed') {
    return {
      title: '镜像目标检测完成',
      detailLabel: trivyCountDetail(payload, findingDetail(payload)),
    }
  }
  if (eventType === 'trivy.target_failed' && phase === 'target_failed') {
    const errorCode = safePayloadToken(payload, 'error_code', safeErrorCode)
    return {
      title: '镜像目标检测失败',
      detailLabel: trivyCountDetail(
        payload,
        errorCode ? `错误码 ${errorCode}` : null,
      ),
    }
  }
  if (eventType === 'trivy.completed' && phase === 'completed') {
    return {
      title: 'Trivy 镜像检测已完成',
      detailLabel: trivyCountDetail(payload, findingDetail(payload)),
    }
  }
  if (eventType === 'trivy.failed' && phase === 'failed') {
    const errorCode = safePayloadToken(payload, 'error_code', safeErrorCode)
    return {
      title: 'Trivy 镜像检测失败',
      detailLabel: errorCode ? `错误码 ${errorCode}` : null,
    }
  }
  return null
}

function safeSummary(message: TaskEventMessage): SafeEventSummary | null {
  const taskTitle = taskEventTitles[message.data.type]
  if (taskTitle) return { title: taskTitle, detailLabel: null }

  const payload = payloadRecord(message.data.payload)
  if (!payload) return null
  if (message.data.type.startsWith('decompile.')) {
    return decompileSummary(message.data.type, payload)
  }
  if (message.data.type.startsWith('trivy.')) {
    return trivySummary(message.data.type, payload)
  }
  return null
}

function knownStageLabel(value: string | null): string | null {
  if (!value) return null
  return stageLabels[value.trim().toUpperCase()] ?? null
}

function progressLabel(message: TaskEventMessage): string | null {
  if (message.data.progress_indeterminate) return '计算中'
  const progress = message.data.progress
  if (
    typeof progress !== 'number'
    || !Number.isFinite(progress)
    || progress < 0
    || progress > 100
  ) {
    return null
  }
  return `${Math.round(progress)}%`
}

/**
 * Builds a fixed-label view model. It never reads the free-form message and
 * copies only explicitly allowlisted analyzer payload scalars.
 */
export function toTaskExecutionLogEntry(
  message: TaskEventMessage,
): TaskExecutionLogEntry | null {
  if (
    !Number.isSafeInteger(message.data.sequence)
    || message.data.sequence < 1
    || !Number.isFinite(Date.parse(message.data.created_at))
  ) {
    return null
  }
  const summary = safeSummary(message)
  if (!summary) return null

  const severity = severityModels[message.data.severity] ?? defaultSeverity
  const payload = payloadRecord(message.data.payload)
  const workflow: TaskWorkflowKind = message.data.type.startsWith('decompile.')
    ? 'decompile'
    : message.data.type.startsWith('trivy.')
      || message.data.type === 'image_scan.queued'
      ? 'image-scan'
      : 'task'
  const phase = message.data.type === 'decompile.queued'
    || message.data.type === 'image_scan.queued'
    ? 'queued'
    : payload === null
      ? null
      : safePayloadToken(payload, 'phase')
  return {
    key: String(message.data.sequence),
    sequence: message.data.sequence,
    title: summary.title,
    detailLabel: summary.detailLabel,
    stageLabel: knownStageLabel(message.data.stage),
    progressLabel: message.data.type.startsWith('task.')
      ? progressLabel(message)
      : null,
    severityLabel: severity.label,
    tone: severity.tone,
    createdAt: message.data.created_at,
    workflow,
    phase,
    current: payload === null ? null : safeCounter(payload, 'current'),
    total: payload === null ? null : safeCounter(payload, 'total'),
  }
}
