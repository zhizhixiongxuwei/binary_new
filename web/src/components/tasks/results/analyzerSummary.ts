import { isProxy, toRaw } from 'vue'

import { hasUnsafeDisplayCharacter } from '@/components/tasks/results/displayText'

const MAX_IDENTITY_LENGTH = 128
const MAX_VERSION_LENGTH = 64
const MAX_ISSUE_LENGTH = 512
const MAX_ISSUES_TO_PARSE = 100
const MAX_ISSUES_TO_DISPLAY = 4
const MAX_DIAGNOSTIC_CONTAINERS = 30_000
const MAX_DIAGNOSTIC_PROPERTIES = 150_000
const MAX_DIAGNOSTIC_TEXT_LENGTH = 8 * 1024 * 1024

const TEXT_FIELDS = [
  { key: 'engine', label: '分析引擎', maxLength: MAX_IDENTITY_LENGTH },
  { key: 'format', label: '输入格式', maxLength: MAX_IDENTITY_LENGTH },
  { key: 'python_version', label: 'Python 版本', maxLength: MAX_VERSION_LENGTH },
  { key: 'magic', label: 'Magic', maxLength: MAX_IDENTITY_LENGTH },
] as const

const METRIC_FIELDS = [
  { key: 'header_size', label: '头部大小', unit: 'bytes', tone: 'neutral' },
  { key: 'dex_file_count', label: 'DEX 文件', unit: 'count', tone: 'neutral' },
  { key: 'class_count', label: '类', unit: 'count', tone: 'neutral' },
  { key: 'method_count', label: '方法', unit: 'count', tone: 'neutral' },
  { key: 'code_object_count', label: 'Code object', unit: 'count', tone: 'neutral' },
  { key: 'missing_class_count', label: '缺失类', unit: 'count', tone: 'danger' },
  { key: 'error_count', label: '错误', unit: 'count', tone: 'danger' },
  { key: 'warning_count', label: '警告', unit: 'count', tone: 'warning' },
] as const

const KNOWN_FIELDS = new Set<string>([
  ...TEXT_FIELDS.map((field) => field.key),
  ...METRIC_FIELDS.map((field) => field.key),
  'errors',
  'warnings',
])

export interface AnalyzerSummaryTextField {
  key: string
  label: string
  value: string
}

export interface AnalyzerSummaryMetric {
  key: string
  label: string
  value: number
  unit: 'bytes' | 'count'
  tone: 'neutral' | 'warning' | 'danger'
}

export interface AnalyzerSummaryIssueGroup {
  kind: 'error' | 'warning'
  label: string
  messages: readonly string[]
  omittedCount: number
}

export interface ParsedAnalyzerSummary {
  present: boolean
  identity: readonly AnalyzerSummaryTextField[]
  metrics: readonly AnalyzerSummaryMetric[]
  issues: readonly AnalyzerSummaryIssueGroup[]
}

function emptySummary(): ParsedAnalyzerSummary {
  return { present: false, identity: [], metrics: [], issues: [] }
}

function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function boundedDisplayString(
  value: unknown,
  maxLength: number,
): string | undefined {
  if (typeof value !== 'string') return undefined
  if (value.length > maxLength || hasUnsafeDisplayCharacter(value)) {
    return undefined
  }
  const normalized = value.trim()
  if (!normalized) return undefined
  return normalized
}

function safeUnsignedInteger(value: unknown): number | undefined {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    !Object.is(value, -0) &&
    value >= 0
    ? value
    : undefined
}

function parseIssueGroup(
  value: unknown,
  kind: AnalyzerSummaryIssueGroup['kind'],
): AnalyzerSummaryIssueGroup | undefined {
  if (!Array.isArray(value) || value.length > MAX_ISSUES_TO_PARSE) {
    return undefined
  }

  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) return undefined
  }
  const parsed = value.map((item) =>
    boundedDisplayString(item, MAX_ISSUE_LENGTH),
  )
  if (parsed.some((item) => item === undefined)) return undefined

  const messages = (parsed as string[]).slice(0, MAX_ISSUES_TO_DISPLAY)
  if (messages.length === 0) return undefined
  return {
    kind,
    label: kind === 'error' ? '错误摘要' : '警告摘要',
    messages,
    omittedCount: Math.max(0, parsed.length - messages.length),
  }
}

interface ValidationBudget {
  containers: number
  properties: number
  textLength: number
}

function isArrayIndex(key: string): boolean {
  if (!/^(0|[1-9]\d*)$/.test(key)) return false
  const index = Number(key)
  return Number.isSafeInteger(index) && index >= 0 && index < 0xffff_ffff
}

function isSafeJsonDataGraph(
  value: unknown,
  budget: ValidationBudget,
  ancestors: WeakSet<object>,
): boolean {
  if (value === null || typeof value === 'boolean') return true
  if (typeof value === 'string') {
    budget.textLength += value.length
    return budget.textLength <= MAX_DIAGNOSTIC_TEXT_LENGTH
  }
  if (typeof value === 'number') return Number.isFinite(value)
  if (typeof value !== 'object') return false

  if (ancestors.has(value)) return false
  budget.containers += 1
  if (budget.containers > MAX_DIAGNOSTIC_CONTAINERS) return false

  const array = Array.isArray(value)
  if (!array && !isPlainRecord(value)) return false

  ancestors.add(value)
  const keys = Reflect.ownKeys(value)
  budget.properties += keys.length
  if (budget.properties > MAX_DIAGNOSTIC_PROPERTIES) return false

  if (array) {
    const expectedLength = value.length
    if (keys.length !== expectedLength + 1) return false
  }

  for (const key of keys) {
    if (typeof key !== 'string') return false
    if (array && key !== 'length' && !isArrayIndex(key)) return false
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (
      !descriptor ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      return false
    }
    if (key === 'length' && array) continue
    if (!isSafeJsonDataGraph(descriptor.value, budget, ancestors)) return false
  }
  ancestors.delete(value)
  return true
}

function cloneTrustedDiagnostics(value: unknown): unknown {
  if (typeof globalThis.structuredClone !== 'function') return undefined
  const candidate = isProxy(value) ? toRaw(value) : value
  if (!isPlainRecord(candidate)) return undefined

  const keys = Reflect.ownKeys(candidate)
  if (
    !keys.some((key) => typeof key === 'string' && KNOWN_FIELDS.has(key))
  ) {
    return undefined
  }
  for (const key of keys) {
    if (typeof key !== 'string') return undefined
    if (!KNOWN_FIELDS.has(key)) continue
    const descriptor = Object.getOwnPropertyDescriptor(candidate, key)
    if (
      !descriptor ||
      !Object.prototype.hasOwnProperty.call(descriptor, 'value')
    ) {
      return undefined
    }
  }

  if (
    !isSafeJsonDataGraph(
      candidate,
      { containers: 0, properties: 0, textLength: 0 },
      new WeakSet<object>(),
    )
  ) {
    return undefined
  }

  return globalThis.structuredClone(candidate)
}

function parseSummary(diagnostics: unknown): ParsedAnalyzerSummary {
  const cloned = cloneTrustedDiagnostics(diagnostics)
  if (!isPlainRecord(cloned)) return emptySummary()

  const identity: AnalyzerSummaryTextField[] = []
  for (const field of TEXT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(cloned, field.key)) continue
    const value = boundedDisplayString(cloned[field.key], field.maxLength)
    if (value !== undefined) {
      identity.push({ key: field.key, label: field.label, value })
    }
  }

  const metrics: AnalyzerSummaryMetric[] = []
  for (const field of METRIC_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(cloned, field.key)) continue
    const value = safeUnsignedInteger(cloned[field.key])
    if (value !== undefined) {
      metrics.push({
        key: field.key,
        label: field.label,
        value,
        unit: field.unit,
        tone: field.tone,
      })
    }
  }

  const issues = [
    Object.prototype.hasOwnProperty.call(cloned, 'errors')
      ? parseIssueGroup(cloned.errors, 'error')
      : undefined,
    Object.prototype.hasOwnProperty.call(cloned, 'warnings')
      ? parseIssueGroup(cloned.warnings, 'warning')
      : undefined,
  ].filter((group): group is AnalyzerSummaryIssueGroup => group !== undefined)

  return {
    present: identity.length > 0 || metrics.length > 0 || issues.length > 0,
    identity,
    metrics,
    issues,
  }
}

export function parseAnalyzerSummary(
  diagnostics: unknown,
): ParsedAnalyzerSummary {
  try {
    return parseSummary(diagnostics)
  } catch {
    return emptySummary()
  }
}
