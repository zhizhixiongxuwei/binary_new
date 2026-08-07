import type {
  RiskLevel,
  TaskDetail,
  TaskPage,
  TaskStatus,
} from '@/api/types'

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const sha256 = /^[0-9a-f]{64}$/
const opaqueCursor = /^[A-Za-z0-9_-]+$/
const taskStatuses = new Set<TaskStatus>([
  'UPLOADING',
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'SUCCEEDED',
  'PARTIAL_SUCCEEDED',
  'FAILED',
  'CANCEL_REQUESTED',
  'CANCELLED',
  'DELETING',
  'DELETED',
])
const riskLevels = new Set<RiskLevel>([
  'UNKNOWN',
  'NONE',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
])
const requiredTaskKeys = [
  'id',
  'name',
  'input_type',
  'status',
  'risk_level',
  'progress',
  'progress_indeterminate',
  'creator_id',
  'creator_name',
  'tags',
  'created_at',
  'updated_at',
  'original_filename',
  'size_bytes',
  'sha256',
  'sample_expires_at',
  'sample_deleted_at',
] as const
const optionalTaskKeys = [
  'current_stage',
  'error_code',
  'error_message',
] as const

export class TaskContractError extends Error {
  constructor(field: string) {
    super(`任务响应不符合接口契约：${field}`)
    this.name = 'TaskContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TaskContractError(field)
  }
  return value as Record<string, unknown>
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[],
  field: string,
): void {
  const allowed = new Set([...required, ...optional])
  if (
    required.some((key) => !Object.prototype.hasOwnProperty.call(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new TaskContractError(field)
  }
}

function text(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): string {
  if (
    typeof value !== 'string' ||
    value.length < minimum ||
    value.length > maximum
  ) {
    throw new TaskContractError(field)
  }
  return value
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 1, 64)
  if (!Number.isFinite(Date.parse(result))) throw new TaskContractError(field)
  return result
}

function optionalText(
  task: Record<string, unknown>,
  key: string,
  maximum: number,
): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(task, key)) return undefined
  return text(task[key], key, 0, maximum)
}

export function parseTaskDetail(value: unknown): TaskDetail {
  const task = record(value, 'task')
  exactKeys(task, requiredTaskKeys, optionalTaskKeys, 'task')

  const id = text(task.id, 'id', 36, 36)
  const creatorId = text(task.creator_id, 'creator_id', 36, 36)
  const digest = text(task.sha256, 'sha256', 64, 64)
  const status = text(task.status, 'status', 1, 32) as TaskStatus
  const riskLevel = text(task.risk_level, 'risk_level', 1, 16) as RiskLevel
  if (!uuid.test(id)) throw new TaskContractError('id')
  if (!uuid.test(creatorId)) throw new TaskContractError('creator_id')
  if (!sha256.test(digest)) throw new TaskContractError('sha256')
  if (!taskStatuses.has(status)) throw new TaskContractError('status')
  if (!riskLevels.has(riskLevel)) throw new TaskContractError('risk_level')
  if (
    typeof task.progress !== 'number' ||
    !Number.isFinite(task.progress) ||
    task.progress < 0 ||
    task.progress > 100
  ) {
    throw new TaskContractError('progress')
  }
  if (typeof task.progress_indeterminate !== 'boolean') {
    throw new TaskContractError('progress_indeterminate')
  }
  if (
    !Number.isSafeInteger(task.size_bytes) ||
    (task.size_bytes as number) < 0 ||
    (task.size_bytes as number) > 10 * 1024 * 1024 * 1024
  ) {
    throw new TaskContractError('size_bytes')
  }
  if (
    !Array.isArray(task.tags) ||
    !task.tags.every(
      (tag) => typeof tag === 'string' && tag.length <= 64,
    )
  ) {
    throw new TaskContractError('tags')
  }
  const sampleDeletedAt = task.sample_deleted_at === null
    ? null
    : timestamp(task.sample_deleted_at, 'sample_deleted_at')
  const currentStage = optionalText(task, 'current_stage', 32)
  const errorCode = optionalText(task, 'error_code', 128)
  const errorMessage = optionalText(task, 'error_message', 2_048)

  return {
    id,
    name: text(task.name, 'name', 1, 255),
    input_type: text(task.input_type, 'input_type', 1, 64),
    status,
    risk_level: riskLevel,
    progress: task.progress,
    progress_indeterminate: task.progress_indeterminate,
    creator_id: creatorId,
    creator_name: text(task.creator_name, 'creator_name', 1, 128),
    tags: [...task.tags] as string[],
    created_at: timestamp(task.created_at, 'created_at'),
    updated_at: timestamp(task.updated_at, 'updated_at'),
    original_filename: text(
      task.original_filename,
      'original_filename',
      1,
      512,
    ),
    size_bytes: task.size_bytes as number,
    sha256: digest,
    ...(currentStage === undefined ? {} : { current_stage: currentStage }),
    ...(errorCode === undefined ? {} : { error_code: errorCode }),
    ...(errorMessage === undefined ? {} : { error_message: errorMessage }),
    sample_expires_at: timestamp(task.sample_expires_at, 'sample_expires_at'),
    sample_deleted_at: sampleDeletedAt,
  }
}

export function parseTaskPage(value: unknown): TaskPage {
  const page = record(value, 'task_page')
  exactKeys(page, ['items'], ['next_cursor'], 'task_page')
  if (!Array.isArray(page.items)) throw new TaskContractError('items')
  if (
    page.items.length > 100 ||
    (page.next_cursor !== undefined &&
      (typeof page.next_cursor !== 'string' ||
        page.next_cursor.length > 256 ||
        !opaqueCursor.test(page.next_cursor)))
  ) {
    throw new TaskContractError('cursor_pagination')
  }
  return {
    items: page.items.map((item) => parseTaskDetail(item)),
    ...(page.next_cursor === undefined
      ? {}
      : { next_cursor: page.next_cursor as string }),
  }
}
