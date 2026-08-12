import type {
  CompletedUpload,
  InputCategory,
  UploadSession,
  UploadValidationError,
  UploadValidationStatus,
} from '@/api/types'

const inputCategories = new Set<InputCategory>([
  'binary',
  'archive',
  'container',
])
const validationStatuses = new Set<UploadValidationStatus>([
  'pending',
  'valid',
  'mismatch',
  'unsupported',
])
const uploadStatuses = new Set<UploadSession['status']>([
  'created',
  'uploading',
  'assembling',
  'completed',
  'failed',
  'expired',
  'cancelled',
])
const sha256Pattern = /^[a-f0-9]{64}$/
const canonicalUUIDPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export class UploadIntakeContractError extends Error {
  constructor(field: string) {
    super(`上传响应不符合接口契约：${field}`)
    this.name = 'UploadIntakeContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new UploadIntakeContractError(field)
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
    throw new UploadIntakeContractError(field)
  }
}

function text(
  value: unknown,
  field: string,
  maximum: number,
  allowEmpty = false,
): string {
  const invalidControl =
    typeof value === 'string' &&
    Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0
      return point === 0 || (point < 32 && point !== 9) || point === 127
    })
  if (
    typeof value !== 'string' ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum ||
    invalidControl
  ) {
    throw new UploadIntakeContractError(field)
  }
  return value
}

function enumValue<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  field: string,
): T {
  const parsed = text(value, field, 64)
  if (!allowed.has(parsed as T)) throw new UploadIntakeContractError(field)
  return parsed as T
}

function integer(
  value: unknown,
  field: string,
  { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {},
): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new UploadIntakeContractError(field)
  }
  return value
}

function timestamp(value: unknown, field: string): string {
  const parsed = text(value, field, 64)
  if (!Number.isFinite(Date.parse(parsed))) {
    throw new UploadIntakeContractError(field)
  }
  return parsed
}

function identifier(value: unknown, field: string): string {
  const parsed = text(value, field, 128)
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(parsed)) {
    throw new UploadIntakeContractError(field)
  }
  return parsed
}

function validationError(
  value: unknown,
  field: string,
): UploadValidationError {
  const error = record(value, field)
  exactKeys(error, ['code', 'message'], [], field)
  return {
    code: text(error.code, `${field}.code`, 128),
    message: text(error.message, `${field}.message`, 2_048),
  }
}

function sessionValue(value: unknown, completed: boolean): UploadSession {
  const session = record(value, 'data')
  exactKeys(
    session,
    ['id', 'part_size', 'status', 'uploaded_parts', 'expires_at'],
    [
      'sha256',
      'size_bytes',
      'input_category',
      'validation_status',
      'detected_category',
      'detected_format',
      'validation_error',
      'archive_import_id',
      'task_id',
    ],
    'data',
  )
  if (!Array.isArray(session.uploaded_parts) || session.uploaded_parts.length > 65_536) {
    throw new UploadIntakeContractError('data.uploaded_parts')
  }

  const parsed: UploadSession = {
    id: identifier(session.id, 'data.id'),
    part_size: integer(session.part_size, 'data.part_size', {
      minimum: 1,
      maximum: 2 * 1024 ** 3,
    }),
    status: enumValue(session.status, uploadStatuses, 'data.status'),
    uploaded_parts: session.uploaded_parts.map((part, index) =>
      integer(part, `data.uploaded_parts[${index}]`, {
        minimum: 1,
        maximum: 65_536,
      }),
    ),
    expires_at: timestamp(session.expires_at, 'data.expires_at'),
  }

  if (new Set(parsed.uploaded_parts).size !== parsed.uploaded_parts.length) {
    throw new UploadIntakeContractError('data.uploaded_parts')
  }
  if (session.size_bytes !== undefined) {
    parsed.size_bytes = integer(session.size_bytes, 'data.size_bytes', {
      maximum: 2 * 1024 ** 3,
    })
  }
  if (session.input_category !== undefined) {
    parsed.input_category = enumValue(
      session.input_category,
      inputCategories,
      'data.input_category',
    )
  }
  if (session.validation_status !== undefined) {
    parsed.validation_status = enumValue(
      session.validation_status,
      validationStatuses,
      'data.validation_status',
    )
  }
  if (
    (parsed.input_category === undefined) !==
    (parsed.validation_status === undefined)
  ) {
    throw new UploadIntakeContractError('data.validation_status')
  }
  if (session.detected_category !== undefined) {
    parsed.detected_category = enumValue(
      session.detected_category,
      inputCategories,
      'data.detected_category',
    )
  }
  if (session.detected_format !== undefined) {
    parsed.detected_format = text(
      session.detected_format,
      'data.detected_format',
      128,
    )
  }
  if (session.validation_error !== undefined) {
    parsed.validation_error = validationError(
      session.validation_error,
      'data.validation_error',
    )
  }
  if (session.archive_import_id !== undefined) {
    parsed.archive_import_id = identifier(
      session.archive_import_id,
      'data.archive_import_id',
    )
  }
  if (session.task_id !== undefined) {
    const taskId = text(session.task_id, 'data.task_id', 36)
    if (!canonicalUUIDPattern.test(taskId)) {
      throw new UploadIntakeContractError('data.task_id')
    }
    parsed.task_id = taskId
  }
  if (session.sha256 !== undefined) {
    const sha256 = text(session.sha256, 'data.sha256', 64)
    if (!sha256Pattern.test(sha256)) {
      throw new UploadIntakeContractError('data.sha256')
    }
    parsed.sha256 = sha256
  }

  if (
    parsed.validation_status === 'valid' &&
    (parsed.detected_category === undefined ||
      parsed.detected_format === undefined ||
      parsed.detected_category !== parsed.input_category)
  ) {
    throw new UploadIntakeContractError('data.validation_status')
  }
  if (
    parsed.archive_import_id !== undefined &&
    (parsed.input_category !== 'archive' ||
      parsed.validation_status !== 'valid' ||
      parsed.status !== 'completed')
  ) {
    throw new UploadIntakeContractError('data.archive_import_id')
  }
  if (
    parsed.task_id !== undefined &&
    (parsed.input_category === undefined ||
      parsed.input_category === 'archive' ||
      parsed.validation_status !== 'valid' ||
      parsed.status !== 'completed' ||
      parsed.archive_import_id !== undefined)
  ) {
    throw new UploadIntakeContractError('data.task_id')
  }

  if (completed) {
    if (
      parsed.status !== 'completed' ||
      parsed.size_bytes === undefined ||
      !('sha256' in parsed)
    ) {
      throw new UploadIntakeContractError('data.status')
    }
  }
  return parsed
}

function assertExpectedId(parsed: UploadSession, expectedId?: string): void {
  if (expectedId !== undefined && parsed.id !== expectedId) {
    throw new UploadIntakeContractError('data.id')
  }
}

export function parseUploadSession(
  value: unknown,
  expectedId?: string,
): UploadSession {
  const parsed = sessionValue(value, false)
  assertExpectedId(parsed, expectedId)
  return parsed
}

export function parseCreatedUploadSession(
  value: unknown,
  expectedCategory?: InputCategory,
): UploadSession {
  const parsed = sessionValue(value, false)
  if (
    parsed.input_category === undefined ||
    parsed.validation_status === undefined ||
    (expectedCategory !== undefined && parsed.input_category !== expectedCategory)
  ) {
    throw new UploadIntakeContractError('data.input_category')
  }
  return parsed
}

export function parseCompletedUpload(
  value: unknown,
  expectedId?: string,
): CompletedUpload {
  const parsed = sessionValue(value, true)
  assertExpectedId(parsed, expectedId)
  if (
    parsed.input_category === undefined ||
    parsed.validation_status !== 'valid' ||
    parsed.detected_category === undefined ||
    parsed.detected_format === undefined ||
    parsed.detected_category !== parsed.input_category ||
    (parsed.input_category === 'archive'
      ? parsed.archive_import_id === undefined || parsed.task_id !== undefined
      : parsed.task_id === undefined || parsed.archive_import_id !== undefined)
  ) {
    throw new UploadIntakeContractError('data.validation_status')
  }
  return parsed as CompletedUpload
}
