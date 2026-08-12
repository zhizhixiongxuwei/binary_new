import type {
  ArchiveImport,
  ArchiveImportEntry,
  ArchiveImportEntryPage,
  ArchiveImportEntryStatus,
  ArchiveImportPage,
  ArchiveImportStatus,
  ArchiveTaskBatchOutcome,
  ArchiveTaskBatchResult,
  InputCategory,
} from '@/api/types'

const importStatuses = new Set<ArchiveImportStatus>([
  'queued',
  'running',
  'ready',
  'failed',
  'deleting',
  'deleted',
])
const entryStatuses = new Set<ArchiveImportEntryStatus>([
  'eligible',
  'skipped',
  'created',
  'failed',
])
const detectedCategories = new Set<Exclude<InputCategory, 'archive'>>([
  'binary',
  'container',
])
const batchOutcomes = new Set<ArchiveTaskBatchOutcome>([
  'created',
  'existing',
  'failed',
])
const sha256Pattern = /^[a-f0-9]{64}$/

export class ArchiveImportContractError extends Error {
  constructor(field: string) {
    super(`归档导入响应不符合接口契约：${field}`)
    this.name = 'ArchiveImportContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ArchiveImportContractError(field)
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
    throw new ArchiveImportContractError(field)
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
    throw new ArchiveImportContractError(field)
  }
  return value
}

function identifier(value: unknown, field: string): string {
  const parsed = text(value, field, 128)
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(parsed)) {
    throw new ArchiveImportContractError(field)
  }
  return parsed
}

function integer(value: unknown, field: string, maximum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new ArchiveImportContractError(field)
  }
  return value
}

function enumValue<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  field: string,
): T {
  const parsed = text(value, field, 64)
  if (!allowed.has(parsed as T)) throw new ArchiveImportContractError(field)
  return parsed as T
}

function timestamp(value: unknown, field: string): string {
  const parsed = text(value, field, 64)
  if (!Number.isFinite(Date.parse(parsed))) {
    throw new ArchiveImportContractError(field)
  }
  return parsed
}

function optionalText(
  source: Record<string, unknown>,
  key: string,
  field: string,
  maximum: number,
): string | undefined {
  return source[key] === undefined
    ? undefined
    : text(source[key], `${field}.${key}`, maximum)
}

function importValue(value: unknown, field: string): ArchiveImport {
  const item = record(value, field)
  exactKeys(
    item,
    [
      'id',
      'upload_id',
      'filename',
      'status',
      'scanned_entries',
      'total_entries',
      'eligible_entries',
      'skipped_entries',
      'created_tasks',
      'created_at',
      'updated_at',
    ],
    ['error_code', 'error_message'],
    field,
  )
  const parsed: ArchiveImport = {
    id: identifier(item.id, `${field}.id`),
    upload_id: identifier(item.upload_id, `${field}.upload_id`),
    filename: text(item.filename, `${field}.filename`, 1_024),
    status: enumValue(item.status, importStatuses, `${field}.status`),
    scanned_entries: integer(
      item.scanned_entries,
      `${field}.scanned_entries`,
      20_000,
    ),
    total_entries: integer(item.total_entries, `${field}.total_entries`, 20_000),
    eligible_entries: integer(
      item.eligible_entries,
      `${field}.eligible_entries`,
      20_000,
    ),
    skipped_entries: integer(
      item.skipped_entries,
      `${field}.skipped_entries`,
      20_000,
    ),
    created_tasks: integer(item.created_tasks, `${field}.created_tasks`, 20_000),
    created_at: timestamp(item.created_at, `${field}.created_at`),
    updated_at: timestamp(item.updated_at, `${field}.updated_at`),
  }
  const errorCode = optionalText(item, 'error_code', field, 128)
  const errorMessage = optionalText(item, 'error_message', field, 2_048)
  if (errorCode !== undefined) parsed.error_code = errorCode
  if (errorMessage !== undefined) parsed.error_message = errorMessage
  if (
    parsed.eligible_entries + parsed.skipped_entries > parsed.total_entries ||
    parsed.scanned_entries > parsed.total_entries ||
    parsed.created_tasks > parsed.eligible_entries
  ) {
    throw new ArchiveImportContractError(`${field}.counts`)
  }
  return parsed
}

function entryValue(value: unknown, field: string): ArchiveImportEntry {
  const item = record(value, field)
  exactKeys(
    item,
    [
      'id',
      'path',
      'size_bytes',
      'sha256',
      'detected_format',
      'detected_category',
      'status',
    ],
    ['skip_reason', 'task_id'],
    field,
  )
  const status = enumValue(item.status, entryStatuses, `${field}.status`)
  const sha256 =
    item.sha256 === null
      ? null
      : text(item.sha256, `${field}.sha256`, 64)
  if (sha256 !== null && !sha256Pattern.test(sha256)) {
    throw new ArchiveImportContractError(`${field}.sha256`)
  }
  const detectedCategory =
    item.detected_category === null
      ? null
      : enumValue(
          item.detected_category,
          detectedCategories,
          `${field}.detected_category`,
        )
  if (
    status !== 'skipped' &&
    (sha256 === null || detectedCategory === null || item.detected_format === null)
  ) {
    throw new ArchiveImportContractError(field)
  }

  const parsed: ArchiveImportEntry = {
    id: identifier(item.id, `${field}.id`),
    path: text(item.path, `${field}.path`, 4_096),
    size_bytes: integer(item.size_bytes, `${field}.size_bytes`, 10 * 1024 ** 3),
    sha256,
    detected_format:
      item.detected_format === null
        ? null
        : text(item.detected_format, `${field}.detected_format`, 128),
    detected_category: detectedCategory,
    status,
  }
  const skipReason = optionalText(item, 'skip_reason', field, 2_048)
  const taskId = optionalText(item, 'task_id', field, 128)
  if (skipReason !== undefined) parsed.skip_reason = skipReason
  if (taskId !== undefined) parsed.task_id = identifier(taskId, `${field}.task_id`)
  return parsed
}

export function parseArchiveImport(value: unknown): ArchiveImport {
  return importValue(value, 'data')
}

export function parseArchiveImportPage(value: unknown): ArchiveImportPage {
  const page = record(value, 'data')
  exactKeys(page, ['items'], ['next_cursor'], 'data')
  if (!Array.isArray(page.items) || page.items.length > 100) {
    throw new ArchiveImportContractError('data.items')
  }
  const parsed: ArchiveImportPage = {
    items: page.items.map((item, index) => {
      const parsedItem = importValue(item, `data.items[${index}]`)
      if (parsedItem.status === 'deleted') {
        throw new ArchiveImportContractError(`data.items[${index}].status`)
      }
      return parsedItem
    }),
  }
  if (
    new Set(parsed.items.map((item) => item.id)).size !== parsed.items.length ||
    new Set(parsed.items.map((item) => item.upload_id)).size !== parsed.items.length
  ) {
    throw new ArchiveImportContractError('data.items')
  }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = text(page.next_cursor, 'data.next_cursor', 2_048)
  }
  return parsed
}

export function parseArchiveImportEntryPage(
  value: unknown,
): ArchiveImportEntryPage {
  const page = record(value, 'data')
  exactKeys(page, ['items'], ['next_cursor'], 'data')
  if (!Array.isArray(page.items) || page.items.length > 100) {
    throw new ArchiveImportContractError('data.items')
  }
  const parsed: ArchiveImportEntryPage = {
    items: page.items.map((item, index) =>
      entryValue(item, `data.items[${index}]`),
    ),
  }
  if (new Set(parsed.items.map((item) => item.id)).size !== parsed.items.length) {
    throw new ArchiveImportContractError('data.items')
  }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = text(page.next_cursor, 'data.next_cursor', 2_048)
  }
  return parsed
}

export function parseArchiveTaskBatchResult(
  value: unknown,
  expectedEntryIds?: readonly string[],
): ArchiveTaskBatchResult {
  const result = record(value, 'data')
  exactKeys(result, ['items'], [], 'data')
  if (!Array.isArray(result.items) || result.items.length > 20) {
    throw new ArchiveImportContractError('data.items')
  }
  const parsed: ArchiveTaskBatchResult = {
    items: result.items.map((value, index) => {
      const field = `data.items[${index}]`
      const item = record(value, field)
      exactKeys(
        item,
        ['entry_id', 'outcome'],
        ['task_id', 'error_code', 'message'],
        field,
      )
      const parsed = {
        entry_id: identifier(item.entry_id, `${field}.entry_id`),
        outcome: enumValue(item.outcome, batchOutcomes, `${field}.outcome`),
      } as ArchiveTaskBatchResult['items'][number]
      const taskId = optionalText(item, 'task_id', field, 128)
      const errorCode = optionalText(item, 'error_code', field, 128)
      const message = optionalText(item, 'message', field, 2_048)
      if (taskId !== undefined) parsed.task_id = identifier(taskId, `${field}.task_id`)
      if (errorCode !== undefined) parsed.error_code = errorCode
      if (message !== undefined) parsed.message = message
      if (
        parsed.outcome === 'created' &&
        parsed.task_id === undefined
      ) {
        throw new ArchiveImportContractError(`${field}.task_id`)
      }
      return parsed
    }),
  }
  if (
    new Set(parsed.items.map((item) => item.entry_id)).size !==
    parsed.items.length
  ) {
    throw new ArchiveImportContractError('data.items')
  }
  if (expectedEntryIds !== undefined) {
    const expected = new Set(expectedEntryIds)
    const actual = new Set(parsed.items.map((item) => item.entry_id))
    if (
      expected.size !== expectedEntryIds.length ||
      expected.size !== actual.size ||
      [...expected].some((entryId) => !actual.has(entryId))
    ) {
      throw new ArchiveImportContractError('data.items')
    }
  }
  return parsed
}
