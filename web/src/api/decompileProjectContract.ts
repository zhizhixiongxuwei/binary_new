import type {
  DecompileProject,
  DecompileProjectDeletionCounts,
  DecompileProjectDeletionOperation,
  DecompileProjectDeletionPreview,
  DecompileProjectDeletionStatus,
  DecompileProjectLayoutVersion,
  DecompileProjectPage,
  DecompileProjectSourceKind,
  DecompileProjectStatus,
} from '@/api/types'

const layoutVersions = new Set<DecompileProjectLayoutVersion>([
  'project-v1',
  'legacy-v1',
])
const sourceKinds = new Set<DecompileProjectSourceKind>([
  'ghidra-pseudoc',
  'java',
  'kotlin',
  'python',
  'bytecode',
])
const statuses = new Set<DecompileProjectStatus>([
  'complete',
  'partial',
  'bytecode_only',
])
const deletionStatuses = new Set<DecompileProjectDeletionStatus>([
  'pending',
  'cancelling',
  'deleting',
  'complete',
  'failed',
])
const projectKeys = [
  'id',
  'task_id',
  'file_node_id',
  'target_path',
  'layout_version',
  'source_kind',
  'language',
  'engine_name',
  'engine_version',
  'status',
  'source_file_count',
  'symbol_count',
  'source_size_bytes',
  'manifest_available',
  'created_at',
] as const
const optionalProjectKeys = [
  'job_id',
  'canonical_filename',
  'completed_at',
] as const

export class DecompileProjectContractError extends Error {
  constructor(field: string) {
    super(`反编译源码项目响应不符合接口契约：${field}`)
    this.name = 'DecompileProjectContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new DecompileProjectContractError(field)
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
    throw new DecompileProjectContractError(field)
  }
}

function stringValue(
  value: unknown,
  field: string,
  minLength: number,
  maxLength: number,
): string {
  const hasControlCharacter =
    typeof value === 'string' &&
    Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0
      return codePoint <= 31 || codePoint === 127
    })
  if (
    typeof value !== 'string' ||
    value.length < minLength ||
    value.length > maxLength ||
    hasControlCharacter
  ) {
    throw new DecompileProjectContractError(field)
  }
  return value
}

function identifier(value: unknown, field: string): string {
  const parsed = stringValue(value, field, 1, 128)
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(parsed)) {
    throw new DecompileProjectContractError(field)
  }
  return parsed
}

function enumValue<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  field: string,
): T {
  const parsed = stringValue(value, field, 1, 64)
  if (!allowed.has(parsed as T)) throw new DecompileProjectContractError(field)
  return parsed as T
}

function nonNegativeInteger(value: unknown, field: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new DecompileProjectContractError(field)
  }
  return value as number
}

function timestamp(value: unknown, field: string): string {
  const parsed = stringValue(value, field, 1, 64)
  if (!Number.isFinite(Date.parse(parsed))) {
    throw new DecompileProjectContractError(field)
  }
  return parsed
}

function projectValue(value: unknown, field: string): DecompileProject {
  const project = record(value, field)
  exactKeys(project, projectKeys, optionalProjectKeys, field)
  if (typeof project.manifest_available !== 'boolean') {
    throw new DecompileProjectContractError(`${field}.manifest_available`)
  }

  const parsed: DecompileProject = {
    id: identifier(project.id, `${field}.id`),
    task_id: identifier(project.task_id, `${field}.task_id`),
    file_node_id: identifier(project.file_node_id, `${field}.file_node_id`),
    target_path: stringValue(
      project.target_path,
      `${field}.target_path`,
      1,
      2_048,
    ),
    layout_version: enumValue(
      project.layout_version,
      layoutVersions,
      `${field}.layout_version`,
    ),
    source_kind: enumValue(
      project.source_kind,
      sourceKinds,
      `${field}.source_kind`,
    ),
    language: stringValue(project.language, `${field}.language`, 1, 64),
    engine_name: stringValue(
      project.engine_name,
      `${field}.engine_name`,
      1,
      128,
    ),
    engine_version: stringValue(
      project.engine_version,
      `${field}.engine_version`,
      1,
      128,
    ),
    status: enumValue(project.status, statuses, `${field}.status`),
    source_file_count: nonNegativeInteger(
      project.source_file_count,
      `${field}.source_file_count`,
    ),
    symbol_count: nonNegativeInteger(
      project.symbol_count,
      `${field}.symbol_count`,
    ),
    source_size_bytes: nonNegativeInteger(
      project.source_size_bytes,
      `${field}.source_size_bytes`,
    ),
    manifest_available: project.manifest_available,
    created_at: timestamp(project.created_at, `${field}.created_at`),
  }
  if (project.job_id !== undefined) {
    parsed.job_id = identifier(project.job_id, `${field}.job_id`)
  }
  if (project.canonical_filename !== undefined) {
    parsed.canonical_filename = stringValue(
      project.canonical_filename,
      `${field}.canonical_filename`,
      1,
      2_048,
    )
  }
  if (project.completed_at !== undefined) {
    parsed.completed_at = timestamp(
      project.completed_at,
      `${field}.completed_at`,
    )
  }
  return parsed
}

export function parseDecompileProjectPage(value: unknown): DecompileProjectPage {
  const page = record(value, 'data')
  exactKeys(page, ['items'], ['next_cursor'], 'data')
  if (!Array.isArray(page.items) || page.items.length > 200) {
    throw new DecompileProjectContractError('data.items')
  }

  const parsed: DecompileProjectPage = {
    items: page.items.map((item, index) =>
      projectValue(item, `data.items[${index}]`),
    ),
  }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = stringValue(
      page.next_cursor,
      'data.next_cursor',
      1,
      2_048,
    )
  }
  return parsed
}

export function parseDecompileProject(value: unknown): DecompileProject {
  return projectValue(value, 'data')
}

function deletionCountsValue(
  value: unknown,
  field: string,
): DecompileProjectDeletionCounts {
  const counts = record(value, field)
  const keys = [
    'c_analysis_runs',
    'c_analysis_findings',
    'java_analysis_runs',
    'java_analysis_findings',
    'reports',
    'report_files',
    'artifacts',
    'decompile_results',
    'source_files',
  ] as const
  exactKeys(counts, keys, [], field)
  return {
    c_analysis_runs: nonNegativeInteger(
      counts.c_analysis_runs,
      `${field}.c_analysis_runs`,
    ),
    c_analysis_findings: nonNegativeInteger(
      counts.c_analysis_findings,
      `${field}.c_analysis_findings`,
    ),
    java_analysis_runs: nonNegativeInteger(
      counts.java_analysis_runs,
      `${field}.java_analysis_runs`,
    ),
    java_analysis_findings: nonNegativeInteger(
      counts.java_analysis_findings,
      `${field}.java_analysis_findings`,
    ),
    reports: nonNegativeInteger(counts.reports, `${field}.reports`),
    report_files: nonNegativeInteger(
      counts.report_files,
      `${field}.report_files`,
    ),
    artifacts: nonNegativeInteger(counts.artifacts, `${field}.artifacts`),
    decompile_results: nonNegativeInteger(
      counts.decompile_results,
      `${field}.decompile_results`,
    ),
    source_files: nonNegativeInteger(
      counts.source_files,
      `${field}.source_files`,
    ),
  }
}

export function parseDecompileProjectDeletionPreview(
  value: unknown,
): DecompileProjectDeletionPreview {
  const preview = record(value, 'data')
  exactKeys(
    preview,
    [
      'project_id',
      'counts',
      'typed_suffix',
      'confirmation_token',
      'expires_at',
    ],
    [],
    'data',
  )
  const projectID = identifier(preview.project_id, 'data.project_id')
  const typedSuffix = stringValue(preview.typed_suffix, 'data.typed_suffix', 8, 8)
  if (typedSuffix !== projectID.slice(-8)) {
    throw new DecompileProjectContractError('data.typed_suffix')
  }
  return {
    project_id: projectID,
    counts: deletionCountsValue(preview.counts, 'data.counts'),
    typed_suffix: typedSuffix,
    confirmation_token: stringValue(
      preview.confirmation_token,
      'data.confirmation_token',
      32,
      512,
    ),
    expires_at: timestamp(preview.expires_at, 'data.expires_at'),
  }
}

export function parseDecompileProjectDeletionOperation(
  value: unknown,
): DecompileProjectDeletionOperation {
  const operation = record(value, 'data')
  exactKeys(
    operation,
    [
      'id',
      'project_id',
      'status',
      'counts',
      'created_at',
      'completed_at',
      'error_code',
      'error_message',
    ],
    [],
    'data',
  )
  const parsed: DecompileProjectDeletionOperation = {
    id: identifier(operation.id, 'data.id'),
    project_id: identifier(operation.project_id, 'data.project_id'),
    status: enumValue(operation.status, deletionStatuses, 'data.status'),
    counts: deletionCountsValue(operation.counts, 'data.counts'),
    created_at: timestamp(operation.created_at, 'data.created_at'),
    completed_at:
      operation.completed_at === null
        ? null
        : timestamp(operation.completed_at, 'data.completed_at'),
    error_code:
      operation.error_code === null
        ? null
        : stringValue(operation.error_code, 'data.error_code', 1, 128),
    error_message:
      operation.error_message === null
        ? null
        : stringValue(operation.error_message, 'data.error_message', 1, 2_048),
  }
  return parsed
}
