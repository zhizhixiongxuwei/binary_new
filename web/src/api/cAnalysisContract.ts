import type {
  CAnalysisFinding,
  CAnalysisFindingPage,
  CAnalysisRun,
  CAnalysisRunPage,
  CAnalysisRunStatus,
  CAnalysisSeverity,
} from '@/api/types'

const runStatuses = new Set<CAnalysisRunStatus>([
  'queued',
  'running',
  'succeeded',
  'partial',
  'failed',
  'cancel_requested',
  'cancelled',
])
const severities = new Set<CAnalysisSeverity>([
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
])
const projectStatuses = new Set(['complete', 'partial'] as const)
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const sha256Pattern = /^[a-f0-9]{64}$/

export class CAnalysisContractError extends Error {
  constructor(field: string) {
    super(`C 源码检测响应不符合接口契约：${field}`)
    this.name = 'CAnalysisContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new CAnalysisContractError(field)
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
    throw new CAnalysisContractError(field)
  }
}

function textValue(
  value: unknown,
  field: string,
  maxLength: number,
  allowEmpty = false,
): string {
  if (
    typeof value !== 'string' ||
    (!allowEmpty && value.length === 0) ||
    value.length > maxLength ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0
      return point === 0 || point === 127
    })
  ) {
    throw new CAnalysisContractError(field)
  }
  return value
}

function uuid(value: unknown, field: string): string {
  const parsed = textValue(value, field, 36)
  if (!uuidPattern.test(parsed)) throw new CAnalysisContractError(field)
  return parsed
}

function integer(value: unknown, field: string, maximum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new CAnalysisContractError(field)
  }
  return value
}

function positiveInteger(
  value: unknown,
  field: string,
  maximum: number,
): number {
  const parsed = integer(value, field, maximum)
  if (parsed === 0) throw new CAnalysisContractError(field)
  return parsed
}

function timestamp(value: unknown, field: string): string {
  const parsed = textValue(value, field, 64)
  if (!Number.isFinite(Date.parse(parsed))) {
    throw new CAnalysisContractError(field)
  }
  return parsed
}

function nullableTimestamp(value: unknown, field: string): string | null {
  return value === null ? null : timestamp(value, field)
}

function nullableText(
  value: unknown,
  field: string,
  maximum: number,
): string | null {
  return value === null ? null : textValue(value, field, maximum)
}

function booleanValue(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new CAnalysisContractError(field)
  return value
}

function enumValue<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  field: string,
): T {
  const parsed = textValue(value, field, 64)
  if (!allowed.has(parsed as T)) throw new CAnalysisContractError(field)
  return parsed as T
}

function runValue(value: unknown, field: string): CAnalysisRun {
  const run = record(value, field)
  exactKeys(
    run,
    [
      'id',
      'task_id',
      'source_project_id',
      'source_project',
      'job_id',
      'status',
      'analyzer_name',
      'analyzer_version',
      'source_sha256',
      'source_size_bytes',
      'finding_count',
      'diagnostic_count',
      'coverage',
      'severity_counts',
      'findings_truncated',
      'diagnostics_truncated',
      'error_code',
      'error_message',
      'started_at',
      'completed_at',
      'created_at',
      'updated_at',
    ],
    ['ruleset_version'],
    field,
  )

  const project = record(run.source_project, `${field}.source_project`)
  exactKeys(
    project,
    ['id', 'target_path', 'status', 'engine_name', 'engine_version'],
    [],
    `${field}.source_project`,
  )
  const coverage = record(run.coverage, `${field}.coverage`)
  exactKeys(
    coverage,
    ['total_functions', 'parsed_functions', 'failed_functions'],
    [],
    `${field}.coverage`,
  )
  const severityCounts = record(
    run.severity_counts,
    `${field}.severity_counts`,
  )
  exactKeys(
    severityCounts,
    ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    [],
    `${field}.severity_counts`,
  )

  const sourceSHA256 = textValue(run.source_sha256, `${field}.source_sha256`, 64)
  if (!sha256Pattern.test(sourceSHA256)) {
    throw new CAnalysisContractError(`${field}.source_sha256`)
  }
  const totalFunctions = positiveInteger(
    coverage.total_functions,
    `${field}.coverage.total_functions`,
    3_000,
  )
  const parsedFunctions = integer(
    coverage.parsed_functions,
    `${field}.coverage.parsed_functions`,
    totalFunctions,
  )
  const failedFunctions = integer(
    coverage.failed_functions,
    `${field}.coverage.failed_functions`,
    totalFunctions,
  )
  if (parsedFunctions + failedFunctions > totalFunctions) {
    throw new CAnalysisContractError(`${field}.coverage`)
  }
  const findingCount = integer(
    run.finding_count,
    `${field}.finding_count`,
    10_000,
  )
  const severityCountValues = {
    LOW: integer(severityCounts.LOW, `${field}.severity_counts.LOW`, 10_000),
    MEDIUM: integer(
      severityCounts.MEDIUM,
      `${field}.severity_counts.MEDIUM`,
      10_000,
    ),
    HIGH: integer(severityCounts.HIGH, `${field}.severity_counts.HIGH`, 10_000),
    CRITICAL: integer(
      severityCounts.CRITICAL,
      `${field}.severity_counts.CRITICAL`,
      10_000,
    ),
  }
  if (
    Object.values(severityCountValues).reduce((sum, count) => sum + count, 0) !==
    findingCount
  ) {
    throw new CAnalysisContractError(`${field}.severity_counts`)
  }

  const parsed: CAnalysisRun = {
    id: uuid(run.id, `${field}.id`),
    task_id: uuid(run.task_id, `${field}.task_id`),
    source_project_id: uuid(
      run.source_project_id,
      `${field}.source_project_id`,
    ),
    source_project: {
      id: uuid(project.id, `${field}.source_project.id`),
      target_path: textValue(
        project.target_path,
        `${field}.source_project.target_path`,
        2_048,
      ),
      status: enumValue(
        project.status,
        projectStatuses,
        `${field}.source_project.status`,
      ),
      engine_name: textValue(
        project.engine_name,
        `${field}.source_project.engine_name`,
        128,
      ),
      engine_version: textValue(
        project.engine_version,
        `${field}.source_project.engine_version`,
        128,
      ),
    },
    job_id: uuid(run.job_id, `${field}.job_id`),
    status: enumValue(run.status, runStatuses, `${field}.status`),
    analyzer_name: textValue(run.analyzer_name, `${field}.analyzer_name`, 128),
    analyzer_version: textValue(
      run.analyzer_version,
      `${field}.analyzer_version`,
      128,
    ),
    source_sha256: sourceSHA256,
    source_size_bytes: positiveInteger(
      run.source_size_bytes,
      `${field}.source_size_bytes`,
      128 * 1024 * 1024,
    ),
    finding_count: findingCount,
    diagnostic_count: integer(
      run.diagnostic_count,
      `${field}.diagnostic_count`,
      1_000,
    ),
    coverage: {
      total_functions: totalFunctions,
      parsed_functions: parsedFunctions,
      failed_functions: failedFunctions,
    },
    severity_counts: severityCountValues,
    findings_truncated: booleanValue(
      run.findings_truncated,
      `${field}.findings_truncated`,
    ),
    diagnostics_truncated: booleanValue(
      run.diagnostics_truncated,
      `${field}.diagnostics_truncated`,
    ),
    error_code: nullableText(run.error_code, `${field}.error_code`, 128),
    error_message: nullableText(
      run.error_message,
      `${field}.error_message`,
      2_048,
    ),
    started_at: nullableTimestamp(run.started_at, `${field}.started_at`),
    completed_at: nullableTimestamp(run.completed_at, `${field}.completed_at`),
    created_at: timestamp(run.created_at, `${field}.created_at`),
    updated_at: timestamp(run.updated_at, `${field}.updated_at`),
  }
  if (run.ruleset_version !== undefined) {
    parsed.ruleset_version = textValue(
      run.ruleset_version,
      `${field}.ruleset_version`,
      128,
    )
  }
  return parsed
}

function findingValue(value: unknown, field: string): CAnalysisFinding {
  const finding = record(value, field)
  exactKeys(
    finding,
    ['id', 'cwe', 'rule_id', 'severity', 'function', 'location', 'message'],
    ['snippet', 'created_at'],
    field,
  )
  const functionValue = record(finding.function, `${field}.function`)
  exactKeys(
    functionValue,
    ['result_id', 'address', 'name'],
    [],
    `${field}.function`,
  )
  const location = record(finding.location, `${field}.location`)
  exactKeys(
    location,
    ['start_line', 'start_column', 'end_line', 'end_column'],
    [],
    `${field}.location`,
  )
  const startLine = positiveInteger(
    location.start_line,
    `${field}.location.start_line`,
    10_000_000,
  )
  const startColumn = positiveInteger(
    location.start_column,
    `${field}.location.start_column`,
    1_000_000,
  )
  const endLine = positiveInteger(
    location.end_line,
    `${field}.location.end_line`,
    10_000_000,
  )
  const endColumn = positiveInteger(
    location.end_column,
    `${field}.location.end_column`,
    1_000_000,
  )
  if (endLine < startLine || (endLine === startLine && endColumn < startColumn)) {
    throw new CAnalysisContractError(`${field}.location`)
  }

  const parsed: CAnalysisFinding = {
    id: textValue(finding.id, `${field}.id`, 32),
    cwe: textValue(finding.cwe, `${field}.cwe`, 16),
    rule_id: textValue(finding.rule_id, `${field}.rule_id`, 64),
    severity: enumValue(finding.severity, severities, `${field}.severity`),
    function: {
      result_id: uuid(
        functionValue.result_id,
        `${field}.function.result_id`,
      ),
      address: textValue(
        functionValue.address,
        `${field}.function.address`,
        128,
        true,
      ),
      name: textValue(functionValue.name, `${field}.function.name`, 512),
    },
    location: {
      start_line: startLine,
      start_column: startColumn,
      end_line: endLine,
      end_column: endColumn,
    },
    message: textValue(finding.message, `${field}.message`, 2_048),
  }
  if (finding.snippet !== undefined) {
    const snippet = textValue(
      finding.snippet,
      `${field}.snippet`,
      1_024,
      true,
    )
    if (new TextEncoder().encode(snippet).byteLength > 1_024) {
      throw new CAnalysisContractError(`${field}.snippet`)
    }
    parsed.snippet = snippet
  }
  if (finding.created_at !== undefined) {
    parsed.created_at = timestamp(finding.created_at, `${field}.created_at`)
  }
  return parsed
}

function pageValue<T>(
  value: unknown,
  field: string,
  parseItem: (value: unknown, field: string) => T,
): { items: T[]; next_cursor?: string } {
  const page = record(value, field)
  exactKeys(page, ['items'], ['next_cursor'], field)
  if (!Array.isArray(page.items) || page.items.length > 200) {
    throw new CAnalysisContractError(`${field}.items`)
  }
  const parsed = {
    items: page.items.map((item, index) =>
      parseItem(item, `${field}.items[${index}]`),
    ),
  } as { items: T[]; next_cursor?: string }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = textValue(
      page.next_cursor,
      `${field}.next_cursor`,
      2_048,
    )
  }
  return parsed
}

export function parseCAnalysisRun(value: unknown): CAnalysisRun {
  return runValue(value, 'data')
}

export function parseCAnalysisRunPage(value: unknown): CAnalysisRunPage {
  return pageValue(value, 'data', runValue)
}

export function parseCAnalysisFindingPage(
  value: unknown,
): CAnalysisFindingPage {
  return pageValue(value, 'data', findingValue)
}
