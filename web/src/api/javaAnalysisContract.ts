import type {
  JavaAnalysisFinding,
  JavaAnalysisFindingPage,
  JavaAnalysisRun,
  JavaAnalysisRunPage,
  JavaAnalysisRunStatus,
  JavaAnalysisSeverity,
} from '@/api/types'

const runStatuses = new Set<JavaAnalysisRunStatus>([
  'queued',
  'running',
  'succeeded',
  'partial',
  'failed',
  'cancel_requested',
  'cancelled',
])
const severities = new Set<JavaAnalysisSeverity>([
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
])
const projectStatuses = new Set(['complete', 'partial'] as const)
const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/
const sha256Pattern = /^[a-f0-9]{64}$/
const positiveDecimalPattern = /^[1-9][0-9]*$/

export class JavaAnalysisContractError extends Error {
  constructor(field: string) {
    super(`Java 源码检测响应不符合接口契约：${field}`)
    this.name = 'JavaAnalysisContractError'
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new JavaAnalysisContractError(field)
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
    throw new JavaAnalysisContractError(field)
  }
}

function textValue(
  value: unknown,
  field: string,
  maximum: number,
  allowEmpty = false,
): string {
  if (
    typeof value !== 'string' ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximum ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0) ?? 0
      return point === 0 || (point < 32 && point !== 9 && point !== 10 && point !== 13) || point === 127
    })
  ) {
    throw new JavaAnalysisContractError(field)
  }
  return value
}

function uuid(value: unknown, field: string): string {
  const parsed = textValue(value, field, 36)
  if (!uuidPattern.test(parsed)) throw new JavaAnalysisContractError(field)
  return parsed
}

function integer(value: unknown, field: string, maximum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > maximum
  ) {
    throw new JavaAnalysisContractError(field)
  }
  return value
}

function positiveInteger(value: unknown, field: string, maximum: number): number {
  const parsed = integer(value, field, maximum)
  if (parsed === 0) throw new JavaAnalysisContractError(field)
  return parsed
}

function booleanValue(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new JavaAnalysisContractError(field)
  return value
}

function timestamp(value: unknown, field: string): string {
  const parsed = textValue(value, field, 64)
  if (!Number.isFinite(Date.parse(parsed))) throw new JavaAnalysisContractError(field)
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

function enumValue<T extends string>(
  value: unknown,
  allowed: ReadonlySet<T>,
  field: string,
): T {
  const parsed = textValue(value, field, 64)
  if (!allowed.has(parsed as T)) throw new JavaAnalysisContractError(field)
  return parsed as T
}

function sha256(value: unknown, field: string, allowEmpty = false): string {
  const parsed = textValue(value, field, 64, allowEmpty)
  if (parsed !== '' && !sha256Pattern.test(parsed)) {
    throw new JavaAnalysisContractError(field)
  }
  return parsed
}

function runValue(value: unknown, field: string): JavaAnalysisRun {
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
      'ruleset_version',
      'source_manifest_sha256',
      'input_sha256',
      'bundle_sha256',
      'source_size_bytes',
      'source_file_count',
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
    [],
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
    [
      'total_files',
      'analyzed_files',
      'parsed_files',
      'recovered_files',
      'failed_files',
    ],
    [],
    `${field}.coverage`,
  )
  const severityCounts = record(run.severity_counts, `${field}.severity_counts`)
  exactKeys(
    severityCounts,
    ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    [],
    `${field}.severity_counts`,
  )

  const status = enumValue(run.status, runStatuses, `${field}.status`)
  const sourceFileCount = positiveInteger(
    run.source_file_count,
    `${field}.source_file_count`,
    3_000,
  )
  const totalFiles = positiveInteger(
    coverage.total_files,
    `${field}.coverage.total_files`,
    3_000,
  )
  if (totalFiles !== sourceFileCount) {
    throw new JavaAnalysisContractError(`${field}.coverage.total_files`)
  }
  const parsedFiles = integer(
    coverage.parsed_files,
    `${field}.coverage.parsed_files`,
    totalFiles,
  )
  const analyzedFiles = integer(
    coverage.analyzed_files,
    `${field}.coverage.analyzed_files`,
    parsedFiles,
  )
  const recoveredFiles = integer(
    coverage.recovered_files,
    `${field}.coverage.recovered_files`,
    parsedFiles,
  )
  const failedFiles = integer(
    coverage.failed_files,
    `${field}.coverage.failed_files`,
    totalFiles,
  )
  if (
    ['succeeded', 'partial'].includes(status) &&
    parsedFiles + failedFiles !== totalFiles
  ) {
    throw new JavaAnalysisContractError(`${field}.coverage`)
  }

  const findingCount = integer(run.finding_count, `${field}.finding_count`, 10_000)
  const parsedSeverityCounts = {
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
    Object.values(parsedSeverityCounts).reduce((sum, count) => sum + count, 0) !==
    findingCount
  ) {
    throw new JavaAnalysisContractError(`${field}.severity_counts`)
  }
  const sourceProjectID = uuid(
    run.source_project_id,
    `${field}.source_project_id`,
  )
  const projectID = uuid(project.id, `${field}.source_project.id`)
  if (sourceProjectID !== projectID) {
    throw new JavaAnalysisContractError(`${field}.source_project.id`)
  }

  return {
    id: uuid(run.id, `${field}.id`),
    task_id: uuid(run.task_id, `${field}.task_id`),
    source_project_id: sourceProjectID,
    source_project: {
      id: projectID,
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
    status,
    analyzer_name: textValue(run.analyzer_name, `${field}.analyzer_name`, 128),
    analyzer_version: textValue(
      run.analyzer_version,
      `${field}.analyzer_version`,
      128,
    ),
    ruleset_version: textValue(
      run.ruleset_version,
      `${field}.ruleset_version`,
      128,
      true,
    ),
    source_manifest_sha256: sha256(
      run.source_manifest_sha256,
      `${field}.source_manifest_sha256`,
    ),
    input_sha256: sha256(run.input_sha256, `${field}.input_sha256`),
    bundle_sha256: sha256(
      run.bundle_sha256,
      `${field}.bundle_sha256`,
      true,
    ),
    source_size_bytes: positiveInteger(
      run.source_size_bytes,
      `${field}.source_size_bytes`,
      128 * 1024 * 1024,
    ),
    source_file_count: sourceFileCount,
    finding_count: findingCount,
    diagnostic_count: integer(
      run.diagnostic_count,
      `${field}.diagnostic_count`,
      1_000,
    ),
    coverage: {
      total_files: totalFiles,
      analyzed_files: analyzedFiles,
      parsed_files: parsedFiles,
      recovered_files: recoveredFiles,
      failed_files: failedFiles,
    },
    severity_counts: parsedSeverityCounts,
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
}

function findingValue(value: unknown, field: string): JavaAnalysisFinding {
  const finding = record(value, field)
  exactKeys(
    finding,
    [
      'id',
      'cwe',
      'rule_id',
      'severity',
      'file',
      'callable',
      'location',
      'message',
    ],
    ['snippet', 'snippet_start_line', 'created_at'],
    field,
  )
  const file = record(finding.file, `${field}.file`)
  exactKeys(
    file,
    ['result_id', 'logical_path', 'binary_name'],
    [],
    `${field}.file`,
  )
  const callable = record(finding.callable, `${field}.callable`)
  exactKeys(
    callable,
    ['kind', 'type_name', 'name', 'signature'],
    [],
    `${field}.callable`,
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
    0xffff_ffff,
  )
  const startColumn = positiveInteger(
    location.start_column,
    `${field}.location.start_column`,
    0xffff_ffff,
  )
  const endLine = positiveInteger(
    location.end_line,
    `${field}.location.end_line`,
    0xffff_ffff,
  )
  const endColumn = positiveInteger(
    location.end_column,
    `${field}.location.end_column`,
    0xffff_ffff,
  )
  if (endLine < startLine || (endLine === startLine && endColumn < startColumn)) {
    throw new JavaAnalysisContractError(`${field}.location`)
  }
  const id = textValue(finding.id, `${field}.id`, 20)
  if (!positiveDecimalPattern.test(id)) {
    throw new JavaAnalysisContractError(`${field}.id`)
  }

  const parsed: JavaAnalysisFinding = {
    id,
    cwe: textValue(finding.cwe, `${field}.cwe`, 16),
    rule_id: textValue(finding.rule_id, `${field}.rule_id`, 64),
    severity: enumValue(finding.severity, severities, `${field}.severity`),
    file: {
      result_id: uuid(file.result_id, `${field}.file.result_id`),
      logical_path: textValue(
        file.logical_path,
        `${field}.file.logical_path`,
        1_024,
      ),
      binary_name: textValue(
        file.binary_name,
        `${field}.file.binary_name`,
        1_024,
      ),
    },
    callable: {
      kind: textValue(callable.kind, `${field}.callable.kind`, 32),
      type_name: textValue(
        callable.type_name,
        `${field}.callable.type_name`,
        1_024,
      ),
      name: textValue(callable.name, `${field}.callable.name`, 512),
      signature: textValue(
        callable.signature,
        `${field}.callable.signature`,
        2_048,
        true,
      ),
    },
    location: {
      start_line: startLine,
      start_column: startColumn,
      end_line: endLine,
      end_column: endColumn,
    },
    message: textValue(finding.message, `${field}.message`, 2_048),
  }

  const hasSnippet = finding.snippet !== undefined
  const hasSnippetStartLine = finding.snippet_start_line !== undefined
  if (hasSnippet !== hasSnippetStartLine) {
    throw new JavaAnalysisContractError(`${field}.snippet`)
  }
  if (hasSnippet) {
    const snippet = textValue(
      finding.snippet,
      `${field}.snippet`,
      1_024,
      true,
    )
    if (!snippet || new TextEncoder().encode(snippet).byteLength > 1_024) {
      throw new JavaAnalysisContractError(`${field}.snippet`)
    }
    parsed.snippet = snippet
    parsed.snippet_start_line = positiveInteger(
      finding.snippet_start_line,
      `${field}.snippet_start_line`,
      0xffff_ffff,
    )
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
    throw new JavaAnalysisContractError(`${field}.items`)
  }
  const parsed: { items: T[]; next_cursor?: string } = {
    items: page.items.map((item, index) =>
      parseItem(item, `${field}.items[${index}]`),
    ),
  }
  if (page.next_cursor !== undefined) {
    parsed.next_cursor = textValue(
      page.next_cursor,
      `${field}.next_cursor`,
      2_048,
    )
  }
  return parsed
}

export function parseJavaAnalysisRun(value: unknown): JavaAnalysisRun {
  return runValue(value, 'data')
}

export function parseJavaAnalysisRunPage(value: unknown): JavaAnalysisRunPage {
  return pageValue(value, 'data', runValue)
}

export function parseJavaAnalysisFindingPage(
  value: unknown,
): JavaAnalysisFindingPage {
  return pageValue(value, 'data', findingValue)
}
