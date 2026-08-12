import { describe, expect, it } from 'vitest'

import {
  JavaAnalysisContractError,
  parseJavaAnalysisFindingPage,
  parseJavaAnalysisRun,
} from '@/api/javaAnalysisContract'

const run = {
  id: '123e4567-e89b-42d3-a456-426614174001',
  task_id: '123e4567-e89b-42d3-a456-426614174002',
  source_project_id: '123e4567-e89b-42d3-a456-426614174003',
  source_project: {
    id: '123e4567-e89b-42d3-a456-426614174003',
    target_path: '/app/example.jar',
    status: 'complete',
    engine_name: 'cfr',
    engine_version: '0.152',
  },
  job_id: '123e4567-e89b-42d3-a456-426614174004',
  status: 'partial',
  analyzer_name: 'binaryscan-java-checker',
  analyzer_version: '0.1.0',
  ruleset_version: 'java-rules-v1',
  source_manifest_sha256: 'a'.repeat(64),
  input_sha256: 'b'.repeat(64),
  bundle_sha256: 'c'.repeat(64),
  source_size_bytes: 4096,
  source_file_count: 3,
  finding_count: 2,
  diagnostic_count: 1,
  coverage: {
    total_files: 3,
    analyzed_files: 2,
    parsed_files: 2,
    recovered_files: 1,
    failed_files: 1,
  },
  severity_counts: { LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 0 },
  findings_truncated: false,
  diagnostics_truncated: false,
  error_code: null,
  error_message: null,
  started_at: '2026-08-10T08:00:00Z',
  completed_at: '2026-08-10T08:01:00Z',
  created_at: '2026-08-10T07:59:00Z',
  updated_at: '2026-08-10T08:01:00Z',
}

const finding = {
  id: '42',
  cwe: 'CWE-89',
  rule_id: 'java-sql-injection',
  severity: 'HIGH',
  file: {
    result_id: '123e4567-e89b-42d3-a456-426614174005',
    logical_path: 'src/main/java/app/QueryService.java',
    binary_name: 'app.QueryService',
  },
  callable: {
    kind: 'method',
    type_name: 'app.QueryService',
    name: 'lookup',
    signature: 'lookup(java.lang.String)',
  },
  location: {
    start_line: 81,
    start_column: 5,
    end_line: 81,
    end_column: 31,
  },
  message: 'SQL query includes untrusted input.',
  snippet: 'String sql = "SELECT " + name;',
  snippet_start_line: 79,
  created_at: '2026-08-10T08:01:00Z',
}

describe('Java analysis runtime contract', () => {
  it('accepts the file coverage and four-severity run contract', () => {
    expect(parseJavaAnalysisRun(run)).toMatchObject({
      status: 'partial',
      source_file_count: 3,
      coverage: { parsed_files: 2, recovered_files: 1 },
      severity_counts: { HIGH: 1, MEDIUM: 1 },
    })
  })

  it('accepts file, callable, location and exact snippet line metadata', () => {
    expect(parseJavaAnalysisFindingPage({ items: [finding] }).items[0]).toEqual(
      finding,
    )
  })

  it.each([
    'confidence',
    'remediation',
    'fix_suggestion',
    'review_state',
    'manual_review',
  ])('rejects the forbidden %s field', (field) => {
    expect(() =>
      parseJavaAnalysisFindingPage({
        items: [{ ...finding, [field]: 'not-part-of-contract' }],
      }),
    ).toThrow(JavaAnalysisContractError)
  })

  it('rejects impossible coverage and snippet metadata without its source line', () => {
    expect(() =>
      parseJavaAnalysisRun({
        ...run,
        coverage: { ...run.coverage, parsed_files: 3, failed_files: 1 },
      }),
    ).toThrow(JavaAnalysisContractError)
    const withoutLine: Partial<typeof finding> = { ...finding }
    delete withoutLine.snippet_start_line
    expect(() =>
      parseJavaAnalysisFindingPage({ items: [withoutLine] }),
    ).toThrow(JavaAnalysisContractError)
  })
})
