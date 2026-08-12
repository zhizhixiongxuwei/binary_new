import { describe, expect, it } from 'vitest'

import {
  CAnalysisContractError,
  parseCAnalysisFindingPage,
  parseCAnalysisRun,
} from '@/api/cAnalysisContract'

const run = {
  id: '123e4567-e89b-42d3-a456-426614174001',
  task_id: '123e4567-e89b-42d3-a456-426614174002',
  source_project_id: '123e4567-e89b-42d3-a456-426614174003',
  source_project: {
    id: '123e4567-e89b-42d3-a456-426614174003',
    target_path: '/usr/bin/example',
    status: 'complete',
    engine_name: 'ghidra',
    engine_version: '12.1.2',
  },
  job_id: '123e4567-e89b-42d3-a456-426614174004',
  status: 'partial',
  analyzer_name: 'binaryscan-c-checker',
  analyzer_version: '0.1.0',
  ruleset_version: 'c-rules-v1',
  source_sha256: 'a'.repeat(64),
  source_size_bytes: 4096,
  finding_count: 2,
  diagnostic_count: 1,
  coverage: {
    total_functions: 3,
    parsed_functions: 2,
    failed_functions: 1,
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
  cwe: 'CWE-120',
  rule_id: 'cwe-120-bounds',
  severity: 'HIGH',
  function: {
    result_id: '123e4567-e89b-42d3-a456-426614174005',
    address: '0x401000',
    name: 'copy_input',
  },
  location: {
    start_line: 81,
    start_column: 3,
    end_line: 81,
    end_column: 18,
  },
  message: 'Unbounded string copy writes into a fixed buffer.',
  snippet: 'strcpy(local, input);',
  created_at: '2026-08-10T08:01:00Z',
}

describe('C analysis runtime contract', () => {
  it('accepts the fixed run, coverage and four-severity contract', () => {
    expect(parseCAnalysisRun(run)).toMatchObject({
      status: 'partial',
      finding_count: 2,
      severity_counts: { HIGH: 1, MEDIUM: 1 },
    })
  })

  it('accepts findings without confidence, remediation or review state', () => {
    expect(parseCAnalysisFindingPage({ items: [finding] }).items[0]).toEqual(
      finding,
    )
  })

  it.each(['confidence', 'remediation', 'review_state'])(
    'rejects the forbidden %s field',
    (field) => {
      expect(() =>
        parseCAnalysisFindingPage({
          items: [{ ...finding, [field]: 'not-part-of-contract' }],
        }),
      ).toThrow(CAnalysisContractError)
    },
  )

  it('rejects impossible coverage and oversized snippets', () => {
    expect(() =>
      parseCAnalysisRun({
        ...run,
        coverage: { total_functions: 3, parsed_functions: 3, failed_functions: 1 },
      }),
    ).toThrow(CAnalysisContractError)
    expect(() =>
      parseCAnalysisFindingPage({
        items: [{ ...finding, snippet: 'x'.repeat(1_025) }],
      }),
    ).toThrow(CAnalysisContractError)
    expect(() =>
      parseCAnalysisFindingPage({
        items: [{ ...finding, snippet: '界'.repeat(400) }],
      }),
    ).toThrow(CAnalysisContractError)
  })
})
