import { describe, expect, it } from 'vitest'

import {
  DecompileProjectContractError,
  parseDecompileProject,
  parseDecompileProjectDeletionOperation,
  parseDecompileProjectPage,
} from '@/api/decompileProjectContract'

function project() {
  return {
    id: '123e4567-e89b-42d3-a456-426614174000',
    task_id: '223e4567-e89b-42d3-a456-426614174001',
    job_id: '323e4567-e89b-42d3-a456-426614174002',
    file_node_id: '18446744073709551614',
    target_path: '/opt/sample/bin/server',
    layout_version: 'project-v1',
    source_kind: 'ghidra-pseudoc',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '11.3.2',
    status: 'complete',
    source_file_count: 1,
    symbol_count: 2899,
    source_size_bytes: 8_388_608,
    canonical_filename: 'src/decompiled.c',
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:03:00Z',
  }
}

describe('decompile-project runtime contract', () => {
  it('parses project and cursor fields without changing identifiers', () => {
    const value = project()
    const page = parseDecompileProjectPage({
      items: [value],
      next_cursor: 'opaque:cursor-2',
    })

    expect(page.items[0]).toEqual(value)
    expect(page.next_cursor).toBe('opaque:cursor-2')
    expect(parseDecompileProject(value)).toEqual(value)
  })

  it('accepts a legacy item without job, canonical file, or completion time', () => {
    const legacy = Object.fromEntries(
      Object.entries(project()).filter(
        ([key]) =>
          !['job_id', 'canonical_filename', 'completed_at'].includes(key),
      ),
    )

    expect(
      parseDecompileProject({
        ...legacy,
        layout_version: 'legacy-v1',
        source_kind: 'java',
        language: 'java',
        manifest_available: false,
      }),
    ).toMatchObject({
      layout_version: 'legacy-v1',
      source_kind: 'java',
      manifest_available: false,
    })
  })

  it.each([
    ['negative size', { ...project(), source_size_bytes: -1 }],
    ['unknown source kind', { ...project(), source_kind: 'plain-c' }],
    ['invalid date', { ...project(), completed_at: 'not-a-date' }],
    ['leaked storage path', { ...project(), storage_key: 'source-projects/private' }],
  ])('rejects %s', (_label, invalid) => {
    expect(() => parseDecompileProject(invalid)).toThrow(
      DecompileProjectContractError,
    )
  })

  it('parses pending deletion operations with explicit nullable fields', () => {
    expect(
      parseDecompileProjectDeletionOperation({
        id: '423e4567-e89b-42d3-a456-426614174003',
        project_id: project().id,
        status: 'cancelling',
        counts: {
          c_analysis_runs: 1,
          c_analysis_findings: 3,
          java_analysis_runs: 2,
          java_analysis_findings: 5,
          reports: 2,
          report_files: 2,
          artifacts: 2,
          decompile_results: 42,
          source_files: 1,
        },
        created_at: '2026-08-10T01:04:00Z',
        completed_at: null,
        error_code: null,
        error_message: null,
      }),
    ).toMatchObject({
      status: 'cancelling',
      completed_at: null,
      error_code: null,
      error_message: null,
    })
  })
})
