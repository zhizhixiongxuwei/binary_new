import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, resetApiClient } from '@/api/client'

function queuedRun() {
  return {
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
    status: 'queued',
    analyzer_name: 'binaryscan-java-checker',
    analyzer_version: '0.1.0',
    ruleset_version: '',
    source_manifest_sha256: 'a'.repeat(64),
    input_sha256: 'b'.repeat(64),
    bundle_sha256: '',
    source_size_bytes: 4096,
    source_file_count: 2,
    finding_count: 0,
    diagnostic_count: 0,
    coverage: {
      total_files: 2,
      analyzed_files: 0,
      parsed_files: 0,
      recovered_files: 0,
      failed_files: 0,
    },
    severity_counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    findings_truncated: false,
    diagnostics_truncated: false,
    error_code: null,
    error_message: null,
    started_at: null,
    completed_at: null,
    created_at: '2026-08-10T07:59:00Z',
    updated_at: '2026-08-10T07:59:00Z',
  }
}

describe('Java analysis API client', () => {
  afterEach(() => {
    resetApiClient()
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('creates a run at the Java route with an idempotency key and no body', async () => {
    document.cookie = 'binaryscan_csrf=create-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: queuedRun() }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.createJavaAnalysisRun('task/id', 'project/id', 'java-request-key'),
    ).resolves.toMatchObject({ status: 'queued' })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      '/api/v1/tasks/task%2Fid/decompile-projects/project%2Fid/java-analysis-runs',
    )
    expect(init.method).toBe('POST')
    expect(init.body).toBeUndefined()
    const headers = new Headers(init.headers)
    expect(headers.get('Idempotency-Key')).toBe('java-request-key')
    expect(headers.get('X-CSRF-Token')).toBe('create-token')
  })

  it('encodes Java file and callable finding filters', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { items: [], next_cursor: '42' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.listJavaAnalysisFindings('task/id', 'run/id', {
      cursor: '41',
      page_size: 100,
      cwe: 'CWE-89',
      severity: 'HIGH',
      file: 'src/main/java',
      callable: 'Query Service',
    })

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit]
    const target = new URL(url, 'http://localhost')
    expect(target.pathname).toBe(
      '/api/v1/tasks/task%2Fid/java-analysis-runs/run%2Fid/findings',
    )
    expect(Object.fromEntries(target.searchParams)).toEqual({
      cursor: '41',
      page_size: '100',
      cwe: 'CWE-89',
      severity: 'HIGH',
      file: 'src/main/java',
      callable: 'Query Service',
    })
  })

  it('uses empty-body cancel and delete endpoints', async () => {
    document.cookie = 'binaryscan_csrf=action-token; Path=/'
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              ...queuedRun(),
              status: 'cancel_requested',
              started_at: '2026-08-10T08:00:00Z',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    await api.cancelJavaAnalysisRun('task/id', 'run/id')
    await api.deleteJavaAnalysisRun('task/id', 'run/id')

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/tasks/task%2Fid/java-analysis-runs/run%2Fid/cancel',
      '/api/v1/tasks/task%2Fid/java-analysis-runs/run%2Fid',
    ])
    expect(fetchMock.mock.calls.map(([, init]) => init?.body)).toEqual([
      undefined,
      undefined,
    ])
  })
})
