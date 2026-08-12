import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, resetApiClient } from '@/api/client'

function run() {
  return {
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
    status: 'queued',
    analyzer_name: 'binaryscan-c-checker',
    analyzer_version: '0.1.0',
    ruleset_version: 'c-rules-v1',
    source_sha256: 'a'.repeat(64),
    source_size_bytes: 4096,
    finding_count: 0,
    diagnostic_count: 0,
    coverage: {
      total_functions: 3,
      parsed_functions: 0,
      failed_functions: 0,
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

describe('C analysis API client', () => {
  afterEach(() => {
    resetApiClient()
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('creates a run with an encoded path and idempotency key', async () => {
    document.cookie = 'binaryscan_csrf=create-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: run() }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.createCAnalysisRun('task/id', 'project/id', 'request-key'),
    ).resolves.toMatchObject({ id: run().id, status: 'queued' })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      '/api/v1/tasks/task%2Fid/decompile-projects/project%2Fid/c-analysis-runs',
    )
    expect(init.method).toBe('POST')
    expect(init.body).toBeUndefined()
    expect(init.credentials).toBe('include')
    const headers = new Headers(init.headers)
    expect(headers.get('Idempotency-Key')).toBe('request-key')
    expect(headers.get('X-CSRF-Token')).toBe('create-token')
  })

  it('encodes all finding filters and pagination values', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { items: [], next_cursor: 'next' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listCAnalysisFindings('task/id', 'run/id', {
        cursor: 'after:1',
        page_size: 100,
        cwe: 'CWE-120',
        severity: 'HIGH',
        function: 'copy input',
      }),
    ).resolves.toEqual({ items: [], next_cursor: 'next' })

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit]
    const target = new URL(url, 'http://localhost')
    expect(target.pathname).toBe(
      '/api/v1/tasks/task%2Fid/c-analysis-runs/run%2Fid/findings',
    )
    expect(Object.fromEntries(target.searchParams)).toEqual({
      cursor: 'after:1',
      page_size: '100',
      cwe: 'CWE-120',
      severity: 'HIGH',
      function: 'copy input',
    })
  })

  it('cancels a run with an empty authenticated request body', async () => {
    document.cookie = 'binaryscan_csrf=cancel-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            ...run(),
            status: 'cancel_requested',
            started_at: '2026-08-10T08:00:00Z',
            updated_at: '2026-08-10T08:00:00Z',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.cancelCAnalysisRun('task/id', 'run/id'),
    ).resolves.toMatchObject({ status: 'cancel_requested' })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/v1/tasks/task%2Fid/c-analysis-runs/run%2Fid/cancel')
    expect(init.method).toBe('POST')
    expect(init.body).toBeUndefined()
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('cancel-token')
  })
})
