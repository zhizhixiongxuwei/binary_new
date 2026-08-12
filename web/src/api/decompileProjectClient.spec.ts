import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError, resetApiClient } from '@/api/client'

function project() {
  return {
    id: '123e4567-e89b-42d3-a456-426614174000',
    task_id: '223e4567-e89b-42d3-a456-426614174001',
    job_id: '323e4567-e89b-42d3-a456-426614174002',
    file_node_id: '18446744073709551614',
    target_path: '/bin/server',
    layout_version: 'project-v1',
    source_kind: 'ghidra-pseudoc',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '11.3.2',
    status: 'complete',
    source_file_count: 1,
    symbol_count: 42,
    source_size_bytes: 4096,
    canonical_filename: 'src/decompiled.c',
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
  }
}

describe('decompile-project API client', () => {
  afterEach(() => {
    resetApiClient()
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('lists a cursor page through the runtime contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { items: [project()], next_cursor: 'project:cursor-2' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listDecompileProjects('task/id', {
        page_size: 100,
        cursor: 'project:cursor-1',
      }),
    ).resolves.toMatchObject({
      items: [{ id: project().id }],
      next_cursor: 'project:cursor-2',
    })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const target = new URL(url, 'http://localhost')
    expect(target.pathname).toBe('/api/v1/tasks/task%2Fid/decompile-projects')
    expect(Object.fromEntries(target.searchParams)).toEqual({
      page_size: '100',
      cursor: 'project:cursor-1',
    })
    expect(init.method).toBe('GET')
  })

  it('turns an invalid project payload into a bounded gateway error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ data: { ...project(), storage_key: '/data/private' } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    const error = await api
      .getDecompileProject('task-id', 'project-id')
      .catch((reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 502,
      code: 'INVALID_DECOMPILE_PROJECT_RESPONSE',
    })
  })

  it('builds an encoded same-origin ZIP URL without fetching it eagerly', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.downloadDecompileProject('task/id', 'project/id'),
    ).resolves.toEqual({
      kind: 'url',
      url: '/api/v1/tasks/task%2Fid/decompile-projects/project%2Fid.zip',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('deletes one project with credentials and CSRF protection', async () => {
    document.cookie = 'binaryscan_csrf=delete-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.deleteDecompileProject('task/id', 'project/id'),
    ).resolves.toBeUndefined()

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      '/api/v1/tasks/task%2Fid/decompile-projects/project%2Fid',
    )
    expect(init.method).toBe('DELETE')
    expect(init.credentials).toBe('include')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('delete-token')
  })
})
