import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError, resetApiClient } from '@/api/client'

const importValue = {
  id: 'import-1',
  upload_id: 'upload-1',
  filename: 'bundle.zip',
  status: 'ready',
  scanned_entries: 1,
  total_entries: 1,
  eligible_entries: 1,
  skipped_entries: 0,
  created_tasks: 0,
  created_at: '2026-08-11T08:00:00Z',
  updated_at: '2026-08-11T08:01:00Z',
}

describe('archive import API client', () => {
  afterEach(() => {
    resetApiClient()
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('lists a filtered cursor page through the strict response parser', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { items: [], next_cursor: 'next:1' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listArchiveImportEntries('import/id', {
        filter: 'eligible',
        cursor: 'cursor:1',
        page_size: 50,
      }),
    ).resolves.toEqual({ items: [], next_cursor: 'next:1' })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const target = new URL(url, 'http://localhost')
    expect(target.pathname).toBe('/api/v1/archive-imports/import%2Fid/entries')
    expect(Object.fromEntries(target.searchParams)).toEqual({
      filter: 'eligible',
      cursor: 'cursor:1',
      page_size: '50',
    })
    expect(init.method).toBe('GET')
  })

  it('recovers an owner-scoped import cursor page', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { items: [importValue], next_cursor: 'opaque:next' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listArchiveImports({ cursor: 'opaque:start', page_size: 25 }),
    ).resolves.toEqual({
      items: [importValue],
      next_cursor: 'opaque:next',
    })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const target = new URL(url, 'http://localhost')
    expect(target.pathname).toBe('/api/v1/archive-imports')
    expect(Object.fromEntries(target.searchParams)).toEqual({
      cursor: 'opaque:start',
      page_size: '25',
    })
    expect(init.method).toBe('GET')
  })

  it('posts a bounded task batch with CSRF and idempotency headers', async () => {
    document.cookie = 'binaryscan_csrf=archive-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            items: [
              { entry_id: 'entry-1', outcome: 'created', task_id: 'task-1' },
            ],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.createArchiveTaskBatch(
      'import-1',
      { entry_ids: ['entry-1'] },
      'stable-batch-key',
    )

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({ entry_ids: ['entry-1'] })
    expect(headers.get('Idempotency-Key')).toBe('stable-batch-key')
    expect(headers.get('X-CSRF-Token')).toBe('archive-token')
  })

  it('maps malformed import data to a bounded gateway error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ data: { ...importValue, internal_lease: 'secret' } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )

    const error = await api.getArchiveImport('import-1').catch((value) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 502,
      code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
    })
  })

  it('rejects a mismatched import id and incomplete batch coverage', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: { ...importValue, id: 'import-other' },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { items: [] } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.getArchiveImport('import-1')).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
    })
    await expect(
      api.createArchiveTaskBatch(
        'import-1',
        { entry_ids: ['entry-1'] },
        'batch-key',
      ),
    ).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
    })
  })
})
