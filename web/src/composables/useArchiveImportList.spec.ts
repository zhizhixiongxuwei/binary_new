import { effectScope } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { ArchiveImport, ArchiveImportPage } from '@/api/types'
import { useArchiveImportList } from '@/composables/useArchiveImportList'

function importValue(id: string): ArchiveImport {
  return {
    id,
    upload_id: `upload-${id}`,
    filename: `${id}.zip`,
    status: 'ready',
    scanned_entries: 1,
    total_entries: 1,
    eligible_entries: 1,
    skipped_entries: 0,
    created_tasks: 0,
    created_at: '2026-08-11T08:00:00Z',
    updated_at: '2026-08-11T08:01:00Z',
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}

describe('useArchiveImportList', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('restores and extends cursor pages without duplicate imports', async () => {
    const list = vi
      .spyOn(api, 'listArchiveImports')
      .mockResolvedValueOnce({
        items: [importValue('import-2')],
        next_cursor: 'next-page',
      })
      .mockResolvedValueOnce({
        items: [importValue('import-2'), importValue('import-1')],
      })
    const scope = effectScope()
    const model = scope.run(() => useArchiveImportList())!

    await vi.waitFor(() => expect(model.items.value).toHaveLength(1))
    await model.loadMore()

    expect(model.items.value.map((item) => item.id)).toEqual([
      'import-2',
      'import-1',
    ])
    expect(list).toHaveBeenNthCalledWith(1, { page_size: 25 })
    expect(list).toHaveBeenNthCalledWith(2, {
      cursor: 'next-page',
      page_size: 25,
    })
    scope.stop()
  })

  it('lets the newest refresh win when responses arrive out of order', async () => {
    const first = deferred<ArchiveImportPage>()
    const second = deferred<ArchiveImportPage>()
    vi.spyOn(api, 'listArchiveImports')
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise)
    const scope = effectScope()
    const model = scope.run(() => useArchiveImportList())!

    const refresh = model.refresh()
    second.resolve({ items: [importValue('newest')] })
    await refresh
    first.resolve({ items: [importValue('stale')] })
    await first.promise

    expect(model.items.value.map((item) => item.id)).toEqual(['newest'])
    scope.stop()
  })

  it('does not resurrect a terminally removed import from an in-flight refresh', async () => {
    const item = importValue('import-1')
    const refreshResponse = deferred<ArchiveImportPage>()
    vi.spyOn(api, 'listArchiveImports')
      .mockResolvedValueOnce({ items: [item] })
      .mockReturnValueOnce(refreshResponse.promise)
    const scope = effectScope()
    const model = scope.run(() => useArchiveImportList())!
    await vi.waitFor(() => expect(model.items.value).toHaveLength(1))

    const refresh = model.refresh()
    model.remove(item.id)
    refreshResponse.resolve({ items: [item] })
    await refresh

    expect(model.items.value).toEqual([])
    scope.stop()
  })
})
