import { effectScope } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { ArchiveImport, ArchiveImportEntry } from '@/api/types'
import { useArchiveImport } from '@/composables/useArchiveImport'

function importValue(
  id: string,
  overrides: Partial<ArchiveImport> = {},
): ArchiveImport {
  return {
    id,
    upload_id: `upload-${id}`,
    filename: `${id}.zip`,
    status: 'ready',
    scanned_entries: 25,
    total_entries: 25,
    eligible_entries: 25,
    skipped_entries: 0,
    created_tasks: 0,
    created_at: '2026-08-11T08:00:00Z',
    updated_at: '2026-08-11T08:01:00Z',
    ...overrides,
  }
}

function entry(id: string): ArchiveImportEntry {
  return {
    id,
    path: `bin/${id}`,
    size_bytes: 4,
    sha256: 'a'.repeat(64),
    detected_format: 'elf64',
    detected_category: 'binary',
    status: 'eligible',
  }
}

describe('useArchiveImport', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('keeps multiple archive selections isolated and defaults each to at most 20', async () => {
    vi.spyOn(api, 'getArchiveImport').mockImplementation(async (id) =>
      importValue(id),
    )
    vi.spyOn(api, 'listArchiveImportEntries').mockImplementation(async (id) => ({
      items: Array.from({ length: 25 }, (_, index) =>
        entry(`${id}-entry-${index + 1}`),
      ),
    }))
    const scope = effectScope()
    const models = scope.run(() => ({
      first: useArchiveImport({ importId: 'first', uploadId: 'upload-first' }),
      second: useArchiveImport({ importId: 'second', uploadId: 'upload-second' }),
    }))!

    await vi.waitFor(() => {
      expect(models.first.entries.value).toHaveLength(25)
      expect(models.second.entries.value).toHaveLength(25)
    })

    expect(models.first.selectedCount.value).toBe(20)
    expect(models.second.selectedCount.value).toBe(20)
    expect(
      [...models.first.selectedIds.value].every((id) => id.startsWith('first-')),
    ).toBe(true)
    expect(
      [...models.second.selectedIds.value].every((id) => id.startsWith('second-')),
    ).toBe(true)
    scope.stop()
  })

  it('reuses the same batch idempotency key after an uncertain failure', async () => {
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        scanned_entries: 1,
        total_entries: 1,
        eligible_entries: 1,
      }),
    )
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({
      items: [entry('entry-1')],
    })
    const createBatch = vi
      .spyOn(api, 'createArchiveTaskBatch')
      .mockRejectedValueOnce(new ApiError('uncertain', 503))
      .mockResolvedValueOnce({
        items: [
          { entry_id: 'entry-1', outcome: 'created', task_id: 'task-1' },
        ],
      })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(model.selectedCount.value).toBe(1))

    await model.createTasks()
    await model.createTasks()

    expect(createBatch).toHaveBeenCalledTimes(2)
    expect(createBatch.mock.calls[0]?.[2]).toBe(createBatch.mock.calls[1]?.[2])
    scope.stop()
  })

  it('allows a failed entry to be selected manually and rotates the key after a definitive failure', async () => {
    const failedEntry: ArchiveImportEntry = {
      ...entry('entry-failed'),
      status: 'failed',
    }
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        scanned_entries: 1,
        total_entries: 1,
        eligible_entries: 0,
      }),
    )
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({
      items: [failedEntry],
    })
    const createBatch = vi
      .spyOn(api, 'createArchiveTaskBatch')
      .mockResolvedValueOnce({
        items: [
          {
            entry_id: failedEntry.id,
            outcome: 'failed',
            error_code: 'task_create_failed',
            message: 'temporary failure',
          },
        ],
      })
      .mockResolvedValueOnce({
        items: [
          {
            entry_id: failedEntry.id,
            outcome: 'created',
            task_id: 'task-1',
          },
        ],
      })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(model.entries.value).toHaveLength(1))

    expect(model.selectedCount.value).toBe(0)
    model.toggleEntry(failedEntry, true)
    expect(model.selectedCount.value).toBe(1)

    await model.createTasks()
    await model.createTasks()

    expect(createBatch).toHaveBeenCalledTimes(2)
    expect(createBatch.mock.calls[0]?.[2]).not.toBe(
      createBatch.mock.calls[1]?.[2],
    )
    scope.stop()
  })

  it('applies the default selection only once and never refills after clear', async () => {
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(importValue('import-1'))
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({
      items: Array.from({ length: 25 }, (_, index) => entry(`entry-${index + 1}`)),
    })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(model.selectedCount.value).toBe(20))

    model.clearSelection()
    await model.refreshImport()

    expect(model.selectedCount.value).toBe(0)
    scope.stop()
  })

  it('can reopen a disposed workspace without applying defaults again', async () => {
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        scanned_entries: 2,
        total_entries: 2,
        eligible_entries: 2,
      }),
    )
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({
      items: [entry('entry-1'), entry('entry-2')],
    })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({
        importId: 'import-1',
        uploadId: 'upload-import-1',
        applyInitialSelection: false,
        initialSelectedIds: ['entry-2'],
      }),
    )!
    await vi.waitFor(() => expect(model.entries.value).toHaveLength(2))

    expect([...model.selectedIds.value]).toEqual(['entry-2'])
    scope.stop()
  })

  it('keeps only failed selections after a partial batch result', async () => {
    const initialEntries = ['entry-1', 'entry-2', 'entry-3'].map(entry)
    const refreshedEntries: ArchiveImportEntry[] = [
      { ...entry('entry-1'), status: 'created', task_id: 'task-1' },
      { ...entry('entry-2'), status: 'failed' },
      { ...entry('entry-3'), status: 'created', task_id: 'task-3' },
      entry('entry-4'),
    ]
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        scanned_entries: 4,
        total_entries: 4,
        eligible_entries: 4,
      }),
    )
    vi.spyOn(api, 'listArchiveImportEntries')
      .mockResolvedValueOnce({ items: initialEntries })
      .mockResolvedValue({ items: refreshedEntries })
    vi.spyOn(api, 'createArchiveTaskBatch').mockResolvedValue({
      items: [
        { entry_id: 'entry-1', outcome: 'created', task_id: 'task-1' },
        {
          entry_id: 'entry-2',
          outcome: 'failed',
          error_code: 'task_create_failed',
        },
        { entry_id: 'entry-3', outcome: 'created', task_id: 'task-3' },
      ],
    })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(model.selectedCount.value).toBe(3))

    await model.createTasks()

    expect([...model.selectedIds.value]).toEqual(['entry-2'])
    expect(model.entries.value.map((item) => item.id)).toContain('entry-4')
    scope.stop()
  })

  it('changes only the current page and respects the remaining batch capacity', async () => {
    const firstPage = Array.from({ length: 19 }, (_, index) =>
      entry(`page-1-${index + 1}`),
    )
    const secondPage = [entry('page-2-1'), entry('page-2-2'), entry('page-2-3')]
    vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        scanned_entries: 22,
        total_entries: 22,
        eligible_entries: 22,
      }),
    )
    vi.spyOn(api, 'listArchiveImportEntries')
      .mockResolvedValueOnce({ items: firstPage, next_cursor: 'page-2' })
      .mockResolvedValueOnce({ items: secondPage })
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(model.selectedCount.value).toBe(19))
    await model.nextPage()

    model.toggleVisibleEligible(true)

    expect(model.selectedCount.value).toBe(20)
    expect(
      secondPage.filter((item) => model.selectedIds.value.has(item.id)),
    ).toHaveLength(1)

    model.toggleVisibleEligible(false)

    expect(model.selectedCount.value).toBe(19)
    expect(
      firstPage.every((item) => model.selectedIds.value.has(item.id)),
    ).toBe(true)
    scope.stop()
  })

  it('polls a remotely deleting import until deleted', async () => {
    vi.useFakeTimers()
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockResolvedValueOnce(
        importValue('import-1', {
          status: 'deleting',
          scanned_entries: 0,
          total_entries: 0,
          eligible_entries: 0,
        }),
      )
      .mockResolvedValueOnce(
        importValue('import-1', {
          status: 'deleted',
          scanned_entries: 0,
          total_entries: 0,
          eligible_entries: 0,
        }),
      )
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.runAllTicks()
    await Promise.resolve()

    expect(model.isPolling.value).toBe(true)
    await vi.advanceTimersByTimeAsync(1_500)

    expect(getImport).toHaveBeenCalledTimes(2)
    expect(model.deleted.value).toBe(true)
    scope.stop()
  })

  it('treats 404 as authoritative and ignores a stale entries response', async () => {
    let resolveEntries!: (value: { items: ArchiveImportEntry[] }) => void
    const pendingEntries = new Promise<{ items: ArchiveImportEntry[] }>((resolve) => {
      resolveEntries = resolve
    })
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockResolvedValueOnce(importValue('import-1'))
      .mockRejectedValueOnce(new ApiError('not found', 404))
    vi.spyOn(api, 'listArchiveImportEntries').mockReturnValue(pendingEntries)
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.waitFor(() => expect(getImport).toHaveBeenCalledOnce())
    await vi.waitFor(() =>
      expect(api.listArchiveImportEntries).toHaveBeenCalledOnce(),
    )

    await model.refreshImport()
    resolveEntries({ items: [entry('stale-entry')] })
    await pendingEntries
    await Promise.resolve()

    expect(model.deleted.value).toBe(true)
    expect(model.entries.value).toEqual([])
    scope.stop()
  })

  it('stops polling after a forbidden status response', async () => {
    vi.useFakeTimers()
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockResolvedValueOnce(
        importValue('import-1', {
          status: 'deleting',
          scanned_entries: 0,
          total_entries: 0,
          eligible_entries: 0,
        }),
      )
      .mockRejectedValue(new ApiError('无权读取归档导入', 403))
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.runAllTicks()
    await Promise.resolve()

    expect(model.isPolling.value).toBe(true)
    await vi.advanceTimersByTimeAsync(1_500)
    expect(model.importError.value).toBe('无权读取归档导入')
    expect(model.isPolling.value).toBe(false)
    await vi.advanceTimersByTimeAsync(5_000)
    expect(getImport).toHaveBeenCalledTimes(2)
    scope.stop()
  })

  it('recovers a durable deleting tombstone after an ambiguous DELETE response', async () => {
    vi.useFakeTimers()
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockResolvedValueOnce(
        importValue('import-1', {
          scanned_entries: 0,
          total_entries: 0,
          eligible_entries: 0,
        }),
      )
      .mockResolvedValueOnce(
        importValue('import-1', {
          status: 'deleting',
          scanned_entries: 0,
          total_entries: 0,
          eligible_entries: 0,
        }),
      )
      .mockRejectedValueOnce(new ApiError('not found', 404))
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'deleteUpload').mockRejectedValue(
      new ApiError('commit acknowledgement lost', 503),
    )
    const scope = effectScope()
    const model = scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )!
    await vi.runAllTicks()
    await Promise.resolve()
    await Promise.resolve()
    expect(model.canDelete.value).toBe(true)

    await model.deleteUpload()

    expect(getImport).toHaveBeenCalledTimes(2)
    expect(model.archiveImport.value?.status).toBe('deleting')
    expect(model.isPolling.value).toBe(true)
    expect(model.deletionError.value).toBe('commit acknowledgement lost')

    await vi.advanceTimersByTimeAsync(1_500)

    expect(getImport).toHaveBeenCalledTimes(3)
    expect(model.deleted.value).toBe(true)
    scope.stop()
  })

  it('disposes polling timers and ignores later refresh work', async () => {
    vi.useFakeTimers()
    const getImport = vi.spyOn(api, 'getArchiveImport').mockResolvedValue(
      importValue('import-1', {
        status: 'queued',
        scanned_entries: 0,
        total_entries: 0,
        eligible_entries: 0,
      }),
    )
    const scope = effectScope()
    scope.run(() =>
      useArchiveImport({ importId: 'import-1', uploadId: 'upload-import-1' }),
    )
    await vi.runAllTicks()
    await Promise.resolve()
    expect(getImport).toHaveBeenCalledOnce()

    scope.stop()
    await vi.advanceTimersByTimeAsync(5_000)

    expect(getImport).toHaveBeenCalledOnce()
  })
})
