import {
  computed,
  getCurrentScope,
  onScopeDispose,
  readonly,
  shallowRef,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  ArchiveImport,
  ArchiveImportEntry,
  ArchiveImportEntryFilter,
  ArchiveTaskBatchResult,
} from '@/api/types'
import { createIdempotencyKey } from '@/utils/idempotency'

const POLL_INTERVAL_MS = 1_500
const PAGE_SIZE = 50
const MAX_BATCH_SIZE = 20

export interface UseArchiveImportOptions {
  importId: string
  uploadId: string
  applyInitialSelection?: boolean
  initialSelectedIds?: readonly string[]
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

export function useArchiveImport(options: UseArchiveImportOptions) {
  const archiveImport = shallowRef<ArchiveImport | null>(null)
  const entries = shallowRef<ArchiveImportEntry[]>([])
  const entryLabels = shallowRef<Record<string, string>>({})
  const filter = shallowRef<ArchiveImportEntryFilter>('all')
  const cursorHistory = shallowRef<(string | undefined)[]>([undefined])
  const pageIndex = shallowRef(0)
  const nextCursor = shallowRef<string | undefined>()
  const selectedIds = shallowRef<Set<string>>(
    new Set((options.initialSelectedIds ?? []).slice(0, MAX_BATCH_SIZE)),
  )
  const deselectedIds = new Set<string>()
  const loadingImport = shallowRef(false)
  const loadingEntries = shallowRef(false)
  const submitting = shallowRef(false)
  const deleting = shallowRef(false)
  const deleted = shallowRef(false)
  const importError = shallowRef('')
  const entriesError = shallowRef('')
  const batchError = shallowRef('')
  const deletionError = shallowRef('')
  const batchResult = shallowRef<ArchiveTaskBatchResult | null>(null)
  const pollingBlocked = shallowRef(false)
  const batchKeys = new Map<string, string>()
  let pollTimer: ReturnType<typeof globalThis.setTimeout> | null = null
  let importGeneration = 0
  let entriesGeneration = 0
  let lifecycleGeneration = 0
  let initialSelectionApplied = options.applyInitialSelection === false
  let disposed = false

  const currentCursor = computed(
    () => cursorHistory.value[pageIndex.value],
  )
  const selectedCount = computed(() => selectedIds.value.size)
  const hasPreviousPage = computed(() => pageIndex.value > 0)
  const hasNextPage = computed(() => Boolean(nextCursor.value))
  const isPolling = computed(() => {
    const status = archiveImport.value?.status
    return (
      !pollingBlocked.value &&
      (status === 'queued' || status === 'running' || status === 'deleting')
    )
  })
  const isReady = computed(() => archiveImport.value?.status === 'ready')
  const isEmpty = computed(
    () =>
      archiveImport.value?.status === 'ready' &&
      archiveImport.value.eligible_entries === 0,
  )
  const canDelete = computed(() => {
    const status = archiveImport.value?.status
    return (
      !submitting.value &&
      !deleting.value &&
      (status === 'ready' || status === 'failed')
    )
  })
  const progress = computed(() => {
    const current = archiveImport.value
    if (!current || current.total_entries === 0) return 0
    return Math.min(
      100,
      Math.round((current.scanned_entries / current.total_entries) * 100),
    )
  })

  function clearPoll(): void {
    if (pollTimer === null) return
    globalThis.clearTimeout(pollTimer)
    pollTimer = null
  }

  function schedulePoll(): void {
    clearPoll()
    if (disposed || deleted.value || pollingBlocked.value) return
    pollTimer = globalThis.setTimeout(() => {
      pollTimer = null
      void refreshImport()
    }, POLL_INTERVAL_MS)
  }

  function applyInitialSelection(items: readonly ArchiveImportEntry[]): void {
    if (
      initialSelectionApplied ||
      !isReady.value ||
      selectedIds.value.size >= MAX_BATCH_SIZE
    ) {
      return
    }
    initialSelectionApplied = true
    const next = new Set(selectedIds.value)
    for (const entry of items) {
      if (
        entry.status !== 'eligible' ||
        deselectedIds.has(entry.id) ||
        next.size >= MAX_BATCH_SIZE
      ) {
        continue
      }
      next.add(entry.id)
    }
    selectedIds.value = next
  }

  function markDeleted(): void {
    clearPoll()
    pollingBlocked.value = false
    lifecycleGeneration += 1
    importGeneration += 1
    entriesGeneration += 1
    deleted.value = true
    archiveImport.value = archiveImport.value
      ? { ...archiveImport.value, status: 'deleted' }
      : null
    entries.value = []
    selectedIds.value = new Set()
    nextCursor.value = undefined
    loadingImport.value = false
    loadingEntries.value = false
    submitting.value = false
    deleting.value = false
  }

  async function loadEntries(): Promise<void> {
    if (disposed || deleted.value) return
    const requestGeneration = ++entriesGeneration
    const lifecycle = lifecycleGeneration
    loadingEntries.value = true
    entriesError.value = ''
    try {
      const page = await api.listArchiveImportEntries(options.importId, {
        filter: filter.value,
        ...(currentCursor.value ? { cursor: currentCursor.value } : {}),
        page_size: PAGE_SIZE,
      })
      if (
        disposed ||
        lifecycle !== lifecycleGeneration ||
        requestGeneration !== entriesGeneration
      ) {
        return
      }
      entries.value = page.items
      entryLabels.value = {
        ...entryLabels.value,
        ...Object.fromEntries(page.items.map((entry) => [entry.id, entry.path])),
      }
      nextCursor.value = page.next_cursor
      applyInitialSelection(page.items)
    } catch (error) {
      if (
        disposed ||
        lifecycle !== lifecycleGeneration ||
        requestGeneration !== entriesGeneration
      ) {
        return
      }
      if (error instanceof ApiError && error.status === 404) {
        markDeleted()
        return
      }
      entriesError.value = errorMessage(error, '无法读取归档条目')
    } finally {
      if (requestGeneration === entriesGeneration) loadingEntries.value = false
    }
  }

  async function refreshImport(): Promise<void> {
    if (disposed || deleted.value) return
    clearPoll()
    pollingBlocked.value = false
    const requestGeneration = ++importGeneration
    const lifecycle = lifecycleGeneration
    loadingImport.value = true
    importError.value = ''
    try {
      const value = await api.getArchiveImport(options.importId)
      if (
        disposed ||
        lifecycle !== lifecycleGeneration ||
        requestGeneration !== importGeneration
      ) {
        return
      }
      if (value.upload_id !== options.uploadId) {
        throw new ApiError('归档导入与上传记录不一致', 502, {
          code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
        })
      }
      archiveImport.value = value
      if (value.status !== 'ready') selectedIds.value = new Set()
      if (value.status === 'deleted') {
        markDeleted()
        return
      }
      if (
        value.status === 'queued' ||
        value.status === 'running' ||
        value.status === 'deleting'
      ) {
        schedulePoll()
        return
      }
      if (value.status === 'ready' || value.status === 'failed') {
        await loadEntries()
      }
    } catch (error) {
      if (
        disposed ||
        lifecycle !== lifecycleGeneration ||
        requestGeneration !== importGeneration
      ) {
        return
      }
      if (error instanceof ApiError && error.status === 404) {
        markDeleted()
        return
      }
      importError.value = errorMessage(error, '无法读取归档导入状态')
      if (error instanceof ApiError && error.status === 403) {
        pollingBlocked.value = true
      } else {
        schedulePoll()
      }
    } finally {
      if (requestGeneration === importGeneration) loadingImport.value = false
    }
  }

  async function setFilter(value: ArchiveImportEntryFilter): Promise<void> {
    if (filter.value === value && pageIndex.value === 0) return
    entriesGeneration += 1
    filter.value = value
    cursorHistory.value = [undefined]
    pageIndex.value = 0
    nextCursor.value = undefined
    await loadEntries()
  }

  async function nextPage(): Promise<void> {
    if (!nextCursor.value || loadingEntries.value) return
    const nextHistory = cursorHistory.value.slice(0, pageIndex.value + 1)
    nextHistory.push(nextCursor.value)
    cursorHistory.value = nextHistory
    pageIndex.value += 1
    nextCursor.value = undefined
    await loadEntries()
  }

  async function previousPage(): Promise<void> {
    if (pageIndex.value === 0 || loadingEntries.value) return
    pageIndex.value -= 1
    nextCursor.value = undefined
    await loadEntries()
  }

  function toggleEntry(entry: ArchiveImportEntry, checked: boolean): void {
    if (
      !isReady.value ||
      (entry.status !== 'eligible' && entry.status !== 'failed') ||
      submitting.value
    ) {
      return
    }
    const next = new Set(selectedIds.value)
    if (checked) {
      if (next.size >= MAX_BATCH_SIZE && !next.has(entry.id)) return
      next.add(entry.id)
      deselectedIds.delete(entry.id)
    } else {
      next.delete(entry.id)
      deselectedIds.add(entry.id)
    }
    selectedIds.value = next
  }

  function toggleVisibleEligible(checked: boolean): void {
    if (!isReady.value) return
    const next = new Set(selectedIds.value)
    for (const entry of entries.value) {
      if (entry.status !== 'eligible') continue
      if (checked) {
        if (next.size >= MAX_BATCH_SIZE) continue
        next.add(entry.id)
        deselectedIds.delete(entry.id)
      } else {
        next.delete(entry.id)
        deselectedIds.add(entry.id)
      }
    }
    selectedIds.value = next
  }

  function clearSelection(): void {
    for (const id of selectedIds.value) deselectedIds.add(id)
    selectedIds.value = new Set()
  }

  async function createTasks(): Promise<void> {
    if (
      submitting.value ||
      selectedIds.value.size === 0 ||
      selectedIds.value.size > MAX_BATCH_SIZE ||
      !isReady.value ||
      disposed
    ) {
      return
    }
    const lifecycle = lifecycleGeneration
    const entryIds = [...selectedIds.value].sort()
    const signature = entryIds.join('\n')
    const idempotencyKey = batchKeys.get(signature) ?? createIdempotencyKey()
    batchKeys.set(signature, idempotencyKey)
    submitting.value = true
    batchError.value = ''
    batchResult.value = null
    try {
      const result = await api.createArchiveTaskBatch(
        options.importId,
        { entry_ids: entryIds },
        idempotencyKey,
      )
      if (disposed || lifecycle !== lifecycleGeneration) return
      batchResult.value = result
      if (result.items.some((item) => item.outcome === 'failed')) {
        batchKeys.delete(signature)
      }
      const completedIds = new Set(
        result.items
          .filter((item) => item.outcome !== 'failed')
          .map((item) => item.entry_id),
      )
      selectedIds.value = new Set(
        [...selectedIds.value].filter((id) => !completedIds.has(id)),
      )
      await refreshImport()
    } catch (error) {
      if (disposed || lifecycle !== lifecycleGeneration) return
      if (error instanceof ApiError && error.status === 404) {
        markDeleted()
        return
      }
      batchError.value = errorMessage(error, '批量创建任务失败')
    } finally {
      if (!disposed && lifecycle === lifecycleGeneration) submitting.value = false
    }
  }

  async function deleteUpload(): Promise<void> {
    if (!canDelete.value || disposed) return
    const lifecycle = ++lifecycleGeneration
    clearPoll()
    deleting.value = true
    deletionError.value = ''
    try {
      await api.deleteUpload(options.uploadId)
      if (disposed || lifecycle !== lifecycleGeneration) return
      markDeleted()
    } catch (error) {
      if (disposed || lifecycle !== lifecycleGeneration) return
      if (error instanceof ApiError && error.status === 404) {
        markDeleted()
        return
      }
      deletionError.value = errorMessage(error, '归档删除失败，请重试')
      const definitiveClientFailure =
        error instanceof ApiError && error.status >= 400 && error.status < 500
      if (!definitiveClientFailure) await refreshImport()
    } finally {
      if (!disposed && lifecycle === lifecycleGeneration) deleting.value = false
    }
  }

  function dispose(): void {
    if (disposed) return
    disposed = true
    lifecycleGeneration += 1
    importGeneration += 1
    entriesGeneration += 1
    clearPoll()
  }

  if (getCurrentScope()) onScopeDispose(dispose)
  void refreshImport()

  return {
    archiveImport: readonly(archiveImport),
    entries: readonly(entries),
    entryLabels: readonly(entryLabels),
    filter: readonly(filter),
    pageIndex: readonly(pageIndex),
    selectedIds: readonly(selectedIds),
    selectedCount,
    loadingImport: readonly(loadingImport),
    loadingEntries: readonly(loadingEntries),
    submitting: readonly(submitting),
    deleting: readonly(deleting),
    deleted: readonly(deleted),
    importError: readonly(importError),
    entriesError: readonly(entriesError),
    batchError: readonly(batchError),
    deletionError: readonly(deletionError),
    batchResult: readonly(batchResult),
    hasPreviousPage,
    hasNextPage,
    isPolling,
    isReady,
    isEmpty,
    canDelete,
    progress,
    refreshImport,
    loadEntries,
    setFilter,
    nextPage,
    previousPage,
    toggleEntry,
    toggleVisibleEligible,
    clearSelection,
    createTasks,
    deleteUpload,
    dispose,
  }
}
