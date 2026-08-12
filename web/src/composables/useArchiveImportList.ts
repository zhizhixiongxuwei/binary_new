import {
  getCurrentScope,
  onScopeDispose,
  readonly,
  shallowRef,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type { ArchiveImport } from '@/api/types'

const PAGE_SIZE = 25

export interface UseArchiveImportListOptions {
  enabled?: boolean
}

function message(error: unknown): string {
  return error instanceof ApiError
    ? error.message
    : '无法读取待处理归档导入'
}

export function useArchiveImportList(
  options: UseArchiveImportListOptions = {},
) {
  const enabled = options.enabled ?? true
  const items = shallowRef<ArchiveImport[]>([])
  const nextCursor = shallowRef<string | undefined>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const error = shallowRef('')
  const removedIds = new Set<string>()
  let generation = 0
  let disposed = false

  function active(requestGeneration: number): boolean {
    return !disposed && requestGeneration === generation
  }

  async function refresh(): Promise<void> {
    if (!enabled || disposed) return
    const requestGeneration = ++generation
    loading.value = true
    loadingMore.value = false
    error.value = ''
    try {
      const page = await api.listArchiveImports({ page_size: PAGE_SIZE })
      if (!active(requestGeneration)) return
      items.value = page.items.filter((item) => !removedIds.has(item.id))
      nextCursor.value = page.next_cursor
    } catch (cause) {
      if (!active(requestGeneration)) return
      error.value = message(cause)
    } finally {
      if (active(requestGeneration)) loading.value = false
    }
  }

  async function loadMore(): Promise<void> {
    const cursor = nextCursor.value
    if (!enabled || disposed || loading.value || loadingMore.value || !cursor) {
      return
    }
    const requestGeneration = generation
    loadingMore.value = true
    error.value = ''
    try {
      const page = await api.listArchiveImports({
        cursor,
        page_size: PAGE_SIZE,
      })
      if (!active(requestGeneration) || cursor !== nextCursor.value) return
      const known = new Set(items.value.map((item) => item.id))
      items.value = [
        ...items.value,
        ...page.items.filter(
          (item) => !known.has(item.id) && !removedIds.has(item.id),
        ),
      ]
      nextCursor.value = page.next_cursor
    } catch (cause) {
      if (!active(requestGeneration)) return
      error.value = message(cause)
    } finally {
      if (active(requestGeneration)) loadingMore.value = false
    }
  }

  function remove(importId: string): void {
    removedIds.add(importId)
    items.value = items.value.filter((item) => item.id !== importId)
  }

  function dispose(): void {
    if (disposed) return
    disposed = true
    generation += 1
  }

  if (getCurrentScope()) onScopeDispose(dispose)
  if (enabled) void refresh()

  return {
    items: readonly(items),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    loadingMore: readonly(loadingMore),
    error: readonly(error),
    refresh,
    loadMore,
    remove,
    dispose,
  }
}
