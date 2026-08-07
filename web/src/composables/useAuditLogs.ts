import { readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { AuditLog, AuditLogListQuery } from '@/api/types'

const PAGE_SIZE = 50

export function useAuditLogs() {
  const logs = shallowRef<AuditLog[]>([])
  const query = shallowRef<AuditLogListQuery>({})
  const nextCursor = shallowRef<string | undefined>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const errorMessage = shallowRef('')
  let requestSequence = 0

  async function load(
    nextQuery: AuditLogListQuery = query.value,
    options: { append?: boolean } = {},
  ): Promise<void> {
    const append = options.append === true
    if (append && (!nextCursor.value || loadingMore.value)) return
    const sequence = ++requestSequence
    if (append) loadingMore.value = true
    else loading.value = true
    errorMessage.value = ''
    if (!append) query.value = { ...nextQuery }
    try {
      const cursor = append ? nextCursor.value : undefined
      const page = await api.listAuditLogs({
        ...query.value,
        ...(cursor ? { cursor } : {}),
        page_size: PAGE_SIZE,
      })
      if (sequence !== requestSequence) return
      logs.value = append ? [...logs.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor
    } catch (error) {
      if (sequence === requestSequence) {
        errorMessage.value =
          error instanceof ApiError ? error.message : '审计日志读取失败'
      }
    } finally {
      if (sequence === requestSequence) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  return {
    logs: readonly(logs),
    query: readonly(query),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    loadingMore: readonly(loadingMore),
    errorMessage: readonly(errorMessage),
    load,
  }
}
