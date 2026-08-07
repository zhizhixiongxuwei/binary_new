import { readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ScanTask, TaskListQuery } from '@/api/types'

export function useTaskList() {
  const items = shallowRef<ScanTask[]>([])
  const nextCursor = shallowRef('')
  const loading = shallowRef(false)
  const errorMessage = shallowRef('')
  const lastQuery = shallowRef<TaskListQuery>({ page_size: 20 })
  let requestGeneration = 0

  async function load(query: TaskListQuery): Promise<void> {
    const generation = ++requestGeneration
    loading.value = true
    errorMessage.value = ''
    nextCursor.value = ''
    lastQuery.value = { ...query }
    try {
      const result = await api.listTasks(query)
      if (generation !== requestGeneration) return
      items.value = result.items
      nextCursor.value = result.next_cursor ?? ''
    } catch (error) {
      if (generation !== requestGeneration) return
      errorMessage.value =
        error instanceof ApiError ? error.message : '无法连接检测服务，请检查服务状态'
    } finally {
      if (generation === requestGeneration) loading.value = false
    }
  }

  async function reload(): Promise<void> {
    await load(lastQuery.value)
  }

  return {
    items: readonly(items),
    nextCursor: readonly(nextCursor),
    loading: readonly(loading),
    errorMessage: readonly(errorMessage),
    load,
    reload,
  }
}
