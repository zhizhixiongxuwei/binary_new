import {
  onScopeDispose,
  shallowReadonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type { FileNodeDetail } from '@/api/types'

export function useFileNodeDetail(
  taskId: MaybeRefOrGetter<string>,
  fileId: MaybeRefOrGetter<string | null>,
) {
  const detail = shallowRef<FileNodeDetail | null>(null)
  const loading = shallowRef(false)
  const errorMessage = shallowRef('')
  let generation = 0

  async function load(): Promise<void> {
    const activeGeneration = ++generation
    const activeTaskId = toValue(taskId)
    const activeFileId = toValue(fileId)

    detail.value = null
    errorMessage.value = ''
    if (!activeTaskId || !activeFileId) {
      loading.value = false
      return
    }

    loading.value = true
    try {
      const loadedDetail = await api.getTaskFile(activeTaskId, activeFileId)
      if (
        activeGeneration !== generation ||
        activeTaskId !== toValue(taskId) ||
        activeFileId !== toValue(fileId)
      ) {
        return
      }
      detail.value = loadedDetail
    } catch (error) {
      if (
        activeGeneration !== generation ||
        activeTaskId !== toValue(taskId) ||
        activeFileId !== toValue(fileId)
      ) {
        return
      }
      errorMessage.value =
        error instanceof ApiError ? error.message : '文件节点详情读取失败'
    } finally {
      if (
        activeGeneration === generation &&
        activeTaskId === toValue(taskId) &&
        activeFileId === toValue(fileId)
      ) {
        loading.value = false
      }
    }
  }

  watch(
    [() => toValue(taskId), () => toValue(fileId)],
    () => void load(),
    { immediate: true },
  )

  onScopeDispose(() => {
    generation += 1
  })

  return {
    detail: shallowReadonly(detail),
    loading: shallowReadonly(loading),
    errorMessage: shallowReadonly(errorMessage),
    reload: load,
  }
}
