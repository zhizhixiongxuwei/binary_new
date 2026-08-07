import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type { ManualImageScanRequest } from '@/api/types'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { createIdempotencyKey } from '@/utils/idempotency'

interface UseManualImageScanOptions {
  taskId: MaybeRefOrGetter<string>
  fileNodeId: MaybeRefOrGetter<string>
  mode: MaybeRefOrGetter<TaskActionMode>
  enabled: MaybeRefOrGetter<boolean>
  disabledReason: MaybeRefOrGetter<string>
}

export function useManualImageScan(
  options: UseManualImageScanOptions,
) {
  const pending = shallowRef(false)
  const errorMessage = shallowRef('')
  const feedbackMessage = shallowRef('')
  const request = shallowRef<ManualImageScanRequest>()
  let operationGeneration = 0
  let idempotencyKey = ''

  async function submit(): Promise<void> {
    if (pending.value || request.value) return
    if (toValue(options.mode) === 'preview' || !toValue(options.enabled)) {
      errorMessage.value =
        toValue(options.disabledReason) ||
        '当前文件节点不能发起镜像检测。'
      feedbackMessage.value = ''
      return
    }

    const taskId = toValue(options.taskId)
    const fileNodeId = toValue(options.fileNodeId)
    if (!taskId || !fileNodeId) return

    const generation = ++operationGeneration
    if (!idempotencyKey) idempotencyKey = createIdempotencyKey()
    pending.value = true
    errorMessage.value = ''
    feedbackMessage.value = ''

    try {
      const created = await api.createManualImageScanRequest(
        taskId,
        fileNodeId,
        idempotencyKey,
      )
      if (
        generation !== operationGeneration ||
        taskId !== toValue(options.taskId) ||
        fileNodeId !== toValue(options.fileNodeId)
      ) {
        return
      }
      request.value = created
      feedbackMessage.value = '镜像检测请求已进入队列。'
    } catch (error) {
      if (
        generation !== operationGeneration ||
        taskId !== toValue(options.taskId) ||
        fileNodeId !== toValue(options.fileNodeId)
      ) {
        return
      }
      const reason =
        error instanceof ApiError
          ? error.message
          : error instanceof Error
            ? error.message
            : '未知错误'
      errorMessage.value = `镜像检测请求提交失败：${reason}`
    } finally {
      if (generation === operationGeneration) pending.value = false
    }
  }

  function reset(): void {
    operationGeneration += 1
    pending.value = false
    errorMessage.value = ''
    feedbackMessage.value = ''
    request.value = undefined
    idempotencyKey = ''
  }

  watch(
    [() => toValue(options.taskId), () => toValue(options.fileNodeId)],
    reset,
  )
  onScopeDispose(reset)

  return {
    pending: readonly(pending),
    errorMessage: readonly(errorMessage),
    feedbackMessage: readonly(feedbackMessage),
    request: readonly(request),
    submit,
    reset,
  }
}
