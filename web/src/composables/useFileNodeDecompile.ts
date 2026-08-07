import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type { FileDecompileRequest } from '@/api/types'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { createIdempotencyKey } from '@/utils/idempotency'

export const DECOMPILE_STATUS_POLL_INTERVAL_MS = 2_000

const ACTIVE_STATUSES = new Set(['queued', 'leased', 'running', 'cancel_requested'])
const FAILED_STATUSES = new Set(['failed', 'cancelled'])

interface UseFileNodeDecompileOptions {
  taskId: MaybeRefOrGetter<string>
  fileNodeId: MaybeRefOrGetter<string>
  mode: MaybeRefOrGetter<TaskActionMode>
  enabled: MaybeRefOrGetter<boolean>
  disabledReason: MaybeRefOrGetter<string>
}

export function useFileNodeDecompile(
  options: UseFileNodeDecompileOptions,
) {
  const pending = shallowRef(false)
  const errorMessage = shallowRef('')
  const statusRefreshError = shallowRef('')
  const feedbackMessage = shallowRef('')
  const request = shallowRef<FileDecompileRequest>()
  let operationGeneration = 0
  let idempotencyKey = ''
  let statusTimer: ReturnType<typeof globalThis.setTimeout> | null = null

  function clearStatusTimer(): void {
    if (statusTimer === null) return
    globalThis.clearTimeout(statusTimer)
    statusTimer = null
  }

  function statusFeedback(value: FileDecompileRequest): string {
    switch (value.status) {
      case 'leased':
        return '反编译 Worker 已领取请求，正在准备分析环境。'
      case 'running':
        return '反编译引擎正在处理该文件节点。'
      case 'succeeded':
        return '反编译已完成，结果已刷新。'
      case 'cancel_requested':
        return '反编译取消请求正在处理。'
      case 'cancelled':
        return '反编译请求已取消。'
      case 'failed':
        return '反编译处理失败。'
      default:
        return '反编译请求已进入队列，等待分析 Worker 处理。'
    }
  }

  function applyStatus(value: FileDecompileRequest): void {
    request.value = value
    feedbackMessage.value = statusFeedback(value)
    statusRefreshError.value = ''
    if (FAILED_STATUSES.has(value.status)) {
      const reason = value.error_message || value.error_code || '未提供失败原因'
      errorMessage.value = `${statusFeedback(value)}${reason ? ` ${reason}` : ''}`
    } else {
      errorMessage.value = ''
    }
  }

  function scheduleStatusRefresh(
    generation: number,
    taskId: string,
    fileNodeId: string,
    jobId: string,
  ): void {
    clearStatusTimer()
    if (!ACTIVE_STATUSES.has(request.value?.status ?? '')) return
    statusTimer = globalThis.setTimeout(() => {
      statusTimer = null
      void refreshStatus(generation, taskId, fileNodeId, jobId)
    }, DECOMPILE_STATUS_POLL_INTERVAL_MS)
  }

  async function refreshStatus(
    generation: number,
    taskId: string,
    fileNodeId: string,
    jobId: string,
  ): Promise<void> {
    try {
      const current = await api.getFileDecompileRequest(taskId, jobId)
      if (
        generation !== operationGeneration ||
        taskId !== toValue(options.taskId) ||
        fileNodeId !== toValue(options.fileNodeId)
      ) {
        return
      }
      if (
        current.task_id !== taskId ||
        current.file_node_id !== fileNodeId ||
        current.job_id !== jobId
      ) {
        throw new Error('反编译状态响应与当前请求不一致')
      }
      applyStatus(current)
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
      statusRefreshError.value = `反编译状态自动刷新失败：${reason}`
    } finally {
      if (
        generation === operationGeneration &&
        taskId === toValue(options.taskId) &&
        fileNodeId === toValue(options.fileNodeId)
      ) {
        scheduleStatusRefresh(generation, taskId, fileNodeId, jobId)
      }
    }
  }

  async function submit(): Promise<void> {
    if (pending.value || request.value) return
    const mode = toValue(options.mode)
    if (mode === 'preview' || !toValue(options.enabled)) {
      errorMessage.value =
        toValue(options.disabledReason) ||
        '当前文件节点不能发起反编译。'
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
    statusRefreshError.value = ''
    feedbackMessage.value = ''

    try {
      const created = await api.createFileDecompileRequest(
        taskId,
        fileNodeId,
        {
          engine_target: 'auto',
          options: {},
        },
        idempotencyKey,
      )
      if (
        generation !== operationGeneration ||
        taskId !== toValue(options.taskId) ||
        fileNodeId !== toValue(options.fileNodeId)
      ) {
        return
      }
      if (
        created.task_id !== taskId ||
        created.file_node_id !== fileNodeId
      ) {
        throw new Error('反编译请求响应与当前文件节点不一致')
      }
      applyStatus(created)
      scheduleStatusRefresh(
        generation,
        taskId,
        fileNodeId,
        created.job_id,
      )
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
      errorMessage.value = `反编译请求提交失败：${reason}`
    } finally {
      if (generation === operationGeneration) pending.value = false
    }
  }

  function reset(): void {
    operationGeneration += 1
    clearStatusTimer()
    pending.value = false
    errorMessage.value = ''
    statusRefreshError.value = ''
    feedbackMessage.value = ''
    request.value = undefined
    idempotencyKey = ''
  }

  function retry(): void {
    if (!request.value || !FAILED_STATUSES.has(request.value.status)) return
    reset()
    void submit()
  }

  watch(
    [() => toValue(options.taskId), () => toValue(options.fileNodeId)],
    reset,
  )

  onScopeDispose(reset)

  return {
    pending: readonly(pending),
    errorMessage: readonly(errorMessage),
    statusRefreshError: readonly(statusRefreshError),
    feedbackMessage: readonly(feedbackMessage),
    request: readonly(request),
    submit,
    retry,
    reset,
  }
}
