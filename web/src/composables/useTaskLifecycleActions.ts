import { readonly, shallowRef, toValue, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type { TaskDetail } from '@/api/types'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { createIdempotencyKey } from '@/utils/idempotency'
import { resolveSampleRetention } from '@/utils/sampleRetention'

export type TaskLifecycleAction = 'cancel' | 'retry' | 'delete' | 'extend'

interface UseTaskLifecycleActionsOptions {
  mode: MaybeRefOrGetter<TaskActionMode>
  updateTask: (task: TaskDetail) => void
}

const SUCCESS_MESSAGES: Record<TaskLifecycleAction, Record<TaskActionMode, string>> = {
  cancel: {
    live: '取消请求已提交，任务详情已刷新。',
    preview: '界面预览：任务已模拟进入请求取消状态。',
  },
  retry: {
    live: '重新检测请求已提交，任务详情已刷新。',
    preview: '界面预览：任务已模拟重新进入排队状态。',
  },
  delete: {
    live: '删除请求已提交，任务已进入删除流程。',
    preview: '界面预览：任务已模拟进入删除流程，未删除任何本地数据。',
  },
  extend: {
    live: '样本保留期已延长 15 天。',
    preview: '界面预览：样本到期时间已在本页模拟延长 15 天。',
  },
}

function previewResult(
  action: TaskLifecycleAction,
  task: TaskDetail,
  sampleExpiresAt?: string,
): TaskDetail {
  if (action === 'cancel') {
    return {
      ...task,
      status: 'CANCEL_REQUESTED',
      current_stage: 'CANCEL_REQUESTED',
    }
  }

  if (action === 'delete') {
    return {
      ...task,
      status: 'DELETING',
      current_stage: 'DELETING',
    }
  }

  if (action === 'extend') {
    return sampleExpiresAt
      ? { ...task, sample_expires_at: sampleExpiresAt }
      : { ...task }
  }

  const result = {
    ...task,
    status: 'QUEUED' as const,
    progress: 0,
    progress_indeterminate: false,
    current_stage: 'QUEUED',
  }
  delete result.error_code
  delete result.error_message
  return result
}

function actionLabel(action: TaskLifecycleAction): string {
  if (action === 'cancel') return '取消任务'
  if (action === 'retry') return '重新检测'
  if (action === 'delete') return '删除任务'
  return '延长样本保留期'
}

export function useTaskLifecycleActions(options: UseTaskLifecycleActionsOptions) {
  const pendingAction = shallowRef<TaskLifecycleAction | null>(null)
  const errorMessage = shallowRef('')
  const feedbackMessage = shallowRef('')
  const idempotencyKeys = new Map<string, string>()
  let operationGeneration = 0

  function intentKey(action: TaskLifecycleAction, taskId: string): string {
    return `${action}:${taskId}`
  }

  function getIdempotencyKey(
    action: 'cancel' | 'retry',
    taskId: string,
  ): string {
    const key = intentKey(action, taskId)
    const existing = idempotencyKeys.get(key)
    if (existing) return existing

    const created = createIdempotencyKey()
    idempotencyKeys.set(key, created)
    return created
  }

  async function execute(
    action: TaskLifecycleAction,
    task: TaskDetail,
    sampleExpiresAt?: string,
  ): Promise<void> {
    if (pendingAction.value) return

    if (action === 'retry' || action === 'extend') {
      const retention = resolveSampleRetention({
        sampleExpiresAt: task.sample_expires_at,
        sampleDeletedAt: task.sample_deleted_at,
      })
      if (!retention.canReuseSample) {
        errorMessage.value = `${actionLabel(action)}不可用：${retention.actionReason}`
        feedbackMessage.value = ''
        return
      }
    }

    const generation = ++operationGeneration
    const mode = toValue(options.mode)
    const key = intentKey(action, task.id)
    pendingAction.value = action
    errorMessage.value = ''
    feedbackMessage.value = ''

    try {
      let updatedTask: TaskDetail
      if (mode === 'preview') {
        updatedTask = previewResult(action, task, sampleExpiresAt)
      } else if (action === 'cancel') {
        updatedTask = await api.cancelTask(
          task.id,
          getIdempotencyKey(action, task.id),
        )
      } else if (action === 'retry') {
        updatedTask = await api.retryTask(
          task.id,
          getIdempotencyKey(action, task.id),
        )
      } else if (action === 'delete') {
        updatedTask = await api.deleteTask(task.id)
      } else {
        if (!task.sample_expires_at || !sampleExpiresAt) {
          throw new Error('任务没有可用的样本到期时间')
        }
        updatedTask = await api.extendTaskRetention(task.id, {
          expected_sample_expires_at: task.sample_expires_at,
          sample_expires_at: sampleExpiresAt,
        })
      }

      if (generation !== operationGeneration) return
      options.updateTask(updatedTask)
      feedbackMessage.value = SUCCESS_MESSAGES[action][mode]
      idempotencyKeys.delete(key)
    } catch (error) {
      if (generation !== operationGeneration) return
      const reason =
        error instanceof ApiError
          ? error.message
          : error instanceof Error
            ? error.message
            : '未知错误'
      errorMessage.value = `${actionLabel(action)}失败：${reason}`
    } finally {
      if (generation === operationGeneration) pendingAction.value = null
    }
  }

  function reset(): void {
    operationGeneration += 1
    pendingAction.value = null
    errorMessage.value = ''
    feedbackMessage.value = ''
    idempotencyKeys.clear()
  }

  function showFeedback(message: string): void {
    errorMessage.value = ''
    feedbackMessage.value = message
  }

  return {
    pendingAction: readonly(pendingAction),
    errorMessage: readonly(errorMessage),
    feedbackMessage: readonly(feedbackMessage),
    execute,
    reset,
    showFeedback,
  }
}
