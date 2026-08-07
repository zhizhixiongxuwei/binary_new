import type { TaskDetail, TaskStatus, UserRole } from '@/api/types'
import {
  parseSampleExpiry,
  resolveSampleRetention,
} from '@/utils/sampleRetention'

export {
  extendSampleExpiry,
  isSampleDeleted,
  isSampleExpired,
  parseSampleExpiry,
} from '@/utils/sampleRetention'

export type TaskActionMode = 'live' | 'preview'
export type TaskActionId = 'cancel' | 'retry' | 'delete' | 'extend'

export interface TaskActionState {
  enabled: boolean
  reason: string
}

export interface TaskActionModel {
  cancel: TaskActionState
  retry: TaskActionState
  delete: TaskActionState
  extend: TaskActionState
  sampleExpired: boolean
  sampleDeleted: boolean
}

export interface TaskActionContext {
  task: Pick<
    TaskDetail,
    'status' | 'sample_expires_at' | 'sample_deleted_at'
  >
  mode: TaskActionMode
  userRole: UserRole | null
  isCreator: boolean
  now?: Date | undefined
}

const CANCEL_STATUSES = new Set([
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'RUNNING',
])

const RETRY_STATUSES = new Set([
  'FAILED',
  'CANCELLED',
  'PARTIAL',
  'PARTIAL_SUCCEEDED',
])

const TERMINAL_DELETE_STATUSES = new Set(['DELETING', 'DELETED'])

function normalizedStatus(status: TaskStatus): string {
  return status.trim().toUpperCase()
}

function disabled(reason: string): TaskActionState {
  return { enabled: false, reason }
}

function enabled(reason: string): TaskActionState {
  return { enabled: true, reason }
}

export function getTaskActionModel(context: TaskActionContext): TaskActionModel {
  const { task, userRole, isCreator } = context
  const status = normalizedStatus(task.status)
  const retention = resolveSampleRetention({
    sampleExpiresAt: task.sample_expires_at,
    sampleDeletedAt: task.sample_deleted_at,
    now: context.now,
  })
  const sampleDeleted = retention.status === 'deleted'
  const sampleExpired =
    sampleDeleted || retention.status === 'expired'

  const canOperate = userRole === 'administrator' || userRole === 'operator'
  const cancel = !canOperate
    ? disabled('当前角色没有取消任务的权限。')
    : CANCEL_STATUSES.has(status)
      ? enabled('取消排队中或执行中的任务。')
      : disabled('仅排队中或执行中的任务可以取消。')

  const retry = !canOperate
    ? disabled('当前角色没有重新检测的权限。')
    : sampleDeleted
      ? disabled('任务原始样本已清理，无法重新检测。')
      : sampleExpired
        ? disabled('样本保留期已到，无法重新检测。')
      : !retention.canReuseSample
        ? disabled(retention.actionReason)
      : RETRY_STATUSES.has(status)
        ? enabled('以相同样本创建一次新的检测尝试。')
        : disabled('仅失败、已取消或部分成功的任务可以重试。')

  const canDelete =
    userRole === 'administrator' || (userRole === 'operator' && isCreator)
  const deleteAction = !canDelete
    ? disabled('只有管理员，或作为创建者的检测人员可以删除任务。')
    : TERMINAL_DELETE_STATUSES.has(status)
      ? disabled('任务已进入删除流程。')
      : enabled('提交删除请求；任务先进入待删除状态，后台清理完成后保留审计记录。')

  const expiry = parseSampleExpiry(task.sample_expires_at)
  const extend = userRole !== 'administrator'
      ? disabled('只有管理员可以延长样本保留期。')
      : TERMINAL_DELETE_STATUSES.has(status)
        ? disabled('任务已进入删除流程，不能再延长保留期。')
      : !expiry
        ? disabled('任务没有可用的样本到期时间。')
        : sampleDeleted
          ? disabled('任务原始样本已清理，不能再延长保留期。')
          : sampleExpired
            ? disabled('样本保留期已到，不能再延长保留期。')
          : !retention.canReuseSample
            ? disabled(retention.actionReason)
          : enabled('将当前样本到期时间延长 15 天。')

  return {
    cancel,
    retry,
    delete: deleteAction,
    extend,
    sampleExpired,
    sampleDeleted,
  }
}
