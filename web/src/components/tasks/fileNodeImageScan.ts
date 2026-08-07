import type {
  FileNodeDetail,
  TaskStatus,
  UserRole,
} from '@/api/types'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

export interface FileNodeImageScanActionModel {
  visible: boolean
  enabled: boolean
  reason: string
}

export interface FileNodeImageScanContext {
  node: FileNodeDetail
  taskStatus: TaskStatus
  userRole: UserRole | null
  mode: TaskActionMode
  sampleRetention: SampleRetentionSnapshot
}

const IMAGE_FORMATS = new Set(['docker-tar', 'oci-tar'])
const TERMINAL_TASK_STATUSES = new Set([
  'SUCCEEDED',
  'PARTIAL',
  'PARTIAL_SUCCEEDED',
  'FAILED',
  'CANCELLED',
])

function unavailableSampleReason(
  retention: SampleRetentionSnapshot,
): string {
  switch (retention.status) {
    case 'expired':
      return '样本保留期已到，无法单独检测该镜像。'
    case 'deleted':
      return '任务原始样本已清理，无法单独检测该镜像。'
    default:
      return '样本保留状态不可确认，请刷新任务后重试。'
  }
}

export function isManualImageScanTarget(node: FileNodeDetail): boolean {
  if (
    node.node_type !== 'file' ||
    !IMAGE_FORMATS.has(node.format.trim().toLowerCase())
  ) {
    return false
  }
  if (node.parent_id === null) return true
  return (
    node.extraction_status.trim().toLowerCase() === 'limit_reached' &&
    node.error_code.trim().toLowerCase() === 'max_auto_container_images'
  )
}

export function getFileNodeImageScanActionModel(
  context: FileNodeImageScanContext,
): FileNodeImageScanActionModel {
  const canRequest =
    context.userRole === 'administrator' || context.userRole === 'operator'
  if (!canRequest || !isManualImageScanTarget(context.node)) {
    return { visible: false, enabled: false, reason: '' }
  }

  if (!context.sampleRetention.canReuseSample) {
    return {
      visible: true,
      enabled: false,
      reason: unavailableSampleReason(context.sampleRetention),
    }
  }

  if (
    !TERMINAL_TASK_STATUSES.has(
      context.taskStatus.trim().toUpperCase(),
    )
  ) {
    return {
      visible: true,
      enabled: false,
      reason: context.node.parent_id === null
        ? 'Trivy 检测已随上传任务排队，将在漏洞库和 Worker 就绪后自动执行。'
        : '任务结束后才能单独检测该镜像。',
    }
  }

  if (
    context.node.size_bytes === null ||
    context.node.size_bytes <= 0 ||
    !/^[0-9a-f]{64}$/.test(context.node.sha256)
  ) {
    return {
      visible: true,
      enabled: false,
      reason: '该节点没有可复用的完整镜像内容。',
    }
  }

  if (context.mode === 'preview') {
    return {
      visible: true,
      enabled: false,
      reason: '界面预览不会提交真实镜像检测任务。',
    }
  }

  return {
    visible: true,
    enabled: true,
    reason: context.node.parent_id === null
      ? '将上传的镜像重新加入 Trivy 检测队列。'
      : '绕过自动嵌套镜像数量限制，将该镜像单独加入 Trivy 检测队列。',
  }
}
