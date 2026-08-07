import type {
  FileNodeDetail,
  TaskStatus,
  UserRole,
} from '@/api/types'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

export interface FileNodeDecompileActionModel {
  visible: boolean
  enabled: boolean
  reason: string
}

export interface FileNodeDecompileContext {
  node: FileNodeDetail
  taskStatus: TaskStatus
  userRole: UserRole | null
  mode: TaskActionMode
  sampleRetention: SampleRetentionSnapshot
}

const SUPPORTED_FORMATS = new Set([
  'pe32',
  'pe32+',
  'elf32',
  'elf64',
  'java-class',
  'jar',
  'war',
  'ear',
  'dex',
  'apk',
  'pyc',
])

const TERMINAL_TASK_STATUSES = new Set([
  'SUCCEEDED',
  'PARTIAL',
  'PARTIAL_SUCCEEDED',
  'FAILED',
  'CANCELLED',
])

const AVAILABLE_EXTRACTION_STATUSES = new Set(['indexed', 'extracted'])

export function isFileNodeDecompileFormatSupported(format: string): boolean {
  return SUPPORTED_FORMATS.has(format.trim().toLowerCase())
}

export function isFileNodeDecompileTargetSupported(
  format: string,
  architecture: string,
): boolean {
  const normalizedFormat = format.trim().toLowerCase()
  if (normalizedFormat === 'macho-thin') {
    return architecture.trim().toLowerCase() === 'x86_64'
  }
  // Universal Mach-O needs an explicit architecture-slice selector before it
  // can be sent to Ghidra without silently choosing the wrong program.
  if (normalizedFormat === 'macho-fat') return false
  return isFileNodeDecompileFormatSupported(normalizedFormat)
}

export function getFileNodeDecompileActionModel(
  context: FileNodeDecompileContext,
): FileNodeDecompileActionModel {
  const canRequest =
    context.userRole === 'administrator' || context.userRole === 'operator'
  const supportedNode =
    context.node.node_type === 'file' &&
    isFileNodeDecompileTargetSupported(
      context.node.format,
      context.node.architecture,
    )
  if (!canRequest || !supportedNode) {
    return {
      visible: false,
      enabled: false,
      reason: '',
    }
  }

  if (!context.sampleRetention.canReuseSample) {
    return {
      visible: true,
      enabled: false,
      reason: context.sampleRetention.actionReason,
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
      reason: '任务结束后才能发起反编译。',
    }
  }

  if (
    !AVAILABLE_EXTRACTION_STATUSES.has(
      context.node.extraction_status.trim().toLowerCase(),
    )
  ) {
    return {
      visible: true,
      enabled: false,
      reason: '该文件节点没有可用于反编译的已保留内容。',
    }
  }

  if (context.mode === 'preview') {
    return {
      visible: true,
      enabled: false,
      reason: '界面预览不会提交真实反编译任务。',
    }
  }

  return {
    visible: true,
    enabled: true,
    reason: '将该文件节点的反编译请求加入处理队列。',
  }
}
