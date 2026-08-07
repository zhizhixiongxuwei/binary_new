import type { FileNode } from '@/api/types'

const typeLabels: Readonly<Record<string, string>> = {
  file: '文件',
  directory: '目录',
  symlink: '符号链接',
  hardlink: '硬链接',
  special: '特殊文件',
}

const statusLabels: Readonly<Record<string, string>> = {
  indexed: '已索引',
  extracted: '已提取',
  skipped: '已跳过',
  unsupported: '暂不支持',
  limit_reached: '达到限制',
  failed: '提取失败',
}

export type FileNodeStatusTone = 'success' | 'warning' | 'failed' | 'muted'

export function fileNodeDisplayName(node: FileNode): string {
  return node.display_name || node.logical_path || '/'
}

export function fileNodeTypeLabel(nodeType: string): string {
  return typeLabels[nodeType] || nodeType || '未知'
}

export function fileNodeExtractionLabel(status: string): string {
  return statusLabels[status.toLowerCase()] || status || '未知'
}

export function fileNodeStatusTone(status: string): FileNodeStatusTone {
  const value = status.toLowerCase()
  if (value === 'failed') return 'failed'
  if (value === 'limit_reached' || value === 'unsupported') return 'warning'
  if (value === 'extracted' || value === 'indexed') return 'success'
  return 'muted'
}
