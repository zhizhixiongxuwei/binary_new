export type MaintenanceViewMode = 'preview' | 'live'

export interface MountPathPreview {
  id: string
  label: string
  purpose: string
  hostPath: string
  containerPath: string
  services: string
  serviceMappings?: readonly string[]
  usedBytes: number
  totalBytes: number
}

export interface AnalyzerPreview {
  name: string
  version: string
  scope: string
  state: 'available' | 'standby'
}

export interface RolePreview {
  id: 'administrator' | 'operator' | 'reader'
  label: string
  scope: string
  permissions: readonly string[]
}

export interface UserPreview {
  username: string
  displayName: string
  role: RolePreview['id']
  state: 'enabled' | 'locked'
  lastActive: string
}

export type AuditEventType = 'authentication' | 'task' | 'maintenance' | 'system'

export interface AuditLogPreview {
  id: string
  timestamp: string
  type: AuditEventType
  actor: string
  action: string
  target: string
  result: 'success' | 'denied'
}

export const mountPathPreviews: readonly MountPathPreview[] = [
  {
    id: 'repository',
    label: 'repository',
    purpose: '样本、解包产物与报告仓库',
    hostPath: 'binaryscan-data volume',
    containerPath: '/data/repository',
    services: 'app / scanner / java / ghidra',
    usedBytes: 186 * 1024 ** 3,
    totalBytes: 800 * 1024 ** 3,
  },
  {
    id: 'uploads',
    label: 'uploads',
    purpose: '浏览器分片上传暂存区',
    hostPath: 'binaryscan-data volume',
    containerPath: '/data/uploads',
    services: 'app',
    usedBytes: 38 * 1024 ** 3,
    totalBytes: 200 * 1024 ** 3,
  },
  {
    id: 'task-work',
    label: 'task-work',
    purpose: '任务解包与分析工作目录',
    hostPath: 'binaryscan-data volume',
    containerPath: '/data/task-work',
    services: 'app / scanner / java / ghidra',
    usedBytes: 92 * 1024 ** 3,
    totalBytes: 400 * 1024 ** 3,
  },
  {
    id: 'mysql',
    label: 'mysql',
    purpose: 'MySQL 持久化数据目录',
    hostPath: 'mysql-data volume',
    containerPath: '/var/lib/mysql',
    services: 'mysql',
    usedBytes: 61 * 1024 ** 3,
    totalBytes: 300 * 1024 ** 3,
  },
]

export const analyzerPreviews: readonly AnalyzerPreview[] = [
  {
    name: 'Ghidra',
    version: '12.1.2',
    scope: 'PE / ELF / Mach-O 类 C 代码',
    state: 'available',
  },
  {
    name: 'Trivy',
    version: '0.72.0',
    scope: 'Docker / OCI tar 镜像',
    state: 'available',
  },
  {
    name: 'Archive Engine',
    version: 'builtin-0.1',
    scope: '归档识别与受限解包',
    state: 'available',
  },
  {
    name: 'Filesystem Inspector',
    version: 'builtin-0.1',
    scope: 'tar / img / iso / ext4',
    state: 'standby',
  },
]

export const rolePreviews: readonly RolePreview[] = [
  {
    id: 'administrator',
    label: '系统管理员',
    scope: '平台维护与全部检测任务',
    permissions: ['创建任务', '查看结果', '系统维护', '用户管理'],
  },
  {
    id: 'operator',
    label: '操作员',
    scope: '检测任务的日常操作',
    permissions: ['创建任务', '查看结果', '取消任务'],
  },
  {
    id: 'reader',
    label: '只读用户',
    scope: '查看授权范围内的任务和报告',
    permissions: ['查看任务', '查看结果'],
  },
]

export const userPreviews: readonly UserPreview[] = [
  {
    username: 'admin',
    displayName: '离线平台管理员',
    role: 'administrator',
    state: 'enabled',
    lastActive: '2026-07-30 09:42',
  },
  {
    username: 'scanner-op',
    displayName: '检测操作员',
    role: 'operator',
    state: 'enabled',
    lastActive: '2026-07-30 09:18',
  },
  {
    username: 'audit-reader',
    displayName: '审阅用户',
    role: 'reader',
    state: 'enabled',
    lastActive: '2026-07-29 17:26',
  },
]

export const auditLogPreviews: readonly AuditLogPreview[] = [
  {
    id: 'AUD-00041',
    timestamp: '2026-07-30 09:42:13',
    type: 'authentication',
    actor: 'admin',
    action: '登录成功',
    target: 'local-session',
    result: 'success',
  },
  {
    id: 'AUD-00040',
    timestamp: '2026-07-30 09:18:51',
    type: 'task',
    actor: 'scanner-op',
    action: '创建检测任务',
    target: 'TASK-20260730-013',
    result: 'success',
  },
  {
    id: 'AUD-00039',
    timestamp: '2026-07-30 08:55:06',
    type: 'maintenance',
    actor: 'admin',
    action: '查看 Trivy 数据库 Bundle 状态',
    target: 'bundle-2026.07.29',
    result: 'success',
  },
  {
    id: 'AUD-00038',
    timestamp: '2026-07-30 08:40:32',
    type: 'system',
    actor: 'maintenance',
    action: '清理过期任务工作目录',
    target: '/data/task-work',
    result: 'success',
  },
  {
    id: 'AUD-00037',
    timestamp: '2026-07-29 18:03:27',
    type: 'authentication',
    actor: 'audit-reader',
    action: '访问系统维护被拒绝',
    target: '/system',
    result: 'denied',
  },
]
