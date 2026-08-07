export type MaintenanceTab =
  | 'runtime'
  | 'storage'
  | 'analyzers'
  | 'access'
  | 'audit'

export const MAINTENANCE_TABS: readonly MaintenanceTab[] = [
  'runtime',
  'storage',
  'analyzers',
  'access',
  'audit',
]
