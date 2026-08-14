export const TASK_RESULT_TABS = [
  'files',
  'decompile',
  'c-analysis',
  'java-analysis',
  'python-analysis',
  'vulnerabilities',
  'reports',
] as const

export type TaskResultTab = (typeof TASK_RESULT_TABS)[number]

export type TaskResultStatus =
  | 'loading'
  | 'ready'
  | 'empty'
  | 'unavailable'
  | 'error'

export type TaskResultMode = 'live' | 'preview'

export interface TaskResultState {
  status: TaskResultStatus
  title?: string
  description?: string
  errorCode?: string
}

export type TaskResultStates = Partial<
  Readonly<Record<TaskResultTab, TaskResultState>>
>

export type TaskResultCommand =
  | 'refresh-decompile'
  | 'download-decompile'
  | 'refresh-c-analysis'
  | 'refresh-java-analysis'
  | 'refresh-python-analysis'
  | 'refresh-vulnerabilities'
  | 'export-vulnerabilities'
  | 'refresh-reports'
  | 'download-report-json'
  | 'download-report-html'

export interface TaskResultCommandState {
  enabled: boolean
  pending?: boolean
}

export type TaskResultCommandStates = Partial<
  Readonly<Record<TaskResultCommand, TaskResultCommandState>>
>

export type TaskResultActionIcon = 'refresh' | 'download'

export interface TaskResultPaneAction {
  id: TaskResultCommand
  label: string
  shortLabel?: string
  icon: TaskResultActionIcon
  enabled: boolean
  pending: boolean
  requiresReady: boolean
}
