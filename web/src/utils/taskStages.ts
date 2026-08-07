import type { TaskDetail } from '@/api/types'
import type {
  TaskExecutionLogEntry,
  TaskWorkflowKind,
} from '@/components/tasks/taskExecutionLog'

export type TaskStageId =
  | 'queued'
  | 'preparing'
  | 'starting'
  | 'running'
  | 'verifying'
  | 'database_ready'
  | 'targets_ready'
  | 'scanning'
  | 'publishing'
  | 'completed'

export type TaskStageState =
  | 'completed'
  | 'current'
  | 'pending'
  | 'failed'
  | 'cancelled'

export type TaskStageOutcome =
  | 'active'
  | 'queued'
  | 'succeeded'
  | 'failed'
  | 'cancelled'
  | 'waiting'

export interface TaskStageItem {
  id: TaskStageId
  label: string
  state: TaskStageState
  stateLabel: string
}

export interface TaskStageProgress {
  stages: TaskStageItem[]
  outcome: TaskStageOutcome
  progress: number
  indeterminate: boolean
  summary: string
  workflow: Exclude<TaskWorkflowKind, 'task'>
  workflowLabel: string
}

export type TaskStageSource = Pick<
  TaskDetail,
  | 'status'
  | 'current_stage'
  | 'progress'
  | 'progress_indeterminate'
> & { input_type?: string }

type AnalyzerWorkflow = Exclude<TaskWorkflowKind, 'task'>
type StageDefinition = Pick<TaskStageItem, 'id' | 'label'>

const containerFormats = new Set([
  'docker-tar',
  'docker-archive',
  'oci-tar',
  'oci-archive',
])

const decompileFormats = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'macho-fat',
  'java-class',
  'class',
  'jar',
  'war',
  'ear',
  'apk',
  'dex',
  'pyc',
  'python-bytecode',
])

const javaFormats = new Set([
  'java-class',
  'class',
  'jar',
  'war',
  'ear',
  'apk',
  'dex',
])

const nativeFormats = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'macho-fat',
])

const pythonFormats = new Set(['pyc', 'python-bytecode'])

const workflowDefinitions: Readonly<Record<AnalyzerWorkflow, readonly StageDefinition[]>> = {
  decompile: [
    { id: 'queued', label: '等待调度' },
    { id: 'preparing', label: '准备输入' },
    { id: 'starting', label: '启动引擎' },
    { id: 'running', label: '反编译' },
    { id: 'publishing', label: '保存结果' },
    { id: 'completed', label: '完成' },
  ],
  'image-scan': [
    { id: 'queued', label: '等待调度' },
    { id: 'verifying', label: '校验镜像' },
    { id: 'database_ready', label: '加载漏洞库' },
    { id: 'targets_ready', label: '准备目标' },
    { id: 'scanning', label: '漏洞扫描' },
    { id: 'publishing', label: '保存结果' },
    { id: 'completed', label: '完成' },
  ],
}

const stateLabels: Readonly<Record<TaskStageState, string>> = {
  completed: '已完成',
  current: '进行中',
  pending: '等待中',
  failed: '失败',
  cancelled: '已取消',
}

function normalizedInputType(value: string | undefined): string {
  return value?.trim().toLowerCase() ?? ''
}

function workflowFromTask(
  source: TaskStageSource,
  entries: readonly TaskExecutionLogEntry[],
): AnalyzerWorkflow {
  const inputType = normalizedInputType(source.input_type)
  if (containerFormats.has(inputType)) return 'image-scan'
  if (decompileFormats.has(inputType)) return 'decompile'

  const latestWorkflow = [...entries]
    .reverse()
    .find((entry) => entry.workflow !== 'task')?.workflow
  if (latestWorkflow === 'decompile' || latestWorkflow === 'image-scan') {
    return latestWorkflow
  }
  return 'decompile'
}

function workflowLabel(
  source: TaskStageSource,
  workflow: AnalyzerWorkflow,
): string {
  if (workflow === 'image-scan') return '镜像漏洞扫描'
  const inputType = normalizedInputType(source.input_type)
  if (javaFormats.has(inputType)) return 'Java 反编译'
  if (nativeFormats.has(inputType)) return '类 C 反编译'
  if (pythonFormats.has(inputType)) return 'Python 字节码分析'
  return '反编译分析'
}

function analyzerEntries(
  entries: readonly TaskExecutionLogEntry[],
  workflow: AnalyzerWorkflow,
): readonly TaskExecutionLogEntry[] {
  const matching = entries.filter((entry) => entry.workflow === workflow)
  let latestQueued = -1
  for (let index = matching.length - 1; index >= 0; index -= 1) {
    if (matching[index]?.phase === 'queued') {
      latestQueued = index
      break
    }
  }
  return latestQueued < 0 ? matching : matching.slice(latestQueued)
}

function stageIndex(
  definitions: readonly StageDefinition[],
  phase: string | null,
): number {
  if (phase === 'target_completed' || phase === 'target_failed') {
    return definitions.findIndex((stage) => stage.id === 'scanning')
  }
  return definitions.findIndex((stage) => stage.id === phase)
}

function ratio(entry: TaskExecutionLogEntry | undefined): number | null {
  if (
    !entry
    || entry.current === null
    || entry.total === null
    || entry.total <= 0
    || entry.current < 0
    || entry.current > entry.total
  ) {
    return null
  }
  return entry.current / entry.total
}

function progressFor(
  workflow: AnalyzerWorkflow,
  phase: string | null,
  entry: TaskExecutionLogEntry | undefined,
): number {
  const fraction = ratio(entry)
  if (workflow === 'decompile') {
    if (phase === 'preparing') return 10
    if (phase === 'starting') return 20
    if (phase === 'running') return Math.round(30 + 50 * (fraction ?? 0))
    if (phase === 'publishing') return 90
    if (phase === 'completed') return 100
    return 0
  }
  if (phase === 'verifying') return 10
  if (phase === 'database_ready') return 25
  if (phase === 'targets_ready') return 40
  if (phase === 'scanning' || phase === 'target_completed' || phase === 'target_failed') {
    return Math.round(45 + 40 * (fraction ?? 0))
  }
  if (phase === 'publishing') return 92
  if (phase === 'completed') return 100
  return 0
}

function buildStages(
  definitions: readonly StageDefinition[],
  currentIndex: number,
  currentState: TaskStageState | null,
): TaskStageItem[] {
  return definitions.map((definition, index) => {
    let state: TaskStageState = 'pending'
    if (index < currentIndex) state = 'completed'
    if (index === currentIndex && currentState) state = currentState
    return { ...definition, state, stateLabel: stateLabels[state] }
  })
}

function waitingModel(
  source: TaskStageSource,
  workflow: AnalyzerWorkflow,
): TaskStageProgress {
  const definitions = workflowDefinitions[workflow]
  return {
    stages: buildStages(definitions, -1, null),
    outcome: 'waiting',
    progress: 0,
    indeterminate: false,
    summary: workflow === 'decompile'
      ? '尚未收到反编译执行日志，可从文件结构中手动发起'
      : '尚未收到 Trivy 执行日志，等待镜像扫描任务开始',
    workflow,
    workflowLabel: workflowLabel(source, workflow),
  }
}

export function deriveTaskStageProgress(
  source: TaskStageSource,
  entries: readonly TaskExecutionLogEntry[] = [],
): TaskStageProgress {
  const workflow = workflowFromTask(source, entries)
  const definitions = workflowDefinitions[workflow]
  const relevant = analyzerEntries(entries, workflow)
  const latest = relevant[relevant.length - 1]
  if (!latest) return waitingModel(source, workflow)

  const failed = latest.phase === 'failed' || latest.phase === 'target_failed'
  const completed = latest.phase === 'completed'
  const cancelled = source.status.toUpperCase() === 'CANCELLED'
  let currentIndex = stageIndex(definitions, latest.phase)
  if (latest.phase === 'failed') {
    const previous = [...relevant]
      .reverse()
      .find((entry) => entry.phase !== 'failed')
    currentIndex = Math.max(stageIndex(definitions, previous?.phase ?? null), 0)
  }

  if (completed) {
    return {
      stages: definitions.map((definition) => ({
        ...definition,
        state: 'completed',
        stateLabel: stateLabels.completed,
      })),
      outcome: 'succeeded',
      progress: 100,
      indeterminate: false,
      summary: workflow === 'decompile' ? '反编译结果已保存' : '镜像漏洞扫描已完成',
      workflow,
      workflowLabel: workflowLabel(source, workflow),
    }
  }

  const currentState: TaskStageState = failed
    ? 'failed'
    : cancelled
      ? 'cancelled'
      : 'current'
  const currentLabel = definitions[currentIndex]?.label ?? '当前'
  const progress = progressFor(workflow, latest.phase, latest)
  return {
    stages: buildStages(definitions, Math.max(currentIndex, 0), currentState),
    outcome: failed ? 'failed' : cancelled ? 'cancelled' : latest.phase === 'queued' ? 'queued' : 'active',
    progress,
    indeterminate: latest.phase === 'running' || latest.phase === 'scanning'
      ? ratio(latest) === null
      : false,
    summary: failed
      ? `${currentLabel}阶段失败`
      : cancelled
        ? `已在${currentLabel}阶段取消`
        : latest.phase === 'queued'
          ? `${currentLabel}，等待 Worker 接收任务`
          : `${currentLabel}阶段进行中`,
    workflow,
    workflowLabel: workflowLabel(source, workflow),
  }
}
