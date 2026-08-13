<script setup lang="ts">
import {
  AlertTriangle,
  ArrowLeft,
  FileCode2,
  ShieldAlert,
  TimerReset,
} from 'lucide-vue-next'
import {
  computed,
  defineAsyncComponent,
  nextTick,
  onScopeDispose,
  shallowRef,
  useTemplateRef,
  watch,
} from 'vue'

import { api, ApiError } from '@/api/client'
import { isDemoMode } from '@/api/runtime'
import type {
  FileDecompileRequest,
  FileNodeDetail,
  JsonValue,
  TaskDetail,
  TaskEventMessage,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import DecompileProjectPanel from '@/components/tasks/decompile-projects/DecompileProjectPanel.vue'
import FileTreePanel from '@/components/tasks/FileTreePanel.vue'
import SampleRetentionNotice from '@/components/tasks/SampleRetentionNotice.vue'
import TaskAnalysisActions from '@/components/tasks/TaskAnalysisActions.vue'
import TaskActionBar from '@/components/tasks/TaskActionBar.vue'
import TaskDetailTabs, {
  type TaskDetailTab,
} from '@/components/tasks/TaskDetailTabs.vue'
import TaskExecutionLog from '@/components/tasks/TaskExecutionLog.vue'
import TaskResultTabs from '@/components/tasks/TaskResultTabs.vue'
import TaskStageProgress from '@/components/tasks/TaskStageProgress.vue'
import {
  toTaskExecutionLogEntry,
  type TaskExecutionLogEntry,
} from '@/components/tasks/taskExecutionLog'
import {
  isSampleDeleted,
  parseSampleExpiry,
} from '@/components/tasks/taskActions'
import type {
  TaskResultCommand,
  TaskResultCommandStates,
  TaskResultState,
  TaskResultStates,
  TaskResultTab,
} from '@/components/tasks/taskResultTypes'
import { taskResultTabsForInputType } from '@/components/tasks/taskResultProfile'
import { useTaskLifecycleActions } from '@/composables/useTaskLifecycleActions'
import { useTaskEvents } from '@/composables/useTaskEvents'
import { useSampleRetentionClock } from '@/composables/useSampleRetentionClock'
import { useSessionStore } from '@/stores/session'
import { formatBytes, formatDateTime } from '@/utils/formatters'
import { resolveSampleRetention } from '@/utils/sampleRetention'

const DemoDecompileResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? defineAsyncComponent(
        () => import('@/components/tasks/demo/DemoDecompileResult.vue'),
      )
    : null
const DemoVulnerabilityResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? defineAsyncComponent(
        () => import('@/components/tasks/demo/DemoVulnerabilityResult.vue'),
      )
    : null
const DemoReportResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? defineAsyncComponent(
        () => import('@/components/tasks/demo/DemoReportResult.vue'),
      )
    : null
const LiveDecompileResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? null
    : defineAsyncComponent(
        () => import('@/components/tasks/results/LiveDecompileResult.vue'),
      )
const LiveCAnalysisResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? null
    : defineAsyncComponent(
        () => import('@/components/tasks/c-analysis/CAnalysisWorkspace.vue'),
      )
const LiveJavaAnalysisResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? null
    : defineAsyncComponent(
        () => import('@/components/tasks/java-analysis/JavaAnalysisWorkspace.vue'),
      )
const LiveVulnerabilityResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? null
    : defineAsyncComponent(
        () => import('@/components/tasks/results/LiveVulnerabilityResult.vue'),
      )
const LiveReportResult =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? null
    : defineAsyncComponent(
        () => import('@/components/tasks/results/LiveReportResult.vue'),
      )

const DECOMPILE_PREVIEW_FORMATS = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'mach-o',
  'mach-o32',
  'mach-o64',
  'class',
  'java-class',
  'pyc',
  'python-bytecode',
  'dex',
  'apk',
  'jar',
])

const CONTAINER_PREVIEW_FORMATS = new Set([
  'docker-tar',
  'docker-archive',
  'oci-tar',
  'oci-archive',
  'ext2',
  'ext3',
  'ext4',
  'mbr-img',
  'gpt-img',
])

const props = defineProps<{
  taskId: string
  now?: Date
}>()

const emit = defineEmits<{
  returnList: []
}>()

const session = useSessionStore()
const decompileResultState = shallowRef<TaskResultState>({
  status: 'loading',
})
const vulnerabilityResultState = shallowRef<TaskResultState>({
  status: 'loading',
})
const reportResultState = shallowRef<TaskResultState>({
  status: 'loading',
})
const cAnalysisResultState = shallowRef<TaskResultState>({
  status: 'loading',
})
const cAnalysisBusy = shallowRef(false)
const javaAnalysisResultState = shallowRef<TaskResultState>({
  status: 'loading',
})
const javaAnalysisBusy = shallowRef(false)
const liveDecompileResult = useTemplateRef<{
  refresh: () => void
  openResult: (resultId: string) => Promise<boolean>
}>(
  'liveDecompileResult',
)
const liveCAnalysisResult = useTemplateRef<{
  refresh: () => void
  startProject: (projectId: string) => Promise<void>
}>('liveCAnalysisResult')
const pendingCAnalysisProjectId = shallowRef('')
const liveJavaAnalysisResult = useTemplateRef<{
  refresh: () => void
  startProject: (projectId: string) => Promise<void>
}>('liveJavaAnalysisResult')
const pendingJavaAnalysisProject = shallowRef<{
  taskId: string
  projectId: string
}>()
const decompileProjectPanel = useTemplateRef<{ refresh: () => void }>(
  'decompileProjectPanel',
)
const liveVulnerabilityResult = useTemplateRef<{ refresh: () => void }>(
  'liveVulnerabilityResult',
)
const liveReportResult = useTemplateRef<{ refresh: () => void }>(
  'liveReportResult',
)
const task = shallowRef<TaskDetail | null>(null)
const analysisTarget = shallowRef<FileNodeDetail | null>(null)
const activeResultTab = shallowRef<TaskResultTab>('files')
const activeDetailTab = shallowRef<TaskDetailTab>('progress')
const executionLogEntries = shallowRef<readonly TaskExecutionLogEntry[]>([])
const executionLogKeys = new Set<string>()

const MAX_EXECUTION_LOG_ENTRIES = 500

const loading = shallowRef(true)
const errorMessage = shallowRef('')
const eventRefreshError = shallowRef('')
const actionMode = computed(() => (isDemoMode ? 'preview' as const : 'live' as const))
const lifecycleActions = useTaskLifecycleActions({
  mode: actionMode,
  updateTask(updatedTask) {
    if (updatedTask.id === props.taskId) task.value = updatedTask
  },
})
const taskDeleting = computed(
  () => task.value?.status.toUpperCase() === 'DELETING',
)
const partialResult = computed(() => {
  const status = task.value?.status.toUpperCase()
  return status === 'PARTIAL_SUCCEEDED' || status === 'PARTIAL'
})
const sampleClock = useSampleRetentionClock(
  () => [task.value?.sample_expires_at],
  { now: () => props.now },
)
const sampleRetention = computed(() =>
  resolveSampleRetention({
    sampleExpiresAt: task.value?.sample_expires_at,
    sampleDeletedAt: task.value?.sample_deleted_at,
    now: sampleClock.now.value,
  }),
)
const sampleExpired = computed(
  () => sampleRetention.value.status === 'expired',
)
const sampleDeleted = computed(
  () => sampleRetention.value.status === 'deleted',
)
const visibleResultTabs = computed(() =>
  taskResultTabsForInputType(task.value?.input_type ?? ''),
)
const isCreator = computed(
  () =>
    session.user !== null &&
    task.value !== null &&
    session.user.id === task.value.creator_id,
)
const taskEventsEnabled = computed(
  () => !isDemoMode && !loading.value && task.value?.id === props.taskId,
)
const deferredResultStates = computed<TaskResultStates>(() => {
  if (!isDemoMode) {
    return {
      decompile: decompileResultState.value,
      'c-analysis': cAnalysisResultState.value,
      'java-analysis': javaAnalysisResultState.value,
      vulnerabilities: vulnerabilityResultState.value,
      reports: reportResultState.value,
    }
  }

  const inputType = task.value?.input_type.trim().toLowerCase() ?? ''
  return {
    decompile: DECOMPILE_PREVIEW_FORMATS.has(inputType)
      ? { status: 'ready' }
      : {
          status: 'empty',
          title: '该输入类型没有反编译界面样例',
          description: '请选择 PE、ELF、Mach-O、CLASS、PYC、DEX、APK 或 JAR 示例任务查看。',
        },
    'c-analysis': {
      status: 'unavailable',
      title: '界面预览不执行 C 源码检测',
      description: '连接后端后可对已保存的 Ghidra 类 C 源码项目发起检测。',
    },
    'java-analysis': {
      status: 'unavailable',
      title: '界面预览不执行 Java 源码检测',
      description: '连接后端后可对已保存的 Java 源码项目发起检测。',
    },
    vulnerabilities: CONTAINER_PREVIEW_FORMATS.has(inputType)
      ? { status: 'ready' }
      : {
          status: 'empty',
          title: '该任务不是容器 / 磁盘镜像包',
          description: '容器漏洞界面样例仅对镜像包示例任务展示。',
        },
    reports: { status: 'ready' },
  }
})
const resultCommands = computed<TaskResultCommandStates>(() =>
  isDemoMode
    ? {}
    : {
        'refresh-decompile': {
          enabled: decompileResultState.value.status !== 'loading',
          pending: decompileResultState.value.status === 'loading',
        },
        'refresh-c-analysis': {
          enabled:
            cAnalysisResultState.value.status !== 'loading' &&
            !cAnalysisBusy.value,
          pending:
            cAnalysisResultState.value.status === 'loading' ||
            cAnalysisBusy.value,
        },
        'refresh-java-analysis': {
          enabled:
            javaAnalysisResultState.value.status !== 'loading' &&
            !javaAnalysisBusy.value,
          pending:
            javaAnalysisResultState.value.status === 'loading' ||
            javaAnalysisBusy.value,
        },
        'refresh-vulnerabilities': {
          enabled: vulnerabilityResultState.value.status !== 'loading',
          pending: vulnerabilityResultState.value.status === 'loading',
        },
        'refresh-reports': {
          enabled: reportResultState.value.status !== 'loading',
          pending: reportResultState.value.status === 'loading',
        },
      },
)
let loadGeneration = 0
let eventRefreshGeneration = 0
let eventRefreshTimer: ReturnType<typeof globalThis.setTimeout> | null = null

const eventStatuses = new Set<TaskDetail['status']>([
  'UPLOADING',
  'QUEUED',
  'VALIDATING',
  'IDENTIFYING',
  'EXTRACTING',
  'INDEXING',
  'SCANNING',
  'REPORTING',
  'SUCCEEDED',
  'PARTIAL_SUCCEEDED',
  'FAILED',
  'CANCEL_REQUESTED',
  'CANCELLED',
  'DELETING',
  'DELETED',
  'pending',
  'uploading',
  'queued',
  'running',
  'succeeded',
  'partial',
  'failed',
  'cancelled',
])

function payloadRecord(
  value: JsonValue,
): Readonly<Record<string, JsonValue>> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  return value as Readonly<Record<string, JsonValue>>
}

function mergeTaskEvent(message: TaskEventMessage): void {
  const currentTask = task.value
  if (!currentTask || currentTask.id !== props.taskId) return

  const event = message.data
  const payload = payloadRecord(event.payload)
  const payloadStatus = payload?.status
  const nextStatus =
    typeof payloadStatus === 'string' &&
    eventStatuses.has(payloadStatus as TaskDetail['status'])
      ? (payloadStatus as TaskDetail['status'])
      : currentTask.status
  const payloadProgress = payload?.progress
  const eventProgress =
    typeof payloadProgress === 'number'
      ? payloadProgress
      : typeof event.progress === 'number'
        ? event.progress
        : null
  const progress = eventProgress !== null && Number.isFinite(eventProgress)
    ? Math.min(
        Math.max(eventProgress, 0),
        100,
      )
    : currentTask.progress
  const payloadProgressIndeterminate = payload?.progress_indeterminate
  const progressIndeterminate =
    typeof payloadProgressIndeterminate === 'boolean'
      ? payloadProgressIndeterminate
      : event.progress_indeterminate
  const payloadStage = payload?.current_stage
  const payloadSampleDeletedAt = payload?.sample_deleted_at
  const sampleDeletedAt =
    payloadSampleDeletedAt === null
      ? null
      : typeof payloadSampleDeletedAt === 'string' &&
          isSampleDeleted(payloadSampleDeletedAt)
        ? payloadSampleDeletedAt
        : currentTask.sample_deleted_at
  const payloadSampleExpiresAt = payload?.sample_expires_at
  const sampleExpiresAt =
    typeof payloadSampleExpiresAt === 'string' &&
    parseSampleExpiry(payloadSampleExpiresAt) !== null
      ? payloadSampleExpiresAt
      : currentTask.sample_expires_at

  task.value = {
    ...currentTask,
    status: nextStatus,
    progress,
    progress_indeterminate: progressIndeterminate,
    current_stage:
      typeof payloadStage === 'string' && payloadStage
        ? payloadStage
        : event.stage || currentTask.current_stage || '',
    sample_expires_at: sampleExpiresAt,
    sample_deleted_at: sampleDeletedAt,
    updated_at: event.created_at || currentTask.updated_at || currentTask.created_at,
  }
}

function resetExecutionLog(): void {
  executionLogEntries.value = []
  executionLogKeys.clear()
}

function collectTaskEvent(
  message: TaskEventMessage,
): TaskExecutionLogEntry | null {
  const entry = toTaskExecutionLogEntry(message)
  if (!entry || executionLogKeys.has(entry.key)) return null

  const entries = [...executionLogEntries.value, entry]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-MAX_EXECUTION_LOG_ENTRIES)
  executionLogEntries.value = entries
  executionLogKeys.clear()
  for (const current of entries) executionLogKeys.add(current.key)
  return entry
}

function clearEventRefreshTimer(): void {
  if (eventRefreshTimer === null) return
  globalThis.clearTimeout(eventRefreshTimer)
  eventRefreshTimer = null
}

async function refreshTaskFromEvent(
  taskId: string,
  loadVersion: number,
  refreshVersion: number,
): Promise<void> {
  try {
    const refreshedTask = await api.getTask(taskId)
    if (
      loadVersion !== loadGeneration ||
      refreshVersion !== eventRefreshGeneration ||
      taskId !== props.taskId
    ) {
      return
    }
    task.value = refreshedTask
    eventRefreshError.value = ''
  } catch (error) {
    if (
      loadVersion !== loadGeneration ||
      refreshVersion !== eventRefreshGeneration ||
      taskId !== props.taskId
    ) {
      return
    }
    eventRefreshError.value =
      error instanceof ApiError ? error.message : '任务详情自动刷新失败'
  }
}

function scheduleEventRefresh(): void {
  clearEventRefreshTimer()
  const taskId = props.taskId
  const loadVersion = loadGeneration
  const refreshVersion = eventRefreshGeneration
  eventRefreshTimer = globalThis.setTimeout(() => {
    eventRefreshTimer = null
    void refreshTaskFromEvent(taskId, loadVersion, refreshVersion)
  }, 180)
}

function handleTaskEvent(message: TaskEventMessage): void {
  const logEntry = collectTaskEvent(message)
  if (logEntry && message.data.type === 'decompile.completed') {
    void nextTick(() => {
      liveDecompileResult.value?.refresh()
      decompileProjectPanel.value?.refresh?.()
    })
  } else if (logEntry && message.data.type === 'trivy.completed') {
    void nextTick(() => liveVulnerabilityResult.value?.refresh())
  } else if (logEntry && message.data.type.startsWith('c_analysis.')) {
    void nextTick(() => liveCAnalysisResult.value?.refresh())
  } else if (logEntry && message.data.type.startsWith('java_analysis.')) {
    void nextTick(() => liveJavaAnalysisResult.value?.refresh())
  }
  if (
    !message.data.type.startsWith('task.') &&
    !message.event.startsWith('task.')
  ) {
    return
  }

  eventRefreshGeneration += 1
  mergeTaskEvent(message)
  scheduleEventRefresh()
}

const taskEvents = useTaskEvents({
  taskId: () => props.taskId,
  enabled: taskEventsEnabled,
  onEvent: handleTaskEvent,
})
const taskEventStatusLabel = computed(() => {
  if (taskEvents.status.value === 'connected') return '实时事件已连接'
  if (taskEvents.status.value === 'reconnecting') {
    return `实时事件重连中（第 ${Math.max(taskEvents.retryAttempt.value, 1)} 次）`
  }
  return '正在连接实时事件'
})
const taskEventStatusTitle = computed(
  () => eventRefreshError.value || taskEvents.errorMessage.value || taskEventStatusLabel.value,
)

async function load(): Promise<void> {
  const generation = ++loadGeneration
  eventRefreshGeneration += 1
  clearEventRefreshTimer()
  const taskId = props.taskId
  loading.value = true
  errorMessage.value = ''
  eventRefreshError.value = ''
  resetExecutionLog()
  lifecycleActions.reset()
  decompileResultState.value = { status: 'loading' }
  cAnalysisResultState.value = { status: 'loading' }
  cAnalysisBusy.value = false
  javaAnalysisResultState.value = { status: 'loading' }
  javaAnalysisBusy.value = false
  vulnerabilityResultState.value = { status: 'loading' }
  reportResultState.value = { status: 'loading' }
  activeResultTab.value = 'files'
  activeDetailTab.value = 'progress'
  pendingCAnalysisProjectId.value = ''
  pendingJavaAnalysisProject.value = undefined
  analysisTarget.value = null
  task.value = null
  try {
    const loadedTask = await api.getTask(taskId)
    if (generation !== loadGeneration || taskId !== props.taskId) return
    task.value = loadedTask
  } catch (error) {
    if (generation !== loadGeneration || taskId !== props.taskId) return
    errorMessage.value = error instanceof ApiError ? error.message : '任务详情读取失败'
  } finally {
    if (generation === loadGeneration && taskId === props.taskId) {
      loading.value = false
    }
  }
}

watch(
  () => props.taskId,
  () => void load(),
  { immediate: true },
)

onScopeDispose(() => {
  loadGeneration += 1
  eventRefreshGeneration += 1
  clearEventRefreshTimer()
  lifecycleActions.reset()
})

function handleCancel(): void {
  if (task.value) void lifecycleActions.execute('cancel', task.value)
}

function handleRetry(): void {
  if (!task.value) return
  if (!sampleRetention.value.canReuseSample) {
    lifecycleActions.showFeedback(sampleRetention.value.actionReason)
    return
  }
  void lifecycleActions.execute('retry', task.value)
}

function handleDelete(): void {
  if (task.value) void lifecycleActions.execute('delete', task.value)
}

function handleExtend(sampleExpiresAt: string): void {
  if (task.value) {
    void lifecycleActions.execute('extend', task.value, sampleExpiresAt)
  }
}

function handleResultCommand(command: TaskResultCommand): void {
  if (command === 'refresh-decompile') {
    liveDecompileResult.value?.refresh()
  } else if (command === 'refresh-vulnerabilities') {
    liveVulnerabilityResult.value?.refresh()
  } else if (command === 'refresh-reports') {
    liveReportResult.value?.refresh()
  } else if (command === 'refresh-c-analysis') {
    liveCAnalysisResult.value?.refresh()
  } else if (command === 'refresh-java-analysis') {
    liveJavaAnalysisResult.value?.refresh()
  }
}

function handleDecompileState(state: TaskResultState): void {
  decompileResultState.value = state
}

function handleDecompileCompleted(request: FileDecompileRequest): void {
  if (request.task_id !== props.taskId) return
  const wasActive = activeResultTab.value === 'decompile'
  activeResultTab.value = 'decompile'
  if (wasActive) {
    void nextTick(() => liveDecompileResult.value?.refresh())
  }
  void nextTick(() => decompileProjectPanel.value?.refresh?.())
}

function handleDecompileProjectDeleted(): void {
  void nextTick(() => liveDecompileResult.value?.refresh())
  void nextTick(() => liveCAnalysisResult.value?.refresh())
  void nextTick(() => liveJavaAnalysisResult.value?.refresh())
}

function handleCAnalysisState(state: TaskResultState): void {
  cAnalysisResultState.value = state
}

function handleCAnalysisBusy(busy: boolean): void {
  cAnalysisBusy.value = busy
}

async function openCAnalysisSource(resultId: string): Promise<void> {
  activeResultTab.value = 'decompile'
  await nextTick()
  await liveDecompileResult.value?.openResult(resultId)
}

async function startCAnalysisProject(projectId: string): Promise<void> {
  pendingCAnalysisProjectId.value = projectId
  activeDetailTab.value = 'results'
  activeResultTab.value = 'c-analysis'
  await nextTick()
  await startPendingCAnalysisProject()
}

async function startPendingCAnalysisProject(): Promise<void> {
  const workspace = liveCAnalysisResult.value
  const projectId = pendingCAnalysisProjectId.value
  if (!workspace || !projectId) return
  pendingCAnalysisProjectId.value = ''
  await workspace.startProject(projectId)
}

watch(liveCAnalysisResult, () => {
  void startPendingCAnalysisProject()
})

function handleJavaAnalysisState(state: TaskResultState): void {
  javaAnalysisResultState.value = state
}

function handleJavaAnalysisBusy(busy: boolean): void {
  javaAnalysisBusy.value = busy
}

async function openJavaAnalysisSource(resultId: string): Promise<void> {
  activeResultTab.value = 'decompile'
  await nextTick()
  await liveDecompileResult.value?.openResult(resultId)
}

async function startJavaAnalysisProject(projectId: string): Promise<void> {
  if (javaAnalysisBusy.value) return
  pendingJavaAnalysisProject.value = { taskId: props.taskId, projectId }
  activeDetailTab.value = 'results'
  activeResultTab.value = 'java-analysis'
  await nextTick()
  await startPendingJavaAnalysisProject()
}

async function startPendingJavaAnalysisProject(): Promise<void> {
  const workspace = liveJavaAnalysisResult.value
  const pending = pendingJavaAnalysisProject.value
  if (!pending) return
  if (pending.taskId !== props.taskId) {
    pendingJavaAnalysisProject.value = undefined
    return
  }
  if (!workspace) return
  pendingJavaAnalysisProject.value = undefined
  await workspace.startProject(pending.projectId)
}

watch(liveJavaAnalysisResult, () => {
  void startPendingJavaAnalysisProject()
})

function openAnalysisFiles(): void {
  activeDetailTab.value = 'results'
  activeResultTab.value = 'files'
}

function openVulnerabilityResults(): void {
  activeDetailTab.value = 'results'
  activeResultTab.value = 'vulnerabilities'
}

function handleVulnerabilityState(state: TaskResultState): void {
  vulnerabilityResultState.value = state
}

function handleReportState(state: TaskResultState): void {
  reportResultState.value = state
}
</script>

<template>
  <StatePanel v-if="loading" class="surface-panel" kind="loading" />
  <StatePanel
    v-else-if="errorMessage"
    class="surface-panel"
    kind="error"
    :description="errorMessage"
    retryable
    @retry="load"
  />
  <div v-else-if="task" class="task-detail">
    <div
      v-if="lifecycleActions.feedbackMessage.value"
      class="action-feedback"
      role="status"
      aria-live="polite"
    >
      <span>{{ lifecycleActions.feedbackMessage.value }}</span>
      <el-button
        v-if="taskDeleting"
        text
        :icon="ArrowLeft"
        @click="emit('returnList')"
      >
        返回任务列表
      </el-button>
    </div>

    <p
      v-if="lifecycleActions.errorMessage.value"
      class="action-error"
      role="alert"
    >
      {{ lifecycleActions.errorMessage.value }}
    </p>

    <TaskAnalysisActions
      :task="task"
      :node="analysisTarget"
      :user-role="session.user?.role ?? null"
      :mode="actionMode"
      :sample-retention="sampleRetention"
      @open-files="openAnalysisFiles"
      @open-vulnerabilities="openVulnerabilityResults"
      @decompile-completed="handleDecompileCompleted"
    />

    <TaskDetailTabs v-model:active-tab="activeDetailTab">
      <template #progress>
        <TaskStageProgress :task="task" :entries="executionLogEntries" />

        <section v-if="task.error_message" class="error-band">
          <ShieldAlert :size="18" />
          <div>
            <strong>{{ task.error_code || 'TASK_ERROR' }}</strong>
            <span>{{ task.error_message }}</span>
          </div>
        </section>

        <TaskExecutionLog
          v-if="!isDemoMode"
          :entries="executionLogEntries"
          :connection-status="taskEvents.status.value"
          :connection-label="taskEventStatusLabel"
          :connection-title="taskEventStatusTitle"
        />
      </template>

      <template #results>
        <section v-if="partialResult" class="partial-band" role="status">
          <AlertTriangle :size="18" />
          <div>
            <strong>检测结果不完整</strong>
            <span>部分内容因安全限制、文件损坏或格式暂不支持而未完成处理。</span>
          </div>
        </section>

        <section v-if="sampleDeleted" class="expired-band" role="status">
          <TimerReset :size="18" />
          <div>
            <strong>任务原始样本已清理</strong>
            <span>该任务已不再保留可复用样本；不能重新检测或发起新的反编译。已保存的文件、反编译历史和报告仍可查看。</span>
          </div>
        </section>

        <section v-else-if="sampleExpired" class="expired-band" role="status">
          <TimerReset :size="18" />
          <div>
            <strong>样本保留期已到</strong>
            <span>等待后台清理；不能重新检测或发起新的反编译。已保存的文件、反编译历史和报告仍可查看。</span>
          </div>
        </section>

        <TaskResultTabs
          v-model:active-tab="activeResultTab"
          :task-id="task.id"
          :mode="isDemoMode ? 'preview' : 'live'"
          :states="deferredResultStates"
          :commands="resultCommands"
          :visible-tabs="visibleResultTabs"
          :managed-tabs="
            isDemoMode
              ? []
              : ['decompile', 'c-analysis', 'java-analysis', 'vulnerabilities', 'reports']
          "
          @command="handleResultCommand"
        >
          <template #files="{ taskId: resultTaskId }">
            <FileTreePanel
              :task-id="resultTaskId"
              :sample-retention="sampleRetention"
              @node-detail-change="analysisTarget = $event"
            />
          </template>
          <template #decompile>
            <div class="retained-result">
              <SampleRetentionNotice
                v-if="!sampleRetention.canReuseSample"
                :retention="sampleRetention"
                history-label="反编译历史结果"
              />
              <DemoDecompileResult
                v-if="isDemoMode"
                :task-id="task.id"
                :task-name="task.original_filename || task.name"
                :input-type="task.input_type"
              />
              <LiveDecompileResult
                v-else
                ref="liveDecompileResult"
                :task-id="task.id"
                @state-change="handleDecompileState"
              />
            </div>
          </template>
          <template #c-analysis>
            <LiveCAnalysisResult
              v-if="!isDemoMode"
              ref="liveCAnalysisResult"
              :task-id="task.id"
              :user-role="session.user?.role ?? null"
              @busy-change="handleCAnalysisBusy"
              @state-change="handleCAnalysisState"
              @open-source="openCAnalysisSource"
            />
          </template>
          <template #java-analysis>
            <LiveJavaAnalysisResult
              v-if="!isDemoMode"
              ref="liveJavaAnalysisResult"
              :task-id="task.id"
              :user-role="session.user?.role ?? null"
              @busy-change="handleJavaAnalysisBusy"
              @state-change="handleJavaAnalysisState"
              @open-source="openJavaAnalysisSource"
            />
          </template>
          <template #vulnerabilities>
            <DemoVulnerabilityResult
              v-if="isDemoMode"
              :task-id="task.id"
              :task-name="task.original_filename || task.name"
            />
            <LiveVulnerabilityResult
              v-else
              ref="liveVulnerabilityResult"
              :task-id="task.id"
              @state-change="handleVulnerabilityState"
            />
          </template>
          <template #reports>
            <DemoReportResult
              v-if="isDemoMode"
              :task-id="task.id"
              :task-name="task.original_filename || task.name"
              :input-type="task.input_type"
              :task-status="task.status"
            />
            <LiveReportResult
              v-else
              ref="liveReportResult"
              :task-id="task.id"
              :task-status="task.status"
              :user-role="session.user?.role ?? null"
              @state-change="handleReportState"
            />
          </template>
        </TaskResultTabs>
      </template>

      <template #information>
        <TaskActionBar
          :task="task"
          :mode="actionMode"
          :user-role="session.user?.role ?? null"
          :is-creator="isCreator"
          :now="sampleClock.now.value"
          :pending-action="lifecycleActions.pendingAction.value"
          @cancel="handleCancel"
          @retry="handleRetry"
          @delete="handleDelete"
          @extend="handleExtend"
        />

        <div class="detail-grid">
          <section class="detail-section surface-panel">
            <header><FileCode2 :size="17" /><h2>输入信息</h2></header>
            <dl>
              <div><dt>文件名</dt><dd>{{ task.original_filename || task.name }}</dd></div>
              <div><dt>输入类型</dt><dd>{{ task.input_type }}</dd></div>
              <div><dt>文件大小</dt><dd>{{ formatBytes(task.size_bytes) }}</dd></div>
              <div><dt>SHA-256</dt><dd class="mono hash">{{ task.sha256 || '—' }}</dd></div>
            </dl>
          </section>

          <section class="detail-section surface-panel">
            <header><TimerReset :size="17" /><h2>任务记录</h2></header>
            <dl>
              <div><dt>任务编号</dt><dd class="mono">{{ task.id }}</dd></div>
              <div><dt>创建者</dt><dd>{{ task.creator_name }}</dd></div>
              <div><dt>创建时间</dt><dd>{{ formatDateTime(task.created_at) }}</dd></div>
              <div><dt>样本到期</dt><dd>{{ formatDateTime(task.sample_expires_at) }}</dd></div>
              <div v-if="task.sample_deleted_at">
                <dt>样本删除</dt>
                <dd>{{ formatDateTime(task.sample_deleted_at) }}</dd>
              </div>
            </dl>
          </section>
        </div>

        <DecompileProjectPanel
          v-if="!isDemoMode"
          ref="decompileProjectPanel"
          :task-id="task.id"
          :user-role="session.user?.role ?? null"
          :enabled="activeDetailTab === 'information'"
          @deleted="handleDecompileProjectDeleted"
          @analyze="startCAnalysisProject"
          @analyze-java="startJavaAnalysisProject"
        />
      </template>
    </TaskDetailTabs>
  </div>
</template>

<style scoped>
.task-detail {
  display: grid;
  gap: 16px;
  container-type: inline-size;
}

.retained-result {
  min-width: 0;
}

.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.detail-section header {
  display: flex;
  min-height: 48px;
  align-items: center;
  gap: 8px;
  padding: 0 16px;
  border-bottom: 1px solid var(--line);
  color: var(--teal-strong);
}

.detail-section h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
}

.detail-section dl {
  margin: 0;
}

.detail-section dl div {
  display: grid;
  min-height: 44px;
  grid-template-columns: 110px minmax(0, 1fr);
  align-items: center;
  padding: 8px 16px;
  border-bottom: 1px solid #e8ebec;
}

.detail-section dl div:last-child {
  border-bottom: 0;
}

.detail-section dt {
  color: var(--ink-600);
  font-size: 11px;
}

.detail-section dd {
  min-width: 0;
  margin: 0;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hash {
  font-size: 10px !important;
}

.error-band {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 13px 15px;
  border: 1px solid #e3bcbc;
  border-left: 3px solid var(--red);
  border-radius: 4px;
  color: var(--red);
  background: #fff5f5;
}

.partial-band {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 13px 15px;
  border: 1px solid #d9c992;
  border-left: 3px solid #a87913;
  border-radius: 4px;
  color: #7c5b12;
  background: #fffaf0;
}

.expired-band {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 13px 15px;
  border: 1px solid #c8ced0;
  border-left: 3px solid var(--ink-600);
  border-radius: 4px;
  color: var(--ink-800);
  background: #f7f9f9;
}

.expired-band strong,
.expired-band span {
  display: block;
}

.expired-band strong {
  font-size: 11px;
}

.expired-band span {
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 12px;
}

.action-feedback {
  display: flex;
  min-height: 38px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 12px;
  border-left: 3px solid var(--teal);
  color: var(--ink-800);
  background: #eef8f6;
  font-size: 11px;
}

.action-error {
  margin: 0;
  padding: 9px 12px;
  border-left: 3px solid var(--red);
  color: #7e3030;
  background: #fff2f2;
  font-size: 11px;
}

.partial-band strong,
.partial-band span {
  display: block;
}

.partial-band strong {
  color: #5f450e;
  font-size: 11px;
}

.partial-band span {
  margin-top: 4px;
  color: #725c2b;
  font-size: 12px;
}

.error-band strong,
.error-band span {
  display: block;
}

.error-band strong {
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 11px;
}

.error-band span {
  margin-top: 4px;
  color: #7e4040;
  font-size: 12px;
}

@container (max-width: 620px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }
}
</style>
