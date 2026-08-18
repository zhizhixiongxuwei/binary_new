import {
  computed,
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  PythonAnalysisFinding,
  PythonAnalysisRun,
  PythonAnalysisSeverity,
  DecompileProject,
  UserRole,
} from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'

interface UsePythonAnalysisOptions {
  taskId: MaybeRefOrGetter<string>
  userRole: MaybeRefOrGetter<UserRole | null>
  enabled?: MaybeRefOrGetter<boolean>
}

export interface PythonAnalysisFilters {
  cwe: string
  severity?: PythonAnalysisSeverity
  file: string
  callable: string
}

const PROJECT_PAGE_SIZE = 100
const RUN_PAGE_SIZE = 100
const FINDING_PAGE_SIZE = 100
const MAX_SELECTOR_ITEMS = 1_000
const POLL_INTERVAL_MS = 2_000
const terminalStatuses = new Set([
  'succeeded',
  'partial',
  'failed',
  'cancelled',
])

function messageFor(error: unknown, fallback: string): string {
  return error instanceof ApiError || error instanceof Error
    ? error.message
    : fallback
}

function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `python-analysis-${crypto.randomUUID()}`
  }
  return `python-analysis-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function eligibleProject(project: DecompileProject): boolean {
  return (
    project.layout_version === 'project-v1' &&
    project.manifest_available &&
    project.source_kind === 'python' &&
    (project.language === 'python' || project.language === 'mixed') &&
    (project.status === 'complete' || project.status === 'partial')
  )
}

export function usePythonAnalysis(options: UsePythonAnalysisOptions) {
  const projects = shallowRef<readonly DecompileProject[]>([])
  const runs = shallowRef<readonly PythonAnalysisRun[]>([])
  const findings = shallowRef<readonly PythonAnalysisFinding[]>([])
  const selectedProjectId = shallowRef('')
  const selectedRunId = shallowRef('')
  const selectedFinding = shallowRef<PythonAnalysisFinding>()
  const nextFindingCursor = shallowRef('')
  const filters = shallowRef<PythonAnalysisFilters>({
    cwe: '',
    file: '',
    callable: '',
  })
  const loading = shallowRef(false)
  const findingsLoading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const creating = shallowRef(false)
  const cancelling = shallowRef(false)
  const deleting = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const operationError = shallowRef('')
  let generation = 0
  let findingGeneration = 0
  let createRequestContext:
    | { taskId: string; projectId: string; key: string }
    | undefined
  let createSequence = 0
  let cancelSequence = 0
  let deleteSequence = 0
  let pollErrorMessage = ''
  let pollTimer: ReturnType<typeof globalThis.setTimeout> | undefined

  const canOperate = computed(() => {
    const role = toValue(options.userRole)
    return role === 'administrator' || role === 'operator'
  })
  const busy = computed(
    () => creating.value || cancelling.value || deleting.value,
  )
  const selectedProject = computed(() =>
    projects.value.find((project) => project.id === selectedProjectId.value),
  )
  const selectedRun = computed(() =>
    runs.value.find((run) => run.id === selectedRunId.value),
  )
  const activeRun = computed(() =>
    runs.value.find((run) =>
      ['queued', 'running', 'cancel_requested'].includes(run.status),
    ),
  )
  const canCreate = computed(
    () =>
      canOperate.value &&
      Boolean(selectedProject.value) &&
      !activeRun.value &&
      !busy.value,
  )
  const canCancel = computed(
    () =>
      canOperate.value &&
      Boolean(
        selectedRun.value &&
          ['queued', 'running', 'cancel_requested'].includes(
            selectedRun.value.status,
          ),
      ) &&
      !busy.value,
  )
  const canDeleteRun = computed(
    () =>
      canOperate.value &&
      Boolean(
        selectedRun.value && terminalStatuses.has(selectedRun.value.status),
      ) &&
      !busy.value,
  )
  const hasMoreFindings = computed(() => nextFindingCursor.value !== '')
  const state = computed<TaskResultState>(() => {
    if (loading.value) {
      return {
        status: 'loading',
        title: '正在读取 Python 源码检测',
        description: '正在加载可检测的 Python 源码项目和历史运行。',
      }
    }
    if (error.value) {
      return {
        status: 'error',
        title: 'Python 源码检测读取失败',
        description: error.value,
        ...(errorCode.value ? { errorCode: errorCode.value } : {}),
      }
    }
    if (projects.value.length === 0) {
      return {
        status: 'empty',
        title: '暂无可检测的 Python 源码项目',
        description: '请先完成 PYC 反编译并保存 project-v1 源码项目。',
      }
    }
    return { status: 'ready' }
  })

  function enabled(): boolean {
    return options.enabled === undefined || toValue(options.enabled)
  }

  function clearPoll(): void {
    if (pollTimer === undefined) return
    globalThis.clearTimeout(pollTimer)
    pollTimer = undefined
  }

  function schedulePoll(): void {
    clearPoll()
    if (!enabled() || !activeRun.value) return
    pollTimer = globalThis.setTimeout(() => {
      pollTimer = undefined
      void pollActiveRun()
    }, POLL_INTERVAL_MS)
  }

  function replaceRun(next: PythonAnalysisRun): void {
    const index = runs.value.findIndex((run) => run.id === next.id)
    runs.value = index < 0
      ? [next, ...runs.value]
      : runs.value.map((run) => (run.id === next.id ? next : run))
  }

  async function pollActiveRun(): Promise<void> {
    const taskId = toValue(options.taskId)
    const current = activeRun.value
    const currentGeneration = generation
    if (!taskId || !current || !enabled()) return
    try {
      const refreshed = await api.getPythonAnalysisRun(taskId, current.id)
      if (
        currentGeneration !== generation ||
        taskId !== toValue(options.taskId) ||
        !enabled()
      ) {
        return
      }
      if (operationError.value === pollErrorMessage) operationError.value = ''
      pollErrorMessage = ''
      replaceRun(refreshed)
      if (selectedRunId.value === refreshed.id && terminalStatuses.has(refreshed.status)) {
        void loadFindings()
      }
    } catch (caught) {
      if (currentGeneration === generation) {
        pollErrorMessage = `检测状态刷新失败：${messageFor(caught, '未知错误')}`
        operationError.value = pollErrorMessage
      }
    } finally {
      if (currentGeneration === generation) schedulePoll()
    }
  }

  async function listAllProjects(taskId: string): Promise<DecompileProject[]> {
    const result: DecompileProject[] = []
    let cursor = ''
    do {
      const page = await api.listDecompileProjects(taskId, {
        page_size: PROJECT_PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
      })
      result.push(...page.items.filter(eligibleProject))
      cursor = page.next_cursor ?? ''
    } while (cursor && result.length < MAX_SELECTOR_ITEMS)
    return result.slice(0, MAX_SELECTOR_ITEMS)
  }

  async function listAllRuns(
    taskId: string,
    projectId: string,
  ): Promise<PythonAnalysisRun[]> {
    const result: PythonAnalysisRun[] = []
    let cursor = ''
    do {
      const page = await api.listPythonAnalysisRuns(taskId, {
        project_id: projectId,
        page_size: RUN_PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
      })
      result.push(...page.items)
      cursor = page.next_cursor ?? ''
    } while (cursor && result.length < MAX_SELECTOR_ITEMS)
    return result.slice(0, MAX_SELECTOR_ITEMS)
  }

  async function load(): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || !enabled() || busy.value) return
    const currentGeneration = ++generation
    findingGeneration += 1
    clearPoll()
    loading.value = true
    error.value = ''
    errorCode.value = ''
    operationError.value = ''
    try {
      const preferredProjectId = selectedProjectId.value
      let loadedProjects = await listAllProjects(taskId)
      let preferredProjectMissing = false
      if (
        preferredProjectId &&
        !loadedProjects.some((project) => project.id === preferredProjectId)
      ) {
        let preferredProject: DecompileProject | undefined
        try {
          preferredProject = await api.getDecompileProject(taskId, preferredProjectId)
        } catch (caught) {
          if (!(caught instanceof ApiError) || caught.status !== 404) throw caught
          preferredProjectMissing = true
        }
        if (preferredProject) {
          if (
            preferredProject.task_id !== taskId ||
            !eligibleProject(preferredProject)
          ) {
            throw new Error('所选源码项目不支持 Python 检测')
          }
          loadedProjects = [
            preferredProject,
            ...loadedProjects.filter(
              (project) => project.id !== preferredProject.id,
            ),
          ].slice(0, MAX_SELECTOR_ITEMS)
        }
      }
      if (currentGeneration !== generation || taskId !== toValue(options.taskId)) {
        return
      }
      if (preferredProjectMissing) {
        selectedProjectId.value = ''
        selectedRunId.value = ''
        selectedFinding.value = undefined
      }
      projects.value = loadedProjects
      if (!loadedProjects.some((project) => project.id === selectedProjectId.value)) {
        selectedProjectId.value = loadedProjects[0]?.id ?? ''
      }
      const projectId = selectedProjectId.value
      const loadedRuns = projectId ? await listAllRuns(taskId, projectId) : []
      if (currentGeneration !== generation || taskId !== toValue(options.taskId)) {
        return
      }
      runs.value = loadedRuns
      if (!runs.value.some((run) => run.id === selectedRunId.value)) {
        selectedRunId.value = runs.value[0]?.id ?? ''
      }
      await loadFindings()
    } catch (caught) {
      if (currentGeneration !== generation || taskId !== toValue(options.taskId)) {
        return
      }
      error.value = messageFor(caught, 'Python 源码检测读取失败')
      errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
      projects.value = []
      runs.value = []
      findings.value = []
    } finally {
      if (currentGeneration === generation) {
        loading.value = false
        schedulePoll()
      }
    }
  }

  async function selectProject(projectId: string): Promise<void> {
    if (busy.value) return
    if (projectId === selectedProjectId.value) return
    createRequestContext = undefined
    selectedProjectId.value = projectId
    selectedRunId.value = ''
    runs.value = []
    findings.value = []
    await load()
  }

  async function selectRun(runId: string): Promise<void> {
    if (busy.value) return
    if (runId === selectedRunId.value) return
    selectedRunId.value = runId
    selectedFinding.value = undefined
    await loadFindings()
  }

  async function loadFindings(append = false): Promise<void> {
    const taskId = toValue(options.taskId)
    const run = selectedRun.value
    if (
      !taskId ||
      !run ||
      !['succeeded', 'partial'].includes(run.status) ||
      !enabled()
    ) {
      findings.value = []
      nextFindingCursor.value = ''
      selectedFinding.value = undefined
      return
    }
    if (append && (!nextFindingCursor.value || loadingMore.value)) return
    const requestGeneration = ++findingGeneration
    if (append) loadingMore.value = true
    else findingsLoading.value = true
    try {
      const activeFilters = filters.value
      const page = await api.listPythonAnalysisFindings(taskId, run.id, {
        page_size: FINDING_PAGE_SIZE,
        ...(append && nextFindingCursor.value
          ? { cursor: nextFindingCursor.value }
          : {}),
        ...(activeFilters.cwe ? { cwe: activeFilters.cwe } : {}),
        ...(activeFilters.severity
          ? { severity: activeFilters.severity }
          : {}),
        ...(activeFilters.file ? { file: activeFilters.file } : {}),
        ...(activeFilters.callable
          ? { callable: activeFilters.callable }
          : {}),
      })
      if (
        requestGeneration !== findingGeneration ||
        taskId !== toValue(options.taskId) ||
        run.id !== selectedRunId.value
      ) {
        return
      }
      findings.value = append ? [...findings.value, ...page.items] : page.items
      nextFindingCursor.value = page.next_cursor ?? ''
      if (
        selectedFinding.value &&
        !findings.value.some((finding) => finding.id === selectedFinding.value?.id)
      ) {
        selectedFinding.value = undefined
      }
    } catch (caught) {
      if (requestGeneration === findingGeneration) {
        operationError.value = `检测结果读取失败：${messageFor(caught, '未知错误')}`
        if (!append) findings.value = []
      }
    } finally {
      if (requestGeneration === findingGeneration) {
        findingsLoading.value = false
        loadingMore.value = false
      }
    }
  }

  function applyFilters(next: PythonAnalysisFilters): void {
    filters.value = {
      cwe: next.cwe.trim().toUpperCase(),
      ...(next.severity ? { severity: next.severity } : {}),
      file: next.file.trim(),
      callable: next.callable.trim(),
    }
    selectedFinding.value = undefined
    void loadFindings()
  }

  async function createRun(): Promise<void> {
    const taskId = toValue(options.taskId)
    const project = selectedProject.value
    if (!taskId || !project || !canCreate.value) return
    const currentGeneration = generation
    const requestSequence = ++createSequence
    creating.value = true
    operationError.value = ''
    if (
      !createRequestContext ||
      createRequestContext.taskId !== taskId ||
      createRequestContext.projectId !== project.id
    ) {
      createRequestContext = {
        taskId,
        projectId: project.id,
        key: newIdempotencyKey(),
      }
    }
    const requestContext = createRequestContext
    try {
      const run = await api.createPythonAnalysisRun(
        taskId,
        project.id,
        requestContext.key,
      )
      if (createRequestContext?.key === requestContext.key) {
        createRequestContext = undefined
      }
      if (
        currentGeneration !== generation ||
        taskId !== toValue(options.taskId) ||
        project.id !== selectedProjectId.value
      ) {
        return
      }
      if (run.task_id !== taskId || run.source_project_id !== project.id) {
        operationError.value = '创建检测失败：服务返回了不匹配的检测版本'
        return
      }
      replaceRun(run)
      selectedRunId.value = run.id
      findings.value = []
      selectedFinding.value = undefined
      schedulePoll()
    } catch (caught) {
      if (
        caught instanceof ApiError &&
        caught.status > 0 &&
        caught.status < 500 &&
        createRequestContext?.key === requestContext.key
      ) {
        createRequestContext = undefined
      }
      if (
        currentGeneration === generation &&
        taskId === toValue(options.taskId) &&
        project.id === selectedProjectId.value
      ) {
        operationError.value = `创建检测失败：${messageFor(caught, '未知错误')}`
      }
    } finally {
      if (requestSequence === createSequence) creating.value = false
    }
  }

  async function cancelRun(): Promise<void> {
    const taskId = toValue(options.taskId)
    const run = selectedRun.value
    if (!taskId || !run || !canCancel.value) return
    const projectId = selectedProjectId.value
    const currentGeneration = generation
    const requestSequence = ++cancelSequence
    cancelling.value = true
    operationError.value = ''
    try {
      const refreshed = await api.cancelPythonAnalysisRun(taskId, run.id)
      if (
        currentGeneration !== generation ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedProjectId.value ||
        run.id !== selectedRunId.value
      ) {
        return
      }
      if (
        refreshed.id !== run.id ||
        refreshed.task_id !== taskId ||
        refreshed.source_project_id !== projectId
      ) {
        operationError.value = '取消检测失败：服务返回了不匹配的检测版本'
        return
      }
      replaceRun(refreshed)
      schedulePoll()
    } catch (caught) {
      if (
        currentGeneration === generation &&
        taskId === toValue(options.taskId) &&
        projectId === selectedProjectId.value &&
        run.id === selectedRunId.value
      ) {
        operationError.value = `取消检测失败：${messageFor(caught, '未知错误')}`
      }
    } finally {
      if (requestSequence === cancelSequence) cancelling.value = false
    }
  }

  async function deleteRun(): Promise<boolean> {
    const taskId = toValue(options.taskId)
    const run = selectedRun.value
    if (!taskId || !run || !canDeleteRun.value) return false
    const projectId = selectedProjectId.value
    const currentGeneration = generation
    const requestSequence = ++deleteSequence
    deleting.value = true
    operationError.value = ''
    try {
      await api.deletePythonAnalysisRun(taskId, run.id)
      if (
        currentGeneration !== generation ||
        taskId !== toValue(options.taskId) ||
        projectId !== selectedProjectId.value ||
        run.id !== selectedRunId.value
      ) {
        return true
      }
      runs.value = runs.value.filter((candidate) => candidate.id !== run.id)
      selectedRunId.value = runs.value[0]?.id ?? ''
      selectedFinding.value = undefined
      await loadFindings()
      return true
    } catch (caught) {
      if (
        currentGeneration === generation &&
        taskId === toValue(options.taskId) &&
        projectId === selectedProjectId.value &&
        run.id === selectedRunId.value
      ) {
        operationError.value = `删除检测历史失败：${messageFor(caught, '未知错误')}`
      }
      return false
    } finally {
      if (requestSequence === deleteSequence) deleting.value = false
    }
  }

  function selectFinding(finding?: PythonAnalysisFinding): void {
    selectedFinding.value = finding
  }

  function clearOperationError(): void {
    operationError.value = ''
  }

  watch(
    [() => toValue(options.taskId), () => enabled()],
    ([taskId, isEnabled]) => {
      generation += 1
      findingGeneration += 1
      clearPoll()
      projects.value = []
      runs.value = []
      findings.value = []
      selectedProjectId.value = ''
      selectedRunId.value = ''
      selectedFinding.value = undefined
      nextFindingCursor.value = ''
      filters.value = { cwe: '', file: '', callable: '' }
      error.value = ''
      errorCode.value = ''
      operationError.value = ''
      pollErrorMessage = ''
      createSequence += 1
      cancelSequence += 1
      deleteSequence += 1
      creating.value = false
      cancelling.value = false
      deleting.value = false
      createRequestContext = undefined
      if (taskId && isEnabled) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    generation += 1
    findingGeneration += 1
    clearPoll()
  })

  return {
    projects: readonly(projects),
    runs: readonly(runs),
    findings: readonly(findings),
    selectedProjectId: readonly(selectedProjectId),
    selectedRunId: readonly(selectedRunId),
    selectedProject,
    selectedRun,
    activeRun,
    selectedFinding: readonly(selectedFinding),
    filters: readonly(filters),
    loading: readonly(loading),
    findingsLoading: readonly(findingsLoading),
    loadingMore: readonly(loadingMore),
    creating: readonly(creating),
    cancelling: readonly(cancelling),
    deleting: readonly(deleting),
    operationError: readonly(operationError),
    state,
    busy,
    canOperate,
    canCreate,
    canCancel,
    canDeleteRun,
    hasMoreFindings,
    refresh: load,
    selectProject,
    selectRun,
    selectFinding,
    applyFilters,
    loadMoreFindings: () => loadFindings(true),
    createRun,
    cancelRun,
    deleteRun,
    clearOperationError,
  }
}
