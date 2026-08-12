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
  CAnalysisRun,
  JavaAnalysisRun,
  ConfirmDecompileProjectDeletionInput,
  DecompileProject,
  DecompileProjectDeletionOperation,
  DecompileProjectDeletionPreview,
  UserRole,
} from '@/api/types'

interface UseDecompileProjectsOptions {
  taskId: MaybeRefOrGetter<string>
  userRole: MaybeRefOrGetter<UserRole | null>
  enabled?: MaybeRefOrGetter<boolean>
}

const PAGE_SIZE = 100
const BLOB_URL_RELEASE_DELAY_MS = 30_000
const DELETION_POLL_INTERVAL_MS = 2_000
const DELETION_POLL_MAX_BACKOFF_MS = 15_000

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError || error instanceof Error) return error.message
  return fallback
}

export function useDecompileProjects(options: UseDecompileProjectsOptions) {
  const projects = shallowRef<readonly DecompileProject[]>([])
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const operationError = shallowRef('')
  const deletionPollError = shallowRef('')
  const nextCursor = shallowRef('')
  const deletingProjectId = shallowRef('')
  const previewingProjectId = shallowRef('')
  const downloadingProjectId = shallowRef('')
  const deletionOperations = shallowRef<
    Readonly<Record<string, DecompileProjectDeletionOperation>>
  >({})
  const latestCAnalysisByProject = shallowRef<
    Readonly<Record<string, CAnalysisRun>>
  >({})
  const latestJavaAnalysisByProject = shallowRef<
    Readonly<Record<string, JavaAnalysisRun>>
  >({})
  const blobReleaseTimers = new Map<
    string,
    ReturnType<typeof globalThis.setTimeout>
  >()
  const deletionPollTimers = new Map<
    string,
    ReturnType<typeof globalThis.setTimeout>
  >()
  const deletionPollFailures = new Map<string, number>()
  let scopeGeneration = 0
  let listGeneration = 0

  const canDelete = computed(() => {
    const role = toValue(options.userRole)
    return role === 'administrator' || role === 'operator'
  })
  const hasMore = computed(() => nextCursor.value !== '')
  const latestDeletionOperation = computed(() => {
    const values = Object.values(deletionOperations.value)
    return (
      [...values].reverse().find(({ status }) => status !== 'complete') ??
      values[values.length - 1] ??
      null
    )
  })
  const activeDeletionOperationCount = computed(
    () =>
      Object.values(deletionOperations.value).filter(
        ({ status }) => status !== 'complete',
      ).length,
  )

  function isEnabled(): boolean {
    return options.enabled === undefined || toValue(options.enabled)
  }

  function reset(): void {
    listGeneration += 1
    projects.value = []
    loading.value = false
    loadingMore.value = false
    error.value = ''
    errorCode.value = ''
    operationError.value = ''
    deletionPollError.value = ''
    nextCursor.value = ''
    deletingProjectId.value = ''
    previewingProjectId.value = ''
    downloadingProjectId.value = ''
    deletionOperations.value = {}
    latestCAnalysisByProject.value = {}
    latestJavaAnalysisByProject.value = {}
    for (const timer of deletionPollTimers.values()) {
      globalThis.clearTimeout(timer)
    }
    deletionPollTimers.clear()
    deletionPollFailures.clear()
  }

  function rememberDeletionOperation(
    operation: DecompileProjectDeletionOperation,
  ): void {
    deletionOperations.value = {
      ...deletionOperations.value,
      [operation.id]: operation,
    }
  }

  function scheduleDeletionPoll(
    taskId: string,
    operationId: string,
    currentScope: number,
    delay = DELETION_POLL_INTERVAL_MS,
  ): void {
    const existing = deletionPollTimers.get(operationId)
    if (existing !== undefined) globalThis.clearTimeout(existing)
    const timer = globalThis.setTimeout(() => {
      deletionPollTimers.delete(operationId)
      void pollDeletionOperation(taskId, operationId, currentScope)
    }, delay)
    deletionPollTimers.set(operationId, timer)
  }

  async function pollDeletionOperation(
    taskId: string,
    operationId: string,
    currentScope: number,
  ): Promise<void> {
    try {
      const operation = await api.getDecompileProjectDeletion(taskId, operationId)
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      deletionPollFailures.delete(operationId)
      deletionPollError.value = ''
      rememberDeletionOperation(operation)
      if (operation.status !== 'complete') {
        scheduleDeletionPoll(taskId, operationId, currentScope)
      }
    } catch (caught) {
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      const failures = (deletionPollFailures.get(operationId) ?? 0) + 1
      deletionPollFailures.set(operationId, failures)
      deletionPollError.value = `读取源码清理进度失败，正在重试：${errorMessage(caught, '未知错误')}`
      scheduleDeletionPoll(
        taskId,
        operationId,
        currentScope,
        Math.min(
          DELETION_POLL_INTERVAL_MS * 2 ** Math.min(failures, 3),
          DELETION_POLL_MAX_BACKOFF_MS,
        ),
      )
    }
  }

  async function loadLatestCAnalysis(
    taskId: string,
    currentScope: number,
  ): Promise<void> {
    const latest: Record<string, CAnalysisRun> = {}
    let cursor = ''
    try {
      do {
        const page = await api.listCAnalysisRuns(taskId, {
          page_size: 200,
          ...(cursor ? { cursor } : {}),
        })
        if (
          currentScope !== scopeGeneration ||
          taskId !== toValue(options.taskId) ||
          !isEnabled()
        ) {
          return
        }
        for (const run of page.items) {
          latest[run.source_project_id] ??= run
        }
        cursor = page.next_cursor ?? ''
      } while (cursor && Object.keys(latest).length < 1_000)
      latestCAnalysisByProject.value = latest
    } catch {
      if (currentScope === scopeGeneration) {
        latestCAnalysisByProject.value = {}
      }
    }
  }

  async function loadLatestJavaAnalysis(
    taskId: string,
    currentScope: number,
  ): Promise<void> {
    const latest: Record<string, JavaAnalysisRun> = {}
    let cursor = ''
    try {
      do {
        const page = await api.listJavaAnalysisRuns(taskId, {
          page_size: 200,
          ...(cursor ? { cursor } : {}),
        })
        if (
          currentScope !== scopeGeneration ||
          taskId !== toValue(options.taskId) ||
          !isEnabled()
        ) {
          return
        }
        for (const run of page.items) {
          latest[run.source_project_id] ??= run
        }
        cursor = page.next_cursor ?? ''
      } while (cursor && Object.keys(latest).length < 1_000)
      latestJavaAnalysisByProject.value = latest
    } catch {
      if (currentScope === scopeGeneration) {
        latestJavaAnalysisByProject.value = {}
      }
    }
  }

  async function load(append = false): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || !isEnabled()) return
    if (append && (!nextCursor.value || loadingMore.value)) return

    const currentScope = scopeGeneration
    const requestGeneration = ++listGeneration
    const cursor = append ? nextCursor.value : ''
    if (append) {
      loadingMore.value = true
    } else {
      loading.value = true
      error.value = ''
      errorCode.value = ''
      operationError.value = ''
    }

    try {
      const page = await api.listDecompileProjects(taskId, {
        page_size: PAGE_SIZE,
        ...(cursor ? { cursor } : {}),
      })
      if (
        currentScope !== scopeGeneration ||
        requestGeneration !== listGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      projects.value = append
        ? [
            ...projects.value,
            ...page.items.filter(
              (item) =>
                !projects.value.some((current) => current.id === item.id),
            ),
          ]
        : page.items
      nextCursor.value = page.next_cursor ?? ''
      void loadLatestCAnalysis(taskId, currentScope)
      void loadLatestJavaAnalysis(taskId, currentScope)
    } catch (caught) {
      if (
        currentScope !== scopeGeneration ||
        requestGeneration !== listGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      if (append) {
        operationError.value = `加载更多源码项目失败：${errorMessage(caught, '未知错误')}`
      } else {
        projects.value = []
        nextCursor.value = ''
        error.value = errorMessage(caught, '反编译源码项目读取失败')
        errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
      }
    } finally {
      if (
        currentScope === scopeGeneration &&
        requestGeneration === listGeneration
      ) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  function clearOperationError(): void {
    operationError.value = ''
  }

  function clearDeletionPollError(): void {
    deletionPollError.value = ''
  }

  function clickDownload(url: string, filename?: string): void {
    if (typeof document === 'undefined') {
      throw new Error('当前浏览器不支持源码项目下载')
    }
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename ?? ''
    anchor.rel = 'noopener'
    anchor.style.display = 'none'
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
  }

  function scheduleBlobRelease(objectUrl: string): void {
    const timer = globalThis.setTimeout(() => {
      blobReleaseTimers.delete(objectUrl)
      URL.revokeObjectURL(objectUrl)
    }, BLOB_URL_RELEASE_DELAY_MS)
    blobReleaseTimers.set(objectUrl, timer)
  }

  async function downloadProject(projectId: string): Promise<void> {
    const taskId = toValue(options.taskId)
    const project = projects.value.find((item) => item.id === projectId)
    if (
      !taskId ||
      !isEnabled() ||
      !project ||
      project.task_id !== taskId ||
      downloadingProjectId.value ||
      deletingProjectId.value === projectId
    ) {
      return
    }

    const currentScope = scopeGeneration
    downloadingProjectId.value = projectId
    operationError.value = ''
    try {
      const result = await api.downloadDecompileProject(taskId, projectId)
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return
      }
      if (result.kind === 'url') {
        if (typeof window === 'undefined') {
          throw new Error('当前浏览器不支持源码项目下载')
        }
        const target = new URL(result.url, window.location.href)
        if (
          target.origin !== window.location.origin ||
          target.username ||
          target.password
        ) {
          throw new Error('源码项目下载地址不是安全的同源地址')
        }
        clickDownload(target.href)
        return
      }
      if (typeof URL.createObjectURL !== 'function') {
        throw new Error('当前浏览器不支持源码项目下载')
      }
      const objectUrl = URL.createObjectURL(result.blob)
      scheduleBlobRelease(objectUrl)
      clickDownload(objectUrl, `binaryscan-source-project-${projectId}.zip`)
    } catch (caught) {
      if (
        currentScope === scopeGeneration &&
        taskId === toValue(options.taskId)
      ) {
        operationError.value = `下载源码项目失败：${errorMessage(caught, '未知错误')}`
      }
    } finally {
      if (currentScope === scopeGeneration) downloadingProjectId.value = ''
    }
  }

  async function previewProjectDeletion(
    projectId: string,
  ): Promise<DecompileProjectDeletionPreview | undefined> {
    const taskId = toValue(options.taskId)
    const project = projects.value.find((item) => item.id === projectId)
    if (
      !taskId ||
      !isEnabled() ||
      !canDelete.value ||
      !project ||
      project.task_id !== taskId ||
      previewingProjectId.value ||
      deletingProjectId.value
    ) {
      return undefined
    }
    const currentScope = scopeGeneration
    previewingProjectId.value = projectId
    operationError.value = ''
    try {
      const preview = await api.previewDecompileProjectDeletion(taskId, projectId)
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return undefined
      }
      return preview
    } catch (caught) {
      if (currentScope === scopeGeneration) {
        operationError.value = `读取删除影响范围失败：${errorMessage(caught, '未知错误')}`
      }
      return undefined
    } finally {
      if (currentScope === scopeGeneration) previewingProjectId.value = ''
    }
  }

  async function deleteProject(
    projectId: string,
    input: ConfirmDecompileProjectDeletionInput,
  ): Promise<DecompileProjectDeletionOperation | undefined> {
    const taskId = toValue(options.taskId)
    const project = projects.value.find((item) => item.id === projectId)
    if (
      !taskId ||
      !isEnabled() ||
      !canDelete.value ||
      !project ||
      project.task_id !== taskId ||
      deletingProjectId.value ||
      downloadingProjectId.value === projectId
    ) {
      return undefined
    }

    const currentScope = scopeGeneration
    deletingProjectId.value = projectId
    operationError.value = ''
    try {
      const operation = await api.confirmDecompileProjectDeletion(
        taskId,
        projectId,
        input,
      )
      if (
        currentScope !== scopeGeneration ||
        taskId !== toValue(options.taskId) ||
        !isEnabled()
      ) {
        return undefined
      }
      rememberDeletionOperation(operation)
      projects.value = projects.value.filter((item) => item.id !== projectId)
      if (operation.status !== 'complete') {
        scheduleDeletionPoll(taskId, operation.id, currentScope)
      }
      return operation
    } catch (caught) {
      if (
        currentScope === scopeGeneration &&
        taskId === toValue(options.taskId)
      ) {
        operationError.value = `删除源码项目失败：${errorMessage(caught, '未知错误')}`
      }
      return undefined
    } finally {
      if (currentScope === scopeGeneration) deletingProjectId.value = ''
    }
  }

  function refresh(): void {
    if (!isEnabled()) return
    void load()
  }

  function loadMore(): void {
    void load(true)
  }

  watch(
    [
      () => toValue(options.taskId),
      () => isEnabled(),
    ],
    ([taskId, enabled]) => {
      scopeGeneration += 1
      reset()
      if (taskId && enabled) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    scopeGeneration += 1
    reset()
    for (const [objectUrl, timer] of blobReleaseTimers) {
      globalThis.clearTimeout(timer)
      URL.revokeObjectURL(objectUrl)
    }
    blobReleaseTimers.clear()
  })

  return {
    projects: readonly(projects),
    loading: readonly(loading),
    loadingMore: readonly(loadingMore),
    error: readonly(error),
    errorCode: readonly(errorCode),
    operationError: readonly(operationError),
    deletionPollError: readonly(deletionPollError),
    deletingProjectId: readonly(deletingProjectId),
    previewingProjectId: readonly(previewingProjectId),
    downloadingProjectId: readonly(downloadingProjectId),
    deletionOperations: readonly(deletionOperations),
    latestDeletionOperation,
    activeDeletionOperationCount,
    latestCAnalysisByProject: readonly(latestCAnalysisByProject),
    latestJavaAnalysisByProject: readonly(latestJavaAnalysisByProject),
    canDelete,
    hasMore,
    clearOperationError,
    clearDeletionPollError,
    refresh,
    loadMore,
    downloadProject,
    previewProjectDeletion,
    deleteProject,
  }
}
