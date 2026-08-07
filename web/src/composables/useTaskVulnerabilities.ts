import { computed, onScopeDispose, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  VulnerabilityFinding,
  VulnerabilitySeverity,
  VulnerabilitySummary,
} from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'

const FINDING_PAGE_SIZE = 50

const EMPTY_SUMMARY: VulnerabilitySummary = {
  total: 0,
  fixable: 0,
  by_severity: {
    UNKNOWN: 0,
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  },
}

interface UseTaskVulnerabilitiesOptions {
  taskId: MaybeRefOrGetter<string>
  enabled?: MaybeRefOrGetter<boolean>
}

function messageFor(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

function emptySummary(): VulnerabilitySummary {
  return {
    ...EMPTY_SUMMARY,
    by_severity: { ...EMPTY_SUMMARY.by_severity },
  }
}

export function useTaskVulnerabilities(
  options: UseTaskVulnerabilitiesOptions,
) {
  const items = shallowRef<readonly VulnerabilityFinding[]>([])
  const summary = shallowRef<VulnerabilitySummary>(emptySummary())
  const severity = shallowRef<VulnerabilitySeverity>()
  const nextCursor = shallowRef<string>()
  const selectedFindingId = shallowRef('')
  const selectedFinding = shallowRef<VulnerabilityFinding>()
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const detailLoading = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const detailError = shallowRef('')
  let listGeneration = 0
  let detailGeneration = 0

  const state = computed<TaskResultState>(() => {
    if (loading.value) {
      return {
        status: 'loading',
        title: '正在读取容器漏洞结果',
        description: '正在加载严重等级汇总与漏洞明细。',
      }
    }
    if (error.value) {
      return {
        status: 'error',
        title: '容器漏洞结果读取失败',
        description: error.value,
        ...(errorCode.value ? { errorCode: errorCode.value } : {}),
      }
    }
    if (summary.value.total === 0) {
      return {
        status: 'empty',
        title: '未发现容器漏洞',
        description: '当前任务没有可展示的离线漏洞扫描发现。',
      }
    }
    return { status: 'ready' }
  })
  const hasMore = computed(() => Boolean(nextCursor.value))

  async function loadDetail(findingId: string): Promise<void> {
    const generation = ++detailGeneration
    const taskId = toValue(options.taskId)
    detailLoading.value = true
    detailError.value = ''
    try {
      const detail = await api.getTaskVulnerability(taskId, findingId)
      if (
        generation !== detailGeneration ||
        taskId !== toValue(options.taskId) ||
        findingId !== selectedFindingId.value
      ) {
        return
      }
      selectedFinding.value = detail
    } catch (caught) {
      if (
        generation !== detailGeneration ||
        taskId !== toValue(options.taskId) ||
        findingId !== selectedFindingId.value
      ) {
        return
      }
      detailError.value = messageFor(caught, '漏洞详情读取失败')
    } finally {
      if (generation === detailGeneration) detailLoading.value = false
    }
  }

  function selectFinding(findingId: string): void {
    selectedFindingId.value = findingId
    detailGeneration += 1
    detailError.value = ''
    selectedFinding.value = items.value.find((item) => item.id === findingId)
    if (findingId) void loadDetail(findingId)
  }

  async function load(append = false): Promise<void> {
    const taskId = toValue(options.taskId)
    if (!taskId || (options.enabled !== undefined && !toValue(options.enabled))) {
      return
    }
    if (append && (!nextCursor.value || loadingMore.value)) return

    const generation = ++listGeneration
    if (append) {
      loadingMore.value = true
    } else {
      loading.value = true
      error.value = ''
      errorCode.value = ''
      nextCursor.value = undefined
    }

    try {
      const page = await api.listTaskVulnerabilities(taskId, {
        page_size: FINDING_PAGE_SIZE,
        ...(severity.value ? { severity: severity.value } : {}),
        ...(append && nextCursor.value ? { cursor: nextCursor.value } : {}),
      })
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      summary.value = page.summary
      items.value = append ? [...items.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor

      const selectedStillExists = items.value.some(
        (item) => item.id === selectedFindingId.value,
      )
      if (!selectedStillExists) {
        const first = items.value[0]
        selectedFindingId.value = ''
        selectedFinding.value = undefined
        if (first) selectFinding(first.id)
      } else if (!append) {
        const refreshedFinding = items.value.find(
          (item) => item.id === selectedFindingId.value,
        )
        selectedFinding.value = refreshedFinding
        if (refreshedFinding) void loadDetail(refreshedFinding.id)
      }
    } catch (caught) {
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      error.value = messageFor(caught, '容器漏洞结果读取失败')
      errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
      if (!append) {
        items.value = []
        summary.value = emptySummary()
      }
    } finally {
      if (generation === listGeneration) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  function setSeverity(nextSeverity?: VulnerabilitySeverity): void {
    if (severity.value === nextSeverity) return
    severity.value = nextSeverity
    selectedFindingId.value = ''
    selectedFinding.value = undefined
    detailGeneration += 1
    void load()
  }

  function loadMore(): void {
    void load(true)
  }

  function refresh(): void {
    void load()
  }

  watch(
    [() => toValue(options.taskId), () => options.enabled === undefined || toValue(options.enabled)],
    ([taskId, enabled]) => {
      listGeneration += 1
      detailGeneration += 1
      items.value = []
      summary.value = emptySummary()
      severity.value = undefined
      nextCursor.value = undefined
      selectedFindingId.value = ''
      selectedFinding.value = undefined
      error.value = ''
      errorCode.value = ''
      detailError.value = ''
      loading.value = false
      loadingMore.value = false
      detailLoading.value = false
      if (taskId && enabled) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    listGeneration += 1
    detailGeneration += 1
  })

  return {
    items,
    summary,
    severity,
    selectedFindingId,
    selectedFinding,
    loading,
    loadingMore,
    detailLoading,
    detailError,
    state,
    hasMore,
    selectFinding,
    setSeverity,
    loadMore,
    refresh,
  }
}
