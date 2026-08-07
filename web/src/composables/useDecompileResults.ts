import { computed, onScopeDispose, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  DecompileResult,
  DecompileSourceChunk,
} from '@/api/types'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'

const RESULT_PAGE_SIZE = 100
const SOURCE_CHUNK_SIZE = 256 * 1024

interface UseDecompileResultsOptions {
  taskId: MaybeRefOrGetter<string>
  enabled?: MaybeRefOrGetter<boolean>
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof ApiError ? error.message : fallback
}

function supportsSource(result: DecompileResult | undefined): boolean {
  return Boolean(
    result &&
      !['queued', 'running', 'unsupported', 'failed', 'cancelled'].includes(
        result.status,
      ),
  )
}

export function useDecompileResults(options: UseDecompileResultsOptions) {
  const items = shallowRef<readonly DecompileResult[]>([])
  const nextCursor = shallowRef<string>()
  const selectedResultId = shallowRef('')
  const sourceChunk = shallowRef<DecompileSourceChunk>()
  const source = shallowRef('')
  const loading = shallowRef(false)
  const loadingMore = shallowRef(false)
  const sourceLoading = shallowRef(false)
  const error = shallowRef('')
  const errorCode = shallowRef('')
  const sourceError = shallowRef('')
  let listGeneration = 0
  let sourceGeneration = 0

  const selectedResult = computed(() =>
    items.value.find((item) => item.id === selectedResultId.value),
  )
  const hasMoreResults = computed(() => Boolean(nextCursor.value))
  const hasMoreSource = computed(
    () => Boolean(sourceChunk.value && !sourceChunk.value.complete),
  )
  const state = computed<TaskResultState>(() => {
    if (loading.value) {
      return {
        status: 'loading',
        title: '正在读取反编译结果',
        description: '正在加载符号索引和反编译能力状态。',
      }
    }
    if (error.value) {
      return {
        status: 'error',
        title: '反编译结果读取失败',
        description: error.value,
        ...(errorCode.value ? { errorCode: errorCode.value } : {}),
      }
    }
    if (items.value.length === 0) {
      return {
        status: 'empty',
        title: '暂无反编译结果',
        description: '分析器尚未产生可阅读的反编译单元。',
      }
    }
    return { status: 'ready' }
  })

  async function readSource(resultId: string, offset = 0): Promise<void> {
    const generation = ++sourceGeneration
    const taskId = toValue(options.taskId)
    const append = offset > 0
    sourceLoading.value = true
    sourceError.value = ''
    if (!append) {
      source.value = ''
      sourceChunk.value = undefined
    }

    try {
      const chunk = await api.getDecompileSource(taskId, resultId, {
        offset,
        limit: SOURCE_CHUNK_SIZE,
      })
      if (
        generation !== sourceGeneration ||
        taskId !== toValue(options.taskId) ||
        resultId !== selectedResultId.value
      ) {
        return
      }
      source.value = append ? `${source.value}${chunk.content}` : chunk.content
      sourceChunk.value = chunk
    } catch (caught) {
      if (
        generation !== sourceGeneration ||
        taskId !== toValue(options.taskId) ||
        resultId !== selectedResultId.value
      ) {
        return
      }
      sourceError.value = errorMessage(caught, '反编译源码读取失败')
    } finally {
      if (generation === sourceGeneration) sourceLoading.value = false
    }
  }

  function selectResult(resultId: string): void {
    if (selectedResultId.value === resultId && sourceChunk.value) return
    selectedResultId.value = resultId
    sourceGeneration += 1
    source.value = ''
    sourceChunk.value = undefined
    sourceError.value = ''
    const result = items.value.find((item) => item.id === resultId)
    if (supportsSource(result)) void readSource(resultId)
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
      const page = await api.listDecompileResults(taskId, {
        page_size: RESULT_PAGE_SIZE,
        ...(append && nextCursor.value ? { cursor: nextCursor.value } : {}),
      })
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      items.value = append ? [...items.value, ...page.items] : page.items
      nextCursor.value = page.next_cursor

      const selectedStillExists = items.value.some(
        (item) => item.id === selectedResultId.value,
      )
      if (!selectedStillExists) {
        const first = items.value[0]
        selectedResultId.value = ''
        source.value = ''
        sourceChunk.value = undefined
        if (first) selectResult(first.id)
      } else if (!append && selectedResultId.value) {
        void readSource(selectedResultId.value)
      }
    } catch (caught) {
      if (generation !== listGeneration || taskId !== toValue(options.taskId)) {
        return
      }
      error.value = errorMessage(caught, '反编译结果读取失败')
      errorCode.value = caught instanceof ApiError ? (caught.code ?? '') : ''
      if (!append) items.value = []
    } finally {
      if (generation === listGeneration) {
        loading.value = false
        loadingMore.value = false
      }
    }
  }

  function loadMoreResults(): void {
    void load(true)
  }

  function loadMoreSource(): void {
    const resultId = selectedResultId.value
    const nextOffset = sourceChunk.value?.next_offset
    if (!resultId || nextOffset === undefined || sourceLoading.value) return
    void readSource(resultId, nextOffset)
  }

  function refresh(): void {
    void load()
  }

  watch(
    [() => toValue(options.taskId), () => options.enabled === undefined || toValue(options.enabled)],
    ([taskId, enabled]) => {
      listGeneration += 1
      sourceGeneration += 1
      items.value = []
      selectedResultId.value = ''
      source.value = ''
      sourceChunk.value = undefined
      error.value = ''
      errorCode.value = ''
      sourceError.value = ''
      nextCursor.value = undefined
      loading.value = false
      loadingMore.value = false
      sourceLoading.value = false
      if (taskId && enabled) void load()
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    listGeneration += 1
    sourceGeneration += 1
  })

  return {
    items,
    selectedResult,
    selectedResultId,
    source,
    sourceChunk,
    loading,
    loadingMore,
    sourceLoading,
    sourceError,
    state,
    hasMoreResults,
    hasMoreSource,
    selectResult,
    loadMoreResults,
    loadMoreSource,
    refresh,
  }
}
