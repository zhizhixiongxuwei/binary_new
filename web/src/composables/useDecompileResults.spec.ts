import { flushPromises } from '@vue/test-utils'
import {
  effectScope,
  nextTick,
  shallowRef,
  type EffectScope,
} from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  DecompileResult,
  DecompileResultPage,
  DecompileSourceChunk,
} from '@/api/types'
import { useDecompileResults } from '@/composables/useDecompileResults'

const activeScopes: EffectScope[] = []

function inScope<T>(factory: () => T): T {
  const scope = effectScope()
  const value = scope.run(factory)
  if (value === undefined) throw new Error('effect scope did not return a value')
  activeScopes.push(scope)
  return value
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function result(
  id: string,
  overrides: Partial<DecompileResult> = {},
): DecompileResult {
  return {
    id,
    file_node_id: `file-${id}`,
    symbol_key: `symbol-${id}`,
    symbol_kind: 'function',
    display_name: `function_${id}`,
    group_name: 'sample.bin',
    location: '0x00401000',
    signature: `int function_${id}(void)`,
    detail: 'Ghidra decompiler output',
    language: 'c',
    engine_name: 'ghidra',
    engine_version: '11.3.2',
    status: 'complete',
    size_bytes: 128,
    diagnostics: { warnings: [] },
    created_at: '2026-07-30T08:00:00Z',
    completed_at: '2026-07-30T08:00:01Z',
    ...overrides,
  }
}

function page(
  items: DecompileResult[],
  nextCursor?: string,
): DecompileResultPage {
  return {
    items,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
}

function chunk(
  resultId: string,
  content: string,
  overrides: Partial<DecompileSourceChunk> = {},
): DecompileSourceChunk {
  return {
    result_id: resultId,
    offset: 0,
    content,
    complete: true,
    sha256: 'a'.repeat(64),
    size_bytes: content.length,
    ...overrides,
  }
}

describe('useDecompileResults', () => {
  afterEach(() => {
    for (const scope of activeScopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
  })

  it('moves from the initial loading state to ready and reads the first source', async () => {
    const listRequest = deferred<DecompileResultPage>()
    const sourceRequest = deferred<DecompileSourceChunk>()
    const listResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockReturnValue(listRequest.promise)
    const getSource = vi
      .spyOn(api, 'getDecompileSource')
      .mockReturnValue(sourceRequest.promise)

    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-ready' }),
    )

    expect(results.loading.value).toBe(true)
    expect(results.state.value).toMatchObject({
      status: 'loading',
      title: '正在读取反编译结果',
    })
    expect(listResults).toHaveBeenCalledWith('task-ready', {
      page_size: 100,
    })

    listRequest.resolve(page([result('result-1')]))
    await flushPromises()

    expect(results.state.value).toEqual({ status: 'ready' })
    expect(results.selectedResult.value?.id).toBe('result-1')
    expect(results.sourceLoading.value).toBe(true)
    expect(getSource).toHaveBeenCalledWith(
      'task-ready',
      'result-1',
      { offset: 0, limit: 256 * 1024 },
    )

    sourceRequest.resolve(chunk('result-1', 'int main(void) { return 0; }'))
    await flushPromises()

    expect(results.source.value).toBe('int main(void) { return 0; }')
    expect(results.sourceLoading.value).toBe(false)
    expect(results.hasMoreSource.value).toBe(false)
  })

  it('exposes an empty state without requesting source content', async () => {
    vi.spyOn(api, 'listDecompileResults').mockResolvedValue(page([]))
    const getSource = vi.spyOn(api, 'getDecompileSource')

    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-empty' }),
    )
    await flushPromises()

    expect(results.items.value).toEqual([])
    expect(results.state.value).toMatchObject({
      status: 'empty',
      title: '暂无反编译结果',
    })
    expect(getSource).not.toHaveBeenCalled()
  })

  it('surfaces the ApiError message and code, then recovers on refresh', async () => {
    const listResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockRejectedValueOnce(
        new ApiError('Ghidra 服务不可用', 503, {
          code: 'decompiler_unavailable',
        }),
      )
      .mockResolvedValueOnce(page([]))
    vi.spyOn(api, 'getDecompileSource')

    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-error' }),
    )
    await flushPromises()

    expect(results.state.value).toEqual({
      status: 'error',
      title: '反编译结果读取失败',
      description: 'Ghidra 服务不可用',
      errorCode: 'decompiler_unavailable',
    })

    results.refresh()
    await flushPromises()

    expect(listResults).toHaveBeenCalledTimes(2)
    expect(results.state.value.status).toBe('empty')
  })

  it('appends cursor pages once and guards duplicate or exhausted loads', async () => {
    const secondPage = deferred<DecompileResultPage>()
    const listResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValueOnce(page([result('result-1')], 'cursor-2'))
      .mockReturnValueOnce(secondPage.promise)
    vi.spyOn(api, 'getDecompileSource').mockResolvedValue(
      chunk('result-1', 'first source'),
    )
    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-pages' }),
    )
    await flushPromises()

    expect(results.hasMoreResults.value).toBe(true)
    results.loadMoreResults()
    results.loadMoreResults()

    expect(results.loadingMore.value).toBe(true)
    expect(listResults).toHaveBeenCalledTimes(2)
    expect(listResults).toHaveBeenLastCalledWith('task-pages', {
      page_size: 100,
      cursor: 'cursor-2',
    })

    secondPage.resolve(page([result('result-2')]))
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual([
      'result-1',
      'result-2',
    ])
    expect(results.loadingMore.value).toBe(false)
    expect(results.hasMoreResults.value).toBe(false)

    results.loadMoreResults()
    await flushPromises()
    expect(listResults).toHaveBeenCalledTimes(2)
  })

  it('selects a result and appends source chunks with a single-flight guard', async () => {
    const tailRequest = deferred<DecompileSourceChunk>()
    vi.spyOn(api, 'listDecompileResults').mockResolvedValue(
      page([
        result('result-1'),
        result('result-2', { status: 'partial' }),
        result('result-3', { status: 'unsupported' }),
      ]),
    )
    const getSource = vi
      .spyOn(api, 'getDecompileSource')
      .mockResolvedValueOnce(chunk('result-1', 'source one'))
      .mockResolvedValueOnce(
        chunk('result-2', 'int ', {
          complete: false,
          next_offset: 4,
          size_bytes: 12,
        }),
      )
      .mockReturnValueOnce(tailRequest.promise)
    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-source' }),
    )
    await flushPromises()

    results.selectResult('result-2')
    await flushPromises()
    expect(results.selectedResult.value?.id).toBe('result-2')
    expect(results.source.value).toBe('int ')
    expect(results.hasMoreSource.value).toBe(true)

    results.loadMoreSource()
    results.loadMoreSource()
    expect(results.sourceLoading.value).toBe(true)
    expect(getSource).toHaveBeenCalledTimes(3)
    expect(getSource).toHaveBeenLastCalledWith(
      'task-source',
      'result-2',
      { offset: 4, limit: 256 * 1024 },
    )

    tailRequest.resolve(
      chunk('result-2', 'answer(void)', {
        offset: 4,
        size_bytes: 12,
      }),
    )
    await flushPromises()

    expect(results.source.value).toBe('int answer(void)')
    expect(results.hasMoreSource.value).toBe(false)

    results.selectResult('result-3')
    await flushPromises()
    expect(results.selectedResult.value?.id).toBe('result-3')
    expect(results.source.value).toBe('')
    expect(getSource).toHaveBeenCalledTimes(3)
  })

  it('ignores source responses from a previously selected result', async () => {
    const olderSource = deferred<DecompileSourceChunk>()
    const currentSource = deferred<DecompileSourceChunk>()
    vi.spyOn(api, 'listDecompileResults').mockResolvedValue(
      page([result('result-old'), result('result-current')]),
    )
    vi.spyOn(api, 'getDecompileSource')
      .mockReturnValueOnce(olderSource.promise)
      .mockReturnValueOnce(currentSource.promise)
    const results = inScope(() =>
      useDecompileResults({ taskId: 'task-selection-race' }),
    )
    await flushPromises()

    expect(results.selectedResultId.value).toBe('result-old')
    results.selectResult('result-current')
    currentSource.resolve(chunk('result-current', 'current source'))
    await flushPromises()

    expect(results.source.value).toBe('current source')
    expect(results.sourceLoading.value).toBe(false)

    olderSource.resolve(chunk('result-old', 'stale source'))
    await flushPromises()

    expect(results.selectedResultId.value).toBe('result-current')
    expect(results.source.value).toBe('current source')
  })

  it('fully resets when disabled or taskId is cleared, including an in-flight load', async () => {
    const pendingPage = deferred<DecompileResultPage>()
    const taskId = shallowRef('task-a')
    const enabled = shallowRef(true)
    const listResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValueOnce(page([result('result-a')], 'cursor-a'))
      .mockReturnValueOnce(pendingPage.promise)
    vi.spyOn(api, 'getDecompileSource').mockResolvedValue(
      chunk('result-a', 'source a'),
    )
    const results = inScope(() =>
      useDecompileResults({ taskId, enabled }),
    )
    await flushPromises()

    expect(results.hasMoreResults.value).toBe(true)
    enabled.value = false
    await nextTick()

    expect(results.items.value).toEqual([])
    expect(results.selectedResultId.value).toBe('')
    expect(results.source.value).toBe('')
    expect(results.hasMoreResults.value).toBe(false)
    expect(results.loading.value).toBe(false)
    expect(results.state.value.status).toBe('empty')

    taskId.value = 'task-b'
    await nextTick()
    expect(listResults).toHaveBeenCalledOnce()

    enabled.value = true
    await nextTick()
    expect(results.loading.value).toBe(true)
    expect(listResults).toHaveBeenCalledTimes(2)

    enabled.value = false
    await nextTick()
    expect(results.loading.value).toBe(false)

    pendingPage.resolve(page([result('stale-result')], 'stale-cursor'))
    await flushPromises()
    expect(results.items.value).toEqual([])
    expect(results.hasMoreResults.value).toBe(false)

    taskId.value = ''
    enabled.value = true
    await nextTick()
    expect(results.state.value.status).toBe('empty')
    expect(listResults).toHaveBeenCalledTimes(2)
  })

  it('keeps the current task when an older task request resolves last', async () => {
    const olderPage = deferred<DecompileResultPage>()
    const currentPage = deferred<DecompileResultPage>()
    const taskId = shallowRef('task-old')
    vi.spyOn(api, 'listDecompileResults')
      .mockReturnValueOnce(olderPage.promise)
      .mockReturnValueOnce(currentPage.promise)
    const getSource = vi
      .spyOn(api, 'getDecompileSource')
      .mockResolvedValue(chunk('result-current', 'current source'))
    const results = inScope(() => useDecompileResults({ taskId }))

    taskId.value = 'task-current'
    await nextTick()
    currentPage.resolve(page([result('result-current')]))
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual([
      'result-current',
    ])
    expect(results.source.value).toBe('current source')

    olderPage.resolve(page([result('result-old')]))
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual([
      'result-current',
    ])
    expect(results.selectedResultId.value).toBe('result-current')
    expect(getSource).toHaveBeenCalledOnce()
    expect(getSource).toHaveBeenCalledWith(
      'task-current',
      'result-current',
      { offset: 0, limit: 256 * 1024 },
    )
  })
})
