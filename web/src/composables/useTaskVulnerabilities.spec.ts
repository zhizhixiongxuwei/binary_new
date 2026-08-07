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
  VulnerabilityFinding,
  VulnerabilityFindingPage,
  VulnerabilitySeverity,
  VulnerabilitySummary,
} from '@/api/types'
import { useTaskVulnerabilities } from '@/composables/useTaskVulnerabilities'

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

function finding(
  id: string,
  overrides: Partial<VulnerabilityFinding> = {},
): VulnerabilityFinding {
  return {
    id,
    vulnerability_id: `CVE-2026-${id}`,
    severity: 'HIGH',
    package_name: 'openssl',
    installed_version: '3.0.10',
    fixed_version: '3.0.15',
    title: `OpenSSL vulnerability ${id}`,
    description_summary: 'Offline Trivy database finding.',
    image_logical_path: 'usr/lib/libssl.so.3',
    image_platform: 'linux/amd64',
    evidence: {
      package_type: 'deb',
      layer_digest: `sha256:${'b'.repeat(64)}`,
    },
    references: [`https://example.invalid/CVE-2026-${id}`],
		database_bundle: {
			id: 'trivy-db-20260730',
			version: '2026-07-30',
			generated_at: '2026-07-30T00:00:00Z',
			content_sha256: 'a'.repeat(64),
    },
    created_at: '2026-07-30T08:00:00Z',
    ...overrides,
  }
}

function summary(
  counts: Partial<Record<VulnerabilitySeverity, number>> = {},
  fixable = 0,
): VulnerabilitySummary {
  const bySeverity = {
    UNKNOWN: counts.UNKNOWN ?? 0,
    LOW: counts.LOW ?? 0,
    MEDIUM: counts.MEDIUM ?? 0,
    HIGH: counts.HIGH ?? 0,
    CRITICAL: counts.CRITICAL ?? 0,
  }
  return {
    total: Object.values(bySeverity).reduce((total, count) => total + count, 0),
    fixable,
    by_severity: bySeverity,
  }
}

function page(
  items: VulnerabilityFinding[],
  resultSummary: VulnerabilitySummary,
  nextCursor?: string,
): VulnerabilityFindingPage {
  return {
    items,
    summary: resultSummary,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
}

describe('useTaskVulnerabilities', () => {
  afterEach(() => {
    for (const scope of activeScopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
  })

  it('moves from the initial loading state to ready and loads the first detail', async () => {
    const listRequest = deferred<VulnerabilityFindingPage>()
    const detailRequest = deferred<VulnerabilityFinding>()
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockReturnValue(listRequest.promise)
    const getFinding = vi
      .spyOn(api, 'getTaskVulnerability')
      .mockReturnValue(detailRequest.promise)
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-ready' }),
    )

    expect(results.loading.value).toBe(true)
    expect(results.state.value).toMatchObject({
      status: 'loading',
      title: '正在读取容器漏洞结果',
    })
    expect(listFindings).toHaveBeenCalledWith('task-ready', {
      page_size: 50,
    })

    const listItem = finding('0001', { description_summary: 'list summary' })
    listRequest.resolve(page([listItem], summary({ HIGH: 1 }, 1)))
    await flushPromises()

    expect(results.state.value).toEqual({ status: 'ready' })
    expect(results.summary.value).toEqual(summary({ HIGH: 1 }, 1))
    expect(results.selectedFindingId.value).toBe('0001')
    expect(results.selectedFinding.value?.description_summary).toBe(
      'list summary',
    )
    expect(results.detailLoading.value).toBe(true)
    expect(getFinding).toHaveBeenCalledWith('task-ready', '0001')

    detailRequest.resolve(
      finding('0001', { description_summary: 'full detail' }),
    )
    await flushPromises()

    expect(results.selectedFinding.value?.description_summary).toBe(
      'full detail',
    )
    expect(results.detailLoading.value).toBe(false)
  })

  it('exposes an empty state without requesting a detail', async () => {
    vi.spyOn(api, 'listTaskVulnerabilities').mockResolvedValue(
      page([], summary()),
    )
    const getFinding = vi.spyOn(api, 'getTaskVulnerability')

    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-empty' }),
    )
    await flushPromises()

    expect(results.items.value).toEqual([])
    expect(results.summary.value.total).toBe(0)
    expect(results.state.value).toMatchObject({
      status: 'empty',
      title: '未发现容器漏洞',
    })
    expect(getFinding).not.toHaveBeenCalled()
  })

  it('surfaces the ApiError message and code, then recovers on refresh', async () => {
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockRejectedValueOnce(
        new ApiError('离线漏洞库不可用', 503, {
          code: 'trivy_database_bundle_unavailable',
        }),
      )
      .mockResolvedValueOnce(page([], summary()))
    vi.spyOn(api, 'getTaskVulnerability')
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-error' }),
    )
    await flushPromises()

    expect(results.state.value).toEqual({
      status: 'error',
      title: '容器漏洞结果读取失败',
      description: '离线漏洞库不可用',
      errorCode: 'trivy_database_bundle_unavailable',
    })

    results.refresh()
    await flushPromises()

    expect(listFindings).toHaveBeenCalledTimes(2)
    expect(results.state.value.status).toBe('empty')
  })

  it('refreshes the selected finding detail when the finding remains in the list', async () => {
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockResolvedValueOnce(
        page(
          [finding('0001', { description_summary: 'initial list summary' })],
          summary({ HIGH: 1 }, 1),
        ),
      )
      .mockResolvedValueOnce(
        page(
          [finding('0001', { description_summary: 'refreshed list summary' })],
          summary({ HIGH: 1 }, 1),
        ),
      )
    const getFinding = vi
      .spyOn(api, 'getTaskVulnerability')
      .mockResolvedValueOnce(
        finding('0001', { description_summary: 'initial full detail' }),
      )
      .mockResolvedValueOnce(
        finding('0001', { description_summary: 'refreshed full detail' }),
      )
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-refresh-detail' }),
    )
    await flushPromises()

    expect(results.selectedFinding.value?.description_summary).toBe(
      'initial full detail',
    )

    results.refresh()
    await flushPromises()

    expect(listFindings).toHaveBeenCalledTimes(2)
    expect(getFinding).toHaveBeenCalledTimes(2)
    expect(getFinding).toHaveBeenLastCalledWith(
      'task-refresh-detail',
      '0001',
    )
    expect(results.selectedFinding.value?.description_summary).toBe(
      'refreshed full detail',
    )
  })

  it('appends cursor pages once and guards duplicate or exhausted loads', async () => {
    const secondPage = deferred<VulnerabilityFindingPage>()
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockResolvedValueOnce(
        page([finding('0001')], summary({ HIGH: 2 }, 2), 'cursor-2'),
      )
      .mockReturnValueOnce(secondPage.promise)
    vi.spyOn(api, 'getTaskVulnerability').mockImplementation(
      async (_taskId, findingId) => finding(findingId),
    )
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-pages' }),
    )
    await flushPromises()

    expect(results.hasMore.value).toBe(true)
    results.loadMore()
    results.loadMore()

    expect(results.loadingMore.value).toBe(true)
    expect(listFindings).toHaveBeenCalledTimes(2)
    expect(listFindings).toHaveBeenLastCalledWith('task-pages', {
      page_size: 50,
      cursor: 'cursor-2',
    })

    secondPage.resolve(
      page([finding('0002')], summary({ HIGH: 2 }, 2)),
    )
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual(['0001', '0002'])
    expect(results.summary.value).toEqual(summary({ HIGH: 2 }, 2))
    expect(results.loadingMore.value).toBe(false)
    expect(results.hasMore.value).toBe(false)

    results.loadMore()
    await flushPromises()
    expect(listFindings).toHaveBeenCalledTimes(2)
  })

  it('selects a finding and ignores detail from the previous selection', async () => {
    const olderDetail = deferred<VulnerabilityFinding>()
    const currentDetail = deferred<VulnerabilityFinding>()
    vi.spyOn(api, 'listTaskVulnerabilities').mockResolvedValue(
      page(
        [finding('old'), finding('current')],
        summary({ HIGH: 2 }, 2),
      ),
    )
    const getFinding = vi
      .spyOn(api, 'getTaskVulnerability')
      .mockReturnValueOnce(olderDetail.promise)
      .mockReturnValueOnce(currentDetail.promise)
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-selection-race' }),
    )
    await flushPromises()

    expect(results.selectedFindingId.value).toBe('old')
    results.selectFinding('current')
    expect(results.selectedFinding.value?.id).toBe('current')
    expect(getFinding).toHaveBeenLastCalledWith(
      'task-selection-race',
      'current',
    )

    currentDetail.resolve(
      finding('current', { description_summary: 'current full detail' }),
    )
    await flushPromises()
    expect(results.selectedFinding.value?.description_summary).toBe(
      'current full detail',
    )
    expect(results.detailLoading.value).toBe(false)

    olderDetail.resolve(
      finding('old', { description_summary: 'stale full detail' }),
    )
    await flushPromises()

    expect(results.selectedFindingId.value).toBe('current')
    expect(results.selectedFinding.value?.description_summary).toBe(
      'current full detail',
    )
  })

  it('reloads for a severity filter and ignores selecting the same filter twice', async () => {
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockResolvedValueOnce(page([], summary()))
      .mockResolvedValueOnce(
        page([finding('high-1')], summary({ HIGH: 1 }, 1)),
      )
    const getFinding = vi
      .spyOn(api, 'getTaskVulnerability')
      .mockResolvedValue(finding('high-1'))
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId: 'task-filter' }),
    )
    await flushPromises()

    results.setSeverity('HIGH')
    await flushPromises()

    expect(results.severity.value).toBe('HIGH')
    expect(listFindings).toHaveBeenLastCalledWith('task-filter', {
      page_size: 50,
      severity: 'HIGH',
    })
    expect(results.items.value.map(({ id }) => id)).toEqual(['high-1'])
    expect(results.selectedFindingId.value).toBe('high-1')
    expect(getFinding).toHaveBeenCalledWith('task-filter', 'high-1')

    results.setSeverity('HIGH')
    await flushPromises()
    expect(listFindings).toHaveBeenCalledTimes(2)
  })

  it('fully resets when disabled or taskId is cleared, including an in-flight load', async () => {
    const pendingPage = deferred<VulnerabilityFindingPage>()
    const taskId = shallowRef('task-a')
    const enabled = shallowRef(true)
    const listFindings = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockResolvedValueOnce(
        page([finding('finding-a')], summary({ HIGH: 1 }, 1), 'cursor-a'),
      )
      .mockReturnValueOnce(pendingPage.promise)
    vi.spyOn(api, 'getTaskVulnerability').mockResolvedValue(
      finding('finding-a'),
    )
    const results = inScope(() =>
      useTaskVulnerabilities({ taskId, enabled }),
    )
    await flushPromises()

    expect(results.hasMore.value).toBe(true)
    results.setSeverity('HIGH')
    await nextTick()
    expect(results.severity.value).toBe('HIGH')
    expect(results.loading.value).toBe(true)

    enabled.value = false
    await nextTick()

    expect(results.items.value).toEqual([])
    expect(results.summary.value).toEqual(summary())
    expect(results.severity.value).toBeUndefined()
    expect(results.selectedFindingId.value).toBe('')
    expect(results.selectedFinding.value).toBeUndefined()
    expect(results.hasMore.value).toBe(false)
    expect(results.loading.value).toBe(false)
    expect(results.detailLoading.value).toBe(false)
    expect(results.state.value.status).toBe('empty')

    pendingPage.resolve(
      page([finding('stale-finding')], summary({ CRITICAL: 1 })),
    )
    await flushPromises()
    expect(results.items.value).toEqual([])
    expect(results.summary.value.total).toBe(0)

    taskId.value = ''
    enabled.value = true
    await nextTick()
    expect(results.state.value.status).toBe('empty')
    expect(listFindings).toHaveBeenCalledTimes(2)
  })

  it('keeps the current task when an older task request resolves last', async () => {
    const olderPage = deferred<VulnerabilityFindingPage>()
    const currentPage = deferred<VulnerabilityFindingPage>()
    const taskId = shallowRef('task-old')
    vi.spyOn(api, 'listTaskVulnerabilities')
      .mockReturnValueOnce(olderPage.promise)
      .mockReturnValueOnce(currentPage.promise)
    const getFinding = vi
      .spyOn(api, 'getTaskVulnerability')
      .mockImplementation(async (_taskId, findingId) => finding(findingId))
    const results = inScope(() => useTaskVulnerabilities({ taskId }))

    taskId.value = 'task-current'
    await nextTick()
    currentPage.resolve(
      page(
        [finding('finding-current')],
        summary({ CRITICAL: 1 }, 1),
      ),
    )
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual([
      'finding-current',
    ])
    expect(results.summary.value).toEqual(summary({ CRITICAL: 1 }, 1))

    olderPage.resolve(
      page([finding('finding-old')], summary({ LOW: 1 })),
    )
    await flushPromises()

    expect(results.items.value.map(({ id }) => id)).toEqual([
      'finding-current',
    ])
    expect(results.selectedFindingId.value).toBe('finding-current')
    expect(getFinding).toHaveBeenCalledOnce()
    expect(getFinding).toHaveBeenCalledWith(
      'task-current',
      'finding-current',
    )
  })
})
