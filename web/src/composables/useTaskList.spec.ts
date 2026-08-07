import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { ScanTask, TaskPage } from '@/api/types'
import { useTaskList } from '@/composables/useTaskList'

function task(id: string, name: string): ScanTask {
  return {
    id,
    name,
    input_type: 'elf64',
    status: 'SUCCEEDED',
    risk_level: 'NONE',
    progress: 100,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: 'operator',
    tags: [],
    created_at: '2026-07-30T00:00:00Z',
    sample_expires_at: '2099-08-29T00:00:00Z',
    sample_deleted_at: null,
  }
}

function page(items: ScanTask[], nextCursor?: string): TaskPage {
  return {
    items,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
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

describe('useTaskList', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('prevents an older response from overwriting a newer filter result', async () => {
    const older = deferred<TaskPage>()
    const newer = deferred<TaskPage>()
    vi.spyOn(api, 'listTasks')
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise)

    const list = useTaskList()
    const olderLoad = list.load({ page_size: 20, input_type: 'tar' })
    const newerLoad = list.load({ page_size: 20, input_type: 'elf64' })

    newer.resolve(page([task('new', 'new result')], 'cursor-new'))
    await newerLoad
    expect(list.items.value.map((item) => item.id)).toEqual(['new'])
    expect(list.loading.value).toBe(false)

    older.resolve(page([task('old', 'stale result')]))
    await olderLoad
    expect(list.items.value.map((item) => item.id)).toEqual(['new'])
    expect(list.nextCursor.value).toBe('cursor-new')
  })

  it('ignores a stale failure and keeps loading until the current request finishes', async () => {
    const older = deferred<TaskPage>()
    const newer = deferred<TaskPage>()
    vi.spyOn(api, 'listTasks')
      .mockReturnValueOnce(older.promise)
      .mockReturnValueOnce(newer.promise)

    const list = useTaskList()
    const olderLoad = list.load({ page_size: 20 })
    const newerLoad = list.load({ cursor: 'cursor-2', page_size: 20 })

    older.reject(new ApiError('过期请求失败', 503))
    await olderLoad
    expect(list.loading.value).toBe(true)
    expect(list.errorMessage.value).toBe('')

    newer.resolve(page([task('current', 'current result')]))
    await newerLoad
    expect(list.loading.value).toBe(false)
    expect(list.errorMessage.value).toBe('')
  })
})
