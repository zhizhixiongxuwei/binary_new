import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { TaskDetail } from '@/api/types'
import { useTaskLifecycleActions } from '@/composables/useTaskLifecycleActions'

function failedTask(): TaskDetail {
  return {
    id: 'task-lifecycle',
    name: 'sample.exe',
    input_type: 'pe32+',
    status: 'FAILED',
    risk_level: 'HIGH',
    progress: 80,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: 'Operator',
    tags: [],
    created_at: '2026-07-30T00:00:00Z',
    sample_expires_at: '2099-08-29T00:00:00.000Z',
    sample_deleted_at: null,
    error_code: 'SCAN_FAILED',
    error_message: '分析失败',
  }
}

describe('useTaskLifecycleActions', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('reuses one idempotency key after failure and rotates it after success', async () => {
    const randomUUID = vi
      .fn()
      .mockReturnValueOnce('retry-intent-one')
      .mockReturnValueOnce('retry-intent-two')
    vi.stubGlobal('crypto', { randomUUID })
    const retriedTask = {
      ...failedTask(),
      status: 'QUEUED' as const,
      progress: 0,
    }
    const retryTask = vi
      .spyOn(api, 'retryTask')
      .mockRejectedValueOnce(
        new ApiError('暂时不可用', 503, { code: 'UNAVAILABLE' }),
      )
      .mockResolvedValueOnce(retriedTask)
      .mockResolvedValueOnce(retriedTask)
    const updates: TaskDetail[] = []
    const actions = useTaskLifecycleActions({
      mode: 'live',
      updateTask: (task) => updates.push(task),
    })

    await actions.execute('retry', failedTask())
    expect(actions.errorMessage.value).toContain('暂时不可用')

    await actions.execute('retry', failedTask())
    expect(actions.feedbackMessage.value).toContain('已提交')
    expect(updates).toEqual([retriedTask])

    await actions.execute('retry', failedTask())

    expect(retryTask.mock.calls.map(([, key]) => key)).toEqual([
      'retry-intent-one',
      'retry-intent-one',
      'retry-intent-two',
    ])
    expect(randomUUID).toHaveBeenCalledTimes(2)
  })

  it('prevents duplicate submissions while an operation is pending', async () => {
    let resolveRequest: ((task: TaskDetail) => void) | undefined
    const request = new Promise<TaskDetail>((resolve) => {
      resolveRequest = resolve
    })
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('cancel-intent'),
    })
    const cancelTask = vi.spyOn(api, 'cancelTask').mockReturnValue(request)
    const updates: TaskDetail[] = []
    const actions = useTaskLifecycleActions({
      mode: 'live',
      updateTask: (task) => updates.push(task),
    })

    const first = actions.execute('cancel', failedTask())
    const duplicate = actions.execute('cancel', failedTask())

    expect(actions.pendingAction.value).toBe('cancel')
    expect(cancelTask).toHaveBeenCalledTimes(1)
    await duplicate

    const cancelled = {
      ...failedTask(),
      status: 'CANCEL_REQUESTED' as const,
    }
    resolveRequest?.(cancelled)
    await first

    expect(actions.pendingAction.value).toBeNull()
    expect(updates).toEqual([cancelled])
  })

  it('simulates preview actions locally without touching the API facade', async () => {
    const cancelTask = vi.spyOn(api, 'cancelTask')
    const retryTask = vi.spyOn(api, 'retryTask')
    const deleteTask = vi.spyOn(api, 'deleteTask')
    const extendTaskRetention = vi.spyOn(api, 'extendTaskRetention')
    let current = failedTask()
    const actions = useTaskLifecycleActions({
      mode: 'preview',
      updateTask(task) {
        current = task
      },
    })

    await actions.execute('retry', current)
    expect(current).toMatchObject({ status: 'QUEUED', progress: 0 })
    expect(current.error_code).toBeUndefined()
    await actions.execute('delete', current)
    expect(current.status).toBe('DELETING')
    await actions.execute(
      'extend',
      current,
      '2099-09-28T00:00:00.000Z',
    )
    expect(current.sample_expires_at).toBe('2099-09-28T00:00:00.000Z')

    expect(cancelTask).not.toHaveBeenCalled()
    expect(retryTask).not.toHaveBeenCalled()
    expect(deleteTask).not.toHaveBeenCalled()
    expect(extendTaskRetention).not.toHaveBeenCalled()
  })

  it('submits one compare-and-set retention request and locks duplicates', async () => {
    let resolveRequest: ((task: TaskDetail) => void) | undefined
    const request = new Promise<TaskDetail>((resolve) => {
      resolveRequest = resolve
    })
    const extendTaskRetention = vi
      .spyOn(api, 'extendTaskRetention')
      .mockReturnValue(request)
    const updates: TaskDetail[] = []
    const actions = useTaskLifecycleActions({
      mode: 'live',
      updateTask: (task) => updates.push(task),
    })
    const nextExpiry = '2099-09-28T00:00:00.000Z'

    const first = actions.execute('extend', failedTask(), nextExpiry)
    const duplicate = actions.execute('extend', failedTask(), nextExpiry)

    expect(actions.pendingAction.value).toBe('extend')
    expect(extendTaskRetention).toHaveBeenCalledTimes(1)
    expect(extendTaskRetention).toHaveBeenCalledWith('task-lifecycle', {
      expected_sample_expires_at: '2099-08-29T00:00:00.000Z',
      sample_expires_at: nextExpiry,
    })
    await duplicate

    const extended = {
      ...failedTask(),
      sample_expires_at: nextExpiry,
    }
    resolveRequest?.(extended)
    await first

    expect(actions.pendingAction.value).toBeNull()
    expect(actions.feedbackMessage.value).toContain('延长 15 天')
    expect(updates).toEqual([extended])
  })

  it.each(['live', 'preview'] as const)(
    'blocks an expired sample before the %s retry adapter can run',
    async (mode) => {
      vi.useFakeTimers()
      vi.setSystemTime(new Date('2026-07-31T00:00:00.000Z'))
      const retryTask = vi.spyOn(api, 'retryTask')
      const expired = failedTask()
      expired.sample_expires_at = '2026-07-31T00:00:00.000Z'
      const actions = useTaskLifecycleActions({
        mode,
        updateTask: vi.fn(),
      })

      await actions.execute('retry', expired)

      expect(actions.pendingAction.value).toBeNull()
      expect(actions.errorMessage.value).toContain('样本保留期已到')
      expect(actions.errorMessage.value).toContain('无法重新检测')
      expect(retryTask).not.toHaveBeenCalled()
    },
  )

  it('treats a server cleanup marker as authoritative before retry', async () => {
    const retryTask = vi.spyOn(api, 'retryTask')
    const deleted = failedTask()
    deleted.sample_deleted_at = 'server-retention-marker'
    const actions = useTaskLifecycleActions({
      mode: 'live',
      updateTask: vi.fn(),
    })

    await actions.execute('retry', deleted)

    expect(actions.errorMessage.value).toContain('任务原始样本已清理')
    expect(retryTask).not.toHaveBeenCalled()
  })
})
