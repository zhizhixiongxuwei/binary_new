import { flushPromises } from '@vue/test-utils'
import { effectScope, nextTick, shallowRef, type EffectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  ConfirmDecompileProjectDeletionInput,
  DecompileProject,
  DecompileProjectDeletionOperation,
  DecompileProjectPage,
  UserRole,
} from '@/api/types'
import { useDecompileProjects } from '@/composables/useDecompileProjects'

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
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function project(
  id: string,
  taskId: string,
  overrides: Partial<DecompileProject> = {},
): DecompileProject {
  return {
    id,
    task_id: taskId,
    job_id: `job-${id}`,
    file_node_id: `file-${id}`,
    target_path: `/bin/${id}`,
    layout_version: 'project-v1',
    source_kind: 'ghidra-pseudoc',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '11.3.2',
    status: 'complete',
    source_file_count: 1,
    symbol_count: 42,
    source_size_bytes: 4096,
    canonical_filename: 'src/decompiled.c',
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
    ...overrides,
  }
}

function page(
  items: DecompileProject[],
  nextCursor?: string,
): DecompileProjectPage {
  return {
    items,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
}

const confirmation: ConfirmDecompileProjectDeletionInput = {
  confirmation_token: 'token-value',
  cascade: true,
  typed_suffix: 'oject-1',
}

function deletionOperation(
  projectId: string,
  overrides: Partial<DecompileProjectDeletionOperation> = {},
): DecompileProjectDeletionOperation {
  return {
    id: '123e4567-e89b-42d3-a456-426614174010',
    project_id: projectId,
    status: 'pending',
    counts: {
      c_analysis_runs: 1,
      c_analysis_findings: 2,
      java_analysis_runs: 1,
      java_analysis_findings: 4,
      reports: 1,
      report_files: 1,
      artifacts: 0,
      decompile_results: 42,
      source_files: 1,
    },
    created_at: '2026-08-10T02:00:00Z',
    completed_at: null,
    error_code: null,
    error_message: null,
    ...overrides,
  }
}

describe('useDecompileProjects', () => {
  afterEach(() => {
    for (const scope of activeScopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('loads and appends independent project versions once', async () => {
    const secondPage = deferred<DecompileProjectPage>()
    const list = vi
      .spyOn(api, 'listDecompileProjects')
      .mockResolvedValueOnce(page([project('project-1', 'task-1')], 'cursor-2'))
      .mockReturnValueOnce(secondPage.promise)

    const state = inScope(() =>
      useDecompileProjects({
        taskId: 'task-1',
        userRole: 'administrator',
      }),
    )
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-1'])
    expect(state.hasMore.value).toBe(true)
    state.loadMore()
    state.loadMore()
    expect(list).toHaveBeenCalledTimes(2)
    expect(list).toHaveBeenLastCalledWith('task-1', {
      page_size: 100,
      cursor: 'cursor-2',
    })

    secondPage.resolve(
      page([
        project('project-1', 'task-1'),
        project('project-2', 'task-1'),
      ]),
    )
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual([
      'project-1',
      'project-2',
    ])
    expect(state.hasMore.value).toBe(false)
  })

  it('resets while disabled and ignores an older task response', async () => {
    const older = deferred<DecompileProjectPage>()
    const taskId = shallowRef('task-old')
    const enabled = shallowRef(true)
    vi.spyOn(api, 'listDecompileProjects')
      .mockReturnValueOnce(older.promise)
      .mockResolvedValueOnce(page([project('project-new', 'task-new')]))

    const state = inScope(() =>
      useDecompileProjects({
        taskId,
        userRole: 'operator',
        enabled,
      }),
    )
    taskId.value = 'task-new'
    await nextTick()
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-new'])

    older.resolve(page([project('project-old', 'task-old')]))
    await flushPromises()
    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-new'])

    enabled.value = false
    await nextTick()
    expect(state.projects.value).toEqual([])
    expect(state.loading.value).toBe(false)
  })

  it('allows administrators and operators to delete one version', async () => {
    const role = shallowRef<UserRole | null>('operator')
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue(
      page([
        project('project-1', 'task-1'),
        project('project-2', 'task-1'),
      ]),
    )
    const remove = vi
      .spyOn(api, 'confirmDecompileProjectDeletion')
      .mockResolvedValue(deletionOperation('project-1'))
    const state = inScope(() =>
      useDecompileProjects({ taskId: 'task-1', userRole: role }),
    )
    await flushPromises()

    await expect(state.deleteProject('project-1', confirmation)).resolves.toEqual(
      deletionOperation('project-1'),
    )
    expect(remove).toHaveBeenCalledWith('task-1', 'project-1', confirmation)
    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-2'])

    role.value = 'reader'
    await nextTick()
    await expect(state.deleteProject('project-2', confirmation)).resolves.toBeUndefined()
    expect(remove).toHaveBeenCalledOnce()
  })

  it('retains a version and exposes the server error when deletion fails', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue(
      page([project('project-1', 'task-1')]),
    )
    vi.spyOn(api, 'confirmDecompileProjectDeletion').mockRejectedValue(
      new ApiError('目录正在使用', 409, { code: 'PROJECT_BUSY' }),
    )
    const state = inScope(() =>
      useDecompileProjects({ taskId: 'task-1', userRole: 'administrator' }),
    )
    await flushPromises()

    await expect(state.deleteProject('project-1', confirmation)).resolves.toBeUndefined()
    expect(state.projects.value).toHaveLength(1)
    expect(state.operationError.value).toBe('删除源码项目失败：目录正在使用')
    expect(state.deletingProjectId.value).toBe('')
  })

  it('polls an accepted cascade deletion through retryable failure to completion', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue(
      page([project('project-1', 'task-1')]),
    )
    vi.spyOn(api, 'confirmDecompileProjectDeletion').mockResolvedValue(
      deletionOperation('project-1'),
    )
    const getOperation = vi
      .spyOn(api, 'getDecompileProjectDeletion')
      .mockRejectedValueOnce(new Error('临时网络错误'))
      .mockResolvedValueOnce(
        deletionOperation('project-1', {
          status: 'failed',
          error_code: 'cleanup_retry',
          error_message: '文件暂时被占用',
        }),
      )
      .mockResolvedValueOnce(
        deletionOperation('project-1', {
          status: 'complete',
          completed_at: '2026-08-10T02:01:00Z',
        }),
      )
    const state = inScope(() =>
      useDecompileProjects({ taskId: 'task-1', userRole: 'administrator' }),
    )
    await flushPromises()

    await state.deleteProject('project-1', confirmation)
    expect(state.latestDeletionOperation.value?.status).toBe('pending')
    expect(state.activeDeletionOperationCount.value).toBe(1)

    await vi.advanceTimersByTimeAsync(2_000)
    expect(state.latestDeletionOperation.value?.status).toBe('pending')
    expect(state.deletionPollError.value).toContain('临时网络错误')

    await vi.advanceTimersByTimeAsync(4_000)
    expect(state.latestDeletionOperation.value?.status).toBe('failed')
    expect(state.activeDeletionOperationCount.value).toBe(1)
    expect(state.deletionPollError.value).toBe('')

    await vi.advanceTimersByTimeAsync(2_000)
    expect(state.latestDeletionOperation.value?.status).toBe('complete')
    expect(state.activeDeletionOperationCount.value).toBe(0)
    await vi.advanceTimersByTimeAsync(20_000)
    expect(getOperation).toHaveBeenCalledTimes(3)
  })

  it('cancels deletion polling when the selected task changes', async () => {
    vi.useFakeTimers()
    const taskId = shallowRef('task-1')
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) =>
      page(task === 'task-1' ? [project('project-1', task)] : []),
    )
    vi.spyOn(api, 'confirmDecompileProjectDeletion').mockResolvedValue(
      deletionOperation('project-1'),
    )
    const getOperation = vi.spyOn(api, 'getDecompileProjectDeletion')
    const state = inScope(() =>
      useDecompileProjects({ taskId, userRole: 'administrator' }),
    )
    await flushPromises()
    await state.deleteProject('project-1', confirmation)

    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    expect(state.deletionOperations.value).toEqual({})

    await vi.advanceTimersByTimeAsync(20_000)
    expect(getOperation).not.toHaveBeenCalled()
  })

  it('downloads only from a same-origin URL', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue(
      page([project('project-1', 'task-1')]),
    )
    vi.spyOn(api, 'downloadDecompileProject')
      .mockResolvedValueOnce({ kind: 'url', url: '/downloads/project-1.zip' })
      .mockResolvedValueOnce({ kind: 'url', url: 'https://outside.test/project.zip' })
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    const state = inScope(() =>
      useDecompileProjects({ taskId: 'task-1', userRole: 'reader' }),
    )
    await flushPromises()

    await state.downloadProject('project-1')
    expect(click).toHaveBeenCalledOnce()
    expect(state.operationError.value).toBe('')

    await state.downloadProject('project-1')
    expect(click).toHaveBeenCalledOnce()
    expect(state.operationError.value).toContain('不是安全的同源地址')
  })
})
