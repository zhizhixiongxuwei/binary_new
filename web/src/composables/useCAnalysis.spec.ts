import { flushPromises } from '@vue/test-utils'
import { effectScope, nextTick, shallowRef, type EffectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  CAnalysisFinding,
  CAnalysisRun,
  DecompileProject,
  UserRole,
} from '@/api/types'
import { useCAnalysis } from '@/composables/useCAnalysis'

const scopes: EffectScope[] = []

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function inScope<T>(factory: () => T): T {
  const scope = effectScope()
  const value = scope.run(factory)
  if (value === undefined) throw new Error('effect scope did not return a value')
  scopes.push(scope)
  return value
}

function project(
  id: string,
  overrides: Partial<DecompileProject> = {},
): DecompileProject {
  return {
    id,
    task_id: 'task-1',
    job_id: `job-${id}`,
    file_node_id: `file-${id}`,
    target_path: `/bin/${id}`,
    layout_version: 'project-v1',
    source_kind: 'ghidra-pseudoc',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '12.1.2',
    status: 'complete',
    source_file_count: 1,
    symbol_count: 3,
    source_size_bytes: 4096,
    canonical_filename: 'src/decompiled.c',
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
    ...overrides,
  }
}

function run(
  status: CAnalysisRun['status'] = 'succeeded',
): CAnalysisRun {
  return {
    id: 'run-1',
    task_id: 'task-1',
    source_project_id: 'project-valid',
    source_project: {
      id: 'project-valid',
      target_path: '/bin/project-valid',
      status: 'complete',
      engine_name: 'Ghidra',
      engine_version: '12.1.2',
    },
    job_id: 'job-run-1',
    status,
    analyzer_name: 'binaryscan-c-checker',
    analyzer_version: '0.1.0',
    ruleset_version: 'c-rules-v1',
    source_sha256: 'a'.repeat(64),
    source_size_bytes: 4096,
    finding_count: status === 'succeeded' ? 1 : 0,
    diagnostic_count: 0,
    coverage: { total_functions: 3, parsed_functions: 3, failed_functions: 0 },
    severity_counts: {
      LOW: 0,
      MEDIUM: 0,
      HIGH: status === 'succeeded' ? 1 : 0,
      CRITICAL: 0,
    },
    findings_truncated: false,
    diagnostics_truncated: false,
    error_code: null,
    error_message: null,
    started_at: '2026-08-10T01:02:00Z',
    completed_at: status === 'succeeded' ? '2026-08-10T01:03:00Z' : null,
    created_at: '2026-08-10T01:02:00Z',
    updated_at: '2026-08-10T01:03:00Z',
  }
}

const finding: CAnalysisFinding = {
  id: 'finding-1',
  cwe: 'CWE-120',
  rule_id: 'cwe-120-bounds',
  severity: 'HIGH',
  function: {
    result_id: 'result-1',
    address: '0x401000',
    name: 'copy_input',
  },
  location: { start_line: 81, start_column: 3, end_line: 81, end_column: 18 },
  message: 'Unbounded copy.',
  snippet: 'strcpy(local, input);',
}

describe('useCAnalysis', () => {
  afterEach(() => {
    for (const scope of scopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('offers only retained project-v1 Ghidra C sources and loads findings', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-valid'),
        project('project-legacy', { layout_version: 'legacy-v1' }),
        project('project-java', { source_kind: 'bytecode', language: 'java' }),
      ],
    })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [run()] })
    const listFindings = vi
      .spyOn(api, 'listCAnalysisFindings')
      .mockResolvedValue({ items: [finding] })

    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'reader' }),
    )
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-valid'])
    expect(state.selectedRun.value?.id).toBe('run-1')
    expect(state.findings.value).toEqual([finding])
    expect(state.canOperate.value).toBe(false)
    expect(listFindings).toHaveBeenCalledWith('task-1', 'run-1', {
      page_size: 100,
    })
  })

  it('normalizes finding filters before sending them to the API', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-valid')],
    })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [run()] })
    const listFindings = vi
      .spyOn(api, 'listCAnalysisFindings')
      .mockResolvedValue({ items: [finding] })
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    state.applyFilters({
      cwe: ' cwe-120 ',
      severity: 'HIGH',
      function: ' copy_input ',
    })
    await flushPromises()

    expect(listFindings).toHaveBeenLastCalledWith('task-1', 'run-1', {
      page_size: 100,
      cwe: 'CWE-120',
      severity: 'HIGH',
      function: 'copy_input',
    })
  })

  it('creates one active run for an operator and blocks a second click', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-valid')],
    })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    const create = vi
      .spyOn(api, 'createCAnalysisRun')
      .mockResolvedValue(run('queued'))
    const role = shallowRef<UserRole | null>('operator')
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: role }),
    )
    await flushPromises()

    expect(state.canCreate.value).toBe(true)
    await state.createRun()
    await state.createRun()

    expect(create).toHaveBeenCalledOnce()
    expect(create.mock.calls[0]?.[0]).toBe('task-1')
    expect(create.mock.calls[0]?.[1]).toBe('project-valid')
    expect(create.mock.calls[0]?.[2]).toMatch(/^c-analysis-/)
    expect(state.activeRun.value).toMatchObject({ status: 'queued' })
    expect(state.canCreate.value).toBe(false)
  })

  it('serializes mutations and ignores refresh while deletion is pending', async () => {
    const pending = deferred<void>()
    const listProjects = vi
      .spyOn(api, 'listDecompileProjects')
      .mockResolvedValue({ items: [project('project-valid')] })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [run()] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [finding] })
    vi.spyOn(api, 'deleteCAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    const deletion = state.deleteRun()
    await flushPromises()

    expect(state.busy.value).toBe(true)
    expect(state.canCreate.value).toBe(false)
    expect(state.canCancel.value).toBe(false)
    expect(state.canDeleteRun.value).toBe(false)
    await state.refresh()
    expect(listProjects).toHaveBeenCalledOnce()

    pending.resolve()
    await deletion

    expect(state.busy.value).toBe(false)
    expect(state.runs.value).toEqual([])
  })

  it('fetches an explicitly selected project beyond the selector page limit', async () => {
    const selectorProjects = Array.from({ length: 1_000 }, (_, index) =>
      project(`project-${String(index).padStart(4, '0')}`),
    )
    const targetProject = project('project-1001')
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: selectorProjects,
      next_cursor: 'more-projects',
    })
    const getProject = vi
      .spyOn(api, 'getDecompileProject')
      .mockResolvedValue(targetProject)
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    const targetRun: CAnalysisRun = {
      ...run('queued'),
      source_project_id: targetProject.id,
      source_project: {
        ...run('queued').source_project,
        id: targetProject.id,
        target_path: targetProject.target_path,
      },
    }
    const create = vi
      .spyOn(api, 'createCAnalysisRun')
      .mockResolvedValue(targetRun)
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    await state.selectProject(targetProject.id)
    await state.createRun()

    expect(getProject).toHaveBeenCalledWith('task-1', targetProject.id)
    expect(state.selectedProject.value?.id).toBe(targetProject.id)
    expect(create).toHaveBeenCalledWith(
      'task-1',
      targetProject.id,
      expect.stringMatching(/^c-analysis-/),
    )
  })

  it('falls back to a remaining project when the selected source was deleted', async () => {
    const listProjects = vi
      .spyOn(api, 'listDecompileProjects')
      .mockResolvedValueOnce({
        items: [project('project-valid'), project('project-keep')],
      })
      .mockResolvedValueOnce({ items: [project('project-keep')] })
    vi.spyOn(api, 'getDecompileProject').mockRejectedValue(
      new ApiError('源码项目不存在', 404, {
        code: 'decompile_project_not_found',
      }),
    )
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()
    expect(state.selectedProjectId.value).toBe('project-valid')

    await state.refresh()

    expect(listProjects).toHaveBeenCalledTimes(2)
    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-keep'])
    expect(state.selectedProjectId.value).toBe('project-keep')
    expect(state.state.value.status).toBe('ready')
  })

  it('does not clear the new task selection after an old project lookup returns 404', async () => {
    const oldLookup = deferred<DecompileProject>()
    const taskId = shallowRef('task-1')
    const taskTwoProject = project('project-task-2', { task_id: 'task-2' })
    let taskOneLoads = 0
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => {
      if (task === 'task-2') return { items: [taskTwoProject] }
      taskOneLoads += 1
      return { items: taskOneLoads === 1 ? [project('project-valid')] : [] }
    })
    vi.spyOn(api, 'getDecompileProject').mockReturnValue(oldLookup.promise)
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    const state = inScope(() => useCAnalysis({ taskId, userRole: 'operator' }))
    await flushPromises()

    const oldRefresh = state.refresh()
    await flushPromises()
    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    expect(state.selectedProjectId.value).toBe(taskTwoProject.id)

    oldLookup.reject(
      new ApiError('源码项目不存在', 404, {
        code: 'decompile_project_not_found',
      }),
    )
    await oldRefresh

    expect(state.selectedProjectId.value).toBe(taskTwoProject.id)
    expect(state.state.value.status).toBe('ready')
  })

  it('clears a transient status refresh error after polling succeeds', async () => {
    vi.useFakeTimers()
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-valid')],
    })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({
      items: [run('queued')],
    })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'getCAnalysisRun')
      .mockRejectedValueOnce(new Error('临时连接失败'))
      .mockResolvedValueOnce(run('succeeded'))
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    await vi.advanceTimersByTimeAsync(2_000)
    expect(state.operationError.value).toContain('临时连接失败')

    await vi.advanceTimersByTimeAsync(2_000)
    expect(state.operationError.value).toBe('')
    expect(state.selectedRun.value?.status).toBe('succeeded')
  })

  it('does not write a delayed create response into another project', async () => {
    const pending = deferred<CAnalysisRun>()
    const projectB = project('project-b')
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-valid'), projectB],
    })
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    const runB: CAnalysisRun = {
      ...run('queued'),
      id: 'run-b',
      job_id: 'job-run-b',
      source_project_id: projectB.id,
      source_project: {
        ...run('queued').source_project,
        id: projectB.id,
        target_path: projectB.target_path,
      },
    }
    const create = vi
      .spyOn(api, 'createCAnalysisRun')
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(runB)
    const state = inScope(() =>
      useCAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    const firstCreate = state.createRun()
    const firstKey = create.mock.calls[0]?.[2]
    await state.selectProject(projectB.id)
    expect(state.selectedProjectId.value).toBe('project-valid')
    pending.reject(new ApiError('暂时不可用', 503))
    await firstCreate
    await state.selectProject(projectB.id)
    await state.createRun()

    expect(state.selectedProjectId.value).toBe(projectB.id)
    expect(state.runs.value.map(({ id }) => id)).toEqual(['run-b'])
    expect(create.mock.calls[1]?.[2]).not.toBe(firstKey)
  })

  it('ignores a create response from the previously selected task', async () => {
    const pending = deferred<CAnalysisRun>()
    const taskId = shallowRef('task-1')
    const taskTwoProject = project('project-task-2', { task_id: 'task-2' })
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => ({
      items: task === 'task-1' ? [project('project-valid')] : [taskTwoProject],
    }))
    vi.spyOn(api, 'listCAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listCAnalysisFindings').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'createCAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() => useCAnalysis({ taskId, userRole: 'operator' }))
    await flushPromises()

    const create = state.createRun()
    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    pending.resolve(run('queued'))
    await create

    expect(state.selectedProjectId.value).toBe(taskTwoProject.id)
    expect(state.runs.value).toEqual([])
    expect(state.creating.value).toBe(false)
  })
})
