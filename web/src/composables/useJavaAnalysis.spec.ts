import { flushPromises } from '@vue/test-utils'
import { effectScope, nextTick, shallowRef, type EffectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type {
  DecompileProject,
  JavaAnalysisFinding,
  JavaAnalysisRun,
} from '@/api/types'
import { useJavaAnalysis } from '@/composables/useJavaAnalysis'

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
  taskId = 'task-1',
  overrides: Partial<DecompileProject> = {},
): DecompileProject {
  return {
    id,
    task_id: taskId,
    job_id: `job-${id}`,
    file_node_id: `file-${id}`,
    target_path: `/app/${id}.jar`,
    layout_version: 'project-v1',
    source_kind: 'java',
    language: 'mixed',
    engine_name: 'cfr',
    engine_version: '0.152',
    status: 'complete',
    source_file_count: 2,
    symbol_count: 4,
    source_size_bytes: 4096,
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
    ...overrides,
  }
}

function run(
  status: JavaAnalysisRun['status'] = 'succeeded',
  taskId = 'task-1',
  projectId = 'project-java',
): JavaAnalysisRun {
  const terminal = ['succeeded', 'partial', 'failed', 'cancelled'].includes(status)
  const completed = status === 'succeeded' || status === 'partial'
  return {
    id: `run-${taskId}-${projectId}`,
    task_id: taskId,
    source_project_id: projectId,
    source_project: {
      id: projectId,
      target_path: `/app/${projectId}.jar`,
      status: 'complete',
      engine_name: 'cfr',
      engine_version: '0.152',
    },
    job_id: `job-${taskId}-${projectId}`,
    status,
    analyzer_name: 'binaryscan-java-checker',
    analyzer_version: '0.1.0',
    ruleset_version: completed ? 'java-rules-v1' : '',
    source_manifest_sha256: 'a'.repeat(64),
    input_sha256: 'b'.repeat(64),
    bundle_sha256: status === 'queued' ? '' : 'c'.repeat(64),
    source_size_bytes: 4096,
    source_file_count: 2,
    finding_count: completed ? 1 : 0,
    diagnostic_count: 0,
    coverage: {
      total_files: 2,
      analyzed_files: completed ? 2 : 0,
      parsed_files: completed ? 2 : 0,
      recovered_files: 0,
      failed_files: 0,
    },
    severity_counts: {
      LOW: 0,
      MEDIUM: 0,
      HIGH: completed ? 1 : 0,
      CRITICAL: 0,
    },
    findings_truncated: false,
    diagnostics_truncated: false,
    error_code: null,
    error_message: null,
    started_at: status === 'queued' ? null : '2026-08-10T01:02:00Z',
    completed_at: terminal ? '2026-08-10T01:03:00Z' : null,
    created_at: '2026-08-10T01:02:00Z',
    updated_at: '2026-08-10T01:03:00Z',
  }
}

const finding: JavaAnalysisFinding = {
  id: '1',
  cwe: 'CWE-89',
  rule_id: 'java-sql-injection',
  severity: 'HIGH',
  file: {
    result_id: 'result-1',
    logical_path: 'src/main/java/app/QueryService.java',
    binary_name: 'app.QueryService',
  },
  callable: {
    kind: 'method',
    type_name: 'app.QueryService',
    name: 'lookup',
    signature: 'lookup(java.lang.String)',
  },
  location: { start_line: 12, start_column: 5, end_line: 12, end_column: 30 },
  message: 'SQL query includes untrusted input.',
  snippet: 'statement.executeQuery(sql);',
  snippet_start_line: 11,
}

describe('useJavaAnalysis', () => {
  afterEach(() => {
    for (const scope of scopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
  })

  it('selects only eligible Java projects and sends file/callable filters', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-java'),
        project('project-legacy', 'task-1', { layout_version: 'legacy-v1' }),
        project('project-c', 'task-1', {
          source_kind: 'ghidra-pseudoc',
          language: 'c',
        }),
      ],
    })
    vi.spyOn(api, 'listJavaAnalysisRuns').mockResolvedValue({ items: [run()] })
    const listFindings = vi
      .spyOn(api, 'listJavaAnalysisFindings')
      .mockResolvedValue({ items: [finding] })

    const state = inScope(() =>
      useJavaAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual(['project-java'])
    state.applyFilters({
      cwe: ' cwe-89 ',
      severity: 'HIGH',
      file: ' src/main/java ',
      callable: ' QueryService ',
    })
    await flushPromises()

    expect(listFindings).toHaveBeenLastCalledWith(
      'task-1',
      run().id,
      {
        page_size: 100,
        cwe: 'CWE-89',
        severity: 'HIGH',
        file: 'src/main/java',
        callable: 'QueryService',
      },
    )
  })

  it('serializes create and project switching while the request is busy', async () => {
    const pending = deferred<JavaAnalysisRun>()
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-java'), project('project-b')],
    })
    vi.spyOn(api, 'listJavaAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listJavaAnalysisFindings').mockResolvedValue({ items: [] })
    const create = vi
      .spyOn(api, 'createJavaAnalysisRun')
      .mockReturnValue(pending.promise)
    const state = inScope(() =>
      useJavaAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    const creation = state.createRun()
    await flushPromises()
    await state.createRun()
    await state.selectProject('project-b')

    expect(create).toHaveBeenCalledOnce()
    expect(create.mock.calls[0]?.[2]).toMatch(/^java-analysis-/)
    expect(state.busy.value).toBe(true)
    expect(state.selectedProjectId.value).toBe('project-java')

    pending.resolve(run('queued'))
    await creation
    expect(state.busy.value).toBe(false)
  })

  it('ignores a delayed create response after the task changes', async () => {
    const pending = deferred<JavaAnalysisRun>()
    const taskId = shallowRef('task-1')
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => ({
      items: [project(task === 'task-1' ? 'project-java' : 'project-task-2', task)],
    }))
    vi.spyOn(api, 'listJavaAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listJavaAnalysisFindings').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'createJavaAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() =>
      useJavaAnalysis({ taskId, userRole: 'operator' }),
    )
    await flushPromises()

    const creation = state.createRun()
    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    pending.resolve(run('queued'))
    await creation

    expect(state.selectedProjectId.value).toBe('project-task-2')
    expect(state.runs.value).toEqual([])
    expect(state.creating.value).toBe(false)
  })

  it('keeps a new task intact when an old delete response completes', async () => {
    const pending = deferred<void>()
    const taskId = shallowRef('task-1')
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => ({
      items: [project(task === 'task-1' ? 'project-java' : 'project-task-2', task)],
    }))
    vi.spyOn(api, 'listJavaAnalysisRuns').mockImplementation(async (task) => ({
      items: task === 'task-1' ? [run()] : [],
    }))
    vi.spyOn(api, 'listJavaAnalysisFindings').mockResolvedValue({ items: [finding] })
    vi.spyOn(api, 'deleteJavaAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() =>
      useJavaAnalysis({ taskId, userRole: 'operator' }),
    )
    await flushPromises()

    const deletion = state.deleteRun()
    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    pending.resolve()
    await deletion

    expect(state.selectedProjectId.value).toBe('project-task-2')
    expect(state.runs.value).toEqual([])
    expect(state.deleting.value).toBe(false)
  })

  it('blocks project switching during cancellation and ignores a stale cancel response', async () => {
    const pending = deferred<JavaAnalysisRun>()
    const taskId = shallowRef('task-1')
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => ({
      items:
        task === 'task-1'
          ? [project('project-java'), project('project-b')]
          : [project('project-task-2', 'task-2')],
    }))
    vi.spyOn(api, 'listJavaAnalysisRuns').mockImplementation(async (task) => ({
      items: task === 'task-1' ? [run('running')] : [],
    }))
    vi.spyOn(api, 'listJavaAnalysisFindings').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'cancelJavaAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() =>
      useJavaAnalysis({ taskId, userRole: 'operator' }),
    )
    await flushPromises()

    const cancellation = state.cancelRun()
    await state.selectProject('project-b')
    expect(state.selectedProjectId.value).toBe('project-java')

    taskId.value = 'task-2'
    await nextTick()
    await flushPromises()
    pending.resolve(run('cancel_requested'))
    await cancellation

    expect(state.selectedProjectId.value).toBe('project-task-2')
    expect(state.runs.value).toEqual([])
    expect(state.cancelling.value).toBe(false)
  })

  it('keeps the newest project when older run loading finishes later', async () => {
    const projectBRuns = deferred<{ items: JavaAnalysisRun[] }>()
    const projectCRun = run('succeeded', 'task-1', 'project-c')
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-java'),
        project('project-b'),
        project('project-c'),
      ],
    })
    vi.spyOn(api, 'listJavaAnalysisRuns').mockImplementation(
      async (_taskId, query = {}) => {
        if (query.project_id === 'project-b') return projectBRuns.promise
        if (query.project_id === 'project-c') return { items: [projectCRun] }
        return { items: [] }
      },
    )
    vi.spyOn(api, 'listJavaAnalysisFindings').mockResolvedValue({ items: [] })
    const state = inScope(() =>
      useJavaAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    const switchToB = state.selectProject('project-b')
    await flushPromises()
    const switchToC = state.selectProject('project-c')
    await flushPromises()
    projectBRuns.resolve({ items: [run('succeeded', 'task-1', 'project-b')] })
    await Promise.all([switchToB, switchToC])

    expect(state.selectedProjectId.value).toBe('project-c')
    expect(state.runs.value).toEqual([projectCRun])
  })
})
