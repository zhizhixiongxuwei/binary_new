import { flushPromises } from '@vue/test-utils'
import { effectScope, shallowRef, type EffectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type {
  DecompileProject,
  PythonAnalysisFinding,
  PythonAnalysisRun,
} from '@/api/types'
import { usePythonAnalysis } from '@/composables/usePythonAnalysis'

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
    target_path: `/app/${id}.py`,
    layout_version: 'project-v1',
    source_kind: 'python',
    language: 'python',
    engine_name: 'pycdc',
    engine_version: '0.1.0',
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
  status: PythonAnalysisRun['status'] = 'succeeded',
  taskId = 'task-1',
  projectId = 'project-python',
): PythonAnalysisRun {
  const terminal = ['succeeded', 'partial', 'failed', 'cancelled'].includes(status)
  const completed = status === 'succeeded' || status === 'partial'
  return {
    id: `run-${taskId}-${projectId}`,
    task_id: taskId,
    source_project_id: projectId,
    source_project: {
      id: projectId,
      target_path: `/app/${projectId}.py`,
      status: 'complete',
      engine_name: 'pycdc',
      engine_version: '0.1.0',
    },
    job_id: `job-${taskId}-${projectId}`,
    status,
    analyzer_name: 'binaryscan-python-checker',
    analyzer_version: '0.1.0',
    ruleset_version: completed ? 'python-rules-v1' : '',
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

const finding: PythonAnalysisFinding = {
  id: '1',
  cwe: 'CWE-94',
  rule_id: 'python-eval-injection',
  severity: 'HIGH',
  file: {
    result_id: 'result-1',
    logical_path: 'src/main/python/app/runner.py',
    binary_name: 'app.runner',
  },
  callable: {
    kind: 'function',
    type_name: 'app.runner',
    name: 'execute',
    signature: 'execute(code)',
  },
  location: { start_line: 12, start_column: 5, end_line: 12, end_column: 30 },
  message: 'Dynamic code execution includes untrusted input.',
  snippet: 'eval(code)',
  snippet_start_line: 11,
}

describe('usePythonAnalysis', () => {
  afterEach(() => {
    for (const scope of scopes.splice(0)) scope.stop()
    vi.restoreAllMocks()
  })

  it('selects only eligible Python projects (pyc source_kind=python)', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-python'),
        project('project-python-mixed', 'task-1', { language: 'mixed' }),
        project('project-java', 'task-1', {
          source_kind: 'java',
          language: 'java',
        }),
        project('project-c', 'task-1', {
          source_kind: 'ghidra-pseudoc',
          language: 'c',
        }),
        project('project-legacy', 'task-1', { layout_version: 'legacy-v1' }),
        project('project-bytecode-only', 'task-1', {
          status: 'bytecode_only',
        }),
        project('project-no-manifest', 'task-1', {
          manifest_available: false,
        }),
      ],
    })
    vi.spyOn(api, 'listPythonAnalysisRuns').mockResolvedValue({ items: [run()] })
    vi.spyOn(api, 'listPythonAnalysisFindings').mockResolvedValue({
      items: [finding],
    })

    const state = inScope(() =>
      usePythonAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    expect(state.projects.value.map(({ id }) => id)).toEqual([
      'project-python',
      'project-python-mixed',
    ])
  })

  it('sends cwe/severity/file/callable filters to the findings endpoint', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-python')],
    })
    vi.spyOn(api, 'listPythonAnalysisRuns').mockResolvedValue({ items: [run()] })
    const listFindings = vi
      .spyOn(api, 'listPythonAnalysisFindings')
      .mockResolvedValue({ items: [finding] })

    const state = inScope(() =>
      usePythonAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    state.applyFilters({
      cwe: ' cwe-94 ',
      severity: 'HIGH',
      file: ' src/main/python ',
      callable: ' execute ',
    })
    await flushPromises()

    expect(listFindings).toHaveBeenLastCalledWith(
      'task-1',
      run().id,
      {
        page_size: 100,
        cwe: 'CWE-94',
        severity: 'HIGH',
        file: 'src/main/python',
        callable: 'execute',
      },
    )
  })

  it('serializes create while the request is busy', async () => {
    const pending = deferred<PythonAnalysisRun>()
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-python'), project('project-b')],
    })
    vi.spyOn(api, 'listPythonAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listPythonAnalysisFindings').mockResolvedValue({ items: [] })
    const create = vi
      .spyOn(api, 'createPythonAnalysisRun')
      .mockReturnValue(pending.promise)
    const state = inScope(() =>
      usePythonAnalysis({ taskId: 'task-1', userRole: 'operator' }),
    )
    await flushPromises()

    const creation = state.createRun()
    await flushPromises()
    await state.createRun()
    await state.selectProject('project-b')

    expect(create).toHaveBeenCalledOnce()
    expect(create.mock.calls[0]?.[2]).toMatch(/^python-analysis-/)
    expect(state.busy.value).toBe(true)
    expect(state.selectedProjectId.value).toBe('project-python')

    pending.resolve(run('queued'))
    await creation
    expect(state.busy.value).toBe(false)
  })

  it('ignores a delayed create response after the task changes', async () => {
    const pending = deferred<PythonAnalysisRun>()
    const taskId = shallowRef('task-1')
    vi.spyOn(api, 'listDecompileProjects').mockImplementation(async (task) => ({
      items: [project(task === 'task-1' ? 'project-python' : 'project-task-2', task)],
    }))
    vi.spyOn(api, 'listPythonAnalysisRuns').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'listPythonAnalysisFindings').mockResolvedValue({ items: [] })
    vi.spyOn(api, 'createPythonAnalysisRun').mockReturnValue(pending.promise)
    const state = inScope(() =>
      usePythonAnalysis({ taskId, userRole: 'operator' }),
    )
    await flushPromises()

    const creation = state.createRun()
    taskId.value = 'task-2'
    await flushPromises()
    pending.resolve(run('queued'))
    await creation

    expect(state.selectedProjectId.value).toBe('project-task-2')
    expect(state.runs.value).toEqual([])
    expect(state.creating.value).toBe(false)
  })
})
