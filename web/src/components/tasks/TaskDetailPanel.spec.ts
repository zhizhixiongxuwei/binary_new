import { createPinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { CurrentUser, TaskDetail } from '@/api/types'
import TaskDetailPanel from '@/components/tasks/TaskDetailPanel.vue'
import { useSessionStore } from '@/stores/session'

const NOW = new Date('2026-07-31T00:00:00.000Z')

function task(id: string, name: string, inputType = 'archive'): TaskDetail {
  return {
    id,
    name,
    input_type: inputType,
    status: 'SUCCEEDED',
    risk_level: 'NONE',
    progress: 100,
    progress_indeterminate: false,
    creator_id: 'admin-1',
    creator_name: 'Operator',
    tags: [],
    created_at: '2026-07-29T00:00:00Z',
    sample_expires_at: '2099-08-29T00:00:00Z',
    sample_deleted_at: null,
    original_filename: name,
    size_bytes: 42,
    sha256: 'a'.repeat(64),
    current_stage: 'complete',
  }
}

const LifecycleActionBarStub = {
  props: [
    'task',
    'mode',
    'userRole',
    'isCreator',
    'now',
    'pendingAction',
  ],
  emits: ['cancel', 'retry', 'delete', 'extend'],
  template: `
    <section
      data-testid="lifecycle-actions"
      :data-mode="mode"
      :data-role="userRole"
      :data-creator="String(isCreator)"
      :data-pending="pendingAction || ''"
    >
      <button data-action-stub="cancel" @click="$emit('cancel')">cancel</button>
      <button data-action-stub="retry" @click="$emit('retry')">retry</button>
      <button data-action-stub="delete" @click="$emit('delete')">delete</button>
      <button
        data-action-stub="extend"
        @click="$emit('extend', '2099-09-28T00:00:00.000Z')"
      >extend</button>
    </section>
  `,
}

const AnalysisActionsStub = {
  props: ['task', 'node', 'userRole', 'mode', 'sampleRetention'],
  emits: ['openFiles', 'openVulnerabilities', 'decompileCompleted'],
  template: `
    <section data-testid="analysis-actions">
      <button data-testid="open-analysis-files" @click="$emit('openFiles')">files</button>
      <button data-testid="open-trivy-results" @click="$emit('openVulnerabilities')">trivy</button>
      <button
        data-testid="complete-decompile"
        @click="$emit('decompileCompleted', {
          request_id: '423e4567-e89b-42d3-a456-426614174003',
          job_id: '323e4567-e89b-42d3-a456-426614174002',
          task_id: task.id,
          file_node_id: '42',
          target_class: 'native',
          engine_target: 'ghidra',
          status: 'succeeded',
          created_at: '2026-08-03T22:12:39Z',
          completed_at: '2026-08-03T22:16:43Z'
        })"
      >complete decompile</button>
    </section>
  `,
}

function openEventResponse(
  signal?: AbortSignal,
  initialText = '',
): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        if (initialText) {
          controller.enqueue(new TextEncoder().encode(initialText))
        }
        signal?.addEventListener('abort', () => {
          controller.error(new DOMException('aborted', 'AbortError'))
        })
      },
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'text/event-stream' },
    },
  )
}

const administrator: CurrentUser = {
  id: 'admin-1',
  username: 'admin',
  display_name: 'Operator',
  role: 'administrator',
  must_change_password: false,
}

const mountedPanels: Array<{ unmount: () => void }> = []

function mountPanel(
  taskId = 'task-a',
  options: {
    lifecycleActions?: boolean
    realLifecycleActions?: boolean
    useSystemClock?: boolean
    user?: CurrentUser
  } = {},
) {
  if (!vi.isMockFunction(globalThis.fetch)) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        openEventResponse(init?.signal ?? undefined),
      ),
    )
  }
  const pinia = createPinia()
  const session = useSessionStore(pinia)
  session.user = options.user ?? administrator

  const wrapper = mount(TaskDetailPanel, {
    props: {
      taskId,
      ...(options.useSystemClock ? {} : { now: NOW }),
    },
    global: {
      plugins: [pinia],
      stubs: {
        ElButton: {
          inheritAttrs: false,
          props: {
            disabled: { type: Boolean, default: false },
            loading: { type: Boolean, default: false },
          },
          emits: ['click'],
          template: `
            <button
              v-bind="$attrs"
              type="button"
              :disabled="disabled"
              @click="$emit('click')"
            ><slot /></button>
          `,
        },
        ElDialog: true,
        ElInput: true,
        ElProgress: true,
        ElTabs: { template: '<div><slot /></div>' },
        ElTabPane: { template: '<div><slot name="label" /><slot /></div>' },
        FileTreePanel: {
          props: ['taskId'],
          emits: ['nodeDetailChange'],
          template: `
            <div data-testid="file-tree">
              <span data-testid="file-tree-id">{{ taskId }}</span>
            </div>
          `,
        },
        TaskAnalysisActions: AnalysisActionsStub,
        TaskActionBar: options.realLifecycleActions
          ? false
          : options.lifecycleActions
            ? LifecycleActionBarStub
            : true,
      },
    },
  })
  mountedPanels.push(wrapper)
  return wrapper
}

describe('TaskDetailPanel', () => {
  afterEach(() => {
    for (const wrapper of mountedPanels.splice(0)) wrapper.unmount()
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('reloads when the route task changes and ignores the older response', async () => {
    let resolveFirst: ((value: TaskDetail) => void) | undefined
    const firstRequest = new Promise<TaskDetail>((resolve) => {
      resolveFirst = resolve
    })
    const getTask = vi
      .spyOn(api, 'getTask')
      .mockReturnValueOnce(firstRequest)
      .mockResolvedValueOnce(task('task-b', 'second.tar'))

    const wrapper = mountPanel()
    expect(getTask).toHaveBeenCalledWith('task-a')

    await wrapper.setProps({ taskId: 'task-b' })
    await flushPromises()

    expect(getTask).toHaveBeenLastCalledWith('task-b')
    expect(wrapper.text()).toContain('second.tar')
    expect(wrapper.get('[data-testid="file-tree-id"]').text()).toBe('task-b')

    resolveFirst?.(task('task-a', 'first.tar'))
    await flushPromises()

    expect(wrapper.text()).toContain('second.tar')
    expect(wrapper.text()).not.toContain('first.tar')
    expect(wrapper.get('[data-testid="file-tree-id"]').text()).toBe('task-b')
  })

  it('shows a clear warning for partial results', async () => {
    const partial = task('task-partial', 'partial.tar')
    partial.status = 'PARTIAL_SUCCEEDED'
    vi.spyOn(api, 'getTask').mockResolvedValue(partial)

    const wrapper = mountPanel('task-partial')
    await flushPromises()

    expect(wrapper.text()).toContain('检测结果不完整')
    expect(wrapper.text()).toContain('安全限制')
  })

  it('separates decompile and container result workspaces by input type', async () => {
    vi.spyOn(api, 'getTask')
      .mockResolvedValueOnce(task('task-native', 'sample.bin', 'elf64'))
      .mockResolvedValueOnce(task('task-image', 'image.tar', 'docker-tar'))

    const nativeWrapper = mountPanel('task-native')
    await flushPromises()
    expect(
      nativeWrapper.findAll('[data-result-tab]').map((tab) => tab.text()),
    ).toEqual(['文件结构', '反编译', '报告'])

    const imageWrapper = mountPanel('task-image')
    await flushPromises()
    expect(
      imageWrapper.findAll('[data-result-tab]').map((tab) => tab.text()),
    ).toEqual(['文件结构', '容器漏洞', '报告'])
  })

  it('derives creator ownership only from the stable user ID', async () => {
    const operator: CurrentUser = {
      id: 'operator-2',
      username: 'operator-two',
      display_name: 'Operator',
      role: 'operator',
      must_change_password: false,
    }
    const sameNameDifferentID = task('task-not-owned', 'not-owned.exe')
    sameNameDifferentID.creator_id = 'operator-1'
    const differentNameSameID = task('task-owned', 'owned.exe')
    differentNameSameID.creator_id = operator.id
    differentNameSameID.creator_name = 'Previous display name'
    vi.spyOn(api, 'getTask')
      .mockResolvedValueOnce(sameNameDifferentID)
      .mockResolvedValueOnce(differentNameSameID)

    const notOwned = mountPanel('task-not-owned', {
      lifecycleActions: true,
      user: operator,
    })
    await flushPromises()
    expect(
      notOwned
        .get('[data-testid="lifecycle-actions"]')
        .attributes('data-creator'),
    ).toBe('false')

    const owned = mountPanel('task-owned', {
      lifecycleActions: true,
      user: operator,
    })
    await flushPromises()
    expect(
      owned.get('[data-testid="lifecycle-actions"]').attributes('data-creator'),
    ).toBe('true')
  })

  it('keeps primary analysis commands outside compact detail tabs', async () => {
    vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-command-order', 'command-order.exe'),
    )
    const wrapper = mountPanel('task-command-order', {
      lifecycleActions: true,
    })
    await flushPromises()

    const progressTab = wrapper.get('[data-detail-tab="progress"]')
    const resultsTab = wrapper.get('[data-detail-tab="results"]')
    const informationTab = wrapper.get('[data-detail-tab="information"]')
    expect(progressTab.attributes('aria-selected')).toBe('true')
    expect(wrapper.find('.status-band').exists()).toBe(false)

    const resultsPanel = wrapper.get(`#${resultsTab.attributes('aria-controls')}`)
    const informationPanel = wrapper.get(
      `#${informationTab.attributes('aria-controls')}`,
    )
    const analysisActions = wrapper.get('[data-testid="analysis-actions"]')
    expect(analysisActions.element.closest('[role="tabpanel"]')).toBeNull()
    expect(resultsPanel.attributes('hidden')).toBeDefined()
    expect(informationPanel.attributes('hidden')).toBeDefined()
    expect(informationPanel.find('[data-testid="lifecycle-actions"]').exists()).toBe(true)

    await informationTab.trigger('click')
    expect(informationPanel.attributes('hidden')).toBeUndefined()
    expect(informationTab.attributes('aria-selected')).toBe('true')
  })

  it('opens files and Trivy results from the outer analysis commands', async () => {
    vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-analysis-actions', 'analysis.exe'),
    )
    vi.spyOn(api, 'listTaskVulnerabilities').mockResolvedValue({
      summary: {
        total: 0,
        fixable: 0,
        by_severity: {
          UNKNOWN: 0,
          LOW: 0,
          MEDIUM: 0,
          HIGH: 0,
          CRITICAL: 0,
        },
      },
      items: [],
    })
    const wrapper = mountPanel('task-analysis-actions')
    await flushPromises()

    await wrapper.get('[data-testid="open-analysis-files"]').trigger('click')
    expect(
      wrapper.get('[data-detail-tab="results"]').attributes('aria-selected'),
    ).toBe('true')
    expect(
      wrapper.get('[data-result-tab="files"]').attributes('aria-selected'),
    ).toBe('true')

    await wrapper.get('[data-testid="open-trivy-results"]').trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()
    expect(
      wrapper
        .get('[data-result-tab="vulnerabilities"]')
        .attributes('aria-selected'),
    ).toBe('true')
  })

  it('loads live decompile and vulnerability result tabs on demand', async () => {
    const getTask = vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-live', 'live-input.exe'),
    )
    const listDecompileResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValue({ items: [] })
    const listTaskVulnerabilities = vi
      .spyOn(api, 'listTaskVulnerabilities')
      .mockResolvedValue({
        summary: {
          total: 0,
          fixable: 0,
          by_severity: {
            UNKNOWN: 0,
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
          },
        },
        items: [],
      })

    const wrapper = mountPanel('task-live')
    await flushPromises()
    await wrapper
      .get('[role="tab"][data-result-tab="decompile"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(wrapper.text()).toContain('暂无反编译结果')
    expect(listDecompileResults).toHaveBeenCalledWith('task-live', {
      page_size: 100,
    })

    await wrapper.get('[aria-label="刷新反编译历史结果"]').trigger('click')
    await flushPromises()
    expect(listDecompileResults).toHaveBeenCalledTimes(2)

    await wrapper
      .get('[role="tab"][data-result-tab="vulnerabilities"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(wrapper.text()).toContain('未发现容器漏洞')
    expect(listTaskVulnerabilities).toHaveBeenCalledWith('task-live', {
      page_size: 50,
    })
    expect(getTask).toHaveBeenCalledTimes(1)
  })

  it('opens and freshly loads results when a manual decompile completes', async () => {
    vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-decompile-complete', 'gocloc'),
    )
    const listDecompileResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValue({ items: [] })

    const wrapper = mountPanel('task-decompile-complete')
    await flushPromises()
    expect(
      wrapper.get('[role="tab"][data-result-tab="files"]').attributes(
        'aria-selected',
      ),
    ).toBe('true')

    await wrapper.get('[data-testid="complete-decompile"]').trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(
      wrapper.get('[role="tab"][data-result-tab="decompile"]').attributes(
        'aria-selected',
      ),
    ).toBe('true')
    expect(listDecompileResults).toHaveBeenCalledWith(
      'task-decompile-complete',
      { page_size: 100 },
    )
    expect(wrapper.text()).toContain('暂无反编译结果')
  })

  it('loads the live report workspace, generates a format, and refreshes through the tab command', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('report-create-intent'),
    })
    vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-reports', 'report-input.exe'),
    )
    const listTaskReports = vi
      .spyOn(api, 'listTaskReports')
      .mockResolvedValue({ items: [] })
    const createTaskReport = vi
      .spyOn(api, 'createTaskReport')
      .mockResolvedValue({
        id: 'report-json',
        task_id: 'task-reports',
        format: 'json',
        schema_version: '1.1.0',
        status: 'queued',
        sha256: null,
        size_bytes: null,
        error_code: null,
        error_message: null,
        created_at: '2026-07-30T01:00:00Z',
        completed_at: null,
      })

    const wrapper = mountPanel('task-reports')
    await flushPromises()
    await wrapper
      .get('[role="tab"][data-result-tab="reports"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(listTaskReports).toHaveBeenCalledWith('task-reports')
    expect(wrapper.text()).toContain('JSON 报告')
    expect(wrapper.text()).toContain('HTML 报告')
    expect(wrapper.text()).toContain('未生成')

    await wrapper.get('button[aria-label="生成 JSON 报告"]').trigger('click')
    await flushPromises()
    expect(createTaskReport).toHaveBeenCalledWith(
      'task-reports',
      { format: 'json' },
      'report-create-intent',
    )
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain(
      '等待生成',
    )

    await wrapper.get('[aria-label="刷新报告状态"]').trigger('click')
    await flushPromises()
    expect(listTaskReports).toHaveBeenCalledTimes(2)
  })

  it('keeps report generation read-only for an administrator while the task is running', async () => {
    const running = task('task-running-report', 'running-report.exe')
    running.status = 'SCANNING'
    running.progress = 62
    running.current_stage = 'SCANNING'
    vi.spyOn(api, 'getTask').mockResolvedValue(running)
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [] })
    const createTaskReport = vi.spyOn(api, 'createTaskReport')

    const wrapper = mountPanel('task-running-report')
    await flushPromises()
    await wrapper
      .get('[role="tab"][data-result-tab="reports"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(wrapper.text()).toContain(
      '任务完成、部分完成、失败或取消后才能生成报告',
    )
    const generateButtons = wrapper.findAll(
      'button[aria-label^="生成 "][disabled]',
    )
    expect(generateButtons).toHaveLength(2)
    expect(generateButtons[0]?.attributes('title')).toContain('任务完成')

    await generateButtons[0]?.trigger('click')
    expect(createTaskReport).not.toHaveBeenCalled()
  })

  it('marks a task sample as cleaned and keeps retained metadata visible', async () => {
    const expired = task('task-expired', 'expired.exe')
    expired.sample_expires_at = '2020-01-01T00:00:00Z'
    expired.sample_deleted_at = '2020-01-01T00:01:00Z'
    vi.spyOn(api, 'getTask').mockResolvedValue(expired)

    const wrapper = mountPanel('task-expired')
    await flushPromises()

    expect(wrapper.text()).toContain('任务原始样本已清理')
    expect(wrapper.text()).toContain('不再保留可复用样本')
    expect(wrapper.text()).toContain('expired.exe')
    expect(wrapper.text()).not.toContain('下载原始样本')
    expect(wrapper.find('[aria-label="下载原始样本"]').exists()).toBe(false)
  })

  it('does not claim task sample cleanup before the retention sweep completes', async () => {
    const expired = task('task-expiry-pending', 'pending.exe')
    expired.sample_expires_at = '2020-01-01T00:00:00Z'
    vi.spyOn(api, 'getTask').mockResolvedValue(expired)

    const wrapper = mountPanel('task-expiry-pending')
    await flushPromises()

    expect(wrapper.text()).toContain('样本保留期已到')
    expect(wrapper.text()).toContain('等待后台清理')
    expect(wrapper.text()).not.toContain('任务原始样本已清理')
  })

  it('blocks retry while preserving live decompile history and reports after expiry', async () => {
    const expired = task('task-expired-history', 'expired-history.exe')
    expired.input_type = 'pe32+'
    expired.status = 'FAILED'
    expired.sample_expires_at = NOW.toISOString()
    vi.spyOn(api, 'getTask').mockResolvedValue(expired)
    const retryTask = vi.spyOn(api, 'retryTask')
    const listDecompileResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValue({ items: [] })
    const listTaskReports = vi
      .spyOn(api, 'listTaskReports')
      .mockResolvedValue({ items: [] })

    const wrapper = mountPanel('task-expired-history', {
      lifecycleActions: true,
    })
    await flushPromises()

    await wrapper.get('[data-action-stub="retry"]').trigger('click')
    await flushPromises()
    expect(retryTask).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain(
      '样本保留期已到，无法重新检测或发起新的反编译',
    )

    await wrapper
      .get('[role="tab"][data-result-tab="decompile"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(listDecompileResults).toHaveBeenCalledWith(
      'task-expired-history',
      { page_size: 100 },
    )
    expect(wrapper.text()).toContain('当前仍可查看已保存的反编译历史结果')
    expect(
      wrapper.get('button[aria-label="刷新反编译历史结果"]').attributes(
        'disabled',
      ),
    ).toBeUndefined()

    await wrapper
      .get('[role="tab"][data-result-tab="reports"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()

    expect(listTaskReports).toHaveBeenCalledWith('task-expired-history')
    expect(wrapper.text()).toContain('JSON 报告')
    expect(wrapper.text()).toContain('HTML 报告')
  })

  it('disables retry at the expiry boundary without waiting for a server refresh', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    const expiring = task('task-expiry-boundary', 'boundary.exe')
    expiring.status = 'FAILED'
    expiring.sample_expires_at = '2026-07-31T00:00:01.000Z'
    vi.spyOn(api, 'getTask').mockResolvedValue(expiring)

    const wrapper = mountPanel('task-expiry-boundary', {
      realLifecycleActions: true,
      useSystemClock: true,
    })
    await flushPromises()

    const retry = wrapper.get<HTMLButtonElement>('[data-action="retry"]')
    expect(retry.element.disabled).toBe(false)

    await vi.advanceTimersByTimeAsync(1_000)
    await wrapper.vm.$nextTick()

    expect(retry.element.disabled).toBe(true)
    expect(retry.attributes('title')).toContain('样本保留期已到')
  })

  it('applies the persisted task sample cleanup state from SSE before refresh', async () => {
    vi.useFakeTimers()
    const expired = task('task-cleanup-event', 'event-cleanup.exe')
    expired.status = 'FAILED'
    expired.sample_expires_at = '2020-01-01T00:00:00Z'
    const getTask = vi.spyOn(api, 'getTask').mockResolvedValue(expired)
    const cleanupEvent = JSON.stringify({
      sequence: 8,
      type: 'task.sample_deleted',
      stage: null,
      progress: 100,
      progress_indeterminate: false,
      severity: 'info',
      message: 'Task sample retention expired.',
      payload: {
        status: 'FAILED',
        sample_expires_at: '2020-01-01T00:00:00Z',
        sample_deleted_at: '2020-01-01T00:01:00Z',
      },
      created_at: '2020-01-01T00:01:00Z',
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        openEventResponse(
          init?.signal ?? undefined,
          `id: 8\nevent: task.sample_deleted\ndata: ${cleanupEvent}\n\n`,
        ),
      ),
    )

    const wrapper = mountPanel('task-cleanup-event')
    await flushPromises()

    expect(wrapper.text()).toContain('任务原始样本已清理')
    expect(wrapper.text()).not.toContain('保留期已到，等待后台清理')
    expect(getTask).toHaveBeenCalledTimes(1)
  })

  it('submits a live retry once, exposes pending state, and refreshes from the response', async () => {
    const failed = task('task-retry', 'retry.exe')
    failed.status = 'FAILED'
    failed.error_code = 'SCAN_FAILED'
    failed.error_message = '分析失败'
    vi.spyOn(api, 'getTask').mockResolvedValue(failed)
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('retry-intent'),
    })
    let resolveRetry: ((task: TaskDetail) => void) | undefined
    const retryRequest = new Promise<TaskDetail>((resolve) => {
      resolveRetry = resolve
    })
    const retryTask = vi.spyOn(api, 'retryTask').mockReturnValue(retryRequest)
    const wrapper = mountPanel('task-retry', { lifecycleActions: true })
    await flushPromises()

    await wrapper.get('[data-action-stub="retry"]').trigger('click')
    await wrapper.get('[data-action-stub="retry"]').trigger('click')

    expect(retryTask).toHaveBeenCalledTimes(1)
    expect(retryTask).toHaveBeenCalledWith('task-retry', 'retry-intent')
    expect(
      wrapper.get('[data-testid="lifecycle-actions"]').attributes('data-pending'),
    ).toBe('retry')

    const retried: TaskDetail = {
      ...failed,
      status: 'QUEUED',
      progress: 0,
      current_stage: 'QUEUED',
    }
    delete retried.error_code
    delete retried.error_message
    resolveRetry?.(retried)
    await flushPromises()

    expect(wrapper.text()).toContain('重新检测请求已提交')
    expect(wrapper.text()).toContain('尚未收到反编译执行日志')
    expect(
      wrapper.get('[data-testid="lifecycle-actions"]').attributes('data-pending'),
    ).toBe('')
  })

  it('shows a live API error without losing the loaded task', async () => {
    const failed = task('task-error', 'error.exe')
    failed.status = 'FAILED'
    vi.spyOn(api, 'getTask').mockResolvedValue(failed)
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('retry-intent'),
    })
    vi.spyOn(api, 'retryTask').mockRejectedValue(
      new ApiError('任务样本暂不可用', 409, { code: 'SAMPLE_UNAVAILABLE' }),
    )
    const wrapper = mountPanel('task-error', { lifecycleActions: true })
    await flushPromises()

    await wrapper.get('[data-action-stub="retry"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain(
      '重新检测失败：任务样本暂不可用',
    )
    expect(wrapper.text()).toContain('error.exe')
    expect(wrapper.find('.status-band').exists()).toBe(false)
  })

  it('offers a route-neutral return command after a live delete response', async () => {
    const succeeded = task('task-delete', 'delete.exe')
    vi.spyOn(api, 'getTask').mockResolvedValue(succeeded)
    vi.spyOn(api, 'deleteTask').mockResolvedValue({
      ...succeeded,
      status: 'DELETING',
      current_stage: 'DELETING',
    })
    const wrapper = mountPanel('task-delete', { lifecycleActions: true })
    await flushPromises()

    await wrapper.get('[data-action-stub="delete"]').trigger('click')
    await flushPromises()
    const matchingButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('返回任务列表'))
    expect(matchingButton).toBeDefined()
    await matchingButton!.trigger('click')

    expect(wrapper.emitted('returnList')).toHaveLength(1)
  })

  it('merges task events immediately and debounces a non-destructive detail refresh', async () => {
    vi.useFakeTimers()
    const initial = task('task-events', 'events.exe')
    initial.status = 'SCANNING'
    initial.progress = 10
    initial.current_stage = 'IDENTIFYING'
    let resolveRefresh: ((task: TaskDetail) => void) | undefined
    const refresh = new Promise<TaskDetail>((resolve) => {
      resolveRefresh = resolve
    })
    const getTask = vi
      .spyOn(api, 'getTask')
      .mockResolvedValueOnce(initial)
      .mockReturnValueOnce(refresh)
    const firstEvent = JSON.stringify({
      sequence: 1,
      type: 'task.created',
      stage: null,
      progress: null,
      progress_indeterminate: false,
      severity: 'info',
      message: null,
      payload: null,
      created_at: '2026-07-30T08:00:00Z',
    })
    const progressEvent = JSON.stringify({
      sequence: 2,
      type: 'task.progress',
      stage: 'SCANNING',
      progress: 64,
      progress_indeterminate: true,
      severity: 'info',
      message: '<script>raw-tool-output</script>',
      payload: {
        status: 'SCANNING',
        stdout: 'raw-tool-output',
        arbitrary_secret: 'must-not-render',
      },
      created_at: '2026-07-30T08:00:01Z',
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        openEventResponse(
          init?.signal ?? undefined,
          `: heartbeat\r\nid: 18446744073709551614\r\n` +
            `event: task.created\r\ndata: ${firstEvent}\r\n\r\n` +
            `id: 18446744073709551615\r\nevent: task.progress\r\n` +
            `data: ${progressEvent}\r\n\r\n`,
        ),
      ),
    )

    const wrapper = mountPanel('task-events')
    await flushPromises()

    expect(wrapper.text()).toContain('分析扫描')
    expect(wrapper.text()).toContain('计算中')
    expect(wrapper.text()).toContain('实时事件已连接')
    const logRows = wrapper.findAll('.execution-log__item')
    expect(logRows).toHaveLength(2)
    expect(logRows[0]?.text()).toContain('任务已创建')
    expect(logRows[1]?.text()).toContain('任务进度已更新')
    expect(wrapper.text()).not.toContain('raw-tool-output')
    expect(wrapper.text()).not.toContain('must-not-render')
    expect(getTask).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(179)
    expect(getTask).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    await flushPromises()
    expect(getTask).toHaveBeenCalledTimes(2)
    expect(wrapper.find('.task-detail').exists()).toBe(true)
    expect(wrapper.text()).toContain('events.exe')

    resolveRefresh?.({
      ...initial,
      status: 'SUCCEEDED',
      progress: 100,
      current_stage: 'complete',
    })
    await flushPromises()

    expect(wrapper.text()).toContain('complete')
    expect(wrapper.find('.task-detail').exists()).toBe(true)
  })

  it('collects allowlisted analyzer events without refreshing or rendering raw fields', async () => {
    vi.useFakeTimers()
    const initial = task('task-analyzer-events', 'analyzer.exe')
    initial.status = 'SCANNING'
    initial.current_stage = 'SCANNING'
    const getTask = vi.spyOn(api, 'getTask').mockResolvedValue(initial)
    const analyzerEvent = JSON.stringify({
      sequence: 3,
      type: 'decompile.progress',
      stage: 'SCANNING',
      progress: 70,
      progress_indeterminate: false,
      severity: 'info',
      message: 'raw Ghidra stdout must-not-render',
      payload: {
        analyzer: 'ghidra',
        phase: 'running',
        current: 12,
        total: 20,
        elapsed_seconds: 30,
        run_id: 'must-not-render',
        stdout: 'must-not-render',
      },
      created_at: '2026-07-30T08:00:02Z',
    })
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        openEventResponse(
          init?.signal ?? undefined,
          `id: 3\nevent: decompile.progress\ndata: ${analyzerEvent}\n\n`,
        ),
      ),
    )

    const wrapper = mountPanel('task-analyzer-events')
    await flushPromises()

    expect(wrapper.text()).toContain('Ghidra 正在反编译')
    expect(wrapper.text()).toContain('函数 12 / 20 · 已运行 30 秒')
    expect(wrapper.text()).not.toContain('must-not-render')
    await vi.advanceTimersByTimeAsync(200)
    await flushPromises()
    expect(getTask).toHaveBeenCalledTimes(1)
  })

  it('refreshes a mounted decompile result when its completion event arrives', async () => {
    vi.spyOn(api, 'getTask').mockResolvedValue(
      task('task-completed-event', 'completed.exe'),
    )
    const listDecompileResults = vi
      .spyOn(api, 'listDecompileResults')
      .mockResolvedValue({ items: [] })
    let eventController: ReadableStreamDefaultController<Uint8Array> | null = null
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) =>
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              eventController = controller
              init?.signal?.addEventListener('abort', () => {
                controller.error(new DOMException('aborted', 'AbortError'))
              })
            },
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'text/event-stream' },
          },
        ),
      ),
    )

    const wrapper = mountPanel('task-completed-event')
    await flushPromises()
    await wrapper
      .get('[role="tab"][data-result-tab="decompile"]')
      .trigger('click')
    await vi.dynamicImportSettled()
    await flushPromises()
    expect(listDecompileResults).toHaveBeenCalledTimes(1)

    const completedEvent = JSON.stringify({
      sequence: 9,
      type: 'decompile.completed',
      stage: 'SCANNING',
      progress: 100,
      progress_indeterminate: false,
      severity: 'info',
      message: 'raw output is intentionally ignored',
      payload: {
        analyzer: 'ghidra', phase: 'completed', current: 20, total: 20,
      },
      created_at: '2026-07-30T08:00:09Z',
    })
    eventController!.enqueue(new TextEncoder().encode(
      `id: 9\nevent: decompile.completed\ndata: ${completedEvent}\n\n`,
    ))
    await flushPromises()
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('Ghidra 反编译已完成')
    expect(listDecompileResults).toHaveBeenCalledTimes(2)
  })

  it('submits live retention once and applies the server task response', async () => {
    const retained = task('task-retention', 'retention.exe')
    retained.sample_expires_at = '2099-08-29T00:00:00.000Z'
    vi.spyOn(api, 'getTask').mockResolvedValue(retained)
    let resolveRetention: ((task: TaskDetail) => void) | undefined
    const request = new Promise<TaskDetail>((resolve) => {
      resolveRetention = resolve
    })
    const extendTaskRetention = vi
      .spyOn(api, 'extendTaskRetention')
      .mockReturnValue(request)
    const wrapper = mountPanel('task-retention', { lifecycleActions: true })
    await flushPromises()

    await wrapper.get('[data-action-stub="extend"]').trigger('click')
    await wrapper.get('[data-action-stub="extend"]').trigger('click')

    expect(extendTaskRetention).toHaveBeenCalledTimes(1)
    expect(extendTaskRetention).toHaveBeenCalledWith('task-retention', {
      expected_sample_expires_at: '2099-08-29T00:00:00.000Z',
      sample_expires_at: '2099-09-28T00:00:00.000Z',
    })
    expect(
      wrapper.get('[data-testid="lifecycle-actions"]').attributes('data-pending'),
    ).toBe('extend')

    resolveRetention?.({
      ...retained,
      sample_expires_at: '2099-09-28T00:00:00.000Z',
    })
    await flushPromises()

    expect(wrapper.text()).toContain('样本保留期已延长 15 天')
    expect(
      wrapper.get('[data-testid="lifecycle-actions"]').attributes('data-pending'),
    ).toBe('')
  })

  it('keeps task details visible when retention extension fails', async () => {
    const retained = task('task-retention-error', 'retention-error.exe')
    retained.sample_expires_at = '2099-08-29T00:00:00.000Z'
    vi.spyOn(api, 'getTask').mockResolvedValue(retained)
    vi.spyOn(api, 'extendTaskRetention').mockRejectedValue(
      new ApiError('保留期已由其他管理员更新', 409, {
        code: 'RETENTION_CONFLICT',
      }),
    )
    const wrapper = mountPanel('task-retention-error', {
      lifecycleActions: true,
    })
    await flushPromises()

    await wrapper.get('[data-action-stub="extend"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain(
      '延长样本保留期失败：保留期已由其他管理员更新',
    )
    expect(wrapper.text()).toContain('retention-error.exe')
  })
})
