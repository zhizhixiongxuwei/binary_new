import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  FileDecompileRequest,
  FileNodeDetail,
} from '@/api/types'
import FileNodeDecompileAction from '@/components/tasks/FileNodeDecompileAction.vue'
import { resolveSampleRetention } from '@/utils/sampleRetention'

const NOW = new Date('2026-07-31T00:00:00.000Z')
const available = resolveSampleRetention({
  sampleExpiresAt: '2026-08-30T00:00:00.000Z',
  sampleDeletedAt: null,
  now: NOW,
})
const queuedRequest: FileDecompileRequest = {
  request_id: '423e4567-e89b-42d3-a456-426614174003',
  job_id: '323e4567-e89b-42d3-a456-426614174002',
  task_id: '123e4567-e89b-42d3-a456-426614174000',
  file_node_id: '42',
  target_class: 'native',
  engine_target: 'ghidra',
  status: 'queued',
  created_at: '2026-07-31T01:02:03Z',
}

const ElButtonStub = {
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
      :data-loading="String(loading)"
      @click="$emit('click')"
    ><slot /></button>
  `,
}

function node(overrides: Partial<FileNodeDetail> = {}): FileNodeDetail {
  return {
    id: '42',
    parent_id: null,
    logical_path: '/app.exe',
    display_name: 'app.exe',
    archive_name_id: '',
    node_type: 'file',
    depth: 0,
    format: 'pe32+',
    mime_type: 'application/octet-stream',
    architecture: 'x86_64',
    size_bytes: 4096,
    sha256: 'a'.repeat(64),
    extraction_status: 'indexed',
    error_code: '',
    error_message: '',
    source_container: null,
    has_children: false,
    metadata_json: {},
    source_parent: null,
    ...overrides,
  }
}

function mountAction(
  overrides: Partial<{
    node: FileNodeDetail
    mode: 'live' | 'preview'
    role: 'administrator' | 'operator' | 'reader'
    retention: typeof available
  }> = {},
) {
  return mount(FileNodeDecompileAction, {
    props: {
      taskId: queuedRequest.task_id,
      taskStatus: 'FAILED',
      node: overrides.node ?? node(),
      userRole: overrides.role ?? 'operator',
      mode: overrides.mode ?? 'live',
      sampleRetention: overrides.retention ?? available,
    },
    global: {
      stubs: {
        ElButton: ElButtonStub,
      },
    },
  })
}

describe('FileNodeDecompileAction', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('submits one queued request and reports job/request IDs without claiming completion', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('decompile-intent'),
    })
    let resolveRequest: ((value: FileDecompileRequest) => void) | undefined
    const pendingRequest = new Promise<FileDecompileRequest>((resolve) => {
      resolveRequest = resolve
    })
    const createRequest = vi
      .spyOn(api, 'createFileDecompileRequest')
      .mockReturnValue(pendingRequest)
    const wrapper = mountAction()
    const command = wrapper.get<HTMLButtonElement>(
      '[data-action="decompile-file"]',
    )

    await command.trigger('click')
    await command.trigger('click')

    expect(command.element.disabled).toBe(true)
    expect(command.attributes('data-loading')).toBe('true')
    expect(createRequest).toHaveBeenCalledTimes(1)
    expect(createRequest).toHaveBeenCalledWith(
      queuedRequest.task_id,
      '42',
      { engine_target: 'auto', options: {} },
      'decompile-intent',
    )

    resolveRequest?.(queuedRequest)
    await flushPromises()

    expect(wrapper.text()).toContain('反编译请求已进入队列')
    expect(wrapper.text()).toContain(queuedRequest.request_id)
    expect(wrapper.text()).toContain(queuedRequest.job_id)
    expect(wrapper.text()).toContain('状态将自动刷新')
    expect(wrapper.text()).not.toContain('已执行 Ghidra')
    expect(command.element.disabled).toBe(true)
    await command.trigger('click')
    expect(createRequest).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('polls queued work through running and opens the completed result', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('decompile-poll-intent'),
    })
    vi.spyOn(api, 'createFileDecompileRequest').mockResolvedValue(queuedRequest)
    const getRequest = vi
      .spyOn(api, 'getFileDecompileRequest')
      .mockResolvedValueOnce({ ...queuedRequest, status: 'running' })
      .mockResolvedValueOnce({
        ...queuedRequest,
        status: 'succeeded',
        completed_at: '2026-08-03T22:16:43Z',
      })
    const wrapper = mountAction()
    const command = wrapper.get<HTMLButtonElement>(
      '[data-action="decompile-file"]',
    )

    await command.trigger('click')
    await flushPromises()
    expect(command.text()).toContain('等待处理')

    await vi.advanceTimersByTimeAsync(2_000)
    await flushPromises()
    expect(getRequest).toHaveBeenCalledTimes(1)
    expect(command.text()).toContain('正在反编译')
    expect(wrapper.text()).toContain('反编译引擎正在处理')

    await vi.advanceTimersByTimeAsync(2_000)
    await flushPromises()
    expect(getRequest).toHaveBeenCalledTimes(2)
    expect(command.text()).toContain('查看结果')
    expect(command.element.disabled).toBe(false)
    expect(wrapper.text()).toContain('反编译已完成')
    expect(wrapper.emitted('completed')).toEqual([
      [expect.objectContaining({ job_id: queuedRequest.job_id, status: 'succeeded' })],
    ])
    wrapper.unmount()
  })

  it('shows a terminal Worker failure and allows a fresh manual retry', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('crypto', {
      randomUUID: vi
        .fn()
        .mockReturnValueOnce('decompile-first-intent')
        .mockReturnValueOnce('decompile-retry-intent'),
    })
    const createRequest = vi
      .spyOn(api, 'createFileDecompileRequest')
      .mockResolvedValue(queuedRequest)
    vi.spyOn(api, 'getFileDecompileRequest').mockResolvedValueOnce({
      ...queuedRequest,
      status: 'failed',
      error_code: 'ghidra_execution_failed',
      error_message: 'Ghidra execution failed.',
      completed_at: '2026-08-03T22:16:43Z',
    })
    const wrapper = mountAction()
    const command = wrapper.get<HTMLButtonElement>(
      '[data-action="decompile-file"]',
    )

    await command.trigger('click')
    await flushPromises()
    await vi.advanceTimersByTimeAsync(2_000)
    await flushPromises()

    expect(command.text()).toContain('重新反编译')
    expect(command.element.disabled).toBe(false)
    expect(wrapper.get('[role="alert"]').text()).toContain(
      'Ghidra execution failed.',
    )
    expect(wrapper.emitted('completed')).toBeUndefined()

    await command.trigger('click')
    await flushPromises()
    expect(createRequest.mock.calls.map((call) => call[3])).toEqual([
      'decompile-first-intent',
      'decompile-retry-intent',
    ])
    wrapper.unmount()
  })

  it('reuses the same idempotency key after a failed submission', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('stable-decompile-intent'),
    })
    const createRequest = vi
      .spyOn(api, 'createFileDecompileRequest')
      .mockRejectedValueOnce(
        new ApiError('队列暂时不可用', 503, { code: 'UNAVAILABLE' }),
      )
      .mockResolvedValueOnce(queuedRequest)
    const wrapper = mountAction()
    const command = wrapper.get('[data-action="decompile-file"]')

    await command.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('队列暂时不可用')

    await command.trigger('click')
    await flushPromises()

    expect(createRequest.mock.calls.map((call) => call[3])).toEqual([
      'stable-decompile-intent',
      'stable-decompile-intent',
    ])
    wrapper.unmount()
  })

  it('does not call the facade in preview or unavailable retention states', async () => {
    const createRequest = vi.spyOn(api, 'createFileDecompileRequest')
    const preview = mountAction({ mode: 'preview' })
    const previewCommand = preview.get<HTMLButtonElement>(
      '[data-action="decompile-file"]',
    )
    expect(previewCommand.element.disabled).toBe(true)
    expect(previewCommand.attributes('title')).toContain('界面预览')
    await previewCommand.trigger('click')

    const expired = mountAction({
      retention: resolveSampleRetention({
        sampleExpiresAt: NOW.toISOString(),
        sampleDeletedAt: null,
        now: NOW,
      }),
    })
    const expiredCommand = expired.get<HTMLButtonElement>(
      '[data-action="decompile-file"]',
    )
    expect(expiredCommand.element.disabled).toBe(true)
    expect(expiredCommand.attributes('title')).toContain('样本保留期已到')
    expect(expiredCommand.attributes('aria-describedby')).toBeTruthy()
    await expiredCommand.trigger('click')

    expect(createRequest).not.toHaveBeenCalled()
  })

  it('does not render a command for readers or unsupported nodes', () => {
    expect(mountAction({ role: 'reader' }).html()).not.toContain(
      'data-action="decompile-file"',
    )
    expect(
      mountAction({ node: node({ format: 'zip' }) }).html(),
    ).not.toContain('data-action="decompile-file"')
  })
})
