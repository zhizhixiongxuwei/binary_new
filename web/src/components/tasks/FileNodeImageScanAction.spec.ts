import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  FileNodeDetail,
  ManualImageScanRequest,
} from '@/api/types'
import FileNodeImageScanAction from '@/components/tasks/FileNodeImageScanAction.vue'
import { resolveSampleRetention } from '@/utils/sampleRetention'

const NOW = new Date('2026-07-31T00:00:00.000Z')
const available = resolveSampleRetention({
  sampleExpiresAt: '2026-08-30T00:00:00.000Z',
  sampleDeletedAt: null,
  now: NOW,
})
const queuedRequest: ManualImageScanRequest = {
  job_id: '323e4567-e89b-42d3-a456-426614174002',
  task_id: '123e4567-e89b-42d3-a456-426614174000',
  file_node_id: '42',
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
    parent_id: '41',
    logical_path: '/bundle/nested-image.tar',
    display_name: 'nested-image.tar',
    archive_name_id: '',
    node_type: 'file',
    depth: 10,
    format: 'oci-tar',
    mime_type: 'application/x-tar',
    architecture: 'linux/amd64',
    size_bytes: 4096,
    sha256: 'a'.repeat(64),
    extraction_status: 'limit_reached',
    error_code: 'max_auto_container_images',
    error_message: '自动镜像数量上限已达到',
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
    taskStatus: 'SCANNING' | 'PARTIAL_SUCCEEDED' | 'SUCCEEDED'
    mode: 'live' | 'preview'
    role: 'administrator' | 'operator' | 'reader'
    retention: typeof available
  }> = {},
) {
  return mount(FileNodeImageScanAction, {
    props: {
      taskId: queuedRequest.task_id,
      taskStatus: overrides.taskStatus ?? 'PARTIAL_SUCCEEDED',
      node: overrides.node ?? node(),
      userRole: overrides.role ?? 'operator',
      mode: overrides.mode ?? 'live',
      sampleRetention: overrides.retention ?? available,
    },
    global: { stubs: { ElButton: ElButtonStub } },
  })
}

describe('FileNodeImageScanAction', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('queues one request and does not claim Trivy has completed', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('manual-image-intent'),
    })
    let resolveRequest:
      | ((value: ManualImageScanRequest) => void)
      | undefined
    const pendingRequest = new Promise<ManualImageScanRequest>((resolve) => {
      resolveRequest = resolve
    })
    const createRequest = vi
      .spyOn(api, 'createManualImageScanRequest')
      .mockReturnValue(pendingRequest)
    const wrapper = mountAction()
    const command = wrapper.get<HTMLButtonElement>(
      '[data-action="scan-nested-image"]',
    )

    await command.trigger('click')
    await command.trigger('click')

    expect(command.element.disabled).toBe(true)
    expect(command.attributes('data-loading')).toBe('true')
    expect(createRequest).toHaveBeenCalledTimes(1)
    expect(createRequest).toHaveBeenCalledWith(
      queuedRequest.task_id,
      '42',
      'manual-image-intent',
    )

    resolveRequest?.(queuedRequest)
    await flushPromises()

    expect(wrapper.text()).toContain('镜像检测请求已进入队列')
    expect(wrapper.text()).toContain(queuedRequest.job_id)
    expect(wrapper.text()).toContain('尚未完成 Trivy 检测')
    expect(wrapper.text()).not.toContain('检测已完成')
    expect(command.element.disabled).toBe(true)
  })

  it('shows a prominent root-image Trivy command', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('root-image-intent'),
    })
    const createRequest = vi
      .spyOn(api, 'createManualImageScanRequest')
      .mockResolvedValue(queuedRequest)
    const wrapper = mountAction({
      taskStatus: 'SUCCEEDED',
      node: node({
        parent_id: null,
        depth: 0,
        extraction_status: 'indexed',
        error_code: '',
      }),
    })

    const command = wrapper.get('[data-action="scan-root-image"]')
    expect(wrapper.text()).toContain('Trivy 镜像检测')
    expect(command.text()).toContain('开始 Trivy 检测')
    await command.trigger('click')
    await flushPromises()

    expect(createRequest).toHaveBeenCalledWith(
      queuedRequest.task_id,
      '42',
      'root-image-intent',
    )
  })

  it('reuses the idempotency key after a failed submission', async () => {
    vi.stubGlobal('crypto', {
      randomUUID: vi.fn().mockReturnValue('stable-image-intent'),
    })
    const createRequest = vi
      .spyOn(api, 'createManualImageScanRequest')
      .mockRejectedValueOnce(
        new ApiError('镜像队列暂时不可用', 503, { code: 'UNAVAILABLE' }),
      )
      .mockResolvedValueOnce(queuedRequest)
    const wrapper = mountAction()
    const command = wrapper.get('[data-action="scan-nested-image"]')

    await command.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('镜像队列暂时不可用')

    await command.trigger('click')
    await flushPromises()
    expect(createRequest.mock.calls.map((call) => call[2])).toEqual([
      'stable-image-intent',
      'stable-image-intent',
    ])
  })

  it('disables preview and expired samples without calling the API', async () => {
    const createRequest = vi.spyOn(api, 'createManualImageScanRequest')
    const preview = mountAction({ mode: 'preview' })
    const previewCommand = preview.get<HTMLButtonElement>(
      '[data-action="scan-nested-image"]',
    )
    expect(previewCommand.element.disabled).toBe(true)
    expect(previewCommand.attributes('title')).toContain('界面预览')

    const expired = mountAction({
      retention: resolveSampleRetention({
        sampleExpiresAt: NOW.toISOString(),
        sampleDeletedAt: null,
        now: NOW,
      }),
    })
    const expiredCommand = expired.get<HTMLButtonElement>(
      '[data-action="scan-nested-image"]',
    )
    expect(expiredCommand.element.disabled).toBe(true)
    expect(expiredCommand.attributes('title')).toContain('样本保留期已到')

    await previewCommand.trigger('click')
    await expiredCommand.trigger('click')
    expect(createRequest).not.toHaveBeenCalled()
  })

  it('does not render for readers or nodes that were not skipped by the limit', () => {
    expect(mountAction({ role: 'reader' }).html()).not.toContain(
      'data-action="scan-nested-image"',
    )
    expect(
      mountAction({ node: node({ error_code: '' }) }).html(),
    ).not.toContain('data-action="scan-nested-image"')
  })
})
