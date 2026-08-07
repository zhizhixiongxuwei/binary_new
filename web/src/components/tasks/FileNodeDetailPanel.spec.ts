import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { FileNodeDetail } from '@/api/types'
import FileNodeDetailPanel from '@/components/tasks/FileNodeDetailPanel.vue'
import { resolveSampleRetention } from '@/utils/sampleRetention'

function fileDetail(overrides: Partial<FileNodeDetail> = {}): FileNodeDetail {
  return {
    id: '11',
    parent_id: '10',
    logical_path: '/firmware.tar/bin/app',
    display_name: 'app',
    archive_name_id: 'b64:YmluL2FwcA==',
    node_type: 'file',
    depth: 2,
    format: 'elf64',
    mime_type: 'application/x-elf',
    architecture: 'x86_64',
    size_bytes: 8192,
    sha256: 'a'.repeat(64),
    extraction_status: 'indexed',
    error_code: '',
    error_message: '',
    source_container: {
      id: '9',
      logical_path: '/firmware.tar',
      format: 'tar',
    },
    has_children: false,
    metadata_json: {
      entry_point: '0x401000',
      flags: ['executable', 'stripped'],
    },
    source_parent: {
      id: '10',
      logical_path: '/firmware.tar/bin',
    },
    ...overrides,
  }
}

function mountPanel(
  fileId: string | null = '11',
  fileName = 'app',
  sampleRetention = resolveSampleRetention({
    sampleExpiresAt: '2099-08-29T00:00:00.000Z',
    sampleDeletedAt: null,
    now: new Date('2026-07-31T00:00:00.000Z'),
  }),
) {
  return mount(FileNodeDetailPanel, {
    props: {
      taskId: 'task-1',
      fileId,
      fileName,
      sampleRetention,
    },
    global: {
      stubs: {
        ElButton: {
          emits: ['click'],
          template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
        },
      },
    },
  })
}

describe('FileNodeDetailPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('stays idle until a file node is selected', async () => {
    const getDetail = vi.spyOn(api, 'getTaskFile')
    const wrapper = mountPanel(null, '')
    await flushPromises()

    expect(getDetail).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('未选择文件节点')
    expect(wrapper.find('button[aria-label="关闭文件详情"]').exists()).toBe(false)
  })

  it('renders the parent, core attributes, diagnostics and safe structured metadata', async () => {
    const payload = {
      ...fileDetail({
        error_code: 'binary_truncated',
        error_message: '程序头不完整',
        metadata_json: {
          title: '<img src=x onerror=alert(1)>',
          nested: {
            entry_point: '0x401000',
            storage_key: 'blobs/sha256/private',
          },
        },
      }),
      storage_key: 'blobs/sha256/must-not-render',
    }
    vi.spyOn(api, 'getTaskFile').mockResolvedValue(payload)

    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.text()).toContain('/firmware.tar/bin/app')
    expect(wrapper.text()).toContain('/firmware.tar/bin')
    expect(wrapper.text()).toContain('来源容器')
    expect(wrapper.text()).toContain('/firmware.tar')
    expect(
      wrapper.get('button[aria-label="打开来源容器 /firmware.tar"]').attributes(
        'title',
      ),
    ).toContain('/firmware.tar')
    expect(wrapper.text()).toContain('application/x-elf')
    expect(wrapper.text()).toContain('x86_64')
    expect(wrapper.text()).toContain('8 KB')
    expect(wrapper.text()).toContain('binary_truncated')
    expect(wrapper.text()).toContain('程序头不完整')
    expect(wrapper.text()).toContain('entry_point')
    expect(wrapper.html()).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect(wrapper.html()).not.toContain('<img src=x')
    expect(wrapper.text()).not.toContain('storage_key')
    expect(wrapper.text()).not.toContain('blobs/sha256')
  })

  it('emits a navigable source container and keeps a long path in title', async () => {
    const longPath = `/${'nested-archive/'.repeat(24)}rootfs.ext4`
    const source = {
      id: '9',
      logical_path: longPath,
      format: 'ext4',
    }
    vi.spyOn(api, 'getTaskFile').mockResolvedValue(
      fileDetail({ source_container: source }),
    )

    const wrapper = mountPanel()
    await flushPromises()

    const path = wrapper.get('.source-container__identity strong')
    expect(path.attributes('title')).toBe(longPath)
    expect(path.text()).toBe(longPath)
    const command = wrapper.get(
      `button[aria-label="打开来源容器 ${longPath}"]`,
    )
    await command.trigger('click')

    expect(wrapper.emitted('openSourceContainer')).toEqual([[source]])
  })

  it('identifies a root input without offering a source command', async () => {
    vi.spyOn(api, 'getTaskFile').mockResolvedValue(
      fileDetail({
        id: '1',
        parent_id: null,
        logical_path: '/firmware.tar',
        display_name: 'firmware.tar',
        archive_name_id: '',
        depth: 0,
        source_container: null,
        source_parent: null,
      }),
    )

    const wrapper = mountPanel('1', 'firmware.tar')
    await flushPromises()

    expect(wrapper.text()).toContain('根输入样本')
    expect(wrapper.text()).toContain('无来源容器')
    expect(wrapper.find('.source-container__command').exists()).toBe(false)
  })

  it('retries a failed request and emits close without hiding the error reason', async () => {
    const getDetail = vi
      .spyOn(api, 'getTaskFile')
      .mockRejectedValueOnce(new ApiError('节点详情暂时不可用', 503))
      .mockResolvedValueOnce(
        fileDetail({
          extraction_status: 'failed',
          error_code: 'archive_corrupt',
          error_message: '归档成员损坏',
        }),
      )

    const wrapper = mountPanel()
    await flushPromises()
    expect(wrapper.text()).toContain('节点详情暂时不可用')

    const retry = wrapper.findAll('button').find((button) => button.text().includes('重试'))
    if (!retry) throw new Error('retry button not found')
    await retry.trigger('click')
    await flushPromises()

    expect(getDetail).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('archive_corrupt')
    expect(wrapper.text()).toContain('归档成员损坏')

    await wrapper.get('button[aria-label="关闭文件详情"]').trigger('click')
    expect(wrapper.emitted('close')).toHaveLength(1)
  })

  it('ignores an older response after the selected node changes', async () => {
    let resolveFirst: ((value: FileNodeDetail) => void) | undefined
    const firstRequest = new Promise<FileNodeDetail>((resolve) => {
      resolveFirst = resolve
    })
    const getDetail = vi
      .spyOn(api, 'getTaskFile')
      .mockReturnValueOnce(firstRequest)
      .mockResolvedValueOnce(
        fileDetail({
          id: '12',
          logical_path: '/second.bin',
          display_name: 'second.bin',
          source_parent: null,
        }),
      )

    const wrapper = mountPanel('11', 'first.bin')
    expect(getDetail).toHaveBeenCalledWith('task-1', '11')
    expect(wrapper.text()).toContain('正在读取节点详情')

    await wrapper.setProps({ fileId: '12', fileName: 'second.bin' })
    await flushPromises()

    expect(getDetail).toHaveBeenLastCalledWith('task-1', '12')
    expect(wrapper.text()).toContain('/second.bin')

    resolveFirst?.(
      fileDetail({
        id: '11',
        logical_path: '/first.bin',
        display_name: 'first.bin',
      }),
    )
    await flushPromises()

    expect(wrapper.text()).toContain('/second.bin')
    expect(wrapper.text()).not.toContain('/first.bin')
  })

  it('keeps retained file details readable while explaining the analysis lock', async () => {
    vi.spyOn(api, 'getTaskFile').mockResolvedValue(fileDetail())
    const retention = resolveSampleRetention({
      sampleExpiresAt: '2026-07-31T00:00:00.000Z',
      sampleDeletedAt: null,
      now: new Date('2026-07-31T00:00:00.000Z'),
    })

    const wrapper = mountPanel('11', 'app', retention)
    await flushPromises()

    const notice = wrapper.get('.sample-retention-notice')
    expect(notice.attributes('title')).toContain('无法重新检测或发起新的反编译')
    expect(notice.text()).toContain('当前仍可查看已保存的文件详情')
    expect(wrapper.text()).toContain('/firmware.tar/bin/app')
    expect(wrapper.text()).toContain('结构化元数据')
  })

  it('publishes the loaded node detail and clears the target before selection changes', async () => {
    const first = fileDetail()
    const second = fileDetail({ id: '12', display_name: 'second.bin' })
    vi.spyOn(api, 'getTaskFile')
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second)
    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.emitted('detailChange')).toContainEqual([first])

    await wrapper.setProps({ fileId: '12', fileName: 'second.bin' })
    await flushPromises()

    const events = wrapper.emitted('detailChange') ?? []
    expect(events).toContainEqual([null])
    expect(events).toContainEqual([second])
  })
})
