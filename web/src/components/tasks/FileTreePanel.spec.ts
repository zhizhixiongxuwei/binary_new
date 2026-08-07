import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  FileNode,
  FileNodeDetail,
  FileNodePage,
} from '@/api/types'
import FileTreePanel from '@/components/tasks/FileTreePanel.vue'
import { resolveSampleRetention, type SampleRetentionSnapshot } from '@/utils/sampleRetention'

function fileNode(overrides: Partial<FileNode> = {}): FileNode {
  return {
    id: '18446744073709551610',
    parent_id: null,
    logical_path: '/firmware.tar',
    display_name: 'firmware.tar',
    archive_name_id: '',
    node_type: 'file',
    depth: 0,
    format: 'tar',
    mime_type: 'application/x-tar',
    architecture: '',
    size_bytes: 8192,
    sha256: 'a'.repeat(64),
    extraction_status: 'extracted',
    error_code: '',
    error_message: '',
    source_container: null,
    has_children: true,
    ...overrides,
  }
}

function page(items: FileNode[], nextCursor?: string): FileNodePage {
  return {
    items,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  }
}

function mountPanel(
  props: Partial<{
    sampleRetention: SampleRetentionSnapshot | null
  }> = {},
) {
  return mount(FileTreePanel, {
    props: { taskId: 'task-1', ...props },
    global: {
      stubs: {
        ElButton: {
          template: '<button type="button"><slot /></button>',
        },
      },
    },
  })
}

function buttonWithText(
  wrapper: ReturnType<typeof mountPanel>,
  text: string,
): ReturnType<typeof wrapper.get> {
  const button = wrapper.findAll('button').find((candidate) => candidate.text().includes(text))
  if (!button) throw new Error(`button containing ${text} was not found`)
  return button
}

describe('FileTreePanel', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('loads children only after expansion and paginates that parent with its cursor', async () => {
    const root = fileNode()
    const firstChild = fileNode({
      id: '18446744073709551611',
      parent_id: root.id,
      logical_path: '/firmware.tar/bin',
      display_name: 'bin',
      node_type: 'directory',
      depth: 1,
      format: '',
      size_bytes: null,
      has_children: true,
    })
    const secondChild = fileNode({
      id: '18446744073709551612',
      parent_id: root.id,
      logical_path: '/firmware.tar/etc',
      display_name: 'etc',
      node_type: 'directory',
      depth: 1,
      format: '',
      size_bytes: null,
      has_children: false,
    })
    const listSpy = vi
      .spyOn(api, 'listTaskFiles')
      .mockResolvedValueOnce(page([root]))
      .mockResolvedValueOnce(page([firstChild], firstChild.id))
      .mockResolvedValueOnce(page([secondChild]))

    const wrapper = mountPanel()
    await flushPromises()

    expect(listSpy).toHaveBeenCalledTimes(1)
    expect(listSpy).toHaveBeenNthCalledWith(1, 'task-1', { page_size: 200 })
    expect(wrapper.text()).not.toContain('bin')

    await wrapper.get('button[aria-label="展开 firmware.tar"]').trigger('click')
    await flushPromises()

    expect(listSpy).toHaveBeenNthCalledWith(2, 'task-1', {
      parent_id: root.id,
      page_size: 200,
    })
    expect(wrapper.text()).toContain('bin')

    await buttonWithText(wrapper, '加载更多').trigger('click')
    await flushPromises()

    expect(listSpy).toHaveBeenNthCalledWith(3, 'task-1', {
      parent_id: root.id,
      cursor: firstChild.id,
      page_size: 200,
    })
    expect(wrapper.text()).toContain('bin')
    expect(wrapper.text()).toContain('etc')
  })

  it('keeps a child-page failure local and retries only that parent', async () => {
    const root = fileNode({ node_type: 'directory', format: '' })
    const child = fileNode({
      id: '18446744073709551611',
      parent_id: root.id,
      logical_path: '/firmware.tar/recovered.bin',
      display_name: 'recovered.bin',
      depth: 1,
      has_children: false,
    })
    const listSpy = vi
      .spyOn(api, 'listTaskFiles')
      .mockResolvedValueOnce(page([root]))
      .mockRejectedValueOnce(new ApiError('子项暂时不可用', 503))
      .mockResolvedValueOnce(page([child]))

    const wrapper = mountPanel()
    await flushPromises()
    await wrapper.get('button[aria-label="展开 firmware.tar"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('子项暂时不可用')
    expect(wrapper.text()).toContain('firmware.tar')

    await buttonWithText(wrapper, '重试').trigger('click')
    await flushPromises()

    expect(listSpy).toHaveBeenCalledTimes(3)
    expect(listSpy).toHaveBeenLastCalledWith('task-1', {
      parent_id: root.id,
      page_size: 200,
    })
    expect(wrapper.text()).toContain('recovered.bin')
    expect(wrapper.text()).not.toContain('子项暂时不可用')
  })

  it('shows extraction status and exposes a node error reason', async () => {
    vi.spyOn(api, 'listTaskFiles').mockResolvedValueOnce(
      page([
        fileNode({
          extraction_status: 'failed',
          error_code: 'archive_corrupt',
          error_message: '归档目录损坏，已保留可读取节点',
          has_children: false,
        }),
      ]),
    )

    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.text()).toContain('提取失败')
    expect(wrapper.get('summary').attributes('aria-label')).toContain('查看 firmware.tar 的错误原因')
    expect(wrapper.text()).toContain('archive_corrupt')
    expect(wrapper.text()).toContain('归档目录损坏，已保留可读取节点')
    expect(wrapper.find('[role="tree"]').exists()).toBe(false)
    expect(wrapper.get('ul.file-tree-branch').attributes('role')).toBeUndefined()
  })

  it('automatically selects a lone root file and loads its detail', async () => {
    const root = fileNode({ has_children: false })
    const detail: FileNodeDetail = {
      ...root,
      metadata_json: {
        archive: 'tar',
      },
      source_parent: null,
    }
    vi.spyOn(api, 'listTaskFiles').mockResolvedValueOnce(page([root]))
    const getDetail = vi.spyOn(api, 'getTaskFile').mockResolvedValueOnce(detail)

    const wrapper = mountPanel()
    await flushPromises()

    const select = wrapper.get('button[aria-label="查看 firmware.tar 的节点详情"]')
    expect(getDetail).toHaveBeenCalledWith('task-1', root.id)
    expect(select.attributes('aria-current')).toBe('true')
    expect(wrapper.text()).toContain('结构化元数据')
    expect(wrapper.text()).toContain('application/x-tar')

    await wrapper.get('button[aria-label="关闭文件详情"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('未选择文件节点')
    expect(select.attributes('aria-current')).toBe('false')
  })

  it('publishes the lone verified root as the outer analysis target', async () => {
    const root = fileNode({
      logical_path: '/gocloc',
      display_name: 'gocloc',
      format: 'macho-thin',
      architecture: 'x86_64',
      extraction_status: 'indexed',
      has_children: false,
    })
    const detail: FileNodeDetail = {
      ...root,
      metadata_json: {},
      source_parent: null,
    }
    vi.spyOn(api, 'listTaskFiles').mockResolvedValueOnce(page([root]))
    const getDetail = vi.spyOn(api, 'getTaskFile').mockResolvedValueOnce(detail)

    const wrapper = mountPanel({
      sampleRetention: resolveSampleRetention({
        sampleExpiresAt: '2099-08-30T00:00:00Z',
        sampleDeletedAt: null,
      }),
    })
    await flushPromises()

    expect(getDetail).toHaveBeenCalledWith('task-1', root.id)
    expect(wrapper.emitted('nodeDetailChange')).toContainEqual([detail])
  })

  it('does not guess a selection when the root has multiple files', async () => {
    const first = fileNode({ has_children: false })
    const second = fileNode({
      id: '18446744073709551611',
      logical_path: '/second.bin',
      display_name: 'second.bin',
      has_children: false,
    })
    vi.spyOn(api, 'listTaskFiles').mockResolvedValueOnce(page([first, second]))
    const getDetail = vi.spyOn(api, 'getTaskFile')

    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.text()).toContain('未选择文件节点')
    expect(getDetail).not.toHaveBeenCalled()
  })

  it('shows compact provenance and opens the source container node', async () => {
    const root = fileNode()
    const child = fileNode({
      id: '18446744073709551611',
      parent_id: root.id,
      logical_path: '/firmware.tar/bin/app',
      display_name: 'app',
      archive_name_id: 'b64:YmluL2FwcA==',
      depth: 2,
      format: 'elf64',
      source_container: {
        id: root.id,
        logical_path: root.logical_path,
        format: 'tar',
      },
      has_children: false,
    })
    const childDetail: FileNodeDetail = {
      ...child,
      metadata_json: {},
      source_parent: {
        id: root.id,
        logical_path: root.logical_path,
      },
    }
    const rootDetail: FileNodeDetail = {
      ...root,
      metadata_json: {},
      source_parent: null,
    }
    vi.spyOn(api, 'listTaskFiles')
      .mockResolvedValueOnce(page([root]))
      .mockResolvedValueOnce(page([child]))
    const getDetail = vi
      .spyOn(api, 'getTaskFile')
      .mockResolvedValueOnce(rootDetail)
      .mockResolvedValueOnce(childDetail)
      .mockResolvedValueOnce(rootDetail)

    const wrapper = mountPanel()
    await flushPromises()
    await wrapper.get('button[aria-label="展开 firmware.tar"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('.source-format-hint').text()).toContain('来源 tar')
    expect(
      wrapper.get('.source-format-hint').element.parentElement?.title,
    ).toContain('/firmware.tar')
    await wrapper
      .get('button[aria-label="查看 app 的节点详情"]')
      .trigger('click')
    await flushPromises()
    await wrapper
      .get('button[aria-label="打开来源容器 /firmware.tar"]')
      .trigger('click')
    await flushPromises()

    expect(getDetail).toHaveBeenNthCalledWith(1, 'task-1', root.id)
    expect(getDetail).toHaveBeenNthCalledWith(2, 'task-1', child.id)
    expect(getDetail).toHaveBeenNthCalledWith(3, 'task-1', root.id)
    expect(
      wrapper
        .get('button[aria-label="查看 firmware.tar 的节点详情"]')
        .attributes('aria-current'),
    ).toBe('true')
    expect(wrapper.text()).toContain('无来源容器')
  })

  it('allows a hung root request to be superseded by refresh', async () => {
    const never = new Promise<FileNodePage>(() => undefined)
    const listSpy = vi
      .spyOn(api, 'listTaskFiles')
      .mockReturnValueOnce(never)
      .mockResolvedValueOnce(page([fileNode({ display_name: 'refreshed.tar' })]))

    const wrapper = mountPanel()
    const refresh = wrapper.get('button[aria-label="刷新文件结构"]')
    expect(refresh.attributes('disabled')).toBeUndefined()

    await refresh.trigger('click')
    await flushPromises()

    expect(listSpy).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('refreshed.tar')
  })
})
