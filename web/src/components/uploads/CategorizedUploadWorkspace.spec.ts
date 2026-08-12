/* eslint-disable vue/one-component-per-file */
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { ArchiveImport } from '@/api/types'
import CategorizedUploadWorkspace from '@/components/uploads/CategorizedUploadWorkspace.vue'

const ArchiveWorkspaceStub = defineComponent({
  name: 'ArchiveImportWorkspace',
  props: {
    importId: { type: String, required: true },
    uploadId: { type: String, required: true },
    filename: { type: String, required: true },
    applyInitialSelection: Boolean,
    initialSelectedIds: {
      type: Array,
      default: () => [],
    },
  },
  emits: ['deleted', 'openTask', 'selectionChange'],
  template: `
    <article class="archive-workspace-stub">
      {{ importId }} | {{ uploadId }} | {{ filename }}
    </article>
  `,
})

const ButtonStub = defineComponent({
  name: 'ElButton',
  inheritAttrs: false,
  props: {
    disabled: Boolean,
  },
  emits: ['click'],
  template: `
    <button type="button" :disabled="disabled" @click="$emit('click')">
      <slot />
    </button>
  `,
})

function recoveredImport(id = 'import-recovered'): ArchiveImport {
  return {
    id,
    upload_id: `upload-${id}`,
    filename: `${id}.zip`,
    status: 'ready',
    scanned_entries: 2,
    total_entries: 2,
    eligible_entries: 2,
    skipped_entries: 0,
    created_tasks: 0,
    created_at: '2026-08-11T08:00:00Z',
    updated_at: '2026-08-11T08:01:00Z',
  }
}

async function mountWorkspace(stubArchive = true) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      {
        path: '/tasks/:id',
        name: 'task-detail',
        component: { template: '<div />' },
      },
    ],
  })
  await router.push('/')
  await router.isReady()
  return mount(CategorizedUploadWorkspace, {
    props: { category: 'archive' },
    global: {
      plugins: [router],
      stubs: {
        ...(stubArchive
          ? { ArchiveImportWorkspace: ArchiveWorkspaceStub }
          : {}),
        ArchiveImportEntryTable: true,
        ArchiveImportBatchActions: true,
        FileDropzone: true,
        SupportedUploadTypes: true,
        UploadQueue: true,
        ElButton: ButtonStub,
        ElProgress: true,
        ElSelect: true,
        ElOption: true,
      },
    },
  })
}

describe('CategorizedUploadWorkspace archive recovery', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('restores a durable import after a fresh workspace mount', async () => {
    const list = vi.spyOn(api, 'listArchiveImports').mockResolvedValue({
      items: [recoveredImport()],
    })

    const wrapper = await mountWorkspace()
    await flushPromises()

    expect(list).toHaveBeenCalledWith({ page_size: 25 })
    expect(wrapper.get('.archive-list-row').text()).toContain(
      'import-recovered.zip',
    )
    expect(wrapper.find('.archive-workspace-stub').exists()).toBe(false)

    await wrapper.get('.archive-list-row').trigger('click')

    const firstOpen = wrapper.getComponent(ArchiveWorkspaceStub)
    expect(firstOpen.text()).toContain(
      'import-recovered | upload-import-recovered | import-recovered.zip',
    )
    expect(firstOpen.props('applyInitialSelection')).toBe(true)
    firstOpen.vm.$emit('selectionChange', ['entry-kept'])

    await wrapper.get('.archive-list-row').trigger('click')
    await wrapper.get('.archive-list-row').trigger('click')

    expect(
      wrapper
        .getComponent(ArchiveWorkspaceStub)
        .props('applyInitialSelection'),
    ).toBe(false)
    expect(
      wrapper.getComponent(ArchiveWorkspaceStub).props('initialSelectedIds'),
    ).toEqual(['entry-kept'])
    wrapper.unmount()
  })

  it('removes a terminal import when its child reports deleted', async () => {
    vi.spyOn(api, 'listArchiveImports').mockResolvedValue({
      items: [recoveredImport()],
    })
    const wrapper = await mountWorkspace()
    await flushPromises()

    await wrapper.get('.archive-list-row').trigger('click')
    wrapper.getComponent(ArchiveWorkspaceStub).vm.$emit('deleted')
    await flushPromises()

    expect(wrapper.find('.archive-workspace-stub').exists()).toBe(false)
    expect(wrapper.find('.archive-list-row').exists()).toBe(false)
    wrapper.unmount()
  })

  it('renders 25 summaries without requesting details until one is expanded', async () => {
    const imports = Array.from({ length: 25 }, (_, index) =>
      recoveredImport(`import-${index + 1}`),
    )
    vi.spyOn(api, 'listArchiveImports').mockResolvedValue({ items: imports })
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockImplementation(async (id) => imports.find((item) => item.id === id)!)
    const listEntries = vi
      .spyOn(api, 'listArchiveImportEntries')
      .mockResolvedValue({ items: [] })

    const wrapper = await mountWorkspace(false)
    await flushPromises()

    expect(wrapper.findAll('.archive-list-row')).toHaveLength(25)
    expect(wrapper.findAll('.archive-import')).toHaveLength(0)
    expect(getImport).not.toHaveBeenCalled()
    expect(listEntries).not.toHaveBeenCalled()

    await wrapper.findAll('.archive-list-row')[12]!.trigger('click')
    await flushPromises()

    expect(getImport).toHaveBeenCalledOnce()
    expect(getImport).toHaveBeenCalledWith('import-13')
    expect(listEntries).toHaveBeenCalledOnce()
    expect(listEntries).toHaveBeenCalledWith(
      'import-13',
      expect.objectContaining({ page_size: 50 }),
    )
    expect(wrapper.findAll('.archive-import')).toHaveLength(1)
    wrapper.unmount()
  })

  it('disposes the previous expanded workspace when switching rows', async () => {
    vi.useFakeTimers()
    const first = recoveredImport('import-1')
    const second = recoveredImport('import-2')
    vi.spyOn(api, 'listArchiveImports').mockResolvedValue({
      items: [first, second],
    })
    const getImport = vi
      .spyOn(api, 'getArchiveImport')
      .mockImplementation(async (id) =>
        id === first.id
          ? {
              ...first,
              status: 'queued',
              scanned_entries: 0,
              total_entries: 0,
              eligible_entries: 0,
            }
          : second,
      )
    vi.spyOn(api, 'listArchiveImportEntries').mockResolvedValue({ items: [] })
    const wrapper = await mountWorkspace(false)
    await flushPromises()
    const rows = wrapper.findAll('.archive-list-row')

    await rows[0]!.trigger('click')
    await flushPromises()
    expect(getImport).toHaveBeenCalledTimes(1)

    await rows[1]!.trigger('click')
    await flushPromises()
    expect(getImport).toHaveBeenCalledTimes(2)

    await vi.advanceTimersByTimeAsync(5_000)
    expect(getImport).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })
})
