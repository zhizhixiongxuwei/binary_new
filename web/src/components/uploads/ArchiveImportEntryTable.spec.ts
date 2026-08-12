import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import ArchiveImportEntryTable from '@/components/uploads/ArchiveImportEntryTable.vue'

describe('ArchiveImportEntryTable', () => {
  it('keeps a created entry disabled when its task was physically deleted', () => {
    const wrapper = mount(ArchiveImportEntryTable, {
      props: {
        entries: [
          {
            id: 'entry-1',
            path: 'bin/application',
            size_bytes: 4,
            sha256: 'a'.repeat(64),
            detected_format: 'elf64',
            detected_category: 'binary',
            status: 'created',
          },
        ],
        selectedIds: new Set<string>(),
        selectedCount: 0,
        loading: false,
        submitting: false,
        creationEnabled: true,
        hasPreviousPage: false,
        hasNextPage: false,
        pageIndex: 0,
      },
    })

    const checkbox = wrapper.get<HTMLInputElement>(
      'tbody input[type="checkbox"]',
    )
    expect(checkbox.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('已创建（任务已删除）')
    expect(wrapper.find('button[aria-label="查看已创建任务"]').exists()).toBe(
      false,
    )
  })

  it('allows a failed entry to be selected for a manual retry', async () => {
    const failedEntry = {
      id: 'entry-failed',
      path: 'bin/retry-me',
      size_bytes: 4,
      sha256: 'a'.repeat(64),
      detected_format: 'elf64',
      detected_category: 'binary' as const,
      status: 'failed' as const,
    }
    const wrapper = mount(ArchiveImportEntryTable, {
      props: {
        entries: [failedEntry],
        selectedIds: new Set<string>(),
        selectedCount: 0,
        loading: false,
        submitting: false,
        creationEnabled: true,
        hasPreviousPage: false,
        hasNextPage: false,
        pageIndex: 0,
      },
    })

    const checkbox = wrapper.get<HTMLInputElement>(
      'tbody input[type="checkbox"]',
    )
    expect(checkbox.attributes('disabled')).toBeUndefined()

    await checkbox.setValue(true)

    expect(wrapper.emitted('toggle')?.[0]).toEqual([failedEntry, true])
  })

  it('reports partial current-page selection and toggles within remaining capacity', async () => {
    const entries = [
      {
        id: 'entry-1',
        path: 'bin/one',
        size_bytes: 4,
        sha256: 'a'.repeat(64),
        detected_format: 'elf64',
        detected_category: 'binary' as const,
        status: 'eligible' as const,
      },
      {
        id: 'entry-2',
        path: 'bin/two',
        size_bytes: 4,
        sha256: 'b'.repeat(64),
        detected_format: 'elf64',
        detected_category: 'binary' as const,
        status: 'eligible' as const,
      },
    ]
    const wrapper = mount(ArchiveImportEntryTable, {
      props: {
        entries,
        selectedIds: new Set(['entry-1', 'hidden-entry']),
        selectedCount: 2,
        loading: false,
        submitting: false,
        creationEnabled: true,
        hasPreviousPage: true,
        hasNextPage: true,
        pageIndex: 1,
      },
    })
    const pageCheckbox = wrapper.get<HTMLInputElement>(
      'thead input[type="checkbox"]',
    )

    expect(pageCheckbox.element.indeterminate).toBe(true)
    await pageCheckbox.trigger('change')
    expect(wrapper.emitted('toggleVisible')?.[0]).toEqual([true])

    await wrapper.setProps({
      selectedIds: new Set([
        'entry-1',
        ...Array.from({ length: 19 }, (_, index) => `hidden-${index}`),
      ]),
      selectedCount: 20,
    })
    await pageCheckbox.trigger('change')

    expect(wrapper.emitted('toggleVisible')?.[1]).toEqual([false])
    expect(
      wrapper.get('tbody tr:nth-child(2) input').attributes('disabled'),
    ).toBeDefined()
  })
})
