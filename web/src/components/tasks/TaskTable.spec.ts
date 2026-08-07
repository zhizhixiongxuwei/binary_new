/* eslint-disable vue/one-component-per-file */
import { mount } from '@vue/test-utils'
import {
  defineComponent,
  h,
  inject,
  provide,
  type PropType,
} from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ScanTask } from '@/api/types'
import TaskTable from '@/components/tasks/TaskTable.vue'

const NOW = new Date('2026-07-31T00:00:00.000Z')
const tableRowsKey = Symbol('table-rows')

const TableStub = defineComponent({
  name: 'ElTable',
  props: {
    data: {
      type: Array as PropType<readonly ScanTask[]>,
      default: () => [],
    },
  },
  setup(props, { slots }) {
    provide(tableRowsKey, () => props.data)
    return () => h('div', { class: 'table-stub' }, slots.default?.())
  },
})

const TableColumnStub = defineComponent({
  name: 'ElTableColumn',
  props: {
    label: {
      type: String,
      default: '',
    },
  },
  setup(props, { slots }) {
    const rows = inject<() => readonly ScanTask[]>(tableRowsKey, () => [])
    return () =>
      h(
        'section',
        { 'data-column-label': props.label },
        rows().flatMap((row) => slots.default?.({ row }) ?? []),
      )
  },
})

const ProgressStub = defineComponent({
  name: 'ElProgress',
  inheritAttrs: true,
  props: {
    percentage: {
      type: Number,
      required: true,
    },
  },
  template: `
    <div
      class="progress-stub"
      role="progressbar"
      :aria-valuenow="percentage"
    />
  `,
})

const SelectStub = defineComponent({
  name: 'ElSelect',
  inheritAttrs: true,
  props: {
    modelValue: {
      type: Number,
      required: true,
    },
    disabled: Boolean,
  },
  emits: ['update:modelValue'],
  template: '<div class="select-stub"><slot /></div>',
})

const OptionStub = defineComponent({
  name: 'ElOption',
  template: '<span />',
})

const StatusBadgeStub = defineComponent({
  name: 'StatusBadge',
  props: {
    value: {
      type: String,
      required: true,
    },
    kind: {
      type: String,
      required: true,
    },
  },
  template: '<span class="status-stub">{{ value }}</span>',
})

function task(overrides: Partial<ScanTask> = {}): ScanTask {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'very-long-firmware-image-name-without-spaces.img',
    input_type: 'extremely-long-binary-format',
    status: 'SCANNING',
    risk_level: 'HIGH',
    progress: 42,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: 'offline-security-operator-with-a-long-name',
    tags: [],
    created_at: '2026-07-30T00:00:00Z',
    ...overrides,
    sample_expires_at:
      overrides.sample_expires_at ?? '2099-08-29T00:00:00Z',
    sample_deleted_at: overrides.sample_deleted_at ?? null,
  }
}

function mountTable(
  item: ScanTask = task(),
  options: { useSystemClock?: boolean } = {},
) {
  return mount(TaskTable, {
    props: {
      items: [item],
      pageSize: 20,
      hasPrevious: true,
      hasNext: true,
      canReset: true,
      ...(options.useSystemClock ? {} : { now: NOW }),
    },
    global: {
      stubs: {
        ElTable: TableStub,
        ElTableColumn: TableColumnStub,
        ElProgress: ProgressStub,
        ElSelect: SelectStub,
        ElOption: OptionStub,
        StatusBadge: StatusBadgeStub,
      },
    },
  })
}

describe('TaskTable', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('exposes a keyboard-scrollable region and opens a row from its visible task name', async () => {
    const item = task()
    const wrapper = mountTable(item)
    const region = wrapper.get('[role="region"]')
    const taskButton = wrapper.get('.task-cell__open')

    expect(region.attributes()).toMatchObject({
      'aria-label': '任务列表，可横向滚动查看全部字段',
      tabindex: '0',
    })
    expect(taskButton.attributes()).toMatchObject({
      'aria-label': `查看任务：${item.name}`,
      title: item.name,
    })

    await taskButton.trigger('click')

    expect(wrapper.emitted('open')).toEqual([[item.id]])
  })

  it('keeps full long values available and labels progress without relying on truncation', () => {
    const item = task()
    const wrapper = mountTable(item)

    expect(wrapper.get('.task-cell__copy small').attributes('title')).toBe(item.id)
    expect(wrapper.findAll('.table-token').map((node) => node.attributes('title'))).toEqual([
      item.input_type,
      item.creator_name,
    ])
    expect(wrapper.getComponent(ProgressStub).attributes('aria-label')).toBe(
      `${item.name} 检测进度 42%`,
    )
  })

  it('emits bounded cursor navigation and page-size commands', async () => {
    const wrapper = mountTable()

    expect(wrapper.text()).toContain('本批 1 个任务')
    await wrapper.get('[aria-label="返回第一批任务"]').trigger('click')
    await wrapper.get('[aria-label="查看上一批任务"]').trigger('click')
    await wrapper.get('[aria-label="查看下一批任务"]').trigger('click')
    wrapper.getComponent(SelectStub).vm.$emit('update:modelValue', 50)
    await wrapper.vm.$nextTick()

    expect(wrapper.emitted('firstPage')).toEqual([[]])
    expect(wrapper.emitted('previousPage')).toEqual([[]])
    expect(wrapper.emitted('nextPage')).toEqual([[]])
    expect(wrapper.emitted('pageSizeChange')).toEqual([[50]])
  })

  it('locks unavailable cursor commands while keeping stable controls visible', async () => {
    const wrapper = mountTable()
    await wrapper.setProps({
      hasPrevious: false,
      hasNext: false,
      canReset: false,
      loading: true,
    })

    expect(wrapper.findAll('.task-table__cursor-button')).toHaveLength(3)
    expect(
      wrapper.findAll('.task-table__cursor-button').every((button) =>
        button.attributes('disabled') !== undefined,
      ),
    ).toBe(true)
  })

  it('clamps invalid progress values before rendering them', () => {
    const wrapper = mountTable(task({ progress: 130 }))

    expect(wrapper.getComponent(ProgressStub).props('percentage')).toBe(100)
    expect(wrapper.text()).toContain('100%')
  })

  it('labels unknown totals without presenting the weighted boundary as a percentage', () => {
    const item = task({ progress: 70, progress_indeterminate: true })
    const wrapper = mountTable(item)

    expect(wrapper.getComponent(ProgressStub).attributes('aria-label')).toBe(
      `${item.name} 检测进度计算中`,
    )
    expect(wrapper.text()).toContain('计算中')
    expect(wrapper.text()).not.toContain('70%')
  })

  it('marks expired and server-cleaned samples without disabling history access', async () => {
    const expired = task({
      sample_expires_at: NOW.toISOString(),
      sample_deleted_at: null,
    })
    const wrapper = mountTable(expired)
    const retention = wrapper.get('[data-retention-status="expired"]')

    expect(retention.text()).toBe('样本已到期')
    expect(retention.attributes('title')).toContain('无法重新检测')
    await wrapper.get('.task-cell__open').trigger('click')
    expect(wrapper.emitted('open')).toEqual([[expired.id]])

    const deleted = task({
      sample_expires_at: '2099-08-29T00:00:00.000Z',
      sample_deleted_at: 'server-retention-marker',
    })
    await wrapper.setProps({ items: [deleted] })

    expect(wrapper.get('[data-retention-status="deleted"]').text()).toBe(
      '样本已清理',
    )
  })

  it('updates the visible retention state when the nearest expiry is reached', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(NOW)
    const wrapper = mountTable(
      task({ sample_expires_at: '2026-07-31T00:00:01.000Z' }),
      { useSystemClock: true },
    )

    expect(wrapper.find('[data-retention-status]').exists()).toBe(false)

    await vi.advanceTimersByTimeAsync(1_000)
    await wrapper.vm.$nextTick()

    expect(wrapper.get('[data-retention-status="expired"]').text()).toBe(
      '样本已到期',
    )
  })

  it('exposes a permission-aware delete command without opening the row', async () => {
    const item = task({ status: 'SUCCEEDED' })
    const wrapper = mountTable(item)
    await wrapper.setProps({
      userRole: 'operator',
      currentUserId: item.creator_id,
    })

    const command = wrapper.get<HTMLButtonElement>(
      `[aria-label="删除任务：${item.name}"]`,
    )
    expect(command.element.disabled).toBe(false)
    expect(command.attributes('title')).toContain('提交删除请求')
    await command.trigger('click')

    expect(wrapper.emitted('delete')).toEqual([[item]])
    expect(wrapper.emitted('open')).toBeUndefined()

    await wrapper.setProps({ currentUserId: 'different-operator' })
    expect(command.element.disabled).toBe(true)
    expect(command.attributes('title')).toContain('只有管理员')
  })
})
