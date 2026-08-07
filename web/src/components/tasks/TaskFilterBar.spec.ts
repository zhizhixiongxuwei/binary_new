import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TaskFilterBar from '@/components/tasks/TaskFilterBar.vue'
import type { TaskFilterValue } from '@/components/tasks/taskListFilters'

const ElInputStub = {
  inheritAttrs: false,
  props: {
    modelValue: { type: String, default: '' },
  },
  emits: ['update:modelValue'],
  template: `
    <input
      v-bind="$attrs"
      :value="modelValue"
      @input="$emit('update:modelValue', $event.target.value)"
    >
  `,
}

const ElSelectStub = {
  inheritAttrs: false,
  props: {
    modelValue: { type: String, default: '' },
  },
  emits: ['update:modelValue'],
  template: `
    <select
      v-bind="$attrs"
      :value="modelValue"
      @change="$emit('update:modelValue', $event.target.value)"
    ><slot /></select>
  `,
}

const ElOptionStub = {
  props: {
    label: { type: String, required: true },
    value: { type: String, required: true },
  },
  template: '<option :value="value">{{ label }}</option>',
}

const ElOptionGroupStub = {
  props: {
    label: { type: String, required: true },
  },
  template: '<optgroup :label="label"><slot /></optgroup>',
}

const ElButtonStub = {
  inheritAttrs: false,
  props: {
    nativeType: { type: String, default: 'button' },
  },
  template: `
    <button
      v-bind="$attrs"
      :type="nativeType"
    ><slot /></button>
  `,
}

function filters(overrides: Partial<TaskFilterValue> = {}): TaskFilterValue {
  return {
    keyword: '',
    status: '',
    input_type: '',
    creator: '',
    tag: '',
    created_from: '',
    created_to: '',
    ...overrides,
  }
}

function mountBar(initialValue: TaskFilterValue = filters()) {
  return mount(TaskFilterBar, {
    props: { initialValue },
    global: {
      stubs: {
        ElInput: ElInputStub,
        ElSelect: ElSelectStub,
        ElOption: ElOptionStub,
        ElOptionGroup: ElOptionGroupStub,
        ElButton: ElButtonStub,
      },
    },
  })
}

describe('TaskFilterBar', () => {
  it('opens compact advanced filters and emits one normalized filter value', async () => {
    const wrapper = mountBar()
    const advanced = wrapper.get('#task-advanced-filters')
    expect(advanced.attributes('style')).toContain('display: none')

    const advancedTrigger = wrapper.get('[aria-controls="task-advanced-filters"]')
    await advancedTrigger.trigger('click')
    expect(advancedTrigger.attributes('aria-expanded')).toBe('true')
    expect(
      wrapper.get('#task-advanced-filters').attributes('style') ?? '',
    ).not.toContain('display: none')

    await wrapper.get('[aria-label="任务名称或文件名"]').setValue('  kernel  ')
    await wrapper.get('[aria-label="执行状态"]').setValue('SCANNING')
    await wrapper.get('[aria-label="输入格式"]').setValue('elf64')
    await wrapper.get('[aria-label="创建者"]').setValue('  Demo Operator  ')
    await wrapper.get('[aria-label="标签"]').setValue('  firmware  ')
    await wrapper.get('[aria-label="创建日期开始"]').setValue('2026-07-01')
    await wrapper.get('[aria-label="创建日期结束"]').setValue('2026-07-30')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('apply')?.[0]).toEqual([
      {
        keyword: 'kernel',
        status: 'SCANNING',
        input_type: 'elf64',
        creator: 'Demo Operator',
        tag: 'firmware',
        created_from: '2026-07-01',
        created_to: '2026-07-30',
      },
    ])
  })

  it('restores advanced filters, rejects reversed dates, and resets the draft', async () => {
    const wrapper = mountBar(
      filters({
        creator: 'Operator',
        tag: 'firmware',
        created_from: '2026-07-30',
        created_to: '2026-07-30',
      }),
    )

    expect(
      wrapper.get('[aria-controls="task-advanced-filters"]').attributes('aria-expanded'),
    ).toBe('true')
    expect(wrapper.get('.task-filters__count').text()).toBe('4')

    await wrapper.get('[aria-label="创建日期结束"]').setValue('2026-07-01')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('apply')).toBeUndefined()
    expect(wrapper.get('[role="alert"]').text()).toBe('开始日期不能晚于结束日期')

    await wrapper.get('[aria-label="重置筛选"]').trigger('click')
    expect(wrapper.emitted('reset')).toHaveLength(1)
    expect(
      wrapper.get('[aria-controls="task-advanced-filters"]').attributes('aria-expanded'),
    ).toBe('false')
    expect(wrapper.get('#task-advanced-filters').attributes('style')).toContain(
      'display: none',
    )
  })
})
