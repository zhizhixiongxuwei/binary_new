/* eslint-disable vue/one-component-per-file */
import { mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { describe, expect, it } from 'vitest'

import TaskInputCategoryDialog from '@/components/tasks/TaskInputCategoryDialog.vue'

const DialogStub = defineComponent({
  name: 'ElDialog',
  props: {
    modelValue: Boolean,
  },
  emits: ['update:modelValue'],
  template: `
    <section v-if="modelValue" aria-label="dialog">
      <slot name="header" />
      <slot />
      <slot name="footer" />
    </section>
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

function mountDialog(locked = false) {
  return mount(TaskInputCategoryDialog, {
    props: {
      modelValue: true,
      currentCategory: 'binary',
      locked,
    },
    global: {
      stubs: {
        ElDialog: DialogStub,
        ElButton: ButtonStub,
      },
    },
  })
}

describe('TaskInputCategoryDialog', () => {
  it('uses one native radio group and confirms the checked category', async () => {
    const wrapper = mountDialog()
    const radios = wrapper.findAll<HTMLInputElement>('input[type="radio"]')

    expect(radios).toHaveLength(3)
    expect(new Set(radios.map((radio) => radio.attributes('name')))).toEqual(
      new Set(['task-input-category']),
    )
    expect(wrapper.get('[role="radiogroup"]').attributes('aria-label')).toBe(
      '任务输入类别',
    )
    expect(wrapper.find('[role="radio"]').exists()).toBe(false)
    expect(radios[0]?.element.checked).toBe(true)

    await wrapper.get('input[value="archive"]').setValue()
    const confirm = wrapper
      .findAll('button')
      .find((button) => button.text() === '确认类别')!
    await confirm.trigger('click')

    expect(wrapper.emitted('select')?.[0]).toEqual(['archive'])
    const modelUpdates = wrapper.emitted('update:modelValue') ?? []
    expect(modelUpdates[modelUpdates.length - 1]).toEqual([false])
  })

  it('disables every native radio while category changes are locked', () => {
    const wrapper = mountDialog(true)

    expect(
      wrapper
        .findAll('input[type="radio"]')
        .every((radio) => radio.attributes('disabled') !== undefined),
    ).toBe(true)
    expect(wrapper.get('[role="status"]').text()).toContain('不能切换')
  })
})
