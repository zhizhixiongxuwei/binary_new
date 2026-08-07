import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import LoginForm from '@/components/auth/LoginForm.vue'

const ElInputStub = {
  name: 'ElInput',
  inheritAttrs: false,
  props: {
    modelValue: { type: String, default: '' },
    id: { type: String, required: true },
    type: { type: String, default: 'text' },
    autocomplete: { type: String, default: undefined },
    placeholder: { type: String, default: undefined },
  },
  emits: ['update:modelValue'],
  template: `
    <input
      :id="id"
      :value="modelValue"
      :type="type"
      :autocomplete="autocomplete"
      :placeholder="placeholder"
      @input="$emit('update:modelValue', $event.target.value)"
    >
  `,
}

const ElButtonStub = {
  name: 'ElButton',
  inheritAttrs: false,
  props: {
    disabled: Boolean,
    loading: Boolean,
    nativeType: { type: String, default: 'button' },
  },
  template: `
    <button :type="nativeType" :disabled="disabled" :aria-busy="loading">
      <slot />
    </button>
  `,
}

function mountForm(retryAfterSeconds = 0) {
  return mount(LoginForm, {
    props: {
      loading: false,
      retryAfterSeconds,
    },
    global: {
      stubs: {
        ElInput: ElInputStub,
        ElButton: ElButtonStub,
      },
    },
  })
}

describe('LoginForm', () => {
  it('keeps feedback space stable and blocks only submission during cooldown', async () => {
    const wrapper = mountForm(5)
    await wrapper.get('#username').setValue('operator')
    await wrapper.get('#password').setValue('secret-value')

    expect(wrapper.find('.login-feedback').exists()).toBe(true)
    expect(wrapper.get('[role="status"]').text()).toContain('登录尝试过于频繁')
    expect(wrapper.get('button').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')).toBeUndefined()

    await wrapper.setProps({ retryAfterSeconds: 0 })
    expect(wrapper.find('.login-feedback__placeholder').exists()).toBe(true)
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')).toEqual([
      [{ username: 'operator', password: 'secret-value' }],
    ])
  })
})
