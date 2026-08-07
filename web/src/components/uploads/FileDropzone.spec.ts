import { mount } from '@vue/test-utils'
import { defineComponent } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import FileDropzone from '@/components/uploads/FileDropzone.vue'

const ButtonStub = defineComponent({
  name: 'ElButton',
  inheritAttrs: false,
  props: {
    nativeType: {
      type: String,
      default: 'button',
    },
  },
  emits: ['click'],
  template: `
    <button :type="nativeType" @click="$emit('click', $event)">
      <slot />
    </button>
  `,
})

function mountDropzone() {
  return mount(FileDropzone, {
    global: {
      stubs: {
        ElButton: ButtonStub,
      },
    },
  })
}

describe('FileDropzone', () => {
  it('uses one keyboard-operable command to open the hidden file picker', async () => {
    const wrapper = mountDropzone()
    const input = wrapper.get<HTMLInputElement>('input[type="file"]')
    const openPicker = vi.spyOn(input.element, 'click')

    expect(wrapper.get('[role="group"]').attributes('aria-label')).toBe('待检测文件选择')
    expect(input.attributes('tabindex')).toBe('-1')
    expect(wrapper.get('.dropzone__icon').attributes('aria-hidden')).toBe('true')

    const button = wrapper.get('button')
    expect(button.attributes('type')).toBe('button')
    expect(button.text()).toBe('选择文件')

    await button.trigger('click')

    expect(openPicker).toHaveBeenCalledOnce()
  })

  it('emits every selected file through its typed selection boundary', async () => {
    const wrapper = mountDropzone()
    const input = wrapper.get<HTMLInputElement>('input[type="file"]')
    const files = [
      new File(['binary'], 'firmware.img'),
      new File(['archive'], 'offline-container-image.tar'),
    ]

    Object.defineProperty(input.element, 'files', {
      configurable: true,
      value: {
        0: files[0],
        1: files[1],
        length: files.length,
        item: (index: number) => files[index] ?? null,
      },
    })
    await input.trigger('change')

    expect(wrapper.emitted('selected')).toEqual([[files]])
  })
})
