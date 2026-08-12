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

function mountDropzone(category: 'binary' | 'archive' | 'container' = 'binary') {
  return mount(FileDropzone, {
    props: { category },
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

    await vi.waitFor(() => {
      expect(wrapper.emitted('selected')).toBeDefined()
    })

    expect(wrapper.emitted('selected')).toEqual([[files]])
  })

  it('keeps the native picker non-restrictive for extensionless files', () => {
    const wrapper = mountDropzone('archive')
    const input = wrapper.get('input[type="file"]')

    expect(input.attributes('accept')).toBeUndefined()
    expect(input.attributes('data-accept-hint')).toContain('.zip')
    expect(wrapper.text()).toContain('02 压缩包格式')
  })

  it('rejects only a high-confidence category mismatch before upload', async () => {
    const wrapper = mountDropzone('archive')
    const input = wrapper.get<HTMLInputElement>('input[type="file"]')
    const extensionlessElf = new File([
      new Uint8Array([0x7f, 0x45, 0x4c, 0x46]),
    ], 'extensionless')

    Object.defineProperty(input.element, 'files', {
      configurable: true,
      value: {
        0: extensionlessElf,
        length: 1,
        item: () => extensionlessElf,
      },
    })
    await input.trigger('change')
    await vi.waitFor(() => expect(wrapper.emitted('rejected')).toBeDefined())

    expect(wrapper.emitted('selected')).toBeUndefined()
    expect(wrapper.emitted('rejected')?.[0]?.[0]).toEqual([
      expect.stringContaining('ELF'),
    ])
  })

  it('isolates preflight read failures and always resets the native input', async () => {
    const wrapper = mountDropzone('archive')
    const input = wrapper.get<HTMLInputElement>('input[type="file"]')
    const unreadable = new File(['unknown'], 'unreadable.bin')
    const unreadableSlice = new Blob()
    Object.defineProperty(unreadableSlice, 'arrayBuffer', {
      configurable: true,
      value: vi.fn().mockRejectedValue(new Error('read failed')),
    })
    vi.spyOn(unreadable, 'slice').mockReturnValue(unreadableSlice)
    const mismatchedElf = new File(
      [new Uint8Array([0x7f, 0x45, 0x4c, 0x46])],
      'application',
    )

    Object.defineProperty(input.element, 'files', {
      configurable: true,
      value: {
        0: unreadable,
        1: mismatchedElf,
        length: 2,
        item: (index: number) => [unreadable, mismatchedElf][index] ?? null,
      },
    })
    Object.defineProperty(input.element, 'value', {
      configurable: true,
      writable: true,
      value: 'selected-files',
    })

    await input.trigger('change')
    await vi.waitFor(() => expect(wrapper.emitted('selected')).toBeDefined())

    expect(wrapper.emitted('selected')).toEqual([[[unreadable]]])
    expect(wrapper.emitted('rejected')?.[0]?.[0]).toEqual([
      expect.stringContaining('ELF'),
    ])
    expect(input.element.value).toBe('')
  })
})
