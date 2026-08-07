import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import BytecodeMethodIndexPanel from '@/components/tasks/results/BytecodeMethodIndexPanel.vue'
import type { ParsedBytecodeMethodIndex } from '@/components/tasks/results/jvmMethodIndex'

const index: ParsedBytecodeMethodIndex = {
  present: true,
  declaredCount: 3,
  invalidCount: 0,
  omittedCount: 0,
  methods: [
    {
      key: 'method:first',
      name: '<init>',
      qualifiedName: 'com.example.Verifier.<init>',
      descriptor: '()V',
      signature: '',
      bytecode: { offsetBytes: 384, sizeBytes: 5 },
    },
    {
      key: 'method:verify',
      name: 'verifyHeader',
      qualifiedName: 'com.example.Verifier.verifyHeader',
      descriptor: '(Ljava/nio/ByteBuffer;)Z',
      signature: '',
      bytecode: { offsetBytes: 418, sizeBytes: 18 },
    },
    {
      key: 'method:abstract',
      name: 'checkPolicy',
      qualifiedName: 'com.example.Verifier.checkPolicy',
      descriptor: '(I)V',
      signature: '',
    },
  ],
}

describe('BytecodeMethodIndexPanel', () => {
  it('renders descriptors and exact Code ranges without presenting source', async () => {
    const wrapper = mount(BytecodeMethodIndexPanel, {
      props: { index, selectedKey: 'method:verify' },
    })

    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain(
      'verifyHeader',
    )
    expect(wrapper.text()).toContain('(Ljava/nio/ByteBuffer;)Z')
    expect(wrapper.text()).toContain('Code +418')
    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain(
      '18 B',
    )
    expect(wrapper.text()).toContain('不代表 Java 源码')

    const abstractMethod = wrapper
      .findAll('[data-bytecode-method]')
      .find((method) => method.text().includes('checkPolicy'))
    if (!abstractMethod) throw new Error('abstract method row missing')
    await abstractMethod.trigger('click')
    expect(wrapper.emitted('select')).toContainEqual(['method:abstract'])
  })

  it('searches methods and supports Arrow, Home and End selection', async () => {
    const wrapper = mount(BytecodeMethodIndexPanel, {
      props: { index, selectedKey: 'method:first' },
      attachTo: document.body,
    })
    const search = wrapper.get('input[type="search"]')

    expect(wrapper.findAll('[data-bytecode-method]')[0]?.attributes('tabindex')).toBe('0')
    expect(wrapper.findAll('[data-bytecode-method]')[1]?.attributes('tabindex')).toBe('-1')

    await search.setValue('ByteBuffer')
    expect(wrapper.findAll('[data-bytecode-method]')).toHaveLength(1)
    expect(wrapper.get('[data-bytecode-method]').text()).toContain('verifyHeader')
    expect(wrapper.get('[data-bytecode-method]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain('verifyHeader')

    await search.setValue('missing-method')
    expect(wrapper.findAll('[data-bytecode-method]')).toHaveLength(0)
    expect(wrapper.find('[aria-label="当前 JVM 方法摘要"]').exists()).toBe(false)

    await search.setValue('')
    await search.trigger('keydown', { key: 'ArrowDown' })
    let selections = wrapper.emitted('select') ?? []
    expect(selections[selections.length - 1]).toEqual(['method:first'])
    expect(document.activeElement).toBe(wrapper.findAll('[data-bytecode-method]')[0]?.element)

    await wrapper.findAll('[data-bytecode-method]')[0]?.trigger('keydown', {
      key: 'End',
    })
    selections = wrapper.emitted('select') ?? []
    expect(selections[selections.length - 1]).toEqual(['method:abstract'])
    expect(document.activeElement).toBe(wrapper.findAll('[data-bytecode-method]')[2]?.element)

    await wrapper.findAll('[data-bytecode-method]')[2]?.trigger('keydown', {
      key: 'Home',
    })
    selections = wrapper.emitted('select') ?? []
    expect(selections[selections.length - 1]).toEqual(['method:first'])
    wrapper.unmount()
  })

  it('reports invalid diagnostics instead of rendering unsafe rows', () => {
    const wrapper = mount(BytecodeMethodIndexPanel, {
      props: {
        selectedKey: '',
        index: {
          present: true,
          declaredCount: 2,
          invalidCount: 2,
          omittedCount: 0,
          methods: [],
        },
      },
    })

    expect(wrapper.findAll('[data-bytecode-method]')).toHaveLength(0)
    expect(wrapper.get('[role="note"]').text()).toContain('已忽略 2 条')
    expect(wrapper.get('[role="status"]').text()).toContain('没有可安全显示')
  })

  it('renders at most 200 options and keeps status nodes outside the listbox', async () => {
    const methods = Array.from({ length: 205 }, (_, methodIndex) => ({
      key: `method:${methodIndex}`,
      name: `method${methodIndex}`,
      qualifiedName: `Fixture.method${methodIndex}`,
      descriptor: '()V',
      signature: '',
    }))
    const wrapper = mount(BytecodeMethodIndexPanel, {
      props: {
        selectedKey: methods[0]?.key ?? '',
        index: {
          present: true,
          declaredCount: methods.length,
          invalidCount: 0,
          omittedCount: 0,
          methods,
        },
      },
    })

    expect(wrapper.findAll('[role="option"]')).toHaveLength(200)
    expect(wrapper.get('[role="listbox"]').find('[role="status"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('其余 5 个方法')

    await wrapper.get('input[type="search"]').setValue('method204')
    expect(wrapper.findAll('[role="option"]')).toHaveLength(1)
    expect(wrapper.get('[role="option"]').attributes('tabindex')).toBe('0')
  })
})
