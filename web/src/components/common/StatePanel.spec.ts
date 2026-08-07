import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import StatePanel from '@/components/common/StatePanel.vue'

const ElButtonStub = {
  emits: ['click'],
  template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
}

describe('StatePanel', () => {
  it('announces loading as busy status', () => {
    const wrapper = mount(StatePanel, {
      props: { kind: 'loading' },
      global: {
        stubs: { ElButton: ElButtonStub },
      },
    })

    expect(wrapper.attributes('role')).toBe('status')
    expect(wrapper.attributes('aria-busy')).toBe('true')
    expect(wrapper.text()).toContain('正在读取数据')
  })

  it('announces errors assertively and emits retry', async () => {
    const wrapper = mount(StatePanel, {
      props: {
        kind: 'error',
        description: '离线节点暂时不可用',
        retryable: true,
      },
      global: {
        stubs: { ElButton: ElButtonStub },
      },
    })

    expect(wrapper.attributes('role')).toBe('alert')
    expect(wrapper.text()).toContain('离线节点暂时不可用')

    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('retry')).toHaveLength(1)
  })
})
