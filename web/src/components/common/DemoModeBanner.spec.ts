import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import DemoModeBanner from '@/components/common/DemoModeBanner.vue'

describe('DemoModeBanner', () => {
  it('labels preview data without implying a real scan', () => {
    const wrapper = mount(DemoModeBanner)

    expect(wrapper.get('[aria-label="界面预览模式"]').text()).toContain('示例数据')
    expect(wrapper.text()).toContain('不连接后端')
    expect(wrapper.text()).toContain('不执行真实检测')
  })
})
