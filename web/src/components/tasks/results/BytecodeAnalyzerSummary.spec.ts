import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import BytecodeAnalyzerSummary from '@/components/tasks/results/BytecodeAnalyzerSummary.vue'
import { parseAnalyzerSummary } from '@/components/tasks/results/analyzerSummary'

describe('BytecodeAnalyzerSummary', () => {
  it('renders only analyzer fields that survived parsing', () => {
    const wrapper = mount(BytecodeAnalyzerSummary, {
      props: {
        summary: parseAnalyzerSummary({
          format: 'DEX',
          dex_file_count: 2,
          method_count: 4_218,
          warning_count: 1,
          warnings: ['One dependency class was not present'],
        }),
      },
    })

    expect(wrapper.get('[data-analyzer-summary]').attributes('aria-labelledby')).toBeTruthy()
    expect(wrapper.get('[aria-label="摘要数据来源"]').attributes('role')).toBe(
      'group',
    )
    expect(wrapper.text()).toContain('分析器上报')
    expect(wrapper.text()).toContain('DEX')
    expect(wrapper.text()).toContain('4,218')
    expect(wrapper.text()).toContain('One dependency class was not present')
    expect(wrapper.text()).not.toContain('Python 版本')
    expect(wrapper.text()).not.toContain('Magic')
    expect(wrapper.text()).not.toContain('固定示例')
    expect(wrapper.findAll('dl')).toHaveLength(2)
    expect(wrapper.findAll('ul > li')).toHaveLength(1)
  })

  it('marks preview diagnostics as a non-production example', () => {
    const wrapper = mount(BytecodeAnalyzerSummary, {
      props: {
        summary: parseAnalyzerSummary({
          engine: 'PYC 字段契约示例',
          format: 'PYC',
          header_size: 16,
        }),
        example: true,
      },
    })

    expect(wrapper.get('[role="note"]').text()).toBe('固定示例 · 非真实结果')
    expect(wrapper.text()).toContain('16 B')
  })

  it('does not create an empty region when no safe fields are present', () => {
    const wrapper = mount(BytecodeAnalyzerSummary, {
      props: { summary: parseAnalyzerSummary({ unrelated: true }) },
    })

    expect(wrapper.find('[data-analyzer-summary]').exists()).toBe(false)
  })
})
