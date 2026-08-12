import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import { describe, expect, it } from 'vitest'

import type { CAnalysisFinding } from '@/api/types'
import CAnalysisFindingDrawer from '@/components/tasks/c-analysis/CAnalysisFindingDrawer.vue'

const ElDrawerStub = {
  props: ['modelValue', 'title', 'size'],
  emits: ['update:modelValue'],
  template: '<aside v-if="modelValue" :aria-label="title" :data-size="size"><slot /></aside>',
}

const ElButtonStub = {
  emits: ['click'],
  template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
}

function finding(overrides: Partial<CAnalysisFinding> = {}): CAnalysisFinding {
  return {
    id: 'finding-1',
    cwe: 'CWE-120',
    rule_id: 'cwe-120-bounds',
    severity: 'HIGH',
    function: {
      result_id: 'result-1',
      address: '00401000',
      name: 'copy_input',
    },
    location: {
      start_line: 42,
      start_column: 3,
      end_line: 42,
      end_column: 19,
    },
    message: '复制操作缺少长度限制。',
    snippet: 'strcpy(target, input);',
    ...overrides,
  }
}

function mountDrawer(value: CAnalysisFinding) {
  return mount(CAnalysisFindingDrawer, {
    props: { finding: value },
    global: {
      stubs: {
        ElButton: ElButtonStub,
        ElDrawer: ElDrawerStub,
      },
    },
  })
}

describe('CAnalysisFindingDrawer', () => {
  it('uses the source line and highlights it when a single-line snippet is unambiguous', () => {
    const wrapper = mountDrawer(finding())
    const line = wrapper.get('.snippet-line')
    const gutter = line.get('.snippet-gutter')

    expect(wrapper.get('.snippet-hit-location').text()).toContain('命中 42:3 - 42:19')
    expect(gutter.text()).toBe('42')
    expect(gutter.attributes('title')).toBe('源码第 42 行')
    expect(line.classes()).toContain('snippet-line--hit')
    expect(line.attributes('aria-current')).toBe('location')
    expect(line.get('code').text()).toBe('strcpy(target, input);')
  })

  it('numbers multi-line snippets relatively without inventing source lines or a hit line', () => {
    const wrapper = mountDrawer(finding({
      location: {
        start_line: 87,
        start_column: 5,
        end_line: 87,
        end_column: 18,
      },
      snippet: 'prepare();\ncopy_input();\nfinish();',
    }))
    const lines = wrapper.findAll('.snippet-line')
    const gutters = wrapper.findAll('.snippet-gutter')

    expect(lines.map((line) => line.get('code').text())).toEqual([
      'prepare();',
      'copy_input();',
      'finish();',
    ])
    expect(gutters.map((gutter) => gutter.text())).toEqual(['S1', 'S2', 'S3'])
    expect(gutters.map((gutter) => gutter.attributes('title'))).toEqual([
      '片段内第 1 行',
      '片段内第 2 行',
      '片段内第 3 行',
    ])
    expect(wrapper.find('.snippet-line--hit').exists()).toBe(false)
    expect(wrapper.get('.snippet-hit-location').text()).toContain('命中 87:5 - 87:18')
  })

  it('shows a dedicated empty state instead of a fabricated code line', () => {
    const value = finding()
    delete value.snippet
    const wrapper = mountDrawer(value)

    expect(wrapper.find('.snippet-code').exists()).toBe(false)
    expect(wrapper.get('.snippet-empty').text()).toBe('该发现没有保存源码片段。')
  })

  it('passes a splitter-supported responsive pixel size to Element Plus', async () => {
    const originalWidth = window.innerWidth
    const wrapper = mountDrawer(finding())

    expect(wrapper.get('aside').attributes('data-size')).toBe('620')

    Object.defineProperty(window, 'innerWidth', {
      configurable: true,
      value: 390,
    })
    window.dispatchEvent(new Event('resize'))
    await nextTick()

    expect(wrapper.get('aside').attributes('data-size')).toBe('358')
    wrapper.unmount()
    Object.defineProperty(window, 'innerWidth', {
      configurable: true,
      value: originalWidth,
    })
  })
})
