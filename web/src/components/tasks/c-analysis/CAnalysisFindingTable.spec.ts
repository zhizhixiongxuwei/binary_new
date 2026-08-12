import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { CAnalysisFinding } from '@/api/types'
import CAnalysisFindingTable from '@/components/tasks/c-analysis/CAnalysisFindingTable.vue'

const ElButtonStub = {
  emits: ['click'],
  template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
}

const finding: CAnalysisFinding = {
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
}

function mountTable() {
  return mount(CAnalysisFindingTable, {
    props: {
      findings: [finding],
      loading: false,
      loadingMore: false,
      hasMore: false,
    },
    global: { stubs: { ElButton: ElButtonStub } },
  })
}

describe('CAnalysisFindingTable', () => {
  it('renders an explicit code action and emits one selection for its click', async () => {
    const wrapper = mountTable()
    const headers = wrapper.findAll('thead th').map((header) => header.text())
    const action = wrapper.get('button[title="查看代码片段"]')

    expect(headers).toContain('操作')
    expect(action.attributes('aria-label')).toBe('查看 copy_input 的代码片段')
    expect(action.find('svg').exists()).toBe(true)

    await action.trigger('click')

    expect(wrapper.emitted('select')).toEqual([[finding]])
  })

  it('keeps row keyboard selection without letting button keys select twice', async () => {
    const wrapper = mountTable()
    const row = wrapper.get('tbody tr')
    const action = wrapper.get('button[title="查看代码片段"]')

    await action.trigger('keydown', { key: 'Enter' })
    expect(wrapper.emitted('select')).toBeUndefined()

    await action.trigger('click')
    await row.trigger('keydown', { key: 'Enter' })
    await row.trigger('keydown', { key: ' ' })
    await row.trigger('click')

    expect(wrapper.emitted('select')).toEqual([
      [finding],
      [finding],
      [finding],
      [finding],
    ])
  })
})
