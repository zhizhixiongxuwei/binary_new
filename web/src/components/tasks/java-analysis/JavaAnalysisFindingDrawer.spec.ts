import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { JavaAnalysisFinding } from '@/api/types'
import JavaAnalysisFindingDrawer from '@/components/tasks/java-analysis/JavaAnalysisFindingDrawer.vue'

const ElDrawerStub = {
  props: ['modelValue', 'title', 'size'],
  emits: ['update:modelValue'],
  template: '<aside v-if="modelValue" :aria-label="title"><slot /></aside>',
}

const ElButtonStub = {
  emits: ['click'],
  template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
}

const finding: JavaAnalysisFinding = {
  id: '1',
  cwe: 'CWE-89',
  rule_id: 'java-sql-injection',
  severity: 'HIGH',
  file: {
    result_id: 'result-1',
    logical_path: 'src/main/java/app/QueryService.java',
    binary_name: 'app.QueryService',
  },
  callable: {
    kind: 'method',
    type_name: 'app.QueryService',
    name: 'lookup',
    signature: 'lookup(java.lang.String)',
  },
  location: { start_line: 42, start_column: 5, end_line: 42, end_column: 30 },
  message: 'SQL query includes untrusted input.',
  snippet: 'String sql = build(input);\nstatement.executeQuery(sql);\nreturn value;',
  snippet_start_line: 41,
}

describe('JavaAnalysisFindingDrawer', () => {
  it('numbers every excerpt line from snippet_start_line and highlights the hit', async () => {
    const wrapper = mount(JavaAnalysisFindingDrawer, {
      props: { finding },
      global: {
        stubs: { ElDrawer: ElDrawerStub, ElButton: ElButtonStub },
      },
    })

    expect(
      wrapper.findAll('.snippet-gutter').map((gutter) => gutter.text()),
    ).toEqual(['41', '42', '43'])
    expect(wrapper.get('.snippet-line--hit .snippet-gutter').text()).toBe('42')
    expect(wrapper.get('.snippet-line--hit').attributes('aria-current')).toBe(
      'location',
    )
    expect(wrapper.text()).toContain(finding.file.logical_path)
    expect(wrapper.text()).toContain(finding.callable.signature)
    expect(wrapper.text()).not.toMatch(/置信度|修复建议|人工审查/)

    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('openSource')).toEqual([[finding.file.result_id]])
  })
})
