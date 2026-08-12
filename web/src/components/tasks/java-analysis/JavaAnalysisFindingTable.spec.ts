import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { JavaAnalysisFinding } from '@/api/types'
import JavaAnalysisFindingTable from '@/components/tasks/java-analysis/JavaAnalysisFindingTable.vue'

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
  snippet: 'statement.executeQuery(sql);',
  snippet_start_line: 41,
}

const ElButtonStub = {
  emits: ['click'],
  template: '<button type="button" @click="$emit(\'click\')"><slot /></button>',
}

describe('JavaAnalysisFindingTable', () => {
  it('shows the Java file/type/callable/location contract and selects a row', async () => {
    const wrapper = mount(JavaAnalysisFindingTable, {
      props: {
        findings: [finding],
        loading: false,
        loadingMore: false,
        hasMore: false,
      },
      global: { stubs: { ElButton: ElButtonStub } },
    })

    expect(wrapper.findAll('thead th').map((header) => header.text())).toEqual([
      '严重度',
      'CWE',
      '规则',
      '文件',
      '类型',
      '方法',
      '位置',
      '检测结论',
      '操作',
    ])
    expect(wrapper.text()).toContain(finding.file.logical_path)
    expect(wrapper.text()).toContain(finding.callable.type_name)
    expect(wrapper.text()).toContain(finding.callable.name)
    expect(wrapper.text()).toContain('42:5')
    expect(wrapper.text()).not.toMatch(/置信度|修复建议|人工审查/)

    await wrapper.get('button[title="查看代码片段"]').trigger('click')
    expect(wrapper.emitted('select')).toEqual([[finding]])
  })
})
