import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { DecompileResult, TaskReport } from '@/api/types'
import LiveReportResult from '@/components/tasks/results/LiveReportResult.vue'

const taskId = '123e4567-e89b-42d3-a456-426614174000'

const report: TaskReport = {
  id: '223e4567-e89b-42d3-a456-426614174001',
  task_id: taskId,
  format: 'html',
  schema_version: '1.1.0',
  status: 'complete',
  sha256: 'a'.repeat(64),
  size_bytes: 4096,
  error_code: null,
  error_message: null,
  created_at: '2026-08-04T01:00:00Z',
  completed_at: '2026-08-04T01:00:01Z',
}

const result: DecompileResult = {
  id: '323e4567-e89b-42d3-a456-426614174002',
  file_node_id: '42',
  symbol_key: 'FUN_100001000',
  symbol_kind: 'function',
  display_name: 'main',
  group_name: 'gocloc',
  location: '0x100001000',
  signature: 'int main(void)',
  detail: 'Ghidra output',
  language: 'c',
  engine_name: 'ghidra',
  engine_version: '12.1.2',
  status: 'complete',
  size_bytes: 128,
  diagnostics: {},
  created_at: '2026-08-04T01:00:00Z',
  completed_at: '2026-08-04T01:00:01Z',
}

describe('LiveReportResult', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('opens the existing function and Monaco workspace from the report area', async () => {
    vi.spyOn(api, 'listTaskReports').mockResolvedValue({ items: [report] })
    vi.spyOn(api, 'listDecompileResults').mockResolvedValue({ items: [result] })

    const wrapper = mount(LiveReportResult, {
      props: {
        taskId,
        taskStatus: 'SUCCEEDED',
        userRole: 'reader',
      },
      global: {
        stubs: {
          LiveDecompileResult: {
            props: ['taskId'],
            template:
              '<div data-testid="report-decompile-workspace">{{ taskId }}</div>',
          },
        },
      },
    })
    await flushPromises()

    await wrapper.get('button[title="查看反编译代码"]').trigger('click')
    expect(wrapper.get('[data-testid="report-decompile-workspace"]').text()).toBe(
      taskId,
    )
    expect(wrapper.text()).toContain('反编译代码')

    await wrapper.get('button[aria-label="返回报告产物"]').trigger('click')
    expect(wrapper.find('[data-testid="report-decompile-workspace"]').exists()).toBe(
      false,
    )
    expect(wrapper.text()).toContain('报告产物')
  })
})
