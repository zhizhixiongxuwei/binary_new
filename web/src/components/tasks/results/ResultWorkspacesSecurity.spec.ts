import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type {
  DecompileResult,
  VulnerabilityFinding,
  VulnerabilitySummary,
} from '@/api/types'
import DecompileResultWorkspace from '@/components/tasks/results/DecompileResultWorkspace.vue'
import VulnerabilityResultWorkspace from '@/components/tasks/results/VulnerabilityResultWorkspace.vue'

const storedMarkup = '<img src=x onerror="globalThis.compromised=true">'
const storedScript = '<script>globalThis.compromised=true</script>'

describe('result workspace stored-markup handling', () => {
  it('renders analyzer symbols and source strictly as text', () => {
    const result: DecompileResult = {
      id: 'result-id',
      file_node_id: '1',
      symbol_key: 'unsafe-symbol',
      symbol_kind: 'function',
      display_name: storedMarkup,
      group_name: storedScript,
      location: '0x1000',
      signature: storedMarkup,
      detail: storedScript,
      language: 'c',
      engine_name: 'Ghidra',
      engine_version: 'test',
      status: 'complete',
      size_bytes: storedScript.length,
      diagnostics: { message: storedMarkup },
      created_at: '2026-07-30T00:00:00Z',
      completed_at: '2026-07-30T00:00:01Z',
    }
    const wrapper = mount(DecompileResultWorkspace, {
      props: {
        taskId: 'task-id',
        items: [result],
        selectedId: result.id,
        source: storedScript,
        sourceLoading: false,
        sourceError: '',
        hasMoreResults: false,
        loadingMoreResults: false,
        hasMoreSource: false,
      },
      global: {
        stubs: {
          ReadOnlyCodeEditor: {
            props: ['source'],
            template: '<pre data-testid="source">{{ source }}</pre>',
          },
        },
      },
    })

    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('script').exists()).toBe(false)
    expect(wrapper.text()).toContain(storedMarkup)
    expect(wrapper.get('[data-testid="source"]').text()).toContain(storedScript)
  })

  it('escapes finding evidence and never activates non-HTTP references', () => {
    const finding: VulnerabilityFinding = {
      id: '1',
      vulnerability_id: 'CVE-TEST-XSS',
      severity: 'HIGH',
      package_name: storedMarkup,
      installed_version: '1.0',
      fixed_version: '1.1',
      title: storedMarkup,
      description_summary: storedScript,
      image_logical_path: storedMarkup,
      image_platform: 'linux/amd64',
      evidence: { record: storedScript },
      references: ['javascript:globalThis.compromised=true', 'https://example.invalid/cve'],
		database_bundle: null,
      created_at: '2026-07-30T00:00:00Z',
    }
    const summary: VulnerabilitySummary = {
      total: 1,
      fixable: 1,
      by_severity: {
        UNKNOWN: 0,
        LOW: 0,
        MEDIUM: 0,
        HIGH: 1,
        CRITICAL: 0,
      },
    }
    const wrapper = mount(VulnerabilityResultWorkspace, {
      props: {
        taskId: 'task-id',
        summary,
        items: [finding],
        severity: undefined,
        selectedFinding: finding,
        detailLoading: false,
        detailError: '',
        hasMore: false,
        loadingMore: false,
      },
    })

    expect(wrapper.find('img').exists()).toBe(false)
    expect(wrapper.find('script').exists()).toBe(false)
    expect(wrapper.find('a[href^="javascript:"]').exists()).toBe(false)
    expect(wrapper.get('a[href^="https://"]').attributes('rel')).toBe('noreferrer noopener')
    expect(wrapper.text()).toContain(storedMarkup)
    expect(wrapper.text()).toContain(storedScript)
  })
})
