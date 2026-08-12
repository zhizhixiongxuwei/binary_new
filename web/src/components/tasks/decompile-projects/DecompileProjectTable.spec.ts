import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type {
  DecompileProject,
  JavaAnalysisRun,
} from '@/api/types'
import DecompileProjectTable from '@/components/tasks/decompile-projects/DecompileProjectTable.vue'

function project(id: string): DecompileProject {
  return {
    id,
    task_id: 'task-1',
    file_node_id: `file-${id}`,
    target_path: `/app/${id}.jar`,
    layout_version: 'project-v1',
    source_kind: 'java',
    language: 'mixed',
    engine_name: 'cfr',
    engine_version: '0.152',
    status: 'complete',
    source_file_count: 2,
    symbol_count: 4,
    source_size_bytes: 4096,
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
  }
}

function activeRun(projectId: string): JavaAnalysisRun {
  return {
    id: 'run-1',
    task_id: 'task-1',
    source_project_id: projectId,
    source_project: {
      id: projectId,
      target_path: `/app/${projectId}.jar`,
      status: 'complete',
      engine_name: 'cfr',
      engine_version: '0.152',
    },
    job_id: 'job-1',
    status: 'running',
    analyzer_name: 'binaryscan-java-checker',
    analyzer_version: '0.1.0',
    ruleset_version: '',
    source_manifest_sha256: 'a'.repeat(64),
    input_sha256: 'b'.repeat(64),
    bundle_sha256: 'c'.repeat(64),
    source_size_bytes: 4096,
    source_file_count: 2,
    finding_count: 0,
    diagnostic_count: 0,
    coverage: {
      total_files: 2,
      analyzed_files: 0,
      parsed_files: 0,
      recovered_files: 0,
      failed_files: 0,
    },
    severity_counts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    findings_truncated: false,
    diagnostics_truncated: false,
    error_code: null,
    error_message: null,
    started_at: '2026-08-10T01:02:00Z',
    completed_at: null,
    created_at: '2026-08-10T01:02:00Z',
    updated_at: '2026-08-10T01:02:00Z',
  }
}

describe('DecompileProjectTable Java analysis action', () => {
  it('offers Java detection only for eligible projects and disables an active run', async () => {
    const available = project('project-ready')
    const active = project('project-active')
    const unavailable = {
      ...project('project-no-manifest'),
      manifest_available: false,
    }
    const wrapper = mount(DecompileProjectTable, {
      props: {
        projects: [available, active, unavailable],
        canDelete: true,
        canAnalyze: true,
        loadingMore: false,
        hasMore: false,
        downloadingProjectId: '',
        deletingProjectId: '',
        latestCAnalysisByProject: {},
        latestJavaAnalysisByProject: {
          [active.id]: activeRun(active.id),
        },
      },
      global: {
        stubs: {
          ElButton: {
            template: '<button type="button"><slot /></button>',
          },
        },
      },
    })

    const readyButton = wrapper.get(
      `button[aria-label="对源码项目 ${available.id} 执行 Java 检测"]`,
    )
    const activeButton = wrapper.get(
      `button[aria-label="对源码项目 ${active.id} 执行 Java 检测"]`,
    )
    expect(readyButton.attributes('disabled')).toBeUndefined()
    expect(activeButton.attributes('disabled')).toBeDefined()
    expect(
      wrapper.find(
        `button[aria-label="对源码项目 ${unavailable.id} 执行 Java 检测"]`,
      ).exists(),
    ).toBe(false)
    expect(wrapper.text()).toContain('Java 检测：未执行')
    expect(wrapper.text()).toContain('Java 检测：检测中')

    await readyButton.trigger('click')
    expect(wrapper.emitted('analyzeJava')).toEqual([[available]])
  })
})
