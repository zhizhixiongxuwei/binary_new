import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type {
  DecompileProject,
  DecompileProjectDeletionOperation,
  DecompileProjectDeletionPreview,
  UserRole,
} from '@/api/types'
import DecompileProjectPanel from '@/components/tasks/decompile-projects/DecompileProjectPanel.vue'

function project(
  id: string,
  overrides: Partial<DecompileProject> = {},
): DecompileProject {
  return {
    id,
    task_id: 'task-1',
    job_id: `job-${id}`,
    file_node_id: `file-${id}`,
    target_path: `/app/${id}.bin`,
    layout_version: 'project-v1',
    source_kind: 'ghidra-pseudoc',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '11.3.2',
    status: 'complete',
    source_file_count: 1,
    symbol_count: 88,
    source_size_bytes: 8192,
    canonical_filename: 'src/decompiled.c',
    manifest_available: true,
    created_at: '2026-08-10T01:00:00Z',
    completed_at: '2026-08-10T01:01:00Z',
    ...overrides,
  }
}

const wrappers: VueWrapper[] = []

function preview(projectId: string): DecompileProjectDeletionPreview {
  return {
    project_id: projectId,
    counts: {
      c_analysis_runs: 2,
      c_analysis_findings: 17,
      java_analysis_runs: 1,
      java_analysis_findings: 8,
      reports: 1,
      report_files: 1,
      artifacts: 0,
      decompile_results: 88,
      source_files: 1,
    },
    typed_suffix: projectId.slice(-8),
    confirmation_token: 'server-confirmation-token-value',
    expires_at: '2026-08-10T02:05:00Z',
  }
}

function operation(projectId: string): DecompileProjectDeletionOperation {
  return {
    id: '123e4567-e89b-42d3-a456-426614174010',
    project_id: projectId,
    status: 'pending',
    counts: preview(projectId).counts,
    created_at: '2026-08-10T02:00:00Z',
    completed_at: null,
    error_code: null,
    error_message: null,
  }
}

function mountPanel(role: UserRole, enabled = true): VueWrapper {
  const wrapper = mount(DecompileProjectPanel, {
    props: { taskId: 'task-1', userRole: role, enabled },
    global: {
      stubs: {
        ElButton: {
          inheritAttrs: false,
          props: {
            disabled: { type: Boolean, default: false },
            loading: { type: Boolean, default: false },
          },
          emits: ['click'],
          template: `
            <button
              v-bind="$attrs"
              type="button"
              :disabled="disabled"
              :data-loading="String(loading)"
              @click="$emit('click')"
            ><slot /></button>
          `,
        },
        ElDialog: {
          props: ['modelValue', 'title'],
          emits: ['update:modelValue'],
          template: `
            <section v-if="modelValue" role="dialog" :aria-label="title">
              <slot />
              <footer><slot name="footer" /></footer>
            </section>
          `,
        },
        ElCheckbox: {
          props: ['modelValue', 'disabled'],
          emits: ['update:modelValue'],
          template: `<label><input data-cascade-confirm type="checkbox" :disabled="disabled" :checked="modelValue" @change="$emit('update:modelValue', $event.target.checked)"><slot /></label>`,
        },
        ElInput: {
          inheritAttrs: false,
          props: ['modelValue', 'disabled'],
          emits: ['update:modelValue'],
          template: `<input v-bind="$attrs" :disabled="disabled" :value="modelValue" @input="$emit('update:modelValue', $event.target.value)">`,
        },
      },
    },
  })
  wrappers.push(wrapper)
  return wrapper
}

describe('DecompileProjectPanel', () => {
  afterEach(() => {
    for (const wrapper of wrappers.splice(0)) wrapper.unmount()
    vi.restoreAllMocks()
  })

  it('shows version metadata and hides delete controls from readers', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-native'),
        project('project-java', {
          source_kind: 'java',
          language: 'java',
          engine_name: 'Vineflower',
          engine_version: '1.11.1',
          source_file_count: 34,
          symbol_count: 34,
        }),
      ],
    })

    const wrapper = mountPanel('reader')
    await flushPromises()

    expect(wrapper.text()).toContain('project-native')
    expect(wrapper.text()).toContain('Ghidra 伪 C')
    expect(wrapper.text()).toContain('Vineflower 1.11.1')
    expect(wrapper.findAll('[aria-label^="下载源码项目 "]')).toHaveLength(2)
    expect(wrapper.find('[aria-label^="删除源码项目版本 "]').exists()).toBe(false)
  })

  it('waits until enabled before loading the task information panel', async () => {
    const list = vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-lazy')],
    })
    const wrapper = mountPanel('operator', false)
    await flushPromises()

    expect(list).not.toHaveBeenCalled()
    await wrapper.setProps({ enabled: true })
    await flushPromises()

    expect(list).toHaveBeenCalledWith('task-1', { page_size: 100 })
    expect(wrapper.text()).toContain('project-lazy')
  })

  it('confirms one-version deletion and reports it to the parent', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [
        project('project-delete'),
        project('project-keep'),
      ],
    })
    vi.spyOn(api, 'previewDecompileProjectDeletion').mockResolvedValue(
      preview('project-delete'),
    )
    const remove = vi
      .spyOn(api, 'confirmDecompileProjectDeletion')
      .mockResolvedValue(operation('project-delete'))
    const wrapper = mountPanel('administrator')
    await flushPromises()

    await wrapper
      .get('[aria-label="删除源码项目版本 project-delete"]')
      .trigger('click')
    const dialogText = wrapper.get('[role="dialog"]').text()
    expect(dialogText).toContain('project-delete')
    expect(dialogText).toContain('Java 检测版本')
    expect(dialogText).toContain('Java 检测发现')

    await wrapper.get('[data-cascade-confirm]').setValue(true)
    await wrapper
      .get('[aria-label="输入项目 ID 后 8 位确认删除"]')
      .setValue('t-delete')

    await wrapper.get('[data-confirm="delete-project"]').trigger('click')
    await flushPromises()

    expect(remove).toHaveBeenCalledWith('task-1', 'project-delete', {
      confirmation_token: 'server-confirmation-token-value',
      cascade: true,
      typed_suffix: 't-delete',
    })
    expect(wrapper.emitted('deleted')).toEqual([['project-delete']])
    expect(wrapper.text()).not.toContain('/app/project-delete.bin')
    expect(wrapper.text()).toContain('project-keep')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
  })

  it('keeps the confirmation open when directory deletion fails', async () => {
    vi.spyOn(api, 'listDecompileProjects').mockResolvedValue({
      items: [project('project-busy')],
    })
    vi.spyOn(api, 'previewDecompileProjectDeletion').mockResolvedValue(
      preview('project-busy'),
    )
    vi.spyOn(api, 'confirmDecompileProjectDeletion').mockRejectedValue(
      new Error('目录清理失败'),
    )
    const wrapper = mountPanel('operator')
    await flushPromises()

    await wrapper
      .get('[aria-label="删除源码项目版本 project-busy"]')
      .trigger('click')
    await flushPromises()
    await wrapper.get('[data-cascade-confirm]').setValue(true)
    await wrapper
      .get('[aria-label="输入项目 ID 后 8 位确认删除"]')
      .setValue('ect-busy')
    await wrapper.get('[data-confirm="delete-project"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="dialog"]').text()).toContain(
      '删除源码项目失败：目录清理失败',
    )
    expect(wrapper.emitted('deleted')).toBeUndefined()
    expect(wrapper.text()).toContain('project-busy')
  })
})
