import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { FileNodeDetail, TaskDetail } from '@/api/types'
import TaskAnalysisActions from '@/components/tasks/TaskAnalysisActions.vue'
import { resolveSampleRetention } from '@/utils/sampleRetention'

function task(inputType = 'elf64'): TaskDetail {
  return {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'sample.bin',
    input_type: inputType,
    status: 'SUCCEEDED',
    risk_level: 'NONE',
    progress: 100,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: 'Operator',
    tags: [],
    created_at: '2026-08-04T00:00:00Z',
    sample_expires_at: '2099-08-29T00:00:00Z',
    sample_deleted_at: null,
  }
}

function node(overrides: Partial<FileNodeDetail> = {}): FileNodeDetail {
  return {
    id: '1',
    parent_id: null,
    logical_path: '/sample.bin',
    display_name: 'sample.bin',
    archive_name_id: '',
    node_type: 'file',
    depth: 0,
    format: 'elf64',
    mime_type: 'application/x-elf',
    architecture: 'x86_64',
    size_bytes: 1024,
    sha256: 'a'.repeat(64),
    extraction_status: 'indexed',
    error_code: '',
    error_message: '',
    source_container: null,
    has_children: false,
    metadata_json: {},
    source_parent: null,
    ...overrides,
  }
}

const retention = resolveSampleRetention({
  sampleExpiresAt: '2099-08-29T00:00:00Z',
  sampleDeletedAt: null,
  now: new Date('2026-08-04T00:00:00Z'),
})

function mountActions(options: {
  inputType?: string
  target?: FileNodeDetail | null
  role?: 'administrator' | 'operator' | 'reader'
} = {}) {
  return mount(TaskAnalysisActions, {
    props: {
      task: task(options.inputType),
      node: options.target ?? null,
      userRole: options.role ?? 'operator',
      mode: 'live',
      sampleRetention: retention,
    },
    global: {
      stubs: {
        ElButton: {
          inheritAttrs: false,
          props: ['disabled', 'loading'],
          emits: ['click'],
          template: `
            <button
              v-bind="$attrs"
              type="button"
              :disabled="disabled"
              @click="$emit('click')"
            ><slot /></button>
          `,
        },
      },
    },
  })
}

describe('TaskAnalysisActions', () => {
  it('places the real decompile command in the outer task action area', () => {
    const wrapper = mountActions({ target: node() })

    expect(wrapper.get('.analysis-actions__heading').text()).toContain('sample.bin')
    expect(wrapper.get('[data-action="decompile-file"]').text()).toContain(
      '发起反编译',
    )
    expect(wrapper.find('.analysis-actions__commands').exists()).toBe(false)
  })

  it('places an eligible nested Trivy command in the same outer area', () => {
    const wrapper = mountActions({
      inputType: 'oci-tar',
      target: node({
        id: '9',
        parent_id: '2',
        format: 'oci-tar',
        extraction_status: 'limit_reached',
        error_code: 'max_auto_container_images',
      }),
    })

    expect(wrapper.get('[data-action="scan-nested-image"]').text()).toContain(
      '单独检测',
    )
  })

  it('places the uploaded root-image Trivy command in the outer action area', () => {
    const wrapper = mountActions({
      inputType: 'oci-tar',
      target: node({
        format: 'oci-tar',
        extraction_status: 'indexed',
      }),
    })

    expect(wrapper.get('[data-action="scan-root-image"]').text()).toContain(
      '开始 Trivy 检测',
    )
    expect(wrapper.find('.analysis-actions__commands').exists()).toBe(false)
  })

  it('keeps Trivy results and target selection available before a node is selected', async () => {
    const wrapper = mountActions({ inputType: 'docker-tar' })
    const buttons = wrapper.findAll('.analysis-actions__commands button')

    expect(buttons.map((button) => button.text())).toEqual([
      '查看 Trivy 检测',
      '选择嵌套镜像',
    ])
    await buttons[0]!.trigger('click')
    await buttons[1]!.trigger('click')

    expect(wrapper.emitted('openVulnerabilities')).toHaveLength(1)
    expect(wrapper.emitted('openFiles')).toHaveLength(1)
  })

  it('does not expose analysis mutation commands to a reader', () => {
    const wrapper = mountActions({ target: node(), role: 'reader' })

    expect(wrapper.find('.analysis-actions').exists()).toBe(false)
  })
})
