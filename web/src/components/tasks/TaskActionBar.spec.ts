import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskDetail, UserRole } from '@/api/types'
import TaskActionBar from '@/components/tasks/TaskActionBar.vue'

const NOW = new Date('2026-07-31T00:00:00.000Z')

const ElButtonStub = {
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
}

const ElDialogStub = {
  props: {
    modelValue: { type: Boolean, required: true },
    title: { type: String, required: true },
  },
  emits: ['update:modelValue', 'closed'],
  template: `
    <section v-if="modelValue" role="dialog" :aria-label="title">
      <h2>{{ title }}</h2>
      <slot />
      <slot name="footer" />
    </section>
  `,
}

const ElInputStub = {
  inheritAttrs: false,
  props: {
    modelValue: { type: String, default: '' },
  },
  emits: ['update:modelValue'],
  template: `
    <input
      v-bind="$attrs"
      :value="modelValue"
      @input="$emit('update:modelValue', $event.target.value)"
    >
  `,
}

function task(
  status: TaskDetail['status'],
  sampleExpiresAt = '2099-08-29T00:00:00.000Z',
): TaskDetail {
  return {
    id: 'task-action-bar',
    name: 'legacy-backup.iso',
    original_filename: 'legacy-backup.iso',
    input_type: 'iso9660',
    status,
    risk_level: 'UNKNOWN',
    progress: 23,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: '检测人员',
    tags: [],
    created_at: '2026-07-30T00:00:00.000Z',
    sample_expires_at: sampleExpiresAt,
    sample_deleted_at: null,
  }
}

function mountBar(options: {
  status?: TaskDetail['status']
  mode?: 'live' | 'preview'
  userRole?: UserRole
  isCreator?: boolean
  sampleExpiresAt?: string
  sampleDeletedAt?: string
  now?: Date
  pendingAction?: 'cancel' | 'retry' | 'delete' | 'extend' | null
} = {}) {
  const value = task(
    options.status ?? 'FAILED',
    options.sampleExpiresAt ?? '2099-08-29T00:00:00.000Z',
  )
  if (options.sampleDeletedAt) {
    value.sample_deleted_at = options.sampleDeletedAt
  }
  return mount(TaskActionBar, {
    props: {
      task: value,
      mode: options.mode ?? 'preview',
      userRole: options.userRole ?? 'administrator',
      isCreator: options.isCreator ?? true,
      now: options.now ?? NOW,
      pendingAction: options.pendingAction ?? null,
    },
    global: {
      stubs: {
        ElButton: ElButtonStub,
        ElDialog: ElDialogStub,
        ElInput: ElInputStub,
      },
    },
  })
}

describe('TaskActionBar', () => {
  it('labels preview behavior and uses a dedicated cancellation confirmation', async () => {
    const wrapper = mountBar({ status: 'SCANNING' })

    expect(wrapper.text()).toContain('预览模式')
    await wrapper.get('[data-action="cancel"]').trigger('click')

    expect(wrapper.get('[role="dialog"]').attributes('aria-label')).toBe(
      '取消当前任务？',
    )
    expect(wrapper.emitted('cancel')).toBeUndefined()

    await wrapper.get('[data-confirm="cancel"]').trigger('click')
    expect(wrapper.emitted('cancel')).toHaveLength(1)
  })

  it('requires the exact task name in the distinct dangerous delete confirmation', async () => {
    const wrapper = mountBar()

    await wrapper.get('[data-action="delete"]').trigger('click')

    expect(wrapper.get('[role="dialog"]').attributes('aria-label')).toBe(
      '删除任务？',
    )
    expect(wrapper.text()).toContain('清理挂载目录中的样本引用')
    expect(wrapper.text()).toContain('Trivy 检测结果和生成报告')
    const confirm = wrapper.get<HTMLButtonElement>('[data-confirm="delete"]')
    expect(confirm.element.disabled).toBe(true)

    await wrapper.get('#delete-task-name').setValue('wrong-name.iso')
    expect(confirm.element.disabled).toBe(true)

    await wrapper.get('#delete-task-name').setValue('legacy-backup.iso')
    expect(confirm.element.disabled).toBe(false)
    await confirm.trigger('click')

    expect(wrapper.emitted('delete')).toHaveLength(1)
  })

  it('emits retry and a thirty-day retention value only when permitted', async () => {
    const wrapper = mountBar()

    await wrapper.get('[data-action="retry"]').trigger('click')
    await wrapper.get('[data-action="extend"]').trigger('click')

    expect(wrapper.emitted('retry')).toHaveLength(1)
    expect(wrapper.emitted('extend')?.[0]).toEqual([
      '2099-09-28T00:00:00.000Z',
    ])
  })

  it('enables administrator retention extension in live mode', async () => {
    const wrapper = mountBar({ mode: 'live', status: 'SCANNING' })

    expect(wrapper.text()).toContain('在线操作')
    expect(
      wrapper.get<HTMLButtonElement>('[data-action="cancel"]').element.disabled,
    ).toBe(false)
    expect(
      wrapper.get<HTMLButtonElement>('[data-action="retry"]').element.disabled,
    ).toBe(true)
    expect(
      wrapper.get<HTMLButtonElement>('[data-action="extend"]').element.disabled,
    ).toBe(false)
    expect(
      wrapper.get<HTMLButtonElement>('[data-action="delete"]').element.disabled,
    ).toBe(false)
    await wrapper.get('[data-action="extend"]').trigger('click')
    expect(wrapper.emitted('extend')?.[0]).toEqual([
      '2099-09-28T00:00:00.000Z',
    ])
  })

  it('keeps all commands in a compact toolbar and hides reason copy visually', () => {
    const wrapper = mountBar({ mode: 'live', status: 'FAILED' })

    expect(wrapper.get('.task-actions__commands').attributes('role')).toBe(
      'group',
    )
    expect(wrapper.findAll('.task-action')).toHaveLength(4)
    expect(wrapper.findAll('.task-action > small')).toHaveLength(0)
    expect(wrapper.findAll('.task-action .sr-only')).toHaveLength(4)
    expect(wrapper.find('.task-actions__header').exists()).toBe(false)
    const disabledCancel = wrapper.get('.task-action')
    expect(disabledCancel.attributes('tabindex')).toBe('0')
    expect(disabledCancel.attributes('title')).toContain('仅排队中或执行中')
    expect(disabledCancel.attributes('aria-describedby')).toBe(
      'cancel-action-reason',
    )
    expect(wrapper.get('#cancel-action-reason').text()).toContain(
      '仅排队中或执行中',
    )
  })

  it('locks every command while one lifecycle action is pending', async () => {
    const wrapper = mountBar({
      mode: 'live',
      status: 'FAILED',
      pendingAction: 'extend',
    })

    expect(wrapper.get('.task-actions').attributes('aria-busy')).toBe('true')
    for (const action of ['cancel', 'retry', 'extend', 'delete']) {
      const button = wrapper.get<HTMLButtonElement>(`[data-action="${action}"]`)
      expect(button.element.disabled).toBe(true)
      await button.trigger('click')
    }
    expect(wrapper.get('[data-action="extend"]').attributes('data-loading')).toBe(
      'true',
    )

    expect(wrapper.emitted('cancel')).toBeUndefined()
    expect(wrapper.emitted('retry')).toBeUndefined()
    expect(wrapper.emitted('extend')).toBeUndefined()
    expect(wrapper.emitted('delete')).toBeUndefined()
  })

  it('distinguishes retention expiry awaiting cleanup from a cleaned task sample', () => {
    const wrapper = mountBar({
      status: 'FAILED',
      sampleExpiresAt: '2020-01-01T00:00:00.000Z',
    })

    expect(wrapper.text()).toContain('保留期已到，等待后台清理')
    expect(wrapper.text()).not.toContain('任务原始样本已清理')
    expect(
      wrapper.get<HTMLButtonElement>('[data-action="retry"]').element.disabled,
    ).toBe(true)
    expect(wrapper.get('[data-action="retry"]').attributes('title')).toContain(
      '样本保留期已到',
    )

    const deleted = mountBar({
      status: 'FAILED',
      sampleExpiresAt: '2020-01-01T00:00:00.000Z',
      sampleDeletedAt: '2020-01-01T00:01:00.000Z',
    })

    expect(deleted.text()).toContain('任务原始样本已清理')
    expect(
      deleted.get<HTMLButtonElement>('[data-action="retry"]').element.disabled,
    ).toBe(true)
    expect(
      deleted.get<HTMLButtonElement>('[data-action="extend"]').element.disabled,
    ).toBe(true)
    expect(deleted.get('[data-action="retry"]').attributes('title')).toContain(
      '任务原始样本已清理',
    )
  })

  it('recomputes the disabled reason from an injected current time', async () => {
    const expiry = '2026-07-31T00:00:01.000Z'
    const wrapper = mountBar({
      status: 'FAILED',
      sampleExpiresAt: expiry,
      now: NOW,
    })

    const retry = wrapper.get<HTMLButtonElement>('[data-action="retry"]')
    expect(retry.element.disabled).toBe(false)

    await wrapper.setProps({ now: new Date(expiry) })

    expect(retry.element.disabled).toBe(true)
    expect(retry.attributes('title')).toContain('样本保留期已到')
    await retry.trigger('click')
    expect(wrapper.emitted('retry')).toBeUndefined()
  })
})
