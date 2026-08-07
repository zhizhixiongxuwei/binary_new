import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'
import TaskStageProgress from '@/components/tasks/TaskStageProgress.vue'

function analyzerEntry(phase: string, current: number | null = null, total: number | null = null): TaskExecutionLogEntry {
  return {
    key: '1',
    sequence: 1,
    title: phase,
    detailLabel: null,
    stageLabel: null,
    progressLabel: null,
    severityLabel: '信息',
    tone: 'info',
    createdAt: '2026-08-04T08:00:00Z',
    workflow: 'decompile',
    phase,
    current,
    total,
  }
}

function mountProgress(entries: readonly TaskExecutionLogEntry[]) {
  return mount(TaskStageProgress, {
    props: {
      task: {
        input_type: 'pe32+',
        status: 'SCANNING',
        current_stage: 'SCANNING',
        progress: 70,
        progress_indeterminate: true,
      },
      entries,
    },
  })
}

describe('TaskStageProgress', () => {
  it('renders the type-specific workflow with a single current step', () => {
    const wrapper = mountProgress([analyzerEntry('running', 5, 10)])
    const stages = wrapper.findAll('.task-stages__item')

    expect(stages).toHaveLength(6)
    expect(wrapper.text()).toContain('类 C 反编译')
    expect(wrapper.get('[data-stage="running"]').attributes('data-state')).toBe('current')
    expect(wrapper.get('[data-stage="running"]').attributes('aria-current')).toBe('step')
    expect(wrapper.get('[role="progressbar"]').attributes('aria-valuenow')).toBe('55')
  })

  it('uses accessible indeterminate semantics when analyzer counters are unknown', () => {
    const wrapper = mountProgress([analyzerEntry('running')])
    const meter = wrapper.get('[role="progressbar"]')

    expect(meter.attributes('data-progress-mode')).toBe('indeterminate')
    expect(meter.attributes('aria-valuenow')).toBeUndefined()
    expect(wrapper.get('.task-stages__percentage').text()).toBe('计算中')
  })

  it('does not claim completion when no analyzer activity has arrived', () => {
    const wrapper = mountProgress([])

    expect(wrapper.text()).toContain('尚未收到反编译执行日志')
    expect(wrapper.findAll('[data-state="completed"]')).toHaveLength(0)
  })
})
