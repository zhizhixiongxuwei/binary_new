import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TaskExecutionLog from '@/components/tasks/TaskExecutionLog.vue'
import type { TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'

function entry(sequence: number, title: string): TaskExecutionLogEntry {
  return {
    key: String(sequence),
    sequence,
    title,
    detailLabel: sequence === 2 ? '目标 1 / 2 · 7 条发现' : null,
    stageLabel: '分析扫描',
    progressLabel: `${sequence * 10}%`,
    severityLabel: '信息',
    tone: 'info',
    createdAt: `2026-08-04T08:00:0${sequence}Z`,
    workflow: 'task',
    phase: null,
    current: null,
    total: null,
  }
}

describe('TaskExecutionLog', () => {
  it('renders normalized entries in chronological order', () => {
    const wrapper = mount(TaskExecutionLog, {
      props: {
        entries: [entry(1, '任务已创建'), entry(2, '镜像目标检测完成')],
        connectionStatus: 'connected',
        connectionLabel: '实时事件已连接',
        connectionTitle: '实时事件已连接',
      },
    })

    const rows = wrapper.findAll('.execution-log__item')
    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('任务已创建')
    expect(rows[1]?.text()).toContain('镜像目标检测完成')
    expect(rows[1]?.text()).toContain('目标 1 / 2 · 7 条发现')
    expect(wrapper.text()).toContain('实时事件已连接')
  })

  it('automatically follows the newest chronological entry', async () => {
    const wrapper = mount(TaskExecutionLog, {
      props: {
        entries: [entry(1, '任务已创建')],
        connectionStatus: 'connected',
        connectionLabel: '实时事件已连接',
        connectionTitle: '实时事件已连接',
      },
    })
    const list = wrapper.get<HTMLOListElement>('[role="log"]').element
    Object.defineProperty(list, 'scrollHeight', {
      configurable: true,
      value: 480,
    })

    await wrapper.setProps({
      entries: [entry(1, '任务已创建'), entry(2, '任务进度已更新')],
    })
    await wrapper.vm.$nextTick()

    expect(list.scrollTop).toBe(480)
  })
})
