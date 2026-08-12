import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import TaskResultTabs from '@/components/tasks/TaskResultTabs.vue'
import type { TaskResultStates } from '@/components/tasks/taskResultTypes'
import type { TaskResultTab } from '@/components/tasks/taskResultTypes'

function mountTabs(options: {
  states?: TaskResultStates
  mode?: 'live' | 'preview'
  visibleTabs?: readonly TaskResultTab[]
} = {}) {
  const optionalProps = {
    ...(options.states ? { states: options.states } : {}),
    ...(options.mode ? { mode: options.mode } : {}),
    ...(options.visibleTabs ? { visibleTabs: options.visibleTabs } : {}),
  }

  return mount(TaskResultTabs, {
    props: {
      taskId: 'task-result-contract',
      ...optionalProps,
    },
    slots: {
      files: '<div data-testid="file-contract">文件结构契约</div>',
    },
  })
}

describe('TaskResultTabs', () => {
  it('opens the file structure by default through the typed content contract', () => {
    const wrapper = mountTabs()

    expect(wrapper.get('[role="tab"][data-result-tab="files"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[role="tabpanel"]').attributes('aria-labelledby')).toContain('tab-files')
    expect(wrapper.get('[data-testid="file-contract"]').text()).toBe('文件结构契约')
  })

  it('emits the typed active tab contract and keeps unavailable commands disabled', async () => {
    const wrapper = mountTabs()
    const decompileTab = wrapper.get('[role="tab"][data-result-tab="decompile"]')

    await decompileTab.trigger('click')

    expect(wrapper.emitted('update:activeTab')?.[0]).toEqual(['decompile'])
    expect(wrapper.emitted('tabChange')?.[0]).toEqual(['decompile'])
    expect(decompileTab.attributes('aria-selected')).toBe('true')
    expect(wrapper.text()).toContain('反编译结果未接入')
    expect(
      wrapper
        .get('button[aria-label="刷新反编译历史结果"]')
        .attributes(),
    ).toHaveProperty('disabled')
    expect(wrapper.get('button[aria-label="下载反编译结果"]').attributes()).toHaveProperty('disabled')
  })

  it('renders an explicit empty state without inventing vulnerability findings', async () => {
    const wrapper = mountTabs({
      states: {
        vulnerabilities: {
          status: 'empty',
          title: '本次任务暂无容器漏洞结果',
        },
      },
    })

    await wrapper.get('[role="tab"][data-result-tab="vulnerabilities"]').trigger('click')

    expect(wrapper.text()).toContain('本次任务暂无容器漏洞结果')
    expect(wrapper.text()).not.toMatch(/CVE-\d{4}-\d+/i)
    expect(wrapper.text()).not.toMatch(/[a-f0-9]{64}/i)
    expect(wrapper.html()).not.toContain('v-html')
  })

  it('keeps a managed live result mounted while its toolbar reflects loading', async () => {
    const wrapper = mount(TaskResultTabs, {
      props: {
        taskId: 'task-result-contract',
        states: {
          decompile: {
            status: 'loading',
            title: '正在读取真实反编译结果',
          },
        },
        managedTabs: ['decompile'],
      },
      slots: {
        decompile:
          '<div data-testid="managed-decompile">组件内部加载状态</div>',
      },
    })

    await wrapper
      .get('[role="tab"][data-result-tab="decompile"]')
      .trigger('click')

    expect(wrapper.text()).toContain('读取中')
    expect(wrapper.get('[data-testid="managed-decompile"]').text()).toBe(
      '组件内部加载状态',
    )
    expect(wrapper.text()).not.toContain('正在读取真实反编译结果')
  })

  it('supports arrow-key tab navigation and clearly labels preview content', async () => {
    const wrapper = mountTabs({ mode: 'preview' })

    await wrapper
      .get('[role="tab"][data-result-tab="files"]')
      .trigger('keydown', { key: 'ArrowRight' })

    expect(wrapper.get('[role="tab"][data-result-tab="decompile"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.text()).toContain('界面预览')
  })

  it('renders only the result tabs selected by the task profile', async () => {
    const wrapper = mountTabs({
      visibleTabs: ['files', 'vulnerabilities', 'reports'],
    })

    expect(wrapper.find('[data-result-tab="decompile"]').exists()).toBe(false)
    expect(wrapper.findAll('[role="tab"]')).toHaveLength(3)

    await wrapper
      .get('[role="tab"][data-result-tab="files"]')
      .trigger('keydown', { key: 'ArrowRight' })

    expect(
      wrapper
        .get('[role="tab"][data-result-tab="vulnerabilities"]')
        .attributes('aria-selected'),
    ).toBe('true')
  })

  it('exposes the Java analysis tab and its refresh command contract', async () => {
    const wrapper = mount(TaskResultTabs, {
      props: {
        taskId: 'task-java',
        visibleTabs: ['files', 'java-analysis'],
        states: { 'java-analysis': { status: 'ready' } },
        commands: {
          'refresh-java-analysis': { enabled: true, pending: false },
        },
      },
      slots: {
        files: '<div>files</div>',
        'java-analysis': '<div data-testid="java-analysis">Java findings</div>',
      },
    })

    await wrapper
      .get('[role="tab"][data-result-tab="java-analysis"]')
      .trigger('click')
    expect(wrapper.get('[data-testid="java-analysis"]').text()).toBe(
      'Java findings',
    )
    await wrapper
      .get('button[aria-label="刷新 Java 源码检测结果"]')
      .trigger('click')
    expect(wrapper.emitted('command')).toEqual([['refresh-java-analysis']])
  })
})
