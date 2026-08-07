import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import SystemStatusPanel from '@/components/system/SystemStatusPanel.vue'

describe('SystemStatusPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders system capacity and analyzers with semantic status labels', async () => {
    vi.spyOn(api, 'getSystemStatus').mockResolvedValue({
      version: '0.2.0',
      build: {
        version: '0.2.0',
        commit: 'abcdef123456',
        build_time: '2026-07-30T00:00:00Z',
        go_version: 'go1.25.0',
      },
      service_status: 'degraded',
      active_tasks: 2,
      queued_tasks: 1,
      queue_depth: 3,
      task_counts: {
        FAILED: 4,
        SUCCEEDED: 20,
      },
      worker_summary: {
        observed_leases: 2,
        observed_owners: 1,
        leases_by_kind: { scanner: 2 },
        oldest_heartbeat_at: '2026-07-30T00:00:00Z',
        latest_heartbeat_at: '2026-07-30T00:01:00Z',
      },
      repository_used_bytes: 25,
      repository_total_bytes: 100,
      trivy_db_version: 'offline-2026-07',
      analyzers: [
        {
          name: 'Ghidra', version: '12.1.2', expected_version: '12.1.2',
          status: 'available', required_worker_kinds: ['native'],
          ready_worker_kinds: ['native'], ready_workers: 1,
          runtime_name: 'jdk', runtime_version: 'openjdk 21.0.4',
        },
        {
          name: 'ISO 挂载器', version: '', expected_version: '',
          status: 'unavailable', required_worker_kinds: [],
          ready_worker_kinds: [], ready_workers: 0,
          runtime_name: '', runtime_version: '',
        },
      ],
    })

    const wrapper = mount(SystemStatusPanel, {
      global: {
        stubs: {
          ElButton: {
            template: '<button type="button"><slot /></button>',
          },
        },
      },
    })
    await flushPromises()

    expect(wrapper.findAll('.summary-item')).toHaveLength(6)
    expect(wrapper.text()).toContain('部分降级')
    expect(wrapper.text()).toContain('队列深度')
    expect(wrapper.text()).toContain('Worker 租约观测')
    expect(wrapper.text()).toContain('不是进程在线清单')
    expect(wrapper.text()).toContain('abcdef123456')
    expect(wrapper.get('[role="progressbar"]').attributes('aria-valuenow')).toBe('25')
    expect(wrapper.findAll('thead th').map((node) => node.text())).toEqual([
      '分析器',
      '版本',
      '状态',
    ])
    expect(wrapper.text()).toContain('可用')
    expect(wrapper.text()).toContain('不可用')
  })
})
