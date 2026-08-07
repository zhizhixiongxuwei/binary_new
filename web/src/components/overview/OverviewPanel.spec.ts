import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { ScanTask } from '@/api/types'
import OverviewPanel from '@/components/overview/OverviewPanel.vue'

const push = vi.fn()
const ElButtonStub = {
  template: '<button type="button"><slot /></button>',
}

vi.mock('vue-router', () => ({
  useRouter: () => ({ push }),
}))

function task(
  id: string,
  status: ScanTask['status'],
  risk: ScanTask['risk_level'],
): ScanTask {
  return {
    id,
    name: `${id}.tar`,
    input_type: 'tar',
    status,
    risk_level: risk,
    progress: 50,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: 'Operator',
    tags: [],
    created_at: '2026-07-30T00:00:00Z',
    sample_expires_at: '2099-08-29T00:00:00Z',
    sample_deleted_at: null,
  }
}

describe('OverviewPanel', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    push.mockReset()
  })

  it('renders honest recent-task metrics and keeps both status dimensions visible', async () => {
    vi.spyOn(api, 'listTasks').mockResolvedValue({
      items: [
        task('running', 'SCANNING', 'UNKNOWN'),
        task('queued', 'QUEUED', 'UNKNOWN'),
        task('failed', 'FAILED', 'HIGH'),
      ],
    })

    const wrapper = mount(OverviewPanel, {
      global: {
        stubs: {
          ElButton: ElButtonStub,
        },
      },
    })
    await flushPromises()

    const metrics = wrapper.findAll('.metric__copy dd').map((node) => node.text())
    expect(metrics).toEqual(['3', '2', '1', '1'])
    expect(api.listTasks).toHaveBeenCalledWith({ page_size: 8 })
    expect(wrapper.findAll('.activity-row__badges')).toHaveLength(3)
    expect(wrapper.get('[aria-label="风险等级：高危"]')).toBeTruthy()
    expect(wrapper.get('.activity-row__marker--active')).toBeTruthy()
    expect(wrapper.get('time').attributes('datetime')).toBe('2026-07-30T00:00:00Z')
  })

  it('opens a selected task from the recent activity list', async () => {
    vi.spyOn(api, 'listTasks').mockResolvedValue({
      items: [task('task-a', 'SUCCEEDED', 'LOW')],
    })

    const wrapper = mount(OverviewPanel, {
      global: {
        stubs: { ElButton: ElButtonStub },
      },
    })
    await flushPromises()
    await wrapper.get('.activity-row').trigger('click')

    expect(push).toHaveBeenCalledWith({
      name: 'task-detail',
      params: { id: 'task-a' },
    })
  })
})
