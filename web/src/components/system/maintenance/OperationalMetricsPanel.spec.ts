import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import OperationalMetricsPanel from '@/components/system/maintenance/OperationalMetricsPanel.vue'

describe('OperationalMetricsPanel', () => {
  it('renders bounded stage durations and analyzer failure rates', () => {
    const wrapper = mount(OperationalMetricsPanel, {
      props: {
        metrics: {
          window_hours: 168,
          stage_durations: [
            {
              stage: 'IDENTIFYING',
              sample_count: 8,
              average_duration_ms: 420,
            },
            {
              stage: 'SCANNING',
              sample_count: 5,
              average_duration_ms: 61_000,
            },
          ],
          analyzer_failure_rates: [
            {
              name: 'ghidra',
              total_runs: 10,
              failed_runs: 2,
              failure_rate_basis_points: 2_000,
            },
            {
              name: 'trivy',
              total_runs: 8,
              failed_runs: 0,
              failure_rate_basis_points: 0,
            },
          ],
        },
      },
    })

    expect(wrapper.text()).toContain('LIVE / 7 DAYS')
    expect(wrapper.text()).toContain('420 ms')
    expect(wrapper.text()).toContain('1.0 分钟')
    expect(wrapper.text()).toContain('20.00%')
    expect(wrapper.text()).toContain('0.00%')
    expect(wrapper.text()).toContain('18分析运行')
    expect(wrapper.findAll('[role="table"]')).toHaveLength(2)
    expect(wrapper.find('.failure-rate--critical').text()).toBe('20.00%')
    expect(wrapper.find('.failure-rate--healthy').text()).toBe('0.00%')
  })

  it('shows explicit empty states without inventing data', () => {
    const wrapper = mount(OperationalMetricsPanel)

    expect(wrapper.text()).toContain('窗口内暂无完整阶段转换样本')
    expect(wrapper.text()).toContain('窗口内暂无分析器运行记录')
    expect(wrapper.findAll('[role="table"]')).toHaveLength(0)
  })
})
