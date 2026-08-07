import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import StorageMountsPanel from '@/components/system/maintenance/StorageMountsPanel.vue'

describe('StorageMountsPanel', () => {
  it('shows the two named volumes and shared paths with bounded usage meters', () => {
    const wrapper = mount(StorageMountsPanel, {
      props: { mode: 'preview' },
    })

    expect(wrapper.findAll('.mount-row')).toHaveLength(4)
    expect(wrapper.text()).toContain('binaryscan-data volume')
    expect(wrapper.text()).toContain('/data/repository')
    expect(wrapper.text()).toContain('/data/uploads')
    expect(wrapper.text()).toContain('/data/task-work')
    expect(wrapper.text()).toContain('mysql-data volume')
    expect(wrapper.text()).toContain('/var/lib/mysql')
    expect(wrapper.text()).toContain('app / scanner / java / ghidra')

    const meters = wrapper.findAll('[role="progressbar"]')
    expect(meters).toHaveLength(4)
    for (const meter of meters) {
      const value = Number(meter.attributes('aria-valuenow'))
      expect(value).toBeGreaterThanOrEqual(0)
      expect(value).toBeLessThanOrEqual(100)
    }
  })
})
