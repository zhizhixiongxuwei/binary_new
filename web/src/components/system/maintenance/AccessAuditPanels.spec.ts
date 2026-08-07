import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import AuditLogPanel from '@/components/system/maintenance/AuditLogPanel.vue'
import UserRolesPanel from '@/components/system/maintenance/UserRolesPanel.vue'

describe('UserRolesPanel', () => {
  it('previews the three local roles and keeps account creation disabled', () => {
    const wrapper = mount(UserRolesPanel, {
      props: { mode: 'preview' },
    })

    expect(wrapper.findAll('.role-card')).toHaveLength(3)
    expect(wrapper.text()).toContain('administrator')
    expect(wrapper.text()).toContain('operator')
    expect(wrapper.text()).toContain('reader')
    expect(wrapper.findAll('.user-row')).toHaveLength(3)
    expect(wrapper.get('.user-command button').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('命令不可用：后端未接入')
  })
})

describe('AuditLogPanel', () => {
  it('filters fixed audit events locally by event type', async () => {
    const wrapper = mount(AuditLogPanel, {
      props: { mode: 'preview' },
    })

    expect(wrapper.findAll('.audit-row')).toHaveLength(5)
    await wrapper.get('select[aria-label="按审计事件类型筛选"]').setValue(
      'authentication',
    )

    expect(wrapper.findAll('.audit-row')).toHaveLength(2)
    expect(wrapper.text()).toContain('登录成功')
    expect(wrapper.text()).toContain('访问系统维护被拒绝')
    expect(wrapper.text()).not.toContain('创建检测任务')
    expect(wrapper.get('.audit-toolbar__actions button').attributes('disabled')).toBeDefined()
  })
})
