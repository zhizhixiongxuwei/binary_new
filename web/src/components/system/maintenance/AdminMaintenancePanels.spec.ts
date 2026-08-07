import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { AdminUser, SystemStatus } from '@/api/types'
import AnalyzerStatusPanel from '@/components/system/maintenance/AnalyzerStatusPanel.vue'
import AuditLogLivePanel from '@/components/system/maintenance/AuditLogLivePanel.vue'
import StorageStatusPanel from '@/components/system/maintenance/StorageStatusPanel.vue'
import UserManagementPanel from '@/components/system/maintenance/UserManagementPanel.vue'

const currentUser: AdminUser = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'admin',
  display_name: '系统管理员',
  role: 'administrator',
  status: 'active',
  must_change_password: false,
  failed_login_count: 0,
  locked_until: null,
  last_login_at: '2026-07-30T00:00:00Z',
  created_at: '2026-07-01T00:00:00Z',
  updated_at: '2026-07-30T00:00:00Z',
}

const baseSystem: SystemStatus = {
  version: '0.2.0',
  service_status: 'healthy',
  active_tasks: 1,
  queued_tasks: 0,
  repository_used_bytes: 50,
  repository_total_bytes: 100,
}

describe('live storage and analyzer maintenance panels', () => {
  it('distinguishes unobservable mounts from low-water mounts', () => {
    const wrapper = mount(StorageStatusPanel, {
      props: {
        status: {
          ...baseSystem,
          storage_mounts: [
            {
              id: 'mysql',
              label: 'mysql',
              purpose: '数据库目录',
              host_path: null,
              container_path: '/var/lib/mysql',
              services: ['mysql'],
              used_bytes: null,
              total_bytes: null,
              warning_percent: 80,
              critical_percent: 90,
              writable: null,
              status: 'unknown',
            },
            {
              id: 'task-work',
              label: 'task-work',
              purpose: '任务工作目录',
              host_path: '/srv/task-work',
              container_path: '/data/task-work',
              services: ['worker'],
              used_bytes: 95,
              total_bytes: 100,
              warning_percent: 80,
              critical_percent: 90,
              writable: true,
              low_water: true,
              status: 'critical',
            },
          ],
        },
        loading: false,
        errorMessage: '',
      },
    })

    expect(wrapper.findAll('.mount-row')).toHaveLength(2)
    expect(wrapper.text()).toContain('未由 API 容器挂载')
    expect(wrapper.text()).toContain('容量不可观测')
    expect(wrapper.text()).toContain('1 个目录需要处理')
    expect(wrapper.findAll('[role="progressbar"]')).toHaveLength(2)
  })

  it('shows stale fixed bundle health without database mutation commands', () => {
    const wrapper = mount(AnalyzerStatusPanel, {
      props: {
        status: {
          ...baseSystem,
          analyzers: [
            {
              name: 'Ghidra',
              version: '12.1.2',
              expected_version: '12.1.2',
              status: 'available',
              scope: 'PE / ELF',
              required_worker_kinds: ['native'],
              ready_worker_kinds: ['native'],
              ready_workers: 1,
              runtime_name: 'jdk',
              runtime_version: 'openjdk version "21.0.4"',
              last_checked_at: '2026-07-30T00:00:00Z',
              last_run_at: '2026-07-29T00:00:00Z',
              detail: '1 ready worker covers native.',
            },
          ],
          trivy_database_bundle: {
            id: 'db-1',
            version: 'bundle-2026-07-18',
            trivy_db_version: 'db-2026-07-18',
            trivy_java_db_version: 'java-db-2026-07-18',
            status: 'stale',
            generated_at: '2026-07-18T00:00:00Z',
            registered_at: '2026-07-18T00:00:00Z',
            age_days: 12,
            stale_after_days: 7,
            content_sha256: 'a'.repeat(64),
          },
        },
        loading: false,
        errorMessage: '',
      },
    })

    expect(wrapper.text()).toContain('数据库 Bundle 需要更新')
    expect(wrapper.text()).toContain('native')
    expect(wrapper.text()).toContain('1 READY')
    expect(wrapper.text()).toContain('openjdk version "21.0.4"')
    expect(wrapper.text()).toContain('已过旧')
    expect(wrapper.text()).toContain('bundle-2026-07-18')
    expect(wrapper.text()).toContain('java-db-2026-07-18')
    expect(wrapper.findAll('.command-buttons button')).toHaveLength(0)
  })
})

describe('live user management panel', () => {
  function mountUsers(role: 'administrator' | 'reader' = 'administrator') {
    return mount(UserManagementPanel, {
      props: {
        users: [currentUser],
        loading: false,
        loadingMore: false,
        errorMessage: '',
        operationError: '',
        pendingUserId: null,
        operationSucceededId: null,
        hasMore: false,
        currentUserId: currentUser.id,
        currentRole: role,
      },
    })
  }

  it('never offers self downgrade or self disable', async () => {
    const wrapper = mountUsers()
    await wrapper.get('[aria-label="编辑用户"]').trigger('click')

    const selects = wrapper.findAll('.user-dialog select')
    expect(selects).toHaveLength(2)
    expect(selects[0]?.attributes('disabled')).toBeDefined()
    expect(selects[1]?.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('不能降级当前登录账户')
    expect(wrapper.text()).toContain('不能停用当前登录账户')
  })

  it('requires a temporary password, confirms creation, and never renders it', async () => {
    const wrapper = mountUsers()
    await wrapper.get('.primary-command').trigger('click')
    const inputs = wrapper.findAll('.user-dialog input')
    await inputs[0]!.setValue('new-reader')
    await inputs[1]!.setValue('审阅用户')
    await wrapper.get('.user-dialog select').setValue('reader')
    await wrapper.get('.user-dialog input[type="password"]').setValue(
      'temporary-pass-123',
    )
    await wrapper.get('.user-dialog form').trigger('submit')

    const event = wrapper.emitted('create')?.[0]?.[0]
    expect(event).toEqual({
      username: 'new-reader',
      display_name: '审阅用户',
      role: 'reader',
      temporary_password: 'temporary-pass-123',
    })
    expect(wrapper.text()).not.toContain('temporary-pass-123')
    expect(wrapper.text()).toContain('首次登录必须修改密码')
  })

  it('does not unlock a locked user unless the administrator confirms it', async () => {
    const lockedUser: AdminUser = {
      ...currentUser,
      id: '22222222-2222-4222-8222-222222222222',
      username: 'locked-reader',
      display_name: '锁定用户',
      role: 'reader',
      status: 'locked',
      locked_until: '2026-07-31T00:00:00Z',
    }
    const wrapper = mount(UserManagementPanel, {
      props: {
        users: [lockedUser],
        loading: false,
        loadingMore: false,
        errorMessage: '',
        operationError: '',
        pendingUserId: null,
        operationSucceededId: null,
        hasMore: false,
        currentUserId: currentUser.id,
        currentRole: 'administrator',
      },
    })

    await wrapper.get('[aria-label="编辑用户"]').trigger('click')
    expect(wrapper.text()).toContain('不勾选时只更新角色，账户保持锁定')
    await wrapper.get('.user-dialog form').trigger('submit')
    expect(wrapper.emitted('update')?.[0]?.[1]).toEqual({
      role: 'reader',
      expected_updated_at: lockedUser.updated_at,
    })

    await wrapper.get('.locked-edit-control input').setValue(true)
    await wrapper.get('.user-dialog form').trigger('submit')
    expect(wrapper.emitted('update')?.[1]?.[1]).toEqual({
      role: 'reader',
      status: 'active',
      expected_updated_at: lockedUser.updated_at,
    })
  })

  it('hides every write command from non-administrators', () => {
    const wrapper = mountUsers('reader')

    expect(wrapper.find('.primary-command').exists()).toBe(false)
    expect(wrapper.find('.row-actions').exists()).toBe(false)
  })
})

describe('live audit panel', () => {
  it('emits controlled filters and does not expose raw source metadata', async () => {
    const wrapper = mount(AuditLogLivePanel, {
      props: {
        logs: [
          {
            id: '18446744073709551610',
            actor: {
              id: currentUser.id,
              username: currentUser.username,
              display_name: currentUser.display_name,
            },
            action: 'task.create',
            outcome: 'success',
            object_type: 'task',
            object_id: 'task-1',
            request_id: 'request-1',
            metadata: { source_ip: 'should-not-render' },
            created_at: '2026-07-30T00:00:00Z',
          },
        ],
        loading: false,
        loadingMore: false,
        errorMessage: '',
        hasMore: false,
      },
    })

    const textInputs = wrapper.findAll('.audit-filters input')
    await textInputs[0]!.setValue('task.create')
    await wrapper.get('.audit-filters select').setValue('success')
    await textInputs[1]!.setValue('admin')
    await textInputs[3]!.setValue('2026-07-30T10:15')
    await wrapper.get('.audit-filters').trigger('submit')

    const query = wrapper.emitted('search')?.[0]?.[0]
    expect(query).toMatchObject({
      action: 'task.create',
      outcome: 'success',
      actor: 'admin',
    })
    expect(String((query as { created_to?: string }).created_to)).toMatch(
      /:59\.999Z$/,
    )
    expect(wrapper.text()).not.toContain('should-not-render')
    expect(wrapper.text()).toContain('request-1')
  })
})
