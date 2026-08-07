import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/api/client'
import type { AdminUser } from '@/api/types'
import { useAdminUsers } from '@/composables/useAdminUsers'
import { useAuditLogs } from '@/composables/useAuditLogs'
import { useSystemMaintenance } from '@/composables/useSystemMaintenance'

const user: AdminUser = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'scanner-op',
  display_name: '检测操作员',
  role: 'operator',
  status: 'active',
  must_change_password: false,
  failed_login_count: 0,
  locked_until: null,
  last_login_at: null,
  created_at: '2026-07-30T00:00:00Z',
  updated_at: '2026-07-30T00:00:00Z',
}

describe('admin maintenance composables', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('loads the system snapshot once per explicit request', async () => {
    const getStatus = vi.spyOn(api, 'getSystemStatus').mockResolvedValue({
      version: '0.2.0',
      service_status: 'healthy',
      active_tasks: 0,
      queued_tasks: 0,
      repository_used_bytes: 0,
      repository_total_bytes: 100,
    })
    const maintenance = useSystemMaintenance()

    await maintenance.load()

    expect(getStatus).toHaveBeenCalledTimes(1)
    expect(maintenance.status.value?.version).toBe('0.2.0')
    expect(maintenance.loading.value).toBe(false)
  })

  it('paginates users and replaces a mutated row without numeric ID coercion', async () => {
    vi.spyOn(api, 'listAdminUsers')
      .mockResolvedValueOnce({
        items: [user],
        next_cursor: '18446744073709551613',
      })
      .mockResolvedValueOnce({
        items: [
          {
            ...user,
            id: '22222222-2222-4222-8222-222222222222',
            username: 'reader',
          },
        ],
      })
    const update = vi.spyOn(api, 'updateAdminUser').mockResolvedValue({
      ...user,
      role: 'reader',
      updated_at: '2026-07-30T01:00:00Z',
    })
    const users = useAdminUsers()

    await users.load()
    await users.load({ append: true })
    const succeeded = await users.update(user.id, {
      role: 'reader',
      expected_updated_at: user.updated_at,
    })

    expect(users.users.value).toHaveLength(2)
    expect(users.users.value[0]?.id).toBe('11111111-1111-4111-8111-111111111111')
    expect(users.users.value[0]?.role).toBe('reader')
    expect(succeeded).toBe(true)
    expect(users.operationSucceededId.value).toBe(user.id)
    expect(update).toHaveBeenCalledWith(user.id, {
      role: 'reader',
      expected_updated_at: user.updated_at,
    })
  })

  it('keeps audit filters while loading the next cursor', async () => {
    const list = vi
      .spyOn(api, 'listAuditLogs')
      .mockResolvedValueOnce({
        items: [],
        next_cursor: 'audit-next',
      })
      .mockResolvedValueOnce({ items: [] })
    const audit = useAuditLogs()

    await audit.load({ action: 'task.create', actor: 'scanner-op' })
    await audit.load(audit.query.value, { append: true })

    expect(list).toHaveBeenNthCalledWith(1, {
      action: 'task.create',
      actor: 'scanner-op',
      page_size: 50,
    })
    expect(list).toHaveBeenNthCalledWith(2, {
      action: 'task.create',
      actor: 'scanner-op',
      cursor: 'audit-next',
      page_size: 50,
    })
  })
})
