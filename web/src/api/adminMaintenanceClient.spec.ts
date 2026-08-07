import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, resetApiClient } from '@/api/client'
import type { AdminUser, AuditLogPage } from '@/api/types'

const adminUser: AdminUser = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'scanner-op',
  display_name: '检测操作员',
  role: 'operator',
  status: 'active',
  must_change_password: true,
  failed_login_count: 0,
  locked_until: null,
  last_login_at: null,
  created_at: '2026-07-30T00:00:00Z',
  updated_at: '2026-07-30T00:00:00Z',
}

function response<T>(data: T): Response {
  return new Response(JSON.stringify({ data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('admin maintenance HTTP client', () => {
  afterEach(() => {
    resetApiClient()
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('uses cursor pagination and exact audit filter names', async () => {
    const auditPage: AuditLogPage = {
      items: [],
      next_cursor: '18446744073709551610',
    }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response({ items: [adminUser], next_cursor: 'next/user' }))
      .mockResolvedValueOnce(response(auditPage))
    vi.stubGlobal('fetch', fetchMock)

    await api.listAdminUsers({
      keyword: 'scanner',
      role: 'operator',
      status: 'active',
      cursor: 'user/cursor',
      page_size: 25,
    })
    await api.listAuditLogs({
      action: 'task.create',
      outcome: 'success',
      actor: 'scanner-op',
      created_from: '2026-07-01T00:00:00Z',
      created_to: '2026-07-30T23:59:59Z',
      cursor: 'audit/cursor',
      page_size: 50,
    })

    const usersUrl = new URL(fetchMock.mock.calls[0]![0] as string, 'http://localhost')
    expect(Object.fromEntries(usersUrl.searchParams)).toEqual({
      cursor: 'user/cursor',
      page_size: '25',
      keyword: 'scanner',
      role: 'operator',
      status: 'active',
    })

    const auditUrl = new URL(fetchMock.mock.calls[1]![0] as string, 'http://localhost')
    expect(Object.fromEntries(auditUrl.searchParams)).toEqual({
      cursor: 'audit/cursor',
      page_size: '50',
      action: 'task.create',
      outcome: 'success',
      actor: 'scanner-op',
      created_from: '2026-07-01T00:00:00Z',
      created_to: '2026-07-30T23:59:59Z',
    })
  })

  it('sends CSRF-protected user mutations with CAS timestamps', async () => {
    document.cookie = 'binaryscan_csrf=admin-csrf; Path=/'
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(response(adminUser))
      .mockResolvedValueOnce(response({ ...adminUser, role: 'reader' }))
      .mockResolvedValueOnce(response({ ...adminUser, must_change_password: true }))
    vi.stubGlobal('fetch', fetchMock)

    await api.createAdminUser({
      username: 'audit-reader',
      display_name: '审计用户',
      role: 'reader',
      temporary_password: 'temporary-pass-123',
    })
    await api.updateAdminUser(adminUser.id, {
      role: 'reader',
      status: 'active',
      expected_updated_at: adminUser.updated_at,
    })
    await api.resetAdminUserPassword(adminUser.id, {
      temporary_password: 'replacement-pass-123',
      expected_updated_at: adminUser.updated_at,
    })

    const [createUrl, createInit] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ]
    expect(createUrl.endsWith('/api/v1/admin/users')).toBe(true)
    expect(createInit.method).toBe('POST')
    expect(new Headers(createInit.headers).get('X-CSRF-Token')).toBe('admin-csrf')
    expect(JSON.parse(String(createInit.body))).toEqual({
      username: 'audit-reader',
      display_name: '审计用户',
      role: 'reader',
      temporary_password: 'temporary-pass-123',
    })

    const [updateUrl, updateInit] = fetchMock.mock.calls[1] as [
      string,
      RequestInit,
    ]
    expect(updateUrl).toContain(
      '/api/v1/admin/users/11111111-1111-4111-8111-111111111111',
    )
    expect(updateInit.method).toBe('PATCH')
    expect(JSON.parse(String(updateInit.body))).toMatchObject({
      expected_updated_at: adminUser.updated_at,
    })

    const [resetUrl, resetInit] = fetchMock.mock.calls[2] as [
      string,
      RequestInit,
    ]
    expect(
      resetUrl.endsWith(
        '/api/v1/admin/users/11111111-1111-4111-8111-111111111111/reset-password',
      ),
    ).toBe(true)
    expect(resetInit.method).toBe('POST')
    expect(JSON.parse(String(resetInit.body))).toEqual({
      temporary_password: 'replacement-pass-123',
      expected_updated_at: adminUser.updated_at,
    })
  })
})
