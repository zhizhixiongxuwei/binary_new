import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { CurrentUser } from '@/api/types'
import { useSessionStore } from '@/stores/session'

const currentUser: CurrentUser = {
  id: 'user-1',
  username: 'operator',
  display_name: '检测人员',
  role: 'operator',
  must_change_password: false,
}

describe('session store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.restoreAllMocks()
  })

  it('stores the direct CurrentUser returned by login', async () => {
    const login = vi.spyOn(api, 'login').mockResolvedValue(currentUser)
    const store = useSessionStore()

    await store.login({ username: 'operator', password: 'secret' })

    expect(login).toHaveBeenCalledWith({ username: 'operator', password: 'secret' })
    expect(store.user).toEqual(currentUser)
    expect(store.isAuthenticated).toBe(true)
    expect(store.restored).toBe(true)
  })

  it('restores the server-backed session once', async () => {
    const getMe = vi.spyOn(api, 'getMe').mockResolvedValue(currentUser)
    const store = useSessionStore()

    await store.restore()
    await store.restore()

    expect(getMe).toHaveBeenCalledTimes(1)
    expect(store.user).toEqual(currentUser)
    expect(store.restoring).toBe(false)
  })

  it('clears local session state after logout', async () => {
    vi.spyOn(api, 'login').mockResolvedValue(currentUser)
    const logout = vi.spyOn(api, 'logout').mockResolvedValue(undefined)
    const store = useSessionStore()
    await store.login({ username: 'operator', password: 'secret' })

    await store.logout()

    expect(logout).toHaveBeenCalledOnce()
    expect(store.user).toBeNull()
    expect(store.isAuthenticated).toBe(false)
    expect(store.restored).toBe(true)
  })

  it('clears local state when logout reports an already invalid session', async () => {
    vi.spyOn(api, 'login').mockResolvedValue(currentUser)
    vi.spyOn(api, 'logout').mockRejectedValue(
      new ApiError('会话已失效', 401, { code: 'authentication_required' }),
    )
    const store = useSessionStore()
    await store.login({ username: 'operator', password: 'secret' })

    await expect(store.logout()).resolves.toBeUndefined()

    expect(store.user).toBeNull()
    expect(store.isAuthenticated).toBe(false)
  })

  it('keeps local state when server-side logout fails', async () => {
    vi.spyOn(api, 'login').mockResolvedValue(currentUser)
    const failure = new ApiError('注销服务暂不可用', 503, { code: 'logout_failed' })
    vi.spyOn(api, 'logout').mockRejectedValue(failure)
    const store = useSessionStore()
    await store.login({ username: 'operator', password: 'secret' })

    await expect(store.logout()).rejects.toBe(failure)

    expect(store.user).toEqual(currentUser)
    expect(store.isAuthenticated).toBe(true)
  })

  it('replaces the session user after changing the password', async () => {
    const forcedUser = { ...currentUser, must_change_password: true }
    const updatedUser = { ...currentUser, must_change_password: false }
    vi.spyOn(api, 'login').mockResolvedValue(forcedUser)
    const changePassword = vi.spyOn(api, 'changePassword').mockResolvedValue(updatedUser)
    const store = useSessionStore()
    await store.login({ username: 'operator', password: 'current-password' })

    await store.changePassword({
      current_password: 'current-password',
      new_password: 'new-password-value',
    })

    expect(changePassword).toHaveBeenCalledWith({
      current_password: 'current-password',
      new_password: 'new-password-value',
    })
    expect(store.user).toEqual(updatedUser)
    expect(store.user?.must_change_password).toBe(false)
  })
})
