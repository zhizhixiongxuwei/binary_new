import { defineStore } from 'pinia'
import { computed, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { ChangePasswordInput, CurrentUser, LoginInput, UserRole } from '@/api/types'

export const useSessionStore = defineStore('session', () => {
  const user = shallowRef<CurrentUser | null>(null)
  const restored = shallowRef(false)
  const restoring = shallowRef(false)
  let restoreRequest: Promise<void> | null = null

  const isAuthenticated = computed(() => user.value !== null)

  async function restore(): Promise<void> {
    if (restored.value) return
    if (restoreRequest) return restoreRequest

    restoreRequest = (async () => {
      restoring.value = true
      try {
        user.value = await api.getMe()
        restored.value = true
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) throw error
        user.value = null
        restored.value = true
      } finally {
        restoring.value = false
      }
    })()

    try {
      await restoreRequest
    } finally {
      restoreRequest = null
    }
  }

  async function login(input: LoginInput): Promise<void> {
    user.value = await api.login(input)
    restored.value = true
  }

  async function logout(): Promise<void> {
    try {
      await api.logout()
      user.value = null
      restored.value = true
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        user.value = null
        restored.value = true
        return
      }
      throw error
    }
  }

  async function changePassword(input: ChangePasswordInput): Promise<void> {
    user.value = await api.changePassword(input)
    restored.value = true
  }

  function hasRole(roles: UserRole[]): boolean {
    return user.value !== null && roles.includes(user.value.role)
  }

  return {
    user,
    restored,
    restoring,
    isAuthenticated,
    restore,
    login,
    logout,
    changePassword,
    hasRole,
  }
})
