import { readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { SystemStatus } from '@/api/types'

export function useSystemMaintenance() {
  const status = shallowRef<SystemStatus | null>(null)
  const loading = shallowRef(false)
  const errorMessage = shallowRef('')
  let requestSequence = 0

  async function load(): Promise<void> {
    const sequence = ++requestSequence
    loading.value = true
    errorMessage.value = ''
    try {
      const result = await api.getSystemStatus()
      if (sequence === requestSequence) status.value = result
    } catch (error) {
      if (sequence === requestSequence) {
        errorMessage.value =
          error instanceof ApiError ? error.message : '系统维护状态读取失败'
      }
    } finally {
      if (sequence === requestSequence) loading.value = false
    }
  }

  return {
    status: readonly(status),
    loading: readonly(loading),
    errorMessage: readonly(errorMessage),
    load,
  }
}
