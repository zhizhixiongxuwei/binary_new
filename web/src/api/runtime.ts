import { configureApiClient } from '@/api/client'

export const isDemoMode = import.meta.env.VITE_APP_MODE === 'demo'

export async function configureRuntimeApi(): Promise<void> {
  if (!isDemoMode) return
  const { createDemoApiClient } = await import('@/api/demo/client')
  configureApiClient(createDemoApiClient())
}
