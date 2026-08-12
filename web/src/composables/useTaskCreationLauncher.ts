import { useRoute, useRouter } from 'vue-router'

const FALLBACK_ROUTE = { name: 'tasks' as const }

function safeReturnPath(value: unknown): string | null {
  if (
    typeof value !== 'string' ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    value.length > 2_048 ||
    /[\r\n]/.test(value) ||
    value.startsWith('/tasks/new')
  ) {
    return null
  }
  return value
}

export function useTaskCreationLauncher() {
  const route = useRoute()
  const router = useRouter()

  async function launchTaskCreation(): Promise<void> {
    if (route.name === 'task-create') return
    await router.push({
      name: 'task-create',
      query: { return_to: route.fullPath },
    })
  }

  async function cancelTaskCreation(): Promise<void> {
    const returnPath = safeReturnPath(route.query.return_to)
    await router.replace(returnPath ?? FALLBACK_ROUTE)
  }

  return {
    launchTaskCreation,
    cancelTaskCreation,
  }
}
