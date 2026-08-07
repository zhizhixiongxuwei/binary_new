import type { CurrentUser } from '@/api/types'

export function passwordRouteRedirect(
  user: CurrentUser | null,
  routeName: string | symbol | null | undefined,
): 'change-password' | 'overview' | null {
  if (!user) return null
  if (user.must_change_password && routeName !== 'change-password') return 'change-password'
  if (!user.must_change_password && routeName === 'change-password') return 'overview'
  return null
}
