import { describe, expect, it } from 'vitest'

import type { CurrentUser } from '@/api/types'
import { passwordRouteRedirect } from '@/router/guards'

const user: CurrentUser = {
  id: 'user-1',
  username: 'admin',
  display_name: '管理员',
  role: 'administrator',
  must_change_password: true,
}

describe('passwordRouteRedirect', () => {
  it('forces users with an initial password onto the change page', () => {
    expect(passwordRouteRedirect(user, 'overview')).toBe('change-password')
    expect(passwordRouteRedirect(user, 'change-password')).toBeNull()
  })

  it('keeps users who already changed the password out of the change page', () => {
    expect(
      passwordRouteRedirect({ ...user, must_change_password: false }, 'change-password'),
    ).toBe('overview')
  })
})
