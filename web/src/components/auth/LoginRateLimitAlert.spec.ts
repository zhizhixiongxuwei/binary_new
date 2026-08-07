import { render, screen } from '@testing-library/vue'
import { describe, expect, it } from 'vitest'

import LoginRateLimitAlert from '@/components/auth/LoginRateLimitAlert.vue'

describe('LoginRateLimitAlert', () => {
  it('announces an account-agnostic warning and accessible countdown', () => {
    render(LoginRateLimitAlert, {
      props: { remainingSeconds: 37 },
    })

    const status = screen.getByRole('status')
    expect(status.textContent).toContain('登录尝试过于频繁')
    expect(status.textContent).toContain('为保护系统，请稍后再试')
    expect(
      screen.getByLabelText('37 秒后可再次登录'),
    ).toBeTruthy()
    expect(status.textContent).not.toContain('用户名')
    expect(status.getAttribute('aria-atomic')).toBe('true')
  })
})
