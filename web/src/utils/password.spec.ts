import { describe, expect, it } from 'vitest'

import { validatePasswordChange } from '@/utils/password'

describe('validatePasswordChange', () => {
  it('requires at least 12 UTF-8 bytes', () => {
    expect(
      validatePasswordChange({
        currentPassword: 'current-password',
        newPassword: '短密码',
        confirmation: '短密码',
      }).newPassword,
    ).toBe('新密码不能少于 12 字节')

    expect(
      validatePasswordChange({
        currentPassword: 'current-password',
        newPassword: '四个汉字',
        confirmation: '四个汉字',
      }).newPassword,
    ).toBeUndefined()
  })

  it('rejects reuse and mismatched confirmation', () => {
    expect(
      validatePasswordChange({
        currentPassword: 'same-password',
        newPassword: 'same-password',
        confirmation: 'different-password',
      }),
    ).toMatchObject({
      newPassword: '新密码不能与当前密码相同',
      confirmation: '两次输入的新密码不一致',
    })
  })
})
