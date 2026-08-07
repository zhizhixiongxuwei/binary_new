import { afterEach, describe, expect, it, vi } from 'vitest'

import { createIdempotencyKey } from '@/utils/idempotency'

describe('createIdempotencyKey', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('prefers the platform secure UUID implementation', () => {
    const randomUUID = vi.fn().mockReturnValue(
      '1a55dd41-aa7d-49cc-a488-6ef0d15c5719',
    )
    vi.stubGlobal('crypto', { randomUUID })

    expect(createIdempotencyKey()).toBe(
      '1a55dd41-aa7d-49cc-a488-6ef0d15c5719',
    )
    expect(randomUUID).toHaveBeenCalledTimes(1)
  })

  it('builds an RFC 4122 version 4 UUID from secure random bytes', () => {
    const getRandomValues = vi.fn((bytes: Uint8Array) => {
      bytes.fill(0xab)
      return bytes
    })
    vi.stubGlobal('crypto', { getRandomValues })

    expect(createIdempotencyKey()).toBe(
      'abababab-abab-4bab-abab-abababababab',
    )
  })

  it('fails closed instead of using an insecure random fallback', () => {
    vi.stubGlobal('crypto', {})

    expect(() => createIdempotencyKey()).toThrow('不支持安全随机数')
  })
})
