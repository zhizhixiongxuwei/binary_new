import { afterEach, describe, expect, it, vi } from 'vitest'

import { sha256Blob } from '@/utils/hash'

describe('sha256Blob', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('hashes one blob buffer and emits lowercase padded hex', async () => {
    const digest = vi.fn().mockResolvedValue(
      Uint8Array.from([0x00, 0x0f, 0x10, 0xff]).buffer,
    )
    vi.stubGlobal('crypto', { subtle: { digest } })
    const chunk = {
      arrayBuffer: vi.fn().mockResolvedValue(Uint8Array.from([1, 2, 3]).buffer),
    } as unknown as Blob

    await expect(sha256Blob(chunk)).resolves.toBe('000f10ff')
    expect(chunk.arrayBuffer).toHaveBeenCalledOnce()
    expect(digest).toHaveBeenCalledWith('SHA-256', expect.any(ArrayBuffer))
  })
})
