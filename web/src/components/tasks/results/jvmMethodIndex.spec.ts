import { describe, expect, it } from 'vitest'

import { parseBytecodeMethodIndex } from '@/components/tasks/results/jvmMethodIndex'

describe('parseBytecodeMethodIndex', () => {
  it('parses bounded JVM methods and preserves methods without a Code attribute', () => {
    const parsed = parseBytecodeMethodIndex({
      methods: [
        {
          key: 'method:verify-hash',
          name: 'verify',
          qualified_name: 'com.example.Verifier.verify',
          descriptor: '(I)Z',
          signature: 'verify(int): boolean',
          source: { start_line: 14, end_line: 21 },
          bytecode: { offset_bytes: 418, size_bytes: 18 },
        },
        {
          key: 'method:abstract-hash',
          name: 'abstractCheck',
          descriptor: '()V',
        },
      ],
    })

    expect(parsed).toEqual({
      present: true,
      declaredCount: 2,
      invalidCount: 0,
      omittedCount: 0,
      methods: [
        {
          key: 'method:verify-hash',
          name: 'verify',
          qualifiedName: 'com.example.Verifier.verify',
          descriptor: '(I)Z',
          signature: 'verify(int): boolean',
          source: { startLine: 14, endLine: 21 },
          bytecode: { offsetBytes: 418, sizeBytes: 18 },
        },
        {
          key: 'method:abstract-hash',
          name: 'abstractCheck',
          qualifiedName: '',
          descriptor: '()V',
          signature: '',
        },
      ],
    })
  })

  it('isolates malformed, duplicate and unsafe numeric records', () => {
    const parsed = parseBytecodeMethodIndex({
      methods: [
        { key: 'valid', name: 'valid', bytecode: { offset_bytes: 0, size_bytes: 5 } },
        { key: 'valid', name: 'duplicate' },
        { key: 'negative', name: 'negative', bytecode: { offset_bytes: -1, size_bytes: 4 } },
        { key: 'unsafe', name: 'unsafe', bytecode: { offset_bytes: 9_007_199_254_740_992, size_bytes: 4 } },
        { key: 'unsafe-sum', name: 'unsafe-sum', bytecode: { offset_bytes: Number.MAX_SAFE_INTEGER, size_bytes: 1 } },
        { key: 'zero-size', name: 'zero', bytecode: { offset_bytes: 1, size_bytes: 0 } },
        { key: '../invalid', name: 'invalid-key' },
        { key: '', name: 'missing-key' },
        'not-an-object',
      ],
    })

    expect(parsed.methods).toHaveLength(1)
    expect(parsed.methods[0]?.key).toBe('valid')
    expect(parsed.invalidCount).toBe(8)
    expect(parsed.declaredCount).toBe(9)
  })

  it('distinguishes absent and malformed method indexes without throwing', () => {
    expect(parseBytecodeMethodIndex({ message: 'no index' }).present).toBe(false)
    expect(parseBytecodeMethodIndex({ methods: 'invalid' })).toEqual({
      present: true,
      declaredCount: 0,
      invalidCount: 1,
      omittedCount: 0,
      methods: [],
    })
    expect(parseBytecodeMethodIndex(null).present).toBe(false)
  })

  it('bounds large indexes and rejects control or bidi-spoofed display text', () => {
    const methods = Array.from({ length: 10_002 }, (_, index) => ({
      key: `method:${index}`,
      name: `method${index}`,
    }))
    methods[0] = { key: 'method:nul', name: 'hidden\u0000name' }
    methods[1] = { key: 'method:bidi', name: 'safe\u202eevil' }
    methods[2] = { key: 'method:alm', name: 'safe\u061cevil' }

    const parsed = parseBytecodeMethodIndex({ methods })

    expect(parsed.declaredCount).toBe(10_002)
    expect(parsed.methods).toHaveLength(2_997)
    expect(parsed.invalidCount).toBe(3)
    expect(parsed.omittedCount).toBe(7_002)
  })

  it('fails closed instead of invoking a revoked diagnostics proxy', () => {
    const { proxy, revoke } = Proxy.revocable({ methods: [] }, {})
    revoke()

    expect(() => parseBytecodeMethodIndex(proxy)).not.toThrow()
    expect(parseBytecodeMethodIndex(proxy).present).toBe(false)
  })
})
