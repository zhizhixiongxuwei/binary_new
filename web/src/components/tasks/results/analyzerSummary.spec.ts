import { reactive } from 'vue'
import { describe, expect, it, vi } from 'vitest'

import { parseAnalyzerSummary } from '@/components/tasks/results/analyzerSummary'

describe('parseAnalyzerSummary', () => {
  it('parses only explicitly reported identity, counters, and bounded issues', () => {
    const summary = parseAnalyzerSummary({
      engine: 'JADX 1.5',
      format: 'DEX',
      python_version: '3.12',
      magic: 'cb0d0d0a',
      header_size: 16,
      dex_file_count: 2,
      class_count: 684,
      method_count: 4_218,
      code_object_count: 5,
      missing_class_count: 3,
      error_count: 1,
      warning_count: 6,
      errors: ['Unable to decode one method body'],
      warnings: ['one', 'two', 'three', 'four', 'five', 'six'],
      unrelated: 'not part of the display contract',
    })

    expect(summary.present).toBe(true)
    expect(summary.identity.map((field) => field.key)).toEqual([
      'engine',
      'format',
      'python_version',
      'magic',
    ])
    expect(summary.metrics.map((metric) => metric.key)).toEqual([
      'header_size',
      'dex_file_count',
      'class_count',
      'method_count',
      'code_object_count',
      'missing_class_count',
      'error_count',
      'warning_count',
    ])
    expect(summary.issues[0]).toMatchObject({
      kind: 'error',
      messages: ['Unable to decode one method body'],
      omittedCount: 0,
    })
    expect(summary.issues[1]).toMatchObject({
      kind: 'warning',
      messages: ['one', 'two', 'three', 'four'],
      omittedCount: 2,
    })
  })

  it('rejects negative and unsafe counters plus unsafe or oversized text', () => {
    const summary = parseAnalyzerSummary({
      engine: `unsafe\u202eengine`,
      format: 'x'.repeat(129),
      python_version: '3.12\nforged',
      magic: '\u0000magic',
      header_size: -0,
      dex_file_count: Number.MAX_SAFE_INTEGER + 1,
      class_count: 1.5,
      method_count: Number.NaN,
      code_object_count: Number.POSITIVE_INFINITY,
      missing_class_count: -9,
      error_count: -1,
      warning_count: Number.MAX_SAFE_INTEGER + 10,
    })

    expect(summary).toEqual({
      present: false,
      identity: [],
      metrics: [],
      issues: [],
    })
  })

  it('rejects every control, format, surrogate, and line separator class', () => {
    const unsafeCharacters = [
      '\u0009',
      '\u0085',
      '\u00ad',
      '\u061c',
      '\u200e',
      '\u2028',
      '\u2029',
      '\u202a',
      '\u202b',
      '\u202c',
      '\u202d',
      '\u202e',
      '\u2066',
      '\u2067',
      '\u2068',
      '\u2069',
      '\ufeff',
      '\ud800',
    ]

    for (const character of unsafeCharacters) {
      expect(
        parseAnalyzerSummary({ format: `DEX${character}forged` }).present,
        `expected U+${character.charCodeAt(0).toString(16)} to be rejected`,
      ).toBe(false)
    }
  })

  it('rejects invalid and excessive issue collections without partial display', () => {
    const sparseWarnings = Array.from({ length: 2 }, () => 'warning')
    delete sparseWarnings[0]
    const summary = parseAnalyzerSummary({
      format: 'PYC',
      errors: ['valid', 'forged\u2067message'],
      warnings: Array.from({ length: 101 }, (_, index) => `warning-${index}`),
    })

    expect(summary.present).toBe(true)
    expect(summary.identity).toHaveLength(1)
    expect(summary.issues).toEqual([])
    expect(parseAnalyzerSummary({ warnings: sparseWarnings }).present).toBe(false)
  })

  it('fails closed for proxies, accessors, arrays, and non-record values', () => {
    const proxy = new Proxy({ format: 'DEX' }, {})
    const getter = vi.fn(() => 'PYC')
    const accessor = Object.defineProperty({}, 'format', {
      enumerable: true,
      get: getter,
    })

    expect(parseAnalyzerSummary(proxy).present).toBe(false)
    expect(parseAnalyzerSummary(accessor).present).toBe(false)
    expect(getter).not.toHaveBeenCalled()
    expect(parseAnalyzerSummary(['DEX']).present).toBe(false)
    expect(parseAnalyzerSummary(null).present).toBe(false)
    expect(parseAnalyzerSummary('DEX').present).toBe(false)
  })

  it('never evaluates known, unknown, or nested accessors', () => {
    const knownGetter = vi.fn(() => 'DEX')
    const unknownGetter = vi.fn(() => 'not trusted')
    const nestedGetter = vi.fn(() => 'not trusted')
    const knownAccessor = Object.defineProperty({}, 'format', {
      enumerable: true,
      get: knownGetter,
    })
    const unknownAccessor = Object.defineProperties(
      { format: 'DEX' },
      {
        ignored: {
          enumerable: true,
          get: unknownGetter,
        },
      },
    )
    const nested = Object.defineProperty({}, 'ignored', {
      enumerable: true,
      get: nestedGetter,
    })

    expect(parseAnalyzerSummary(knownAccessor).present).toBe(false)
    expect(parseAnalyzerSummary(unknownAccessor).present).toBe(false)
    expect(parseAnalyzerSummary({ format: 'DEX', metadata: nested }).present).toBe(
      false,
    )
    expect(knownGetter).not.toHaveBeenCalled()
    expect(unknownGetter).not.toHaveBeenCalled()
    expect(nestedGetter).not.toHaveBeenCalled()
  })

  it('accepts bounded JSON diagnostics and Vue proxies while ignoring unknown fields', () => {
    const diagnostics = reactive({
      format: 'CLASS',
      method_count: 2,
      methods: [
        { name: '<init>', bytecode: { offset_bytes: 10, size_bytes: 5 } },
        { name: 'verify', bytecode: { offset_bytes: 20, size_bytes: 8 } },
      ],
    })

    expect(parseAnalyzerSummary(diagnostics)).toMatchObject({
      present: true,
      identity: [{ key: 'format', value: 'CLASS' }],
      metrics: [{ key: 'method_count', value: 2 }],
    })
  })

  it('uses own reported fields, preserves zero, and rejects sparse nested arrays', () => {
    const nullPrototype = Object.create(null) as Record<string, unknown>
    nullPrototype.error_count = 0
    expect(parseAnalyzerSummary(nullPrototype)).toMatchObject({
      present: true,
      metrics: [{ key: 'error_count', value: 0 }],
    })

    const inherited = Object.create({ format: 'DEX' })
    expect(parseAnalyzerSummary(inherited).present).toBe(false)

    const methods = Array.from({ length: 2 }, () => ({ name: 'method' }))
    delete methods[0]
    expect(parseAnalyzerSummary({ format: 'CLASS', methods }).present).toBe(false)
  })

  it('contains exceptions from hostile proxy traps', () => {
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('trap')
        },
      },
    )

    expect(() => parseAnalyzerSummary(hostile)).not.toThrow()
    expect(parseAnalyzerSummary(hostile).present).toBe(false)
  })
})
