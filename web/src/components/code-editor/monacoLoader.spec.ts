import { describe, expect, it } from 'vitest'

import {
  resolveMonacoLanguage,
  supportsMonacoRuntime,
} from '@/components/code-editor/monacoLoader'

describe('monaco loader', () => {
  it.each([
    ['c', 'cpp'],
    ['java', 'java'],
    ['jvm-bytecode', 'jvm-bytecode'],
    ['smali', 'smali'],
    ['python-bytecode', 'python-bytecode'],
  ] as const)('maps %s code to the Monaco language %s', (language, expected) => {
    expect(resolveMonacoLanguage(language)).toBe(expected)
  })

  it('does not attempt Monaco in the workerless test runtime', () => {
    expect(supportsMonacoRuntime()).toBe(false)
  })
})
