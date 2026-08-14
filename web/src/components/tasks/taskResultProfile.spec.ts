import { describe, expect, it } from 'vitest'

import {
  isContainerImageInputType,
  taskResultTabsForInputType,
} from '@/components/tasks/taskResultProfile'

describe('taskResultProfile', () => {
  it.each(['java-class', 'jar', 'war', 'apk', 'dex'])(
    'adds Java source analysis for %s tasks',
    (inputType) => {
      expect(taskResultTabsForInputType(inputType)).toEqual([
        'files',
        'decompile',
        'java-analysis',
        'reports',
      ])
    },
  )

  it('keeps Python bytecode on the decompile-only result profile', () => {
    expect(taskResultTabsForInputType('pyc')).toEqual([
      'files',
      'decompile',
      'reports',
    ])
  })

  it.each(['pe32+', 'elf64', 'macho-thin'])(
    'adds C source analysis for native %s tasks',
    (inputType) => {
      expect(taskResultTabsForInputType(inputType)).toEqual([
        'files',
        'decompile',
        'c-analysis',
        'reports',
      ])
    },
  )

  it.each(['docker-tar', 'oci-tar', 'Docker-Archive'])(
    'shows vulnerability results for %s tasks',
    (inputType) => {
      expect(isContainerImageInputType(inputType)).toBe(true)
      expect(taskResultTabsForInputType(inputType)).toEqual([
        'files',
        'vulnerabilities',
        'reports',
      ])
    },
  )

  it('keeps both analyzer views for a generic archive with mixed contents', () => {
    expect(taskResultTabsForInputType('zip')).toEqual([
      'files',
      'decompile',
      'c-analysis',
      'java-analysis',
      'python-analysis',
      'vulnerabilities',
      'reports',
    ])
  })
})
