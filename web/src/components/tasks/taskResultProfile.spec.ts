import { describe, expect, it } from 'vitest'

import {
  isContainerImageInputType,
  taskResultTabsForInputType,
} from '@/components/tasks/taskResultProfile'

describe('taskResultProfile', () => {
  it.each(['pe32+', 'elf64', 'macho-thin', 'java-class', 'jar', 'war', 'apk', 'dex', 'pyc'])(
    'shows decompile results for %s tasks',
    (inputType) => {
      expect(taskResultTabsForInputType(inputType)).toEqual([
        'files',
        'decompile',
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
      'vulnerabilities',
      'reports',
    ])
  })
})
