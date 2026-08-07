import { describe, expect, it } from 'vitest'

import {
  INPUT_FORMAT_GROUPS,
  normalizeInputFormat,
  normalizeTaskDate,
  parseTaskListRouteQuery,
  serializeTaskListRouteQuery,
  taskDateRangeIsValid,
  USER_TASK_STATUS_OPTIONS,
} from '@/components/tasks/taskListFilters'

describe('task list filters', () => {
  it('offers exact stable input formats instead of broad category values', () => {
    expect(INPUT_FORMAT_GROUPS.map((group) => group.label)).toEqual([
      '二进制',
      '字节码',
      '归档',
      '映像',
      '容器',
      '其他',
    ])

    const formats = INPUT_FORMAT_GROUPS.flatMap((group) => group.options)
    expect(formats).toEqual(
      expect.arrayContaining([
        'pe32+',
        'elf64',
        'macho-thin',
        'java-class',
        'pyc',
        'zip',
        'jar',
        'rar',
        'ext4',
        'iso9660',
        'docker-tar',
        'oci-tar',
      ]),
    )
    expect(formats).not.toEqual(
      expect.arrayContaining(['binary', 'bytecode', 'archive', 'image', 'container']),
    )
  })

  it('covers every user-visible canonical task state and omits DELETED', () => {
    expect(USER_TASK_STATUS_OPTIONS.map((option) => option.value)).toEqual([
      'UPLOADING',
      'QUEUED',
      'VALIDATING',
      'IDENTIFYING',
      'EXTRACTING',
      'INDEXING',
      'SCANNING',
      'REPORTING',
      'SUCCEEDED',
      'PARTIAL_SUCCEEDED',
      'FAILED',
      'CANCEL_REQUESTED',
      'CANCELLED',
      'DELETING',
    ])
    expect(
      USER_TASK_STATUS_OPTIONS.map<string>((option) => option.value),
    ).not.toContain('DELETED')
  })

  it('normalizes a custom exact format and rejects values outside the API grammar', () => {
    expect(normalizeInputFormat(' ELF64 ')).toBe('elf64')
    expect(normalizeInputFormat('vendor.format+v2')).toBe('vendor.format+v2')
    expect(normalizeInputFormat('../elf64')).toBeNull()
    expect(normalizeInputFormat('format with spaces')).toBeNull()
  })

  it('accepts only real ISO calendar dates and ordered date ranges', () => {
    expect(normalizeTaskDate(' 2024-02-29 ')).toBe('2024-02-29')
    expect(normalizeTaskDate('2026-02-29')).toBeNull()
    expect(normalizeTaskDate('2026-04-31')).toBeNull()
    expect(normalizeTaskDate('2026-7-01')).toBeNull()
    expect(normalizeTaskDate('')).toBe('')
    expect(taskDateRangeIsValid('2026-07-01', '2026-07-30')).toBe(true)
    expect(taskDateRangeIsValid('', '2026-07-30')).toBe(true)
    expect(taskDateRangeIsValid('2026-07-30', '2026-07-01')).toBe(false)
  })

  it('strictly restores query values and falls back for invalid or repeated values', () => {
    expect(
      parseTaskListRouteQuery({
        keyword: '  firmware  ',
        status: 'EXTRACTING',
        input_type: 'ELF64',
        creator: '  Demo Operator  ',
        tag: ' firmware ',
        created_from: '2026-07-01',
        created_to: '2026-07-30',
        cursor: 'opaque_cursor-3',
        page_size: '50',
      }),
    ).toEqual({
      keyword: 'firmware',
      status: 'EXTRACTING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      cursor: 'opaque_cursor-3',
      page_size: 50,
    })

    expect(
      parseTaskListRouteQuery({
        keyword: 'bad\nkeyword',
        status: ['FAILED', 'SUCCEEDED'],
        input_type: '/etc/passwd',
        creator: ['operator', 'admin'],
        tag: 'bad\ntag',
        created_from: '2026-02-29',
        created_to: '2026-07-30',
        cursor: 'not/a/cursor',
        page_size: '100',
      }),
    ).toEqual({
      keyword: '',
      status: '',
      input_type: '',
      creator: '',
      tag: '',
      created_from: '',
      created_to: '2026-07-30',
      cursor: '',
      page_size: 20,
    })
  })

  it('drops both date bounds when a route contains a reversed range', () => {
    expect(
      parseTaskListRouteQuery({
        created_from: '2026-07-30',
        created_to: '2026-07-01',
      }),
    ).toMatchObject({
      created_from: '',
      created_to: '',
    })
  })

  it('serializes a compact canonical query with explicit cursor pagination', () => {
    expect(
      serializeTaskListRouteQuery({
        keyword: 'kernel',
        status: 'SCANNING',
        input_type: 'elf64',
        creator: 'Demo Operator',
        tag: 'firmware',
        created_from: '2026-07-01',
        created_to: '2026-07-30',
        cursor: 'opaque_cursor-2',
        page_size: 10,
      }),
    ).toEqual({
      keyword: 'kernel',
      status: 'SCANNING',
      input_type: 'elf64',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
      cursor: 'opaque_cursor-2',
      page_size: '10',
    })
  })
})
