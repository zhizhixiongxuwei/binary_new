import { describe, expect, it } from 'vitest'

import {
  parseTaskDetail,
  parseTaskPage,
  TaskContractError,
} from '@/api/taskContract'

function task() {
  return {
    id: '20000000-0000-4000-8000-000000000002',
    name: 'firmware.tar',
    input_type: 'tar',
    status: 'SCANNING',
    risk_level: 'UNKNOWN',
    progress: 70,
    progress_indeterminate: true,
    creator_id: '40000000-0000-4000-8000-000000000004',
    creator_name: 'Operator',
    tags: ['firmware'],
    created_at: '2026-07-31T00:00:00Z',
    updated_at: '2026-07-31T00:01:00Z',
    original_filename: 'firmware.tar',
    size_bytes: 4_096,
    sha256: 'a'.repeat(64),
    current_stage: 'SCANNING',
    error_code: '',
    error_message: '',
    sample_expires_at: '2026-08-30T00:00:00Z',
    sample_deleted_at: null,
  }
}

describe('task API runtime contract', () => {
  it('preserves weighted progress and its indeterminate mode', () => {
    expect(parseTaskDetail(task())).toMatchObject({
      status: 'SCANNING',
      progress: 70,
      progress_indeterminate: true,
      current_stage: 'SCANNING',
    })
  })

  it('rejects missing or mistyped progress mode fields', () => {
    const missing = task() as Record<string, unknown>
    delete missing.progress_indeterminate
    expect(() => parseTaskDetail(missing)).toThrow(TaskContractError)
    expect(() =>
      parseTaskDetail({ ...task(), progress_indeterminate: 'unknown' }),
    ).toThrow(/progress_indeterminate/)
  })

  it('validates every task in a paginated response', () => {
    const page = parseTaskPage({
      items: [task()],
      next_cursor: 'opaque_cursor-1',
    })
    expect(page.items).toHaveLength(1)
    expect(page.items[0]?.progress_indeterminate).toBe(true)
    expect(page.next_cursor).toBe('opaque_cursor-1')

    expect(() =>
      parseTaskPage({
        items: [{ ...task(), progress: 101 }],
      }),
    ).toThrow(/progress/)

    expect(() =>
      parseTaskPage({ items: [task()], next_cursor: 'not/a/cursor' }),
    ).toThrow(/cursor_pagination/)
    expect(() =>
      parseTaskPage({ items: [task()], total: 1 }),
    ).toThrow(/task_page/)
  })
})
