import { describe, expect, it } from 'vitest'

import type { TaskDetail } from '@/api/types'
import {
  extendSampleExpiry,
  getTaskActionModel,
  isSampleExpired,
} from '@/components/tasks/taskActions'

function task(
  status: TaskDetail['status'],
  sampleExpiresAt = '2026-08-29T00:00:00.000Z',
): TaskDetail {
  return {
    id: 'task-actions',
    name: 'sample.iso',
    input_type: 'iso9660',
    status,
    risk_level: 'UNKNOWN',
    progress: 0,
    progress_indeterminate: false,
    creator_id: 'operator-1',
    creator_name: '检测人员',
    tags: [],
    created_at: '2026-07-30T00:00:00.000Z',
    sample_expires_at: sampleExpiresAt,
    sample_deleted_at: null,
  }
}

const NOW = new Date('2026-07-30T00:00:00.000Z')

describe('task action permissions', () => {
  it('limits cancel and retry to operators and their valid task states', () => {
    const queued = getTaskActionModel({
      task: task('QUEUED'),
      mode: 'preview',
      userRole: 'operator',
      isCreator: true,
      now: NOW,
    })
    const failed = getTaskActionModel({
      task: task('FAILED'),
      mode: 'preview',
      userRole: 'operator',
      isCreator: true,
      now: NOW,
    })
    const uploading = getTaskActionModel({
      task: task('UPLOADING'),
      mode: 'preview',
      userRole: 'operator',
      isCreator: true,
      now: NOW,
    })
    const reader = getTaskActionModel({
      task: task('FAILED'),
      mode: 'preview',
      userRole: 'reader',
      isCreator: false,
      now: NOW,
    })

    expect(queued.cancel.enabled).toBe(true)
    expect(queued.retry.enabled).toBe(false)
    expect(failed.cancel.enabled).toBe(false)
    expect(failed.retry.enabled).toBe(true)
    expect(uploading.cancel.enabled).toBe(false)
    expect(reader.cancel.enabled).toBe(false)
    expect(reader.retry.enabled).toBe(false)
  })

  it('allows deletion only for the creator or administrator and extension only for administrators', () => {
    const nonCreator = getTaskActionModel({
      task: task('SUCCEEDED'),
      mode: 'preview',
      userRole: 'operator',
      isCreator: false,
      now: NOW,
    })
    const creator = getTaskActionModel({
      task: task('SUCCEEDED'),
      mode: 'preview',
      userRole: 'operator',
      isCreator: true,
      now: NOW,
    })
    const administrator = getTaskActionModel({
      task: task('SUCCEEDED'),
      mode: 'preview',
      userRole: 'administrator',
      isCreator: false,
      now: NOW,
    })
    const readerCreator = getTaskActionModel({
      task: task('SUCCEEDED'),
      mode: 'preview',
      userRole: 'reader',
      isCreator: true,
      now: NOW,
    })

    expect(nonCreator.delete.enabled).toBe(false)
    expect(creator.delete.enabled).toBe(true)
    expect(creator.extend.enabled).toBe(false)
    expect(administrator.delete.enabled).toBe(true)
    expect(administrator.extend.enabled).toBe(true)
    expect(readerCreator.delete.enabled).toBe(false)
  })

  it('blocks rescanning and extension when retention has expired but cleanup is pending', () => {
    const model = getTaskActionModel({
      task: task('FAILED', '2026-07-29T23:59:59.000Z'),
      mode: 'preview',
      userRole: 'administrator',
      isCreator: true,
      now: NOW,
    })

    expect(model.sampleExpired).toBe(true)
    expect(model.sampleDeleted).toBe(false)
    expect(model.retry.enabled).toBe(false)
    expect(model.retry.reason).toContain('样本保留期已到')
    expect(model.extend.enabled).toBe(false)
    expect(isSampleExpired('2026-07-30T00:00:00.000Z', NOW)).toBe(true)
  })

  it('uses the persisted cleanup timestamp instead of inferring cleanup from expiry', () => {
    const deleted = task('FAILED')
    deleted.sample_deleted_at = 'server-retention-marker'
    const model = getTaskActionModel({
      task: deleted,
      mode: 'live',
      userRole: 'administrator',
      isCreator: true,
      now: NOW,
    })

    expect(model.sampleDeleted).toBe(true)
    expect(model.sampleExpired).toBe(true)
    expect(model.retry.reason).toContain('任务原始样本已清理')
    expect(model.extend.reason).toContain('任务原始样本已清理')
  })

  it('enables supported live commands including administrator retention', () => {
    const model = getTaskActionModel({
      task: task('FAILED'),
      mode: 'live',
      userRole: 'administrator',
      isCreator: true,
      now: NOW,
    })

    expect(model.cancel.enabled).toBe(false)
    expect(model.retry.enabled).toBe(true)
    expect(model.delete.enabled).toBe(true)
    expect(model.extend.enabled).toBe(true)
    expect(model.extend.reason).toContain('延长 15 天')
  })

  it('blocks retention when the task is already being deleted', () => {
    const model = getTaskActionModel({
      task: task('DELETING'),
      mode: 'live',
      userRole: 'administrator',
      isCreator: true,
      now: NOW,
    })

    expect(model.extend.enabled).toBe(false)
    expect(model.extend.reason).toContain('删除流程')
  })

  it('extends a valid expiry from its current value by thirty days', () => {
    expect(extendSampleExpiry('2026-08-29T00:00:00.000Z')).toBe(
      '2026-09-28T00:00:00.000Z',
    )
    expect(extendSampleExpiry('not-a-date')).toBeNull()
  })
})
