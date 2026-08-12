import { describe, expect, it } from 'vitest'

import {
  parseCompletedUpload,
  parseCreatedUploadSession,
  parseUploadSession,
  UploadIntakeContractError,
} from '@/api/uploadIntakeContract'

function session() {
  return {
    id: 'upload-1',
    part_size: 33_554_432,
    size_bytes: 4,
    status: 'created',
    uploaded_parts: [],
    expires_at: '2026-08-30T00:00:00Z',
    input_category: 'binary',
    validation_status: 'pending',
  }
}

const taskId = '90000000-0000-4000-8000-000000000001'

describe('upload intake runtime contract', () => {
  it('parses the immutable category and validation profile', () => {
    expect(parseUploadSession(session())).toMatchObject({
      input_category: 'binary',
      validation_status: 'pending',
    })
  })

  it('parses a valid archive completion with its import id', () => {
    expect(
      parseCompletedUpload({
        ...session(),
        status: 'completed',
        sha256: 'a'.repeat(64),
        input_category: 'archive',
        validation_status: 'valid',
        detected_category: 'archive',
        detected_format: 'zip',
        archive_import_id: 'import-1',
      }),
    ).toMatchObject({
      detected_format: 'zip',
      archive_import_id: 'import-1',
    })
  })

  it('correlates upload ids and the immutable requested category', () => {
    expect(() => parseUploadSession(session(), 'upload-other')).toThrow(
      UploadIntakeContractError,
    )
    expect(() =>
      parseCreatedUploadSession(session(), 'container'),
    ).toThrow(UploadIntakeContractError)
    expect(
      parseCreatedUploadSession(session(), 'binary').input_category,
    ).toBe('binary')
  })

  it('requires complete valid metadata to agree with its category', () => {
    const completedBinary = {
      ...session(),
      status: 'completed',
      sha256: 'b'.repeat(64),
      validation_status: 'valid',
      detected_category: 'binary',
      detected_format: 'elf64',
      task_id: taskId,
    }

    expect(parseCompletedUpload(completedBinary, 'upload-1')).toMatchObject({
      id: 'upload-1',
      detected_category: 'binary',
      detected_format: 'elf64',
      task_id: taskId,
    })
    expect(() =>
      parseCompletedUpload(
        { ...completedBinary, detected_category: 'container' },
        'upload-1',
      ),
    ).toThrow(UploadIntakeContractError)
    expect(() =>
      parseCompletedUpload(
        { ...completedBinary, archive_import_id: 'import-1' },
        'upload-1',
      ),
    ).toThrow(UploadIntakeContractError)
    expect(() =>
      parseCompletedUpload(completedBinary, 'upload-other'),
    ).toThrow(UploadIntakeContractError)
    const withoutTask = { ...completedBinary } as Record<string, unknown>
    delete withoutTask.task_id
    expect(() => parseCompletedUpload(withoutTask, 'upload-1')).toThrow(
      UploadIntakeContractError,
    )
    expect(() =>
      parseCompletedUpload(
        { ...completedBinary, task_id: 'TASK-UPPERCASE-OR-NON-UUID' },
        'upload-1',
      ),
    ).toThrow(UploadIntakeContractError)
  })

  it('rejects partial intake metadata and unknown response fields', () => {
    const withoutStatus = { ...session() } as Record<string, unknown>
    delete withoutStatus.validation_status

    expect(() => parseUploadSession(withoutStatus)).toThrow(
      UploadIntakeContractError,
    )
    expect(() => parseUploadSession({ ...session(), extra: true })).toThrow(
      UploadIntakeContractError,
    )
  })
})
