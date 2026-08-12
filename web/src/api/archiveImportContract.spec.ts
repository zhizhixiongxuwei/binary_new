import { describe, expect, it } from 'vitest'

import {
  ArchiveImportContractError,
  parseArchiveImport,
  parseArchiveImportPage,
  parseArchiveImportEntryPage,
  parseArchiveTaskBatchResult,
} from '@/api/archiveImportContract'

function archiveImport() {
  return {
    id: 'import-1',
    upload_id: 'upload-1',
    filename: 'bundle.zip',
    status: 'ready',
    scanned_entries: 3,
    total_entries: 3,
    eligible_entries: 2,
    skipped_entries: 1,
    created_tasks: 1,
    created_at: '2026-08-11T08:00:00Z',
    updated_at: '2026-08-11T08:01:00Z',
  }
}

describe('archive import runtime contract', () => {
  it('parses import counters and rejects impossible counts', () => {
    expect(parseArchiveImport(archiveImport())).toEqual(archiveImport())
    expect(() =>
      parseArchiveImport({ ...archiveImport(), scanned_entries: 4 }),
    ).toThrow(ArchiveImportContractError)
  })

  it('accepts only active, uniquely identified imports in a cursor page', () => {
    expect(
      parseArchiveImportPage({
        items: [archiveImport()],
        next_cursor: 'opaque:cursor',
      }),
    ).toEqual({
      items: [archiveImport()],
      next_cursor: 'opaque:cursor',
    })
    expect(() =>
      parseArchiveImportPage({
        items: [archiveImport(), archiveImport()],
      }),
    ).toThrow(ArchiveImportContractError)
    expect(() =>
      parseArchiveImportPage({
        items: [{ ...archiveImport(), status: 'deleted' }],
      }),
    ).toThrow(ArchiveImportContractError)
  })

  it('accepts null detection fields only for safely skipped entries', () => {
    const skipped = {
      id: 'entry-1',
      path: 'unsafe-link',
      size_bytes: 0,
      sha256: null,
      detected_format: null,
      detected_category: null,
      status: 'skipped',
      skip_reason: 'symbolic link',
    }

    expect(parseArchiveImportEntryPage({ items: [skipped] }).items[0]).toEqual(
      skipped,
    )
    expect(() =>
      parseArchiveImportEntryPage({
        items: [{ ...skipped, status: 'failed' }],
      }),
    ).toThrow(ArchiveImportContractError)
  })

  it('keeps created entries valid after their task is physically deleted', () => {
    const createdWithoutTask = {
      id: 'entry-2',
      path: 'bin/app',
      size_bytes: 4,
      sha256: 'b'.repeat(64),
      detected_format: 'elf64',
      detected_category: 'binary',
      status: 'created',
    }

    expect(
      parseArchiveImportEntryPage({ items: [createdWithoutTask] }).items[0],
    ).toEqual(createdWithoutTask)
  })

  it('allows an existing batch result with a deleted task but not a new result without one', () => {
    expect(
      parseArchiveTaskBatchResult({
        items: [{ entry_id: 'entry-2', outcome: 'existing' }],
      }),
    ).toEqual({
      items: [{ entry_id: 'entry-2', outcome: 'existing' }],
    })
    expect(() =>
      parseArchiveTaskBatchResult({
        items: [{ entry_id: 'entry-2', outcome: 'created' }],
      }),
    ).toThrow(ArchiveImportContractError)
  })

  it('requires a batch result to cover exactly the requested entry ids', () => {
    const result = {
      items: [
        { entry_id: 'entry-1', outcome: 'created', task_id: 'task-1' },
        {
          entry_id: 'entry-2',
          outcome: 'failed',
          error_code: 'task_create_failed',
        },
      ],
    }

    expect(
      parseArchiveTaskBatchResult(result, ['entry-2', 'entry-1']),
    ).toEqual(result)
    expect(() => parseArchiveTaskBatchResult(result, ['entry-1'])).toThrow(
      ArchiveImportContractError,
    )
    expect(() =>
      parseArchiveTaskBatchResult(
        { items: [{ ...result.items[0], entry_id: 'entry-other' }] },
        ['entry-1'],
      ),
    ).toThrow(ArchiveImportContractError)
  })
})
