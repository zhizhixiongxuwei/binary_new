import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type {
  CompletedUpload,
  InputCategory,
  UploadSession,
} from '@/api/types'
import {
  MAX_CATEGORIZED_UPLOAD_SIZE,
  useCategorizedUpload,
} from '@/composables/useCategorizedUpload'
import { sha256Blob } from '@/utils/hash'

vi.mock('@/utils/hash', () => ({
  sha256Blob: vi.fn().mockResolvedValue('a'.repeat(64)),
}))

const taskId = '90000000-0000-4000-8000-000000000001'

function session(
  category: InputCategory,
  overrides: Partial<UploadSession> = {},
): UploadSession {
  return {
    id: `upload-${category}`,
    part_size: 4,
    size_bytes: 4,
    status: 'created',
    uploaded_parts: [],
    expires_at: '2026-08-30T00:00:00Z',
    input_category: category,
    validation_status: 'pending',
    ...overrides,
  }
}

function completed(
  category: InputCategory,
  overrides: Partial<CompletedUpload> = {},
): CompletedUpload {
  return {
    ...session(category),
    status: 'completed',
    uploaded_parts: [1],
    sha256: 'b'.repeat(64),
    size_bytes: 4,
    validation_status: 'valid',
    detected_category: category,
    detected_format:
      category === 'binary'
        ? 'elf64'
        : category === 'container'
          ? 'docker-tar'
          : 'zip',
    ...(category === 'archive' ? {} : { task_id: taskId }),
    ...overrides,
  }
}

describe('useCategorizedUpload', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.mocked(sha256Blob).mockResolvedValue('a'.repeat(64))
    vi.spyOn(api, 'uploadPart').mockResolvedValue(undefined)
    vi.spyOn(api, 'createTask').mockResolvedValue({ id: 'task-1' })
    vi.spyOn(api, 'deleteUpload').mockResolvedValue(undefined)
  })

  it.each(['binary', 'container'] as const)(
    'automatically creates one task for a valid %s upload',
    async (category) => {
      const createUpload = vi
        .spyOn(api, 'createUpload')
        .mockResolvedValue(session(category))
      vi.spyOn(api, 'completeUpload').mockResolvedValue(completed(category))
      const createTask = vi.spyOn(api, 'createTask')
      const uploads = useCategorizedUpload(category)
      uploads.addFiles([new File(['abcd'], 'extensionless')])

      await uploads.startAll()

      expect(createUpload).toHaveBeenCalledWith(
        expect.objectContaining({ input_category: category }),
        expect.any(String),
      )
      expect(createTask).not.toHaveBeenCalled()
      expect(uploads.queue.value[0]).toMatchObject({
        status: 'completed',
        taskId,
      })
    },
  )

  it('recovers a direct task from GET after an uncertain Complete response', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session('binary'))
    vi.spyOn(api, 'completeUpload').mockRejectedValue(
      new ApiError('response lost', 503),
    )
    vi.spyOn(api, 'getUpload').mockResolvedValue(completed('binary'))
    const createTask = vi.spyOn(api, 'createTask')
    const uploads = useCategorizedUpload('binary')
    uploads.addFiles([new File(['abcd'], 'recover-me')])

    await uploads.startAll()

    expect(api.getUpload).toHaveBeenCalledWith('upload-binary')
    expect(createTask).not.toHaveBeenCalled()
    expect(uploads.queue.value[0]).toMatchObject({
      status: 'completed',
      taskId,
    })
  })

  it('creates an independent import for an archive without creating an outer task', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session('archive'))
    vi.spyOn(api, 'completeUpload').mockResolvedValue(
      completed('archive', { archive_import_id: 'import-1' }),
    )
    const createTask = vi.spyOn(api, 'createTask')
    const uploads = useCategorizedUpload('archive')
    uploads.addFiles([new File(['abcd'], 'bundle.zip')])

    await uploads.startAll()

    expect(createTask).not.toHaveBeenCalled()
    expect(uploads.archiveItems.value).toHaveLength(1)
    expect(uploads.queue.value[0]).toMatchObject({
      status: 'archive',
      archiveImportId: 'import-1',
    })
  })

  it('clears a completed direct item locally and unlocks the category', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session('binary'))
    vi.spyOn(api, 'completeUpload').mockResolvedValue(completed('binary'))
    const uploads = useCategorizedUpload('binary')
    uploads.addFiles([new File(['abcd'], 'application')])

    await uploads.startAll()
    const localId = uploads.queue.value[0]!.localId

    expect(uploads.categoryLocked.value).toBe(true)
    uploads.clearCompleted(localId)

    expect(uploads.queue.value).toEqual([])
    expect(uploads.categoryLocked.value).toBe(false)
    expect(api.deleteUpload).not.toHaveBeenCalled()
  })

  it('recovers authoritative mismatch details after 422 and leaves deletion available', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session('binary'))
    vi.spyOn(api, 'completeUpload').mockRejectedValue(
      new ApiError('mismatch', 422, {
        code: 'input_category_mismatch',
        details: {
          upload_id: 'upload-binary',
          input_category: 'binary',
          detected_category: 'archive',
          detected_format: '7z',
        },
      }),
    )
    vi.spyOn(api, 'getUpload').mockResolvedValue(
      session('binary', {
        status: 'failed',
        validation_status: 'mismatch',
        detected_category: 'archive',
        detected_format: '7z',
      }),
    )
    const uploads = useCategorizedUpload('binary')
    uploads.addFiles([new File(['abcd'], 'wrong.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      canRetry: false,
      detectedFormat: '7z',
      errorMessage: expect.stringContaining('实际识别：7z'),
    })
    await uploads.remove(localId)
    expect(api.deleteUpload).toHaveBeenCalledWith('upload-binary')
    expect(uploads.queue.value).toEqual([])
  })

  it('enforces the exact 2 GiB browser boundary', () => {
    const uploads = useCategorizedUpload('binary')
    const atLimit = new File(['x'], 'at-limit')
    const overLimit = new File(['x'], 'over-limit')
    Object.defineProperty(atLimit, 'size', {
      configurable: true,
      value: MAX_CATEGORIZED_UPLOAD_SIZE,
    })
    Object.defineProperty(overLimit, 'size', {
      configurable: true,
      value: MAX_CATEGORIZED_UPLOAD_SIZE + 1,
    })

    expect(uploads.addFiles([atLimit, overLimit])).toEqual([
      'over-limit 超过 2 GiB',
    ])
    expect(uploads.queue.value).toHaveLength(1)
    expect(uploads.categoryLocked.value).toBe(true)
  })

  it('ignores an old upload response after disposal', async () => {
    let resolveSession!: (value: UploadSession) => void
    vi.spyOn(api, 'createUpload').mockReturnValue(
      new Promise((resolve) => {
        resolveSession = resolve
      }),
    )
    const createTask = vi.spyOn(api, 'createTask')
    const uploadPart = vi.spyOn(api, 'uploadPart')
    const uploads = useCategorizedUpload('binary')
    uploads.addFiles([new File(['abcd'], 'stale.bin')])

    const pending = uploads.startAll()
    await vi.waitFor(() => expect(api.createUpload).toHaveBeenCalledOnce())
    uploads.dispose()
    resolveSession(session('binary'))
    await pending

    expect(uploadPart).not.toHaveBeenCalled()
    expect(createTask).not.toHaveBeenCalled()
  })
})
