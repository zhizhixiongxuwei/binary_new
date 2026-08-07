import { beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import type { CompletedUpload, UploadSession } from '@/api/types'
import { useChunkUpload } from '@/composables/useChunkUpload'
import { sha256Blob } from '@/utils/hash'

vi.mock('@/utils/hash', () => ({
  sha256Blob: vi.fn().mockResolvedValue('a'.repeat(64)),
}))

const expiresAt = '2026-08-01T00:00:00Z'

function session(overrides: Partial<UploadSession> = {}): UploadSession {
  return {
    id: 'upload-1',
    part_size: 4,
    status: 'created',
    uploaded_parts: [],
    expires_at: expiresAt,
    ...overrides,
  }
}

function completedUpload(): CompletedUpload {
  return {
    ...session({ status: 'completed', uploaded_parts: [1, 2, 3] }),
    sha256: 'b'.repeat(64),
    size_bytes: 10,
  }
}

describe('useChunkUpload', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.mocked(sha256Blob).mockResolvedValue('a'.repeat(64))
    vi.spyOn(api, 'completeUpload').mockResolvedValue(completedUpload())
    vi.spyOn(api, 'createTask').mockResolvedValue({ id: 'task-1' })
  })

  it('reuses one upload-create idempotency key after an uncertain response', async () => {
    const createUpload = vi
      .spyOn(api, 'createUpload')
      .mockRejectedValueOnce(new ApiError('network interrupted', 503))
      .mockResolvedValueOnce(session({ status: 'failed' }))
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcd'], 'retry-create.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)
    await uploads.uploadItem(localId)

    expect(createUpload).toHaveBeenCalledTimes(2)
    expect(createUpload.mock.calls[0]?.[1]).toBe(localId)
    expect(createUpload.mock.calls[1]?.[1]).toBe(localId)
  })

  it('keeps uploadId on failure and skips server-confirmed parts on retry', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    const getUpload = vi.spyOn(api, 'getUpload').mockResolvedValue(
      session({ status: 'uploading', uploaded_parts: [1] }),
    )
    const uploadPart = vi
      .spyOn(api, 'uploadPart')
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new ApiError('暂时失败', 503))
      .mockResolvedValue(undefined)
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcdefghij'], 'sample.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      uploadId: 'upload-1',
      progress: 40,
      uploadedBytes: 4,
    })

    await uploads.uploadItem(localId)

    expect(getUpload).toHaveBeenCalledWith('upload-1')
    expect(uploadPart.mock.calls.map(([, input]) => input.part_number)).toEqual([1, 2, 2, 3])
    expect(uploadPart.mock.calls.filter(([, input]) => input.part_number === 1)).toHaveLength(1)
    expect(uploads.queue.value[0]).toMatchObject({
      status: 'completed',
      progress: 100,
      taskId: 'task-1',
    })
  })

  it('pauses after the in-flight part reaches its boundary', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    let resolvePart!: () => void
    const partFinished = new Promise<void>((resolve) => {
      resolvePart = resolve
    })
    const uploadPart = vi.spyOn(api, 'uploadPart').mockReturnValue(partFinished)
    const completeUpload = vi.spyOn(api, 'completeUpload')
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcdefgh'], 'pause.bin')])
    const localId = uploads.queue.value[0]!.localId

    const uploadPromise = uploads.uploadItem(localId)
    await vi.waitFor(() => expect(uploadPart).toHaveBeenCalledOnce())
    uploads.pause(localId)
    resolvePart()
    await uploadPromise

    expect(uploadPart).toHaveBeenCalledOnce()
    expect(completeUpload).not.toHaveBeenCalled()
    expect(uploads.queue.value[0]).toMatchObject({
      status: 'paused',
      progress: 50,
      uploadedBytes: 4,
      uploadId: 'upload-1',
    })
  })

  it('removes an unstarted local item without creating a server request', async () => {
    const deleteUpload = vi.spyOn(api, 'deleteUpload')
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['safe'], 'local-only.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.remove(localId)

    expect(deleteUpload).not.toHaveBeenCalled()
    expect(uploads.queue.value).toEqual([])
  })

  it('cancels an incomplete server upload before removing its queue row', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    let resolvePart!: () => void
    const partFinished = new Promise<void>((resolve) => {
      resolvePart = resolve
    })
    const uploadPart = vi.spyOn(api, 'uploadPart').mockReturnValue(partFinished)
    const deleteUpload = vi.spyOn(api, 'deleteUpload').mockResolvedValue(undefined)
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcdefgh'], 'remove-paused.bin')])
    const localId = uploads.queue.value[0]!.localId

    const uploadPromise = uploads.uploadItem(localId)
    await vi.waitFor(() => expect(uploadPart).toHaveBeenCalledOnce())
    uploads.pause(localId)
    resolvePart()
    await uploadPromise
    await uploads.remove(localId)

    expect(deleteUpload).toHaveBeenCalledWith('upload-1')
    expect(uploads.queue.value).toEqual([])
  })

  it('keeps the queue row when server-side upload cancellation fails', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(
      session({ status: 'failed' }),
    )
    vi.spyOn(api, 'deleteUpload').mockRejectedValue(
      new ApiError('服务暂时不可用', 503),
    )
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['safe'], 'remove-failed.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)
    await uploads.remove(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      localId,
      removing: false,
      errorMessage: '移除失败：服务暂时不可用',
    })
  })

  it('completes an empty file without uploading a part', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    const uploadPart = vi.spyOn(api, 'uploadPart')
    const completeUpload = vi.spyOn(api, 'completeUpload').mockResolvedValue({
      ...session({ status: 'completed' }),
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      size_bytes: 0,
    })
    const createTask = vi.spyOn(api, 'createTask')
    const uploads = useChunkUpload()
    uploads.addFiles([new File([], 'empty.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)

    expect(uploadPart).not.toHaveBeenCalled()
    expect(completeUpload).toHaveBeenCalledWith('upload-1')
    expect(createTask).toHaveBeenCalledOnce()
    expect(uploads.queue.value[0]).toMatchObject({
      status: 'completed',
      progress: 100,
      uploadedBytes: 0,
      taskId: 'task-1',
    })
  })

  it('makes a conflicting upload non-retryable on the old session', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    const uploadPart = vi.spyOn(api, 'uploadPart').mockRejectedValue(
      new ApiError('part conflict', 409, { code: 'upload_conflict' }),
    )
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcd'], 'conflict.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      uploadId: 'upload-1',
      canRetry: false,
      errorMessage: '分片内容冲突，请移除后重新选择文件',
    })

    await uploads.uploadItem(localId)
    await uploads.startAll()
    expect(uploadPart).toHaveBeenCalledOnce()
    expect(uploads.readyCount.value).toBe(0)
  })

  it('describes a completion storage conflict as an assembly failure', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    vi.spyOn(api, 'uploadPart').mockResolvedValue(undefined)
    vi.spyOn(api, 'completeUpload').mockRejectedValue(
      new ApiError('blob conflict', 409, { code: 'upload_conflict' }),
    )
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcd'], 'conflict.bin')])

    await uploads.uploadItem(uploads.queue.value[0]!.localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      canRetry: false,
      errorMessage: '文件合并时检测到存储冲突，请移除后重新选择文件',
    })
  })

  it('classifies completion and task conflicts by stage and error code', async () => {
    vi.spyOn(api, 'createUpload').mockResolvedValue(session())
    vi.spyOn(api, 'uploadPart').mockResolvedValue(undefined)
    vi.spyOn(api, 'completeUpload').mockRejectedValueOnce(
      new ApiError('missing part', 409, { code: 'upload_incomplete' }),
    )
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcd'], 'incomplete.bin')])
    const localId = uploads.queue.value[0]!.localId

    await uploads.uploadItem(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      canRetry: true,
      errorMessage: '上传分片不完整，请重试',
    })

    vi.spyOn(api, 'getUpload').mockResolvedValue(
      session({ status: 'completed', uploaded_parts: [1] }),
    )
    vi.spyOn(api, 'createTask').mockRejectedValue(
      new ApiError('task conflict', 409, { code: 'task_conflict' }),
    )
    await uploads.uploadItem(localId)

    expect(uploads.queue.value[0]).toMatchObject({
      status: 'failed',
      canRetry: false,
      errorMessage: '任务请求与已有记录冲突，无法重试',
    })
  })

  it.each([
    ['assembling', true, '文件正在合并，请稍后重试'],
    ['failed', false, '上传会话已失败，请移除后重新选择文件'],
    ['expired', false, '上传会话已过期，请移除后重新选择文件'],
    ['cancelled', false, '上传会话已取消，请移除后重新选择文件'],
  ] as const)(
    'handles the %s server session explicitly',
    async (status, canRetry, errorMessage) => {
      vi.spyOn(api, 'createUpload').mockResolvedValue(session({ status }))
      const uploadPart = vi.spyOn(api, 'uploadPart')
      const completeUpload = vi.spyOn(api, 'completeUpload')
      const createTask = vi.spyOn(api, 'createTask')
      const uploads = useChunkUpload()
      uploads.addFiles([new File(['abcd'], `${status}.bin`)])
      const localId = uploads.queue.value[0]!.localId

      await uploads.uploadItem(localId)

      expect(uploads.queue.value[0]).toMatchObject({
        status: 'failed',
        canRetry,
        errorMessage,
      })
      expect(uploadPart).not.toHaveBeenCalled()
      expect(completeUpload).not.toHaveBeenCalled()
      expect(createTask).not.toHaveBeenCalled()
    },
  )

  it('prevents the same queue item from entering twice', async () => {
    let resolveSession!: (value: UploadSession) => void
    const pendingSession = new Promise<UploadSession>((resolve) => {
      resolveSession = resolve
    })
    const createUpload = vi.spyOn(api, 'createUpload').mockReturnValue(pendingSession)
    vi.spyOn(api, 'uploadPart').mockResolvedValue(undefined)
    const uploads = useChunkUpload()
    uploads.addFiles([new File(['abcd'], 'single-flight.bin')])
    const localId = uploads.queue.value[0]!.localId

    const first = uploads.uploadItem(localId)
    const second = uploads.uploadItem(localId)
    resolveSession(session())
    await Promise.all([first, second])

    expect(createUpload).toHaveBeenCalledOnce()
  })
})
