import { computed, readonly, shallowRef } from 'vue'

import { api, ApiError } from '@/api/client'
import type { UploadSession } from '@/api/types'
import { sha256Blob } from '@/utils/hash'
import { createIdempotencyKey } from '@/utils/idempotency'

const MAX_FILE_SIZE = 10 * 1024 ** 3

export type UploadItemStatus =
  | 'ready'
  | 'uploading'
  | 'paused'
  | 'completed'
  | 'failed'

export interface UploadQueueItem {
  localId: string
  file: File
  status: UploadItemStatus
  progress: number
  uploadedBytes: number
  errorMessage: string
  uploadId?: string
  partSize?: number
  taskId?: string
  taskIdempotencyKey: string
  canRetry: boolean
  serverStatus?: UploadSession['status']
  removing?: boolean
}

function newLocalId(): string {
  return createIdempotencyKey()
}

function replaceItem(
  items: UploadQueueItem[],
  localId: string,
  patch: Partial<UploadQueueItem>,
): UploadQueueItem[] {
  return items.map((item) => (item.localId === localId ? { ...item, ...patch } : item))
}

function totalPartCount(fileSize: number, partSize: number): number {
  return fileSize === 0 ? 0 : Math.ceil(fileSize / partSize)
}

function partByteLength(
  fileSize: number,
  partSize: number,
  partNumber: number,
): number {
  const start = (partNumber - 1) * partSize
  if (partNumber < 1 || start >= fileSize) return 0
  return Math.min(partSize, fileSize - start)
}

export function uploadedByteCount(
  fileSize: number,
  partSize: number,
  uploadedParts: readonly number[],
): number {
  return [...new Set(uploadedParts)].reduce(
    (total, partNumber) => total + partByteLength(fileSize, partSize, partNumber),
    0,
  )
}

function progressPercent(fileSize: number, uploadedBytes: number): number {
  if (fileSize === 0) return 0
  return Math.min(100, Math.round((uploadedBytes / fileSize) * 100))
}

type UploadStage = 'session' | 'part' | 'complete' | 'task'

interface UploadFailure {
  message: string
  canRetry: boolean
}

class UploadStateError extends Error {
  readonly canRetry: boolean

  constructor(message: string, canRetry: boolean) {
    super(message)
    this.name = 'UploadStateError'
    this.canRetry = canRetry
  }
}

function classifyUploadFailure(error: unknown, stage: UploadStage): UploadFailure {
  if (error instanceof UploadStateError) {
    return { message: error.message, canRetry: error.canRetry }
  }
  if (!(error instanceof ApiError)) {
    return { message: '上传中断，请重试', canRetry: true }
  }

  switch (error.code) {
    case 'upload_conflict':
      return {
        message:
          stage === 'part'
            ? '分片内容冲突，请移除后重新选择文件'
            : stage === 'complete'
              ? '文件合并时检测到存储冲突，请移除后重新选择文件'
              : '上传内容冲突，请移除后重新选择文件',
        canRetry: false,
      }
    case 'upload_incomplete':
      return { message: '上传分片不完整，请重试', canRetry: true }
    case 'upload_invalid_state':
      return { message: '上传状态已变化，请重试同步', canRetry: true }
    case 'upload_expired':
      return {
        message: '上传会话已过期，请移除后重新选择文件',
        canRetry: false,
      }
    case 'upload_not_completed':
      return { message: '文件尚未完成，请重试创建任务', canRetry: true }
    case 'task_conflict':
      return { message: '任务请求与已有记录冲突，无法重试', canRetry: false }
  }

  if (error.status === 409) {
    return {
      message: stage === 'task' ? '任务创建请求冲突' : '上传请求冲突',
      canRetry: false,
    }
  }
  if (error.status === 400 || error.status === 403 || error.status === 404 || error.status === 410) {
    return { message: error.message, canRetry: false }
  }
  return { message: error.message, canRetry: true }
}

export function useChunkUpload() {
  const queue = shallowRef<UploadQueueItem[]>([])
  const activeId = shallowRef<string | null>(null)
  const pauseRequests = new Set<string>()

  const isUploading = computed(() => activeId.value !== null)
  const readyCount = computed(
    () =>
      queue.value.filter(
        (item) =>
          !item.removing &&
          (item.status === 'ready' ||
            (item.status === 'failed' && item.canRetry)),
      ).length,
  )

  function addFiles(files: File[]): string[] {
    const rejected: string[] = []
    const additions: UploadQueueItem[] = []
    for (const file of files) {
      if (file.size > MAX_FILE_SIZE) {
        rejected.push(`${file.name} 超过 10 GB`)
        continue
      }
      additions.push({
        localId: newLocalId(),
        file,
        status: 'ready',
        progress: 0,
        uploadedBytes: 0,
        errorMessage: '',
        taskIdempotencyKey: newLocalId(),
        canRetry: true,
        removing: false,
      })
    }
    queue.value = [...queue.value, ...additions]
    return rejected
  }

  async function remove(localId: string): Promise<void> {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (!item || activeId.value === localId || item.removing) return

    if (!item.uploadId || item.serverStatus === 'completed') {
      queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
      return
    }

    queue.value = replaceItem(queue.value, localId, {
      removing: true,
      errorMessage: '',
    })
    try {
      await api.deleteUpload(item.uploadId)
      queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
    } catch (error) {
      const message =
        error instanceof ApiError ? error.message : '上传会话取消失败，请重试'
      queue.value = replaceItem(queue.value, localId, {
        removing: false,
        errorMessage: `移除失败：${message}`,
      })
    }
  }

  function pause(localId: string): void {
    if (activeId.value === localId) pauseRequests.add(localId)
  }

  function setProgress(
    localId: string,
    fileSize: number,
    partSize: number,
    uploadedParts: readonly number[],
  ): void {
    const uploadedBytes = uploadedByteCount(fileSize, partSize, uploadedParts)
    queue.value = replaceItem(queue.value, localId, {
      uploadedBytes,
      progress: progressPercent(fileSize, uploadedBytes),
    })
  }

  async function resolveSession(item: UploadQueueItem): Promise<UploadSession> {
    if (item.uploadId) return api.getUpload(item.uploadId)
    return api.createUpload(
      {
        filename: item.file.name,
        size: item.file.size,
        content_type: item.file.type || 'application/octet-stream',
      },
      item.localId,
    )
  }

  async function uploadItem(localId: string): Promise<void> {
    const initial = queue.value.find((item) => item.localId === localId)
    if (
      !initial ||
      initial.removing ||
      initial.status === 'completed' ||
      (initial.status === 'failed' && !initial.canRetry) ||
      activeId.value !== null
    ) {
      return
    }

    activeId.value = localId
    pauseRequests.delete(localId)
    queue.value = replaceItem(queue.value, localId, {
      status: 'uploading',
      errorMessage: '',
      canRetry: true,
    })

    let stage: UploadStage = 'session'
    try {
      const session = await resolveSession(initial)
      const uploadedParts = new Set(session.uploaded_parts)
      queue.value = replaceItem(queue.value, localId, {
        uploadId: session.id,
        partSize: session.part_size,
        serverStatus: session.status,
      })
      setProgress(localId, initial.file.size, session.part_size, session.uploaded_parts)

      if (session.status === 'assembling') {
        throw new UploadStateError('文件正在合并，请稍后重试', true)
      }
      if (session.status === 'failed') {
        throw new UploadStateError('上传会话已失败，请移除后重新选择文件', false)
      }
      if (session.status === 'expired') {
        throw new UploadStateError('上传会话已过期，请移除后重新选择文件', false)
      }
      if (session.status === 'cancelled') {
        throw new UploadStateError('上传会话已取消，请移除后重新选择文件', false)
      }

      if (session.status === 'created' || session.status === 'uploading') {
        const partCount = totalPartCount(initial.file.size, session.part_size)
        for (let partNumber = 1; partNumber <= partCount; partNumber += 1) {
          if (pauseRequests.has(localId)) {
            queue.value = replaceItem(queue.value, localId, { status: 'paused' })
            return
          }
          if (uploadedParts.has(partNumber)) continue

          const start = (partNumber - 1) * session.part_size
          const endExclusive = Math.min(start + session.part_size, initial.file.size)
          const chunk = initial.file.slice(start, endExclusive)
          const sha256 = await sha256Blob(chunk)
          stage = 'part'
          await api.uploadPart(session.id, {
            part_number: partNumber,
            start,
            end: endExclusive - 1,
            total: initial.file.size,
            sha256,
            chunk,
          })
          uploadedParts.add(partNumber)
          setProgress(localId, initial.file.size, session.part_size, [...uploadedParts])
        }

        if (pauseRequests.has(localId) && initial.file.size > 0) {
          queue.value = replaceItem(queue.value, localId, { status: 'paused' })
          return
        }
        stage = 'complete'
        await api.completeUpload(session.id)
        queue.value = replaceItem(queue.value, localId, {
          serverStatus: 'completed',
        })
      }

      stage = 'task'
      const task = await api.createTask(
        { upload_id: session.id, name: initial.file.name },
        initial.taskIdempotencyKey,
      )
      queue.value = replaceItem(queue.value, localId, {
        status: 'completed',
        progress: 100,
        uploadedBytes: initial.file.size,
        taskId: task.id,
        canRetry: false,
      })
    } catch (error) {
      const failure = classifyUploadFailure(error, stage)
      queue.value = replaceItem(queue.value, localId, {
        status: 'failed',
        errorMessage: failure.message,
        canRetry: failure.canRetry,
      })
    } finally {
      pauseRequests.delete(localId)
      activeId.value = null
    }
  }

  async function startAll(): Promise<void> {
    const candidates = queue.value
      .filter(
        (item) =>
          !item.removing &&
          (item.status === 'ready' ||
            item.status === 'paused' ||
            (item.status === 'failed' && item.canRetry)),
      )
      .map((item) => item.localId)
    for (const localId of candidates) {
      await uploadItem(localId)
    }
  }

  return {
    queue: readonly(queue),
    activeId: readonly(activeId),
    isUploading,
    readyCount,
    addFiles,
    remove,
    pause,
    uploadItem,
    startAll,
  }
}
