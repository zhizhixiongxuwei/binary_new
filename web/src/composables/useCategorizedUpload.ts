import {
  computed,
  getCurrentScope,
  onScopeDispose,
  readonly,
  shallowRef,
} from 'vue'

import { api, ApiError } from '@/api/client'
import type {
  InputCategory,
  UploadSession,
  UploadValidationStatus,
} from '@/api/types'
import type { UploadQueueDisplayItem } from '@/components/uploads/uploadQueueTypes'
import { sha256Blob } from '@/utils/hash'
import { createIdempotencyKey } from '@/utils/idempotency'

export const MAX_CATEGORIZED_UPLOAD_SIZE = 2 * 1024 ** 3

export interface CategorizedUploadItem extends UploadQueueDisplayItem {
  category: InputCategory
}

type UploadStage = 'session' | 'part' | 'complete' | 'validation'

interface UploadFailure {
  message: string
  canRetry: boolean
}

interface IntakeErrorDetails {
  upload_id?: string
  input_category?: InputCategory
  detected_category?: InputCategory
  detected_format?: string
}

class UploadStateError extends Error {
  readonly canRetry: boolean

  constructor(message: string, canRetry: boolean) {
    super(message)
    this.name = 'UploadStateError'
    this.canRetry = canRetry
  }
}

function newId(): string {
  return createIdempotencyKey()
}

function replaceItem(
  items: CategorizedUploadItem[],
  localId: string,
  patch: Partial<CategorizedUploadItem>,
): CategorizedUploadItem[] {
  return items.map((item) =>
    item.localId === localId ? { ...item, ...patch } : item,
  )
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

function uploadedByteCount(
  fileSize: number,
  partSize: number,
  uploadedParts: readonly number[],
): number {
  return [...new Set(uploadedParts)].reduce(
    (total, partNumber) =>
      total + partByteLength(fileSize, partSize, partNumber),
    0,
  )
}

function progressPercent(fileSize: number, uploadedBytes: number): number {
  if (fileSize === 0) return 0
  return Math.min(100, Math.round((uploadedBytes / fileSize) * 100))
}

function intakeDetails(error: ApiError): IntakeErrorDetails {
  if (
    typeof error.details !== 'object' ||
    error.details === null ||
    Array.isArray(error.details)
  ) {
    return {}
  }
  const details = error.details as Record<string, unknown>
  const category = (value: unknown): InputCategory | undefined =>
    value === 'binary' || value === 'archive' || value === 'container'
      ? value
      : undefined
  const inputCategory = category(details.input_category)
  const detectedCategory = category(details.detected_category)
  return {
    ...(typeof details.upload_id === 'string'
      ? { upload_id: details.upload_id }
      : {}),
    ...(inputCategory ? { input_category: inputCategory } : {}),
    ...(detectedCategory ? { detected_category: detectedCategory } : {}),
    ...(typeof details.detected_format === 'string'
      ? { detected_format: details.detected_format }
      : {}),
  }
}

function validationFailureMessage(
  validationStatus: UploadValidationStatus,
  detectedFormat: string | undefined,
): string {
  const actual = detectedFormat ? `（实际识别：${detectedFormat}）` : ''
  return validationStatus === 'mismatch'
    ? `文件类别与所选入口不匹配${actual}`
    : `暂不支持该文件格式${actual}`
}

function classifyFailure(error: unknown, stage: UploadStage): UploadFailure {
  if (error instanceof UploadStateError) {
    return { message: error.message, canRetry: error.canRetry }
  }
  if (!(error instanceof ApiError)) {
    return { message: '上传中断，请重试', canRetry: true }
  }
  switch (error.code) {
    case 'input_category_mismatch': {
      const details = intakeDetails(error)
      return {
        message: validationFailureMessage('mismatch', details.detected_format),
        canRetry: false,
      }
    }
    case 'unsupported_input_format': {
      const details = intakeDetails(error)
      return {
        message: validationFailureMessage('unsupported', details.detected_format),
        canRetry: false,
      }
    }
    case 'upload_conflict':
      return {
        message:
          stage === 'part'
            ? '分片内容冲突，请删除后重新选择文件'
            : stage === 'complete'
              ? '文件合并时检测到存储冲突，请删除后重新选择文件'
              : '上传内容冲突，请删除后重新选择文件',
        canRetry: false,
      }
    case 'upload_incomplete':
      return { message: '上传分片不完整，请重试', canRetry: true }
    case 'upload_invalid_state':
      return { message: '上传状态已变化，请重试同步', canRetry: true }
    case 'upload_expired':
      return { message: '上传会话已过期，请删除后重新选择文件', canRetry: false }
    case 'upload_not_completed':
      return { message: '文件尚未完成，请重试创建任务', canRetry: true }
    case 'task_conflict':
      return { message: '任务请求与已有记录冲突，无法重试', canRetry: false }
  }
  if (error.status === 409) {
    return {
      message: '上传请求冲突',
      canRetry: false,
    }
  }
  if ([400, 403, 404, 410, 413, 422].includes(error.status)) {
    return { message: error.message, canRetry: false }
  }
  return { message: error.message, canRetry: true }
}

function terminalSessionFailure(session: UploadSession): UploadStateError | null {
  if (session.status === 'failed') {
    if (
      session.validation_status === 'mismatch' ||
      session.validation_status === 'unsupported'
    ) {
      return new UploadStateError(
        validationFailureMessage(
          session.validation_status,
          session.detected_format,
        ),
        false,
      )
    }
    return new UploadStateError('上传会话已失败，请删除后重新选择文件', false)
  }
  if (session.status === 'expired') {
    return new UploadStateError('上传会话已过期，请删除后重新选择文件', false)
  }
  if (session.status === 'cancelled') {
    return new UploadStateError('上传会话已取消，请删除后重新选择文件', false)
  }
  return null
}

export function useCategorizedUpload(category: InputCategory) {
  const queue = shallowRef<CategorizedUploadItem[]>([])
  const activeId = shallowRef<string | null>(null)
  const pauseRequests = new Set<string>()
  let generation = 0
  let disposed = false

  const isUploading = computed(() => activeId.value !== null)
  const readyCount = computed(
    () =>
      queue.value.filter(
        (item) =>
          !item.removing &&
          (item.status === 'ready' ||
            item.status === 'paused' ||
            (item.status === 'failed' && item.canRetry)),
      ).length,
  )
  const categoryLocked = computed(
    () => queue.value.length > 0 || activeId.value !== null,
  )
  const archiveItems = computed(() =>
    queue.value.filter(
      (
        item,
      ): item is CategorizedUploadItem & {
        archiveImportId: string
        uploadId: string
      } =>
        item.status === 'archive' &&
        Boolean(item.archiveImportId) &&
        Boolean(item.uploadId),
    ),
  )

  function current(requestGeneration: number): boolean {
    return !disposed && requestGeneration === generation
  }

  function patchItem(
    localId: string,
    patch: Partial<CategorizedUploadItem>,
    requestGeneration = generation,
  ): void {
    if (!current(requestGeneration)) return
    queue.value = replaceItem(queue.value, localId, patch)
  }

  function addFiles(files: readonly File[]): string[] {
    const rejected: string[] = []
    const additions: CategorizedUploadItem[] = []
    for (const file of files) {
      if (file.size > MAX_CATEGORIZED_UPLOAD_SIZE) {
        rejected.push(`${file.name} 超过 2 GiB`)
        continue
      }
      additions.push({
        localId: newId(),
        file,
        category,
        status: 'ready',
        progress: 0,
        uploadedBytes: 0,
        errorMessage: '',
        canRetry: true,
        removing: false,
      })
    }
    if (!disposed) queue.value = [...queue.value, ...additions]
    return rejected
  }

  async function remove(localId: string): Promise<void> {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (
      !item ||
      item.taskId ||
      activeId.value === localId ||
      item.removing ||
      disposed
    ) {
      return
    }
    const requestGeneration = generation
    if (!item.uploadId) {
      if (current(requestGeneration)) {
        queue.value = queue.value.filter(
          (candidate) => candidate.localId !== localId,
        )
      }
      return
    }
    patchItem(localId, { removing: true, errorMessage: '' }, requestGeneration)
    try {
      await api.deleteUpload(item.uploadId)
      if (current(requestGeneration)) {
        queue.value = queue.value.filter(
          (candidate) => candidate.localId !== localId,
        )
      }
    } catch (error) {
      const message =
        error instanceof ApiError ? error.message : '上传删除失败，请重试'
      patchItem(
        localId,
        { removing: false, errorMessage: `删除失败：${message}` },
        requestGeneration,
      )
    }
  }

  function clearCompleted(localId: string): void {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (item?.status !== 'completed' || !item.taskId) return
    queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
  }

  function forgetDeletedArchive(localId: string): void {
    const item = queue.value.find((candidate) => candidate.localId === localId)
    if (item?.status !== 'archive' || activeId.value === localId) return
    queue.value = queue.value.filter((candidate) => candidate.localId !== localId)
  }

  function pause(localId: string): void {
    if (activeId.value === localId) pauseRequests.add(localId)
  }

  function setProgress(
    localId: string,
    fileSize: number,
    partSize: number,
    uploadedParts: readonly number[],
    requestGeneration: number,
  ): void {
    const uploadedBytes = uploadedByteCount(fileSize, partSize, uploadedParts)
    patchItem(
      localId,
      {
        uploadedBytes,
        progress: progressPercent(fileSize, uploadedBytes),
      },
      requestGeneration,
    )
  }

  async function resolveSession(
    item: CategorizedUploadItem,
  ): Promise<UploadSession> {
    if (item.uploadId) return api.getUpload(item.uploadId)
    return api.createUpload(
      {
        filename: item.file.name,
        size: item.file.size,
        content_type: item.file.type || 'application/octet-stream',
        input_category: category,
      },
      item.localId,
    )
  }

  async function completeWithRecovery(
    uploadId: string,
  ): Promise<UploadSession> {
    try {
      return await api.completeUpload(uploadId)
    } catch (error) {
      if (!(error instanceof ApiError)) throw error
      const canRecover =
        error.code === 'input_category_mismatch' ||
        error.code === 'unsupported_input_format' ||
        error.status >= 500
      if (!canRecover) throw error
      try {
        return await api.getUpload(uploadId)
      } catch {
        throw error
      }
    }
  }

  function assertSessionCategory(session: UploadSession): void {
    if (
      session.input_category === undefined ||
      session.validation_status === undefined
    ) {
      throw new UploadStateError(
        '服务端未返回输入类别校验结果，已停止创建任务',
        false,
      )
    }
    if (session.input_category !== category) {
      throw new UploadStateError('上传类别与当前页面不一致，请删除后重试', false)
    }
  }

  async function uploadItem(localId: string): Promise<void> {
    const initial = queue.value.find((item) => item.localId === localId)
    if (
      !initial ||
      initial.removing ||
      initial.status === 'completed' ||
      initial.status === 'archive' ||
      (initial.status === 'failed' && !initial.canRetry) ||
      activeId.value !== null ||
      disposed
    ) {
      return
    }

    const requestGeneration = generation
    activeId.value = localId
    pauseRequests.delete(localId)
    patchItem(
      localId,
      { status: 'uploading', errorMessage: '', canRetry: true },
      requestGeneration,
    )

    let stage: UploadStage = 'session'
    try {
      let session = await resolveSession(initial)
      if (!current(requestGeneration)) return
      assertSessionCategory(session)
      const uploadedParts = new Set(session.uploaded_parts)
      patchItem(
        localId,
        {
          uploadId: session.id,
          partSize: session.part_size,
          serverStatus: session.status,
          ...(session.validation_status
            ? { validationStatus: session.validation_status }
            : {}),
          ...(session.detected_format
            ? { detectedFormat: session.detected_format }
            : {}),
          ...(session.archive_import_id
            ? { archiveImportId: session.archive_import_id }
            : {}),
          ...(session.task_id ? { taskId: session.task_id } : {}),
        },
        requestGeneration,
      )
      setProgress(
        localId,
        initial.file.size,
        session.part_size,
        session.uploaded_parts,
        requestGeneration,
      )

      const terminalFailure = terminalSessionFailure(session)
      if (terminalFailure) throw terminalFailure
      if (session.status === 'assembling') {
        throw new UploadStateError('文件正在合并，请稍后重试', true)
      }

      if (session.status === 'created' || session.status === 'uploading') {
        const partCount = totalPartCount(initial.file.size, session.part_size)
        for (let partNumber = 1; partNumber <= partCount; partNumber += 1) {
          if (!current(requestGeneration)) return
          if (pauseRequests.has(localId)) {
            patchItem(localId, { status: 'paused' }, requestGeneration)
            return
          }
          if (uploadedParts.has(partNumber)) continue

          const start = (partNumber - 1) * session.part_size
          const endExclusive = Math.min(
            start + session.part_size,
            initial.file.size,
          )
          const chunk = initial.file.slice(start, endExclusive)
          const sha256 = await sha256Blob(chunk)
          if (!current(requestGeneration)) return
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
          setProgress(
            localId,
            initial.file.size,
            session.part_size,
            [...uploadedParts],
            requestGeneration,
          )
        }

        if (pauseRequests.has(localId) && initial.file.size > 0) {
          patchItem(localId, { status: 'paused' }, requestGeneration)
          return
        }
      }

      stage = 'complete'
      session = await completeWithRecovery(session.id)
      if (!current(requestGeneration)) return
      assertSessionCategory(session)
      patchItem(
        localId,
        {
          serverStatus: session.status,
          ...(session.validation_status
            ? { validationStatus: session.validation_status }
            : {}),
          ...(session.detected_format
            ? { detectedFormat: session.detected_format }
            : {}),
          ...(session.archive_import_id
            ? { archiveImportId: session.archive_import_id }
            : {}),
          ...(session.task_id ? { taskId: session.task_id } : {}),
        },
        requestGeneration,
      )

      stage = 'validation'
      const afterCompletionFailure = terminalSessionFailure(session)
      if (afterCompletionFailure) throw afterCompletionFailure
      if (session.validation_status !== 'valid') {
        throw new UploadStateError('文件仍在等待服务端校验，请重试', true)
      }
      if (
        session.detected_category !== undefined &&
        session.detected_category !== category
      ) {
        throw new UploadStateError(
          validationFailureMessage('mismatch', session.detected_format),
          false,
        )
      }

      if (category === 'archive') {
        if (!session.archive_import_id) {
          throw new UploadStateError('归档导入尚未就绪，请重试', true)
        }
        patchItem(
          localId,
          {
            status: 'archive',
            progress: 100,
            uploadedBytes: initial.file.size,
            archiveImportId: session.archive_import_id,
            canRetry: false,
          },
          requestGeneration,
        )
        return
      }

      if (!session.task_id) {
        throw new UploadStateError('任务创建尚未就绪，请重试', true)
      }
      patchItem(
        localId,
        {
          status: 'completed',
          progress: 100,
          uploadedBytes: initial.file.size,
          taskId: session.task_id,
          canRetry: false,
        },
        requestGeneration,
      )
    } catch (error) {
      const failure = classifyFailure(error, stage)
      const details = error instanceof ApiError ? intakeDetails(error) : {}
      let recovered: UploadSession | undefined
      const uploadId =
        queue.value.find((item) => item.localId === localId)?.uploadId ??
        details.upload_id
      if (
        uploadId &&
        error instanceof ApiError &&
        (error.code === 'input_category_mismatch' ||
          error.code === 'unsupported_input_format')
      ) {
        try {
          recovered = await api.getUpload(uploadId)
        } catch {
          recovered = undefined
        }
      }
      patchItem(
        localId,
        {
          status: 'failed',
          errorMessage:
            recovered?.validation_status === 'mismatch' ||
            recovered?.validation_status === 'unsupported'
              ? validationFailureMessage(
                  recovered.validation_status,
                  recovered.detected_format,
                )
              : failure.message,
          canRetry: failure.canRetry,
          ...(uploadId ? { uploadId } : {}),
          ...(recovered?.status ? { serverStatus: recovered.status } : {}),
          ...(recovered?.validation_status
            ? { validationStatus: recovered.validation_status }
            : {}),
          ...(recovered?.detected_format
            ? { detectedFormat: recovered.detected_format }
            : details.detected_format
              ? { detectedFormat: details.detected_format }
              : {}),
        },
        requestGeneration,
      )
    } finally {
      pauseRequests.delete(localId)
      if (current(requestGeneration)) activeId.value = null
    }
  }

  async function startAll(): Promise<void> {
    const requestGeneration = generation
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
      if (!current(requestGeneration)) return
      await uploadItem(localId)
    }
  }

  function dispose(): void {
    if (disposed) return
    disposed = true
    generation += 1
    pauseRequests.clear()
    activeId.value = null
  }

  if (getCurrentScope()) onScopeDispose(dispose)

  return {
    queue: readonly(queue),
    activeId: readonly(activeId),
    isUploading,
    readyCount,
    categoryLocked,
    archiveItems,
    addFiles,
    remove,
    clearCompleted,
    forgetDeletedArchive,
    pause,
    uploadItem,
    startAll,
    dispose,
  }
}
