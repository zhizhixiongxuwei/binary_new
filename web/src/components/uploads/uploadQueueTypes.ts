import type {
  InputCategory,
  UploadSession,
  UploadValidationStatus,
} from '@/api/types'

export type UploadQueueDisplayStatus =
  | 'ready'
  | 'uploading'
  | 'paused'
  | 'completed'
  | 'archive'
  | 'failed'

export interface UploadQueueDisplayItem {
  localId: string
  file: File
  category?: InputCategory
  status: UploadQueueDisplayStatus
  progress: number
  uploadedBytes: number
  errorMessage: string
  uploadId?: string
  partSize?: number
  taskId?: string
  archiveImportId?: string
  detectedFormat?: string
  validationStatus?: UploadValidationStatus
  canRetry: boolean
  serverStatus?: UploadSession['status']
  removing?: boolean
}
