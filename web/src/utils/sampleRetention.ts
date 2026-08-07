export type SampleRetentionStatus =
  | 'available'
  | 'expired'
  | 'deleted'
  | 'unavailable'

export interface SampleRetentionSnapshot {
  status: SampleRetentionStatus
  canReuseSample: boolean
  statusLabel: string
  actionReason: string
}

interface ResolveSampleRetentionOptions {
  sampleExpiresAt?: string | undefined
  sampleDeletedAt?: string | null | undefined
  now?: Date | undefined
}

const AVAILABLE: SampleRetentionSnapshot = {
  status: 'available',
  canReuseSample: true,
  statusLabel: '样本可用',
  actionReason: '样本仍在保留期内。',
}

const EXPIRED: SampleRetentionSnapshot = {
  status: 'expired',
  canReuseSample: false,
  statusLabel: '样本已到期',
  actionReason: '样本保留期已到，无法重新检测或发起新的反编译。',
}

const DELETED: SampleRetentionSnapshot = {
  status: 'deleted',
  canReuseSample: false,
  statusLabel: '样本已清理',
  actionReason: '任务原始样本已清理，无法重新检测或发起新的反编译。',
}

const UNAVAILABLE: SampleRetentionSnapshot = {
  status: 'unavailable',
  canReuseSample: false,
  statusLabel: '样本状态待确认',
  actionReason: '样本保留状态不可确认，请刷新任务后重试。',
}

export function parseSampleExpiry(value: string | undefined): Date | null {
  if (!value) return null
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) ? new Date(timestamp) : null
}

export function isSampleDeleted(value?: string | null): boolean {
  return value !== null && value !== undefined
}

export function resolveSampleRetention(
  options: ResolveSampleRetentionOptions,
): SampleRetentionSnapshot {
  if (isSampleDeleted(options.sampleDeletedAt)) return DELETED

  const expiry = parseSampleExpiry(options.sampleExpiresAt)
  if (!expiry) return UNAVAILABLE

  const now = options.now ?? new Date()
  if (
    !Number.isFinite(now.getTime()) ||
    expiry.getTime() <= now.getTime()
  ) {
    return EXPIRED
  }

  return AVAILABLE
}

export function isSampleExpired(
  value: string | undefined,
  now = new Date(),
): boolean {
  const expiry = parseSampleExpiry(value)
  return expiry !== null && expiry.getTime() <= now.getTime()
}

export function extendSampleExpiry(
  value: string | undefined,
  days = 30,
): string | null {
  const expiry = parseSampleExpiry(value)
  if (!expiry) return null
  expiry.setUTCDate(expiry.getUTCDate() + days)
  return expiry.toISOString()
}
