import { describe, expect, it } from 'vitest'

import {
  resolveSampleRetention,
} from '@/utils/sampleRetention'

const NOW = new Date('2026-07-31T00:00:00.000Z')

describe('sample retention', () => {
  it('treats the persisted deletion marker as authoritative', () => {
    const retention = resolveSampleRetention({
      sampleExpiresAt: '2099-08-29T00:00:00.000Z',
      sampleDeletedAt: 'server-cleanup-marker',
      now: NOW,
    })

    expect(retention).toMatchObject({
      status: 'deleted',
      canReuseSample: false,
      statusLabel: '样本已清理',
    })
    expect(retention.actionReason).toContain('无法重新检测或发起新的反编译')
  })

  it('expires at the exact server timestamp without inferring cleanup', () => {
    const retention = resolveSampleRetention({
      sampleExpiresAt: NOW.toISOString(),
      sampleDeletedAt: null,
      now: NOW,
    })

    expect(retention).toMatchObject({
      status: 'expired',
      canReuseSample: false,
      statusLabel: '样本已到期',
    })
  })

  it('fails closed when the server expiry cannot be interpreted', () => {
    const retention = resolveSampleRetention({
      sampleExpiresAt: 'not-a-timestamp',
      sampleDeletedAt: null,
      now: NOW,
    })

    expect(retention).toMatchObject({
      status: 'unavailable',
      canReuseSample: false,
    })
    expect(retention.actionReason).toContain('状态不可确认')
  })
})
