import { describe, expect, it } from 'vitest'

import { formatBytes, formatDateTime } from '@/utils/formatters'

describe('formatBytes', () => {
  it('formats binary units and handles missing values', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1024)).toBe('1 KB')
    expect(formatBytes()).toBe('—')
  })
})

describe('formatDateTime', () => {
  it('returns an em dash for empty timestamps', () => {
    expect(formatDateTime()).toBe('—')
  })
})
