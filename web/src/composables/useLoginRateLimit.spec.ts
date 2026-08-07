import { mount } from '@vue/test-utils'
import { defineComponent, h, nextTick, type Ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  normalizeRetryAfterSeconds,
  useLoginRateLimit,
} from '@/composables/useLoginRateLimit'

interface RateLimitHarness {
  remainingSeconds: Readonly<Ref<number>>
  start: (seconds?: number) => void
}

function mountHarness(): {
  wrapper: ReturnType<typeof mount>
  rateLimit: RateLimitHarness
} {
  let rateLimit: RateLimitHarness | undefined
  const wrapper = mount(
    defineComponent({
      setup() {
        rateLimit = useLoginRateLimit()
        return () => h('span', String(rateLimit?.remainingSeconds.value ?? 0))
      },
    }),
  )
  if (!rateLimit) throw new Error('rate-limit harness did not initialize')
  return { wrapper, rateLimit }
}

describe('useLoginRateLimit', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('falls back to one second for missing or invalid server guidance', () => {
    expect(normalizeRetryAfterSeconds(undefined)).toBe(1)
    expect(normalizeRetryAfterSeconds(0)).toBe(1)
    expect(normalizeRetryAfterSeconds(86_401)).toBe(1)
    expect(normalizeRetryAfterSeconds(1.5)).toBe(1)
    expect(normalizeRetryAfterSeconds(86_400)).toBe(86_400)
  })

  it('replaces repeated cooldowns and releases the timer on unmount', async () => {
    vi.useFakeTimers()
    const { wrapper, rateLimit } = mountHarness()

    rateLimit.start(3)
    expect(rateLimit.remainingSeconds.value).toBe(3)
    expect(vi.getTimerCount()).toBe(1)

    await vi.advanceTimersByTimeAsync(1_000)
    await nextTick()
    expect(rateLimit.remainingSeconds.value).toBe(2)

    rateLimit.start(5)
    expect(rateLimit.remainingSeconds.value).toBe(5)
    expect(vi.getTimerCount()).toBe(1)

    wrapper.unmount()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('automatically restores submission eligibility when countdown ends', async () => {
    vi.useFakeTimers()
    const { wrapper, rateLimit } = mountHarness()

    rateLimit.start()
    expect(rateLimit.remainingSeconds.value).toBe(1)
    await vi.advanceTimersByTimeAsync(1_000)
    await nextTick()

    expect(rateLimit.remainingSeconds.value).toBe(0)
    expect(vi.getTimerCount()).toBe(0)
    wrapper.unmount()
  })
})
