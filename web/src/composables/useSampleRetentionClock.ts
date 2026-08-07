import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { parseSampleExpiry } from '@/utils/sampleRetention'

const MAX_TIMER_DELAY_MS = 2_147_483_647

interface UseSampleRetentionClockOptions {
  now?: MaybeRefOrGetter<Date | undefined>
}

export function useSampleRetentionClock(
  sampleExpiries: MaybeRefOrGetter<
    readonly (string | null | undefined)[]
  >,
  options: UseSampleRetentionClockOptions = {},
) {
  const now = shallowRef(new Date())
  let expiryTimer: ReturnType<typeof globalThis.setTimeout> | null = null

  function clearExpiryTimer(): void {
    if (expiryTimer === null) return
    globalThis.clearTimeout(expiryTimer)
    expiryTimer = null
  }

  function updateClock(): void {
    clearExpiryTimer()

    const suppliedNow = options.now ? toValue(options.now) : undefined
    if (suppliedNow) {
      now.value = new Date(suppliedNow.getTime())
      return
    }

    const current = new Date()
    now.value = current
    const currentTimestamp = current.getTime()
    const nextExpiry = toValue(sampleExpiries)
      .map((value) => parseSampleExpiry(value ?? undefined)?.getTime())
      .filter(
        (timestamp): timestamp is number =>
          timestamp !== undefined && timestamp > currentTimestamp,
      )
      .reduce<number | null>(
        (nearest, timestamp) =>
          nearest === null || timestamp < nearest ? timestamp : nearest,
        null,
      )

    if (nextExpiry === null) return
    const delay = Math.min(
      Math.max(nextExpiry - currentTimestamp, 1),
      MAX_TIMER_DELAY_MS,
    )
    expiryTimer = globalThis.setTimeout(updateClock, delay)
  }

  watch(
    [
      () => toValue(sampleExpiries),
      () => (options.now ? toValue(options.now) : undefined),
    ],
    updateClock,
    { immediate: true },
  )

  onScopeDispose(clearExpiryTimer)

  return {
    now: readonly(now),
  }
}
