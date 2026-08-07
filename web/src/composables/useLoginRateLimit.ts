import { computed, onUnmounted, readonly, shallowRef } from 'vue'

const MAX_RETRY_AFTER_SECONDS = 86_400

export function normalizeRetryAfterSeconds(value: unknown): number {
  return typeof value === 'number' &&
    Number.isSafeInteger(value) &&
    value >= 1 &&
    value <= MAX_RETRY_AFTER_SECONDS
    ? value
    : 1
}

export function useLoginRateLimit() {
  const remainingSeconds = shallowRef(0)
  let timer: ReturnType<typeof globalThis.setInterval> | undefined

  const isRateLimited = computed(() => remainingSeconds.value > 0)

  function stopTimer(): void {
    if (timer === undefined) return
    globalThis.clearInterval(timer)
    timer = undefined
  }

  function start(retryAfterSeconds?: number): void {
    stopTimer()
    remainingSeconds.value = normalizeRetryAfterSeconds(retryAfterSeconds)
    timer = globalThis.setInterval(() => {
      remainingSeconds.value = Math.max(0, remainingSeconds.value - 1)
      if (remainingSeconds.value === 0) stopTimer()
    }, 1_000)
  }

  function clear(): void {
    stopTimer()
    remainingSeconds.value = 0
  }

  onUnmounted(clear)

  return {
    remainingSeconds: readonly(remainingSeconds),
    isRateLimited,
    start,
    clear,
  }
}
