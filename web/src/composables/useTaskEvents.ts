import {
  onScopeDispose,
  readonly,
  shallowRef,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from 'vue'

import { apiEndpoint } from '@/api/client'
import type {
  JsonValue,
  TaskEvent,
  TaskEventMessage,
} from '@/api/types'
import { SseParser } from '@/utils/sse'

export type TaskEventConnectionStatus =
  | 'disabled'
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'stopped'

interface UseTaskEventsOptions {
  taskId: MaybeRefOrGetter<string>
  enabled?: MaybeRefOrGetter<boolean>
  onEvent: (message: TaskEventMessage) => void
  fetcher?: typeof fetch
  baseRetryMs?: number
  maxRetryMs?: number
}

const DEFAULT_RETRY_MS = 1_000
const MAX_RETRY_MS = 30_000
const taskEventKeys = new Set([
  'sequence',
  'type',
  'stage',
  'progress',
  'progress_indeterminate',
  'severity',
  'message',
  'payload',
  'created_at',
])
const taskEventType = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/
const taskEventSeverities = new Set(['debug', 'info', 'warning', 'error'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isJsonValue(value: unknown): value is JsonValue {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return true
  }
  if (Array.isArray(value)) return value.every(isJsonValue)
  return isRecord(value) && Object.values(value).every(isJsonValue)
}

export function parseTaskEvent(value: string): TaskEvent | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    return null
  }
  if (!isRecord(parsed)) return null
  if (
    Object.keys(parsed).length !== taskEventKeys.size ||
    Object.keys(parsed).some((key) => !taskEventKeys.has(key))
  ) {
    return null
  }

  const {
    sequence,
    type,
    stage,
    progress,
    progress_indeterminate: progressIndeterminate,
    severity,
    message,
    payload,
    created_at: createdAt,
  } = parsed
  if (
    typeof sequence !== 'number' ||
    !Number.isSafeInteger(sequence) ||
    sequence < 1 ||
    typeof type !== 'string' ||
    !taskEventType.test(type) ||
    (stage !== null &&
      (typeof stage !== 'string' || stage.length > 32)) ||
    (progress !== null &&
      (typeof progress !== 'number' ||
        !Number.isFinite(progress) ||
        progress < 0 ||
        progress > 100)) ||
    typeof progressIndeterminate !== 'boolean' ||
    typeof severity !== 'string' ||
    !taskEventSeverities.has(severity) ||
    (message !== null &&
      (typeof message !== 'string' || message.length > 2_048)) ||
    !isJsonValue(payload) ||
    typeof createdAt !== 'string' ||
    !Number.isFinite(Date.parse(createdAt))
  ) {
    return null
  }

  return {
    sequence,
    type,
    stage,
    progress,
    progress_indeterminate: progressIndeterminate,
    severity,
    message,
    payload,
    created_at: createdAt,
  }
}

function clampedDelay(value: number, maximum: number): number {
  return Math.min(Math.max(value, 0), maximum)
}

export function useTaskEvents(options: UseTaskEventsOptions) {
  const status = shallowRef<TaskEventConnectionStatus>('disabled')
  const lastEventId = shallowRef('')
  const errorMessage = shallowRef('')
  const retryAttempt = shallowRef(0)
  const fetcher = options.fetcher ?? globalThis.fetch.bind(globalThis)
  const baseRetryMs = Math.max(options.baseRetryMs ?? DEFAULT_RETRY_MS, 1)
  const maxRetryMs = Math.max(options.maxRetryMs ?? MAX_RETRY_MS, baseRetryMs)

  let generation = 0
  let controller: AbortController | null = null
  let retryTimer: ReturnType<typeof globalThis.setTimeout> | null = null
  let serverRetryMs: number | null = null
  let disposed = false

  function clearRetryTimer(): void {
    if (retryTimer === null) return
    globalThis.clearTimeout(retryTimer)
    retryTimer = null
  }

  function abortConnection(): void {
    controller?.abort()
    controller = null
  }

  function resetConnection(state: TaskEventConnectionStatus): number {
    generation += 1
    clearRetryTimer()
    abortConnection()
    status.value = state
    errorMessage.value = ''
    retryAttempt.value = 0
    serverRetryMs = null
    return generation
  }

  function reconnectDelay(): number {
    if (serverRetryMs !== null) {
      return clampedDelay(serverRetryMs, maxRetryMs)
    }
    const exponential = baseRetryMs * 2 ** Math.min(retryAttempt.value, 10)
    return clampedDelay(exponential, maxRetryMs)
  }

  function scheduleReconnect(
    currentGeneration: number,
    taskId: string,
  ): void {
    if (
      disposed ||
      currentGeneration !== generation ||
      !toValue(options.enabled ?? true) ||
      taskId !== toValue(options.taskId)
    ) {
      return
    }

    status.value = 'reconnecting'
    const delay = reconnectDelay()
    retryAttempt.value += 1
    retryTimer = globalThis.setTimeout(() => {
      retryTimer = null
      if (currentGeneration === generation) {
        void connect(currentGeneration, taskId)
      }
    }, delay)
  }

  async function connect(
    currentGeneration: number,
    taskId: string,
  ): Promise<void> {
    if (currentGeneration !== generation || disposed) return

    status.value = retryAttempt.value > 0 ? 'reconnecting' : 'connecting'
    errorMessage.value = ''
    const nextController = new AbortController()
    controller = nextController
    const headers = new Headers({
      Accept: 'text/event-stream',
      'Cache-Control': 'no-cache',
    })
    if (lastEventId.value) headers.set('Last-Event-ID', lastEventId.value)

    try {
      const response = await fetcher(
        apiEndpoint(`/tasks/${encodeURIComponent(taskId)}/events`),
        {
          method: 'GET',
          credentials: 'include',
          headers,
          signal: nextController.signal,
        },
      )
      if (currentGeneration !== generation || nextController.signal.aborted) {
        return
      }
      if (!response.ok) {
        throw new Error(`事件流连接失败（HTTP ${response.status}）`)
      }
      if (!response.body) {
        throw new Error('事件流响应不可读取')
      }

      status.value = 'connected'
      const decoder = new TextDecoder()
      const parser = new SseParser({
        onRetry(milliseconds) {
          serverRetryMs = clampedDelay(milliseconds, maxRetryMs)
        },
        onMessage(message) {
          if (currentGeneration !== generation || disposed) return
          const event = parseTaskEvent(message.data)
          if (!event) return

          try {
            options.onEvent({
              id: message.id,
              event: message.event,
              data: event,
            })
          } catch {
            return
          }
          if (message.id) lastEventId.value = message.id
          retryAttempt.value = 0
          errorMessage.value = ''
        },
      })
      const reader = response.body.getReader()
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        if (currentGeneration !== generation || nextController.signal.aborted) {
          await reader.cancel()
          return
        }
        parser.push(decoder.decode(value, { stream: true }))
      }
      parser.push(decoder.decode())
      parser.finish()
      if (currentGeneration !== generation || nextController.signal.aborted) {
        return
      }
      errorMessage.value = '事件连接已断开，正在自动重连。'
    } catch (error) {
      if (
        currentGeneration !== generation ||
        nextController.signal.aborted ||
        disposed
      ) {
        return
      }
      errorMessage.value =
        error instanceof Error ? error.message : '事件流连接失败'
    } finally {
      if (controller === nextController) controller = null
    }

    scheduleReconnect(currentGeneration, taskId)
  }

  function start(taskId: string): void {
    const currentGeneration = resetConnection('connecting')
    lastEventId.value = ''
    void connect(currentGeneration, taskId)
  }

  function stop(): void {
    resetConnection(disposed ? 'stopped' : 'disabled')
    lastEventId.value = ''
  }

  watch(
    () => [toValue(options.taskId), toValue(options.enabled ?? true)] as const,
    ([taskId, enabled]) => {
      if (!enabled || !taskId) {
        stop()
        return
      }
      start(taskId)
    },
    { immediate: true },
  )

  onScopeDispose(() => {
    disposed = true
    stop()
  })

  return {
    status: readonly(status),
    lastEventId: readonly(lastEventId),
    errorMessage: readonly(errorMessage),
    retryAttempt: readonly(retryAttempt),
    stop,
  }
}
