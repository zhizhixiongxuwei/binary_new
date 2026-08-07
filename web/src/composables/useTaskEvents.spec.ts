import { flushPromises } from '@vue/test-utils'
import {
  effectScope,
  nextTick,
  shallowRef,
  type EffectScope,
} from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { TaskEventMessage } from '@/api/types'
import {
  parseTaskEvent,
  useTaskEvents,
} from '@/composables/useTaskEvents'

function eventData(type = 'task.progress'): string {
  return JSON.stringify({
    sequence: 1,
    type,
    stage: 'SCANNING',
    progress: 42,
    progress_indeterminate: true,
    severity: 'info',
    message: 'progress',
    payload: { status: 'SCANNING' },
    created_at: '2026-07-30T08:00:00Z',
  })
}

function closedEventResponse(
  text: string,
): Response {
  const bytes = new TextEncoder().encode(text)
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(bytes)
        controller.close()
      },
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'text/event-stream' },
    },
  )
}

function openEventResponse(
  text: string,
  signal?: AbortSignal,
): Response {
  const bytes = new TextEncoder().encode(text)
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        if (text) controller.enqueue(bytes)
        signal?.addEventListener('abort', () => {
          controller.error(new DOMException('aborted', 'AbortError'))
        })
      },
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'text/event-stream' },
    },
  )
}

function inScope<T>(factory: () => T): { scope: EffectScope; value: T } {
  const scope = effectScope()
  const value = scope.run(factory)
  if (value === undefined) throw new Error('effect scope did not return a value')
  return { scope, value }
}

describe('useTaskEvents', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('validates the typed backend event payload', () => {
    expect(parseTaskEvent(eventData())).toMatchObject({
      sequence: 1,
      type: 'task.progress',
      stage: 'SCANNING',
      progress: 42,
      progress_indeterminate: true,
    })
    expect(parseTaskEvent('not-json')).toBeNull()
    expect(parseTaskEvent('{"sequence":"1"}')).toBeNull()
    expect(
      parseTaskEvent(
        JSON.stringify({
          sequence: 2,
          type: 'task.created',
          stage: null,
          progress: null,
          progress_indeterminate: false,
          severity: 'info',
          message: null,
          payload: null,
          created_at: '2026-07-30T08:00:00Z',
        }),
      ),
    ).toEqual({
      sequence: 2,
      type: 'task.created',
      stage: null,
      progress: null,
      progress_indeterminate: false,
      severity: 'info',
      message: null,
      payload: null,
      created_at: '2026-07-30T08:00:00Z',
    })

    for (const invalid of [
      { sequence: 0 },
      { sequence: 1.5 },
      { type: 'task progress' },
      { stage: 'x'.repeat(33) },
      { progress: -0.1 },
      { progress: 100.1 },
      { severity: 'critical' },
      { message: 'x'.repeat(2_049) },
      { created_at: 'not-a-timestamp' },
      { unexpected: true },
    ]) {
      expect(
        parseTaskEvent(JSON.stringify({
          ...JSON.parse(eventData()) as Record<string, unknown>,
          ...invalid,
        })),
      ).toBeNull()
    }
  })

  it('uses server retry and sends the exact SSE id on reconnect', async () => {
    vi.useFakeTimers()
    const id = '18446744073709551615'
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        closedEventResponse(
          `retry: 25\nid: ${id}\nevent: task.progress\ndata: ${eventData()}\n\n`,
        ),
      )
      .mockImplementationOnce(async (_input, init) =>
        openEventResponse('', init?.signal ?? undefined),
      )
    const received: TaskEventMessage[] = []
    const { scope, value: events } = inScope(() =>
      useTaskEvents({
        taskId: 'task/id',
        onEvent: (event) => received.push(event),
        fetcher,
        baseRetryMs: 100,
        maxRetryMs: 1_000,
      }),
    )

    await flushPromises()
    expect(received[0]?.id).toBe(id)
    expect(events.lastEventId.value).toBe(id)
    expect(fetcher).toHaveBeenCalledTimes(1)

    await vi.advanceTimersByTimeAsync(24)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    await flushPromises()

    expect(fetcher).toHaveBeenCalledTimes(2)
    const [, init] = fetcher.mock.calls[1]!
    expect(new Headers(init?.headers).get('Last-Event-ID')).toBe(id)
    expect(init?.credentials).toBe('include')
    expect(String(fetcher.mock.calls[0]?.[0])).toContain(
      '/tasks/task%2Fid/events',
    )

    scope.stop()
  })

  it('backs off exponentially when no server retry is provided', async () => {
    vi.useFakeTimers()
    const fetcher = vi
      .fn<typeof fetch>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockRejectedValueOnce(new Error('still offline'))
      .mockImplementationOnce(async (_input, init) =>
        openEventResponse('', init?.signal ?? undefined),
      )
    const { scope } = inScope(() =>
      useTaskEvents({
        taskId: 'task-a',
        onEvent: vi.fn(),
        fetcher,
        baseRetryMs: 10,
        maxRetryMs: 100,
      }),
    )

    await flushPromises()
    expect(fetcher).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(10)
    await flushPromises()
    expect(fetcher).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(19)
    expect(fetcher).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(1)
    await flushPromises()
    expect(fetcher).toHaveBeenCalledTimes(3)

    scope.stop()
  })

  it('aborts on task changes and ignores stale or disposed streams', async () => {
    let resolveFirst: ((response: Response) => void) | undefined
    const firstResponse = new Promise<Response>((resolve) => {
      resolveFirst = resolve
    })
    let activeSignal: AbortSignal | undefined
    const fetcher = vi
      .fn<typeof fetch>()
      .mockReturnValueOnce(firstResponse)
      .mockImplementationOnce(async (_input, init) => {
        activeSignal = init?.signal ?? undefined
        return openEventResponse(
          `id: 2\nevent: task.updated\ndata: ${eventData('task.updated')}\n\n`,
          activeSignal,
        )
      })
    const taskId = shallowRef('task-a')
    const received: TaskEventMessage[] = []
    const { scope } = inScope(() =>
      useTaskEvents({
        taskId,
        onEvent: (event) => received.push(event),
        fetcher,
      }),
    )

    taskId.value = 'task-b'
    await nextTick()
    await flushPromises()
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(received.map((event) => event.id)).toEqual(['2'])

    resolveFirst?.(
      closedEventResponse(
        `id: 1\nevent: task.updated\ndata: ${eventData('task.updated')}\n\n`,
      ),
    )
    await flushPromises()
    expect(received.map((event) => event.id)).toEqual(['2'])

    scope.stop()
    expect(activeSignal?.aborted).toBe(true)
    await flushPromises()
    expect(received.map((event) => event.id)).toEqual(['2'])
  })

  it('does not open a transport when disabled, including demo mode callers', async () => {
    const fetcher = vi.fn<typeof fetch>()
    const { scope, value: events } = inScope(() =>
      useTaskEvents({
        taskId: 'demo-task',
        enabled: false,
        onEvent: vi.fn(),
        fetcher,
      }),
    )

    await flushPromises()
    expect(fetcher).not.toHaveBeenCalled()
    expect(events.status.value).toBe('disabled')
    scope.stop()
  })
})
