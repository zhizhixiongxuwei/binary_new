import { describe, expect, it, vi } from 'vitest'

import { SseParser } from '@/utils/sse'

describe('SseParser', () => {
  it('parses CRLF chunks, comments, retry, and multiline data without rounding ids', () => {
    const onMessage = vi.fn()
    const onRetry = vi.fn()
    const parser = new SseParser({ onMessage, onRetry })
    const chunks = [
      ': heartbeat\r',
      '\nretry: 2500\r\nid: 184467440737095516',
      '15\r\nevent: task.progress\r\ndata: {"sequence":1,\r\n',
      'data: "type":"task.progress"}\r\n\r',
      '\n',
    ]

    for (const chunk of chunks) parser.push(chunk)

    expect(onRetry).toHaveBeenCalledWith(2500)
    expect(onMessage).toHaveBeenCalledWith({
      id: '18446744073709551615',
      event: 'task.progress',
      data: '{"sequence":1,\n"type":"task.progress"}',
    })
  })

  it('finishes a final unterminated event and ignores id-only heartbeats', () => {
    const onMessage = vi.fn()
    const parser = new SseParser({ onMessage })

    parser.push('id: 9\n\n: ping\n\nid: 10\ndata: ready')
    parser.finish()

    expect(onMessage).toHaveBeenCalledTimes(1)
    expect(onMessage).toHaveBeenCalledWith({
      id: '10',
      event: 'message',
      data: 'ready',
    })
  })
})
