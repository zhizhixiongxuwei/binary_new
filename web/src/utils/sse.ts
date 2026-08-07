export interface SseMessage {
  id: string
  event: string
  data: string
}

export interface SseParserHandlers {
  onMessage: (message: SseMessage) => void
  onRetry?: (milliseconds: number) => void
}

/**
 * Incremental parser for the event-stream wire format. It accepts arbitrary
 * text chunks, including chunks split between CR and LF.
 */
export class SseParser {
  private buffer = ''
  private dataLines: string[] = []
  private eventType = ''
  private eventId: string | undefined

  constructor(private readonly handlers: SseParserHandlers) {}

  push(chunk: string): void {
    this.buffer += chunk
    this.drainLines(false)
  }

  finish(): void {
    this.drainLines(true)
    if (this.buffer) {
      this.processLine(this.buffer)
      this.buffer = ''
    }
    this.dispatch()
  }

  private drainLines(final: boolean): void {
    while (this.buffer) {
      let delimiterIndex = -1
      for (let index = 0; index < this.buffer.length; index += 1) {
        const character = this.buffer[index]
        if (character === '\r' || character === '\n') {
          delimiterIndex = index
          break
        }
      }
      if (delimiterIndex === -1) return

      const delimiter = this.buffer[delimiterIndex]
      if (
        delimiter === '\r' &&
        delimiterIndex === this.buffer.length - 1 &&
        !final
      ) {
        return
      }

      const delimiterLength =
        delimiter === '\r' && this.buffer[delimiterIndex + 1] === '\n'
          ? 2
          : 1
      const line = this.buffer.slice(0, delimiterIndex)
      this.buffer = this.buffer.slice(delimiterIndex + delimiterLength)
      this.processLine(line)
    }
  }

  private processLine(line: string): void {
    if (!line) {
      this.dispatch()
      return
    }
    if (line.startsWith(':')) return

    const separator = line.indexOf(':')
    const field = separator === -1 ? line : line.slice(0, separator)
    let value = separator === -1 ? '' : line.slice(separator + 1)
    if (value.startsWith(' ')) value = value.slice(1)

    if (field === 'data') {
      this.dataLines.push(value)
      return
    }
    if (field === 'event') {
      this.eventType = value
      return
    }
    if (field === 'id') {
      if (!value.includes('\0') && (value === '' || /^\d+$/.test(value))) {
        this.eventId = value
      }
      return
    }
    if (field === 'retry' && /^\d+$/.test(value)) {
      const milliseconds = Number(value)
      if (Number.isSafeInteger(milliseconds)) {
        this.handlers.onRetry?.(milliseconds)
      }
    }
  }

  private dispatch(): void {
    if (this.dataLines.length > 0) {
      this.handlers.onMessage({
        id: this.eventId ?? '',
        event: this.eventType || 'message',
        data: this.dataLines.join('\n'),
      })
    }
    this.dataLines = []
    this.eventType = ''
    this.eventId = undefined
  }
}
