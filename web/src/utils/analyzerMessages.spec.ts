import { describe, expect, it } from 'vitest'

import {
  analyzerDiagnosticMessage,
  cFindingMessage,
  javaFindingMessage,
} from '@/utils/analyzerMessages'

describe('analyzerMessages', () => {
  it('translates known C rule ids and keeps the original detail', () => {
    expect(cFindingMessage('cwe-242-gets', 'use of gets is unsafe')).toBe(
      '使用 gets 读取输入，存在缓冲区溢出风险 — use of gets is unsafe',
    )
    expect(cFindingMessage('cwe-787-oob-write', 'oob write')).toBe(
      '越界写入风险 — oob write',
    )
  })

  it('translates known Java rule ids', () => {
    expect(
      javaFindingMessage('java-sql-injection', 'SQL built from input'),
    ).toBe('SQL 注入风险 — SQL built from input')
    expect(javaFindingMessage('java-xxe-enabled', 'XXE enabled')).toBe(
      '启用 XML 外部实体（XXE）风险 — XXE enabled',
    )
  })

  it('translates diagnostic codes', () => {
    expect(
      analyzerDiagnosticMessage('syntax_error', "expected ';'"),
    ).toBe("源码语法错误 — expected ';'")
    expect(analyzerDiagnosticMessage('analysis_timeout', 'took too long')).toBe(
      '分析超过时间限制 — took too long',
    )
  })

  it('falls back to the original message for unknown codes', () => {
    const detail = 'some future rule detail'
    expect(cFindingMessage('cwe-9999-future', detail)).toBe(detail)
    expect(javaFindingMessage('java-unknown', detail)).toBe(detail)
    expect(analyzerDiagnosticMessage('unknown_code', detail)).toBe(detail)
  })

  it('omits empty or duplicate detail', () => {
    expect(cFindingMessage('cwe-369-zero-divisor', '')).toBe('除零风险')
    expect(javaFindingMessage('java-weak-cipher', '  使用弱加密算法  ')).toBe(
      '使用弱加密算法',
    )
  })
})
