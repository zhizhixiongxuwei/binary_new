import { describe, expect, it } from 'vitest'

import type { JsonValue, TaskEventMessage } from '@/api/types'
import { toTaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'

function message(options: {
  type: string
  sequence?: number
  stage?: string | null
  progress?: number | null
  severity?: string
  message?: string | null
  payload?: JsonValue
}): TaskEventMessage {
  return {
    id: String(options.sequence ?? 1),
    event: options.type,
    data: {
      sequence: options.sequence ?? 1,
      type: options.type,
      stage: options.stage ?? null,
      progress: options.progress ?? null,
      progress_indeterminate: false,
      severity: options.severity ?? 'info',
      message: options.message ?? null,
      payload: options.payload ?? null,
      created_at: '2026-08-04T08:00:00Z',
    },
  }
}

describe('taskExecutionLog', () => {
  it('maps task events through fixed labels without copying message or payload', () => {
    const entry = toTaskExecutionLogEntry(message({
      type: 'task.progress',
      stage: 'SCANNING',
      progress: 42.4,
      message: '<script>raw-tool-output</script>',
      payload: {
        status: 'SCANNING',
        stdout: 'raw-tool-output',
        arbitrary_secret: 'must-not-render',
      },
    }))

    expect(entry).toMatchObject({
      title: '任务进度已更新',
      stageLabel: '分析扫描',
      progressLabel: '42%',
    })
    expect(JSON.stringify(entry)).not.toContain('raw-tool-output')
    expect(JSON.stringify(entry)).not.toContain('must-not-render')
  })

  it.each([
    ['decompile.queued', '反编译请求已排队'],
    ['image_scan.queued', '镜像漏洞检测已排队'],
  ])('maps the safe manual queue event %s', (type, title) => {
    const entry = toTaskExecutionLogEntry(message({
      type,
      message: 'must-not-render',
      payload: { storage_key: 'must-not-render' },
    }))

    expect(entry?.title).toBe(title)
    expect(JSON.stringify(entry)).not.toContain('must-not-render')
  })

  it.each([
    ['decompile.progress', 'preparing', 'Ghidra 正在准备输入'],
    ['decompile.progress', 'starting', 'Ghidra JVM 正在启动'],
    ['decompile.progress', 'running', 'Ghidra 正在反编译'],
    ['decompile.progress', 'publishing', '正在保存反编译结果'],
    ['decompile.completed', 'completed', 'Ghidra 反编译已完成'],
    ['decompile.failed', 'failed', 'Ghidra 反编译失败'],
  ])('allowlists Ghidra %s/%s', (type, phase, title) => {
    const entry = toTaskExecutionLogEntry(message({
      type,
      payload: {
        analyzer: 'ghidra',
        phase,
        current: 12,
        total: 20,
        elapsed_seconds: 30,
        error_code: 'ghidra_output_limit',
        run_id: 'must-not-render',
        stdout: 'must-not-render',
      },
    }))

    expect(entry?.title).toBe(title)
    expect(JSON.stringify(entry)).not.toContain('run_id')
    expect(JSON.stringify(entry)).not.toContain('stdout')
    expect(JSON.stringify(entry)).not.toContain('must-not-render')
  })

  it('formats only allowlisted Ghidra counters and error codes', () => {
    const running = toTaskExecutionLogEntry(message({
      type: 'decompile.progress',
      payload: {
        analyzer: 'ghidra', phase: 'running',
        current: 12, total: 20, elapsed_seconds: 30,
      },
    }))
    const failed = toTaskExecutionLogEntry(message({
      type: 'decompile.failed',
      payload: {
        analyzer: 'ghidra', phase: 'failed',
        error_code: 'ghidra_output_limit',
      },
    }))

    expect(running?.detailLabel).toBe('函数 12 / 20 · 已运行 30 秒')
    expect(failed?.detailLabel).toBe('错误码 ghidra_output_limit')
  })

  it('uses the same safe phases for Java decompiler activity', () => {
    const running = toTaskExecutionLogEntry(message({
      type: 'decompile.progress',
      payload: {
        analyzer: 'vineflower', phase: 'running',
        current: 3, total: 8,
      },
    }))
    const completed = toTaskExecutionLogEntry(message({
      type: 'decompile.completed',
      payload: {
        analyzer: 'vineflower', phase: 'completed',
        current: 8, total: 8,
      },
    }))

    expect(running?.title).toBe('Java 反编译器 正在反编译')
    expect(running?.detailLabel).toBe('类 3 / 8')
    expect(completed?.title).toBe('Java 反编译器 反编译已完成')
  })

  it('labels bounded native output as partially completed', () => {
    const summary = toTaskExecutionLogEntry(message({
      type: 'decompile.completed',
      payload: {
        analyzer: 'ghidra', phase: 'completed', completeness: 'partial',
        current: 3000, total: 3000,
      },
    }))

    expect(summary?.title).toBe('Ghidra 反编译部分完成')
    expect(summary?.detailLabel).toContain('函数 3000 / 3000')
  })

  it.each([
    ['trivy.progress', 'verifying', '正在校验镜像归档'],
    ['trivy.progress', 'database_ready', '离线漏洞库已就绪'],
    ['trivy.progress', 'targets_ready', '镜像检测目标已就绪'],
    ['trivy.progress', 'scanning', 'Trivy 正在检测镜像'],
    ['trivy.target_completed', 'target_completed', '镜像目标检测完成'],
    ['trivy.target_failed', 'target_failed', '镜像目标检测失败'],
    ['trivy.progress', 'publishing', '正在保存漏洞结果'],
    ['trivy.completed', 'completed', 'Trivy 镜像检测已完成'],
    ['trivy.failed', 'failed', 'Trivy 镜像检测失败'],
  ])('allowlists Trivy %s/%s', (type, phase, title) => {
    const entry = toTaskExecutionLogEntry(message({
      type,
      payload: {
        analyzer: 'trivy',
        phase,
        current: 1,
        total: 2,
        elapsed_seconds: 8,
        finding_count: 7,
        database_version: '2',
        java_database_version: '1',
        error_code: 'trivy_target_limit',
        raw_report: 'must-not-render',
      },
    }))

    expect(entry?.title).toBe(title)
    expect(JSON.stringify(entry)).not.toContain('raw_report')
    expect(JSON.stringify(entry)).not.toContain('must-not-render')
  })

  it('formats only allowlisted Trivy scalar details', () => {
    const database = toTaskExecutionLogEntry(message({
      type: 'trivy.progress',
      payload: {
        analyzer: 'trivy', phase: 'database_ready',
        database_version: '2', java_database_version: '1',
      },
    }))
    const completed = toTaskExecutionLogEntry(message({
      type: 'trivy.target_completed',
      payload: {
        analyzer: 'trivy', phase: 'target_completed',
        current: 1, total: 2, finding_count: 7,
      },
    }))

    expect(database?.detailLabel).toBe('漏洞库 2 · Java 库 1')
    expect(completed?.detailLabel).toBe('目标 1 / 2 · 7 条发现')

    const failed = toTaskExecutionLogEntry(message({
      type: 'trivy.failed',
      payload: {
        analyzer: 'trivy', phase: 'failed',
        error_code: 'trivy_database_unavailable',
      },
    }))
    expect(failed?.detailLabel).toBe('错误码 trivy_database_unavailable')
  })

  it('fails closed for unknown event types, analyzer phases, and mismatched pairs', () => {
    expect(toTaskExecutionLogEntry(message({
      type: 'tool.stdout',
      payload: { phase: 'running', stdout: 'secret' },
    }))).toBeNull()
    expect(toTaskExecutionLogEntry(message({
      type: 'decompile.progress',
      payload: { analyzer: 'ghidra', phase: 'raw_output' },
    }))).toBeNull()
    expect(toTaskExecutionLogEntry(message({
      type: 'trivy.completed',
      payload: { analyzer: 'trivy', phase: 'scanning' },
    }))).toBeNull()
  })
})
