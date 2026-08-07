import { describe, expect, it } from 'vitest'

import type { TaskStatus } from '@/api/types'
import type { TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'
import {
  deriveTaskStageProgress,
  type TaskStageSource,
} from '@/utils/taskStages'

function source(
  inputType: string,
  status: TaskStatus = 'SUCCEEDED',
): TaskStageSource {
  return {
    input_type: inputType,
    status,
    current_stage: '',
    progress: 100,
    progress_indeterminate: false,
  }
}

function entry(
  sequence: number,
  workflow: TaskExecutionLogEntry['workflow'],
  phase: string,
  current: number | null = null,
  total: number | null = null,
): TaskExecutionLogEntry {
  return {
    key: String(sequence),
    sequence,
    title: phase,
    detailLabel: null,
    stageLabel: null,
    progressLabel: null,
    severityLabel: '信息',
    tone: 'info',
    createdAt: `2026-08-04T08:00:${String(sequence).padStart(2, '0')}Z`,
    workflow,
    phase,
    current,
    total,
  }
}

describe('deriveTaskStageProgress', () => {
  it('classifies container archives as the Trivy workflow before logs arrive', () => {
    const result = deriveTaskStageProgress(source('oci-tar'))

    expect(result.workflow).toBe('image-scan')
    expect(result.workflowLabel).toBe('镜像漏洞扫描')
    expect(result.stages.map((stage) => stage.label)).toEqual([
      '等待调度', '校验镜像', '加载漏洞库', '准备目标', '漏洞扫描', '保存结果', '完成',
    ])
    expect(result.summary).toContain('尚未收到 Trivy 执行日志')
  })

  it('classifies native and JVM inputs as the decompile workflow', () => {
    for (const format of ['pe32+', 'elf64', 'java-class', 'jar', 'pyc']) {
      expect(deriveTaskStageProgress(source(format)).workflow).toBe('decompile')
    }
    expect(deriveTaskStageProgress(source('pe32+')).workflowLabel).toBe('类 C 反编译')
    expect(deriveTaskStageProgress(source('jar')).workflowLabel).toBe('Java 反编译')
    expect(deriveTaskStageProgress(source('pyc')).workflowLabel).toBe('Python 字节码分析')
  })

  it('keeps the workflow tied to a recognized root input type', () => {
    const result = deriveTaskStageProgress(source('oci-tar'), [
      entry(1, 'image-scan', 'completed'),
      entry(2, 'decompile', 'queued'),
      entry(3, 'decompile', 'preparing'),
    ])

    expect(result.workflow).toBe('image-scan')
    expect(result.summary).toBe('镜像漏洞扫描已完成')
  })

  it('uses analyzer logs to classify an unrecognized root input type', () => {
    const result = deriveTaskStageProgress(source('archive'), [
      entry(1, 'image-scan', 'queued'),
      entry(2, 'image-scan', 'verifying'),
    ])

    expect(result.workflow).toBe('image-scan')
    expect(result.summary).toBe('校验镜像阶段进行中')
  })

  it('derives Ghidra running progress from the safe function counters', () => {
    const result = deriveTaskStageProgress(source('pe32+'), [
      entry(1, 'decompile', 'queued'),
      entry(2, 'decompile', 'preparing'),
      entry(3, 'decompile', 'starting'),
      entry(4, 'decompile', 'running', 10, 20),
    ])

    expect(result.progress).toBe(55)
    expect(result.indeterminate).toBe(false)
    expect(result.stages.find((stage) => stage.id === 'running')?.state).toBe('current')
  })

  it('uses indeterminate progress when an active analyzer omits a measurable total', () => {
    const result = deriveTaskStageProgress(source('pe32+'), [
      entry(1, 'decompile', 'running'),
    ])

    expect(result.indeterminate).toBe(true)
  })

  it('derives Trivy target progress and terminal completion from events', () => {
    const scanning = deriveTaskStageProgress(source('docker-tar'), [
      entry(1, 'image-scan', 'queued'),
      entry(2, 'image-scan', 'verifying'),
      entry(3, 'image-scan', 'database_ready'),
      entry(4, 'image-scan', 'targets_ready'),
      entry(5, 'image-scan', 'scanning', 1, 2),
    ])
    expect(scanning.progress).toBe(65)
    expect(scanning.stages.find((stage) => stage.id === 'scanning')?.state).toBe('current')

    const completed = deriveTaskStageProgress(source('docker-tar'), [
      ...[1, 2, 3, 4, 5].map((sequence) => entry(sequence, 'image-scan', 'scanning', 1, 2)),
      entry(6, 'image-scan', 'completed', 2, 2),
    ])
    expect(completed.progress).toBe(100)
    expect(completed.stages.every((stage) => stage.state === 'completed')).toBe(true)
  })

  it('marks the last reached stage failed without claiming later stages ran', () => {
    const result = deriveTaskStageProgress(source('pe32+', 'FAILED'), [
      entry(1, 'decompile', 'queued'),
      entry(2, 'decompile', 'starting'),
      entry(3, 'decompile', 'failed'),
    ])

    expect(result.stages.find((stage) => stage.id === 'starting')?.state).toBe('failed')
    expect(result.stages.find((stage) => stage.id === 'running')?.state).toBe('pending')
    expect(result.summary).toBe('启动引擎阶段失败')
  })

  it('starts a new phase model after the latest queued retry event', () => {
    const result = deriveTaskStageProgress(source('pe32+'), [
      entry(1, 'decompile', 'completed'),
      entry(2, 'decompile', 'queued'),
    ])

    expect(result.progress).toBe(0)
    expect(result.stages[0]?.state).toBe('current')
    expect(result.stages.slice(1).every((stage) => stage.state === 'pending')).toBe(true)
  })
})
