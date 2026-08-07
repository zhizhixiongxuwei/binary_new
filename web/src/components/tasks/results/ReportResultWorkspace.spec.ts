import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { TaskReport } from '@/api/types'
import ReportResultWorkspace from '@/components/tasks/results/ReportResultWorkspace.vue'

function report(
  format: 'json' | 'html',
  overrides: Partial<TaskReport> = {},
): TaskReport {
  return {
    id: `report-${format}`,
    task_id: 'task-report-ui',
    format,
    schema_version: '1.1.0',
    status: 'complete',
    sha256: format === 'json' ? 'a'.repeat(64) : 'b'.repeat(64),
    size_bytes: format === 'json' ? 1_024 : 2_048,
    error_code: null,
    error_message: null,
    created_at: '2026-07-30T01:00:00Z',
    completed_at: '2026-07-30T01:00:01Z',
    ...overrides,
  }
}

function mountWorkspace(
  options: {
    reports?: readonly TaskReport[]
    canGenerate?: boolean
    generationHint?: string
    generatingFormats?: readonly ('json' | 'html')[]
    downloadingReportId?: string
    actionError?: string
    sampleRelation?: 'retained' | 'expired' | 'deleted' | 'unknown'
    exportingSources?: boolean
    hasDecompileSources?: boolean
  } = {},
) {
  return mount(ReportResultWorkspace, {
    props: {
      taskId: 'task-report-ui',
      reports: options.reports ?? [],
      canGenerate: options.canGenerate ?? true,
      generationHint:
        options.generationHint ??
        (options.canGenerate === false
          ? '当前角色只能查看和下载已有报告，不能生成新报告。'
          : 'JSON 与 HTML 使用独立生成状态。'),
      generatingFormats: options.generatingFormats ?? [],
      downloadingReportKey: options.downloadingReportId
        ? `${options.downloadingReportId}:identity`
        : '',
      sampleRelation: options.sampleRelation ?? 'retained',
      actionError: options.actionError ?? '',
      exportingSources: options.exportingSources ?? false,
      hasDecompileSources: options.hasDecompileSources ?? true,
    },
  })
}

describe('ReportResultWorkspace', () => {
  it('renders two explicit formats and emits generation commands', async () => {
    const wrapper = mountWorkspace()
    const reportRows = wrapper.findAll('.report-row')

    expect(reportRows).toHaveLength(2)
    expect(reportRows[0]?.text()).toContain('JSON 报告')
    expect(reportRows[0]?.text()).toContain('未生成')
    expect(reportRows[1]?.text()).toContain('HTML 报告')
    expect(wrapper.text()).toContain('0/2 已完成')

    await wrapper.get('button[aria-label="生成 JSON 报告"]').trigger('click')
    await wrapper.get('button[aria-label="生成 HTML 报告"]').trigger('click')

    expect(wrapper.emitted('generate')).toEqual([['json'], ['html']])
  })

  it('shows status, schema, size, hash, completion time, and failure reason as text', () => {
    const maliciousReason =
      '<img src=x onerror="globalThis.compromised=true">模板渲染失败'
    const wrapper = mountWorkspace({
      reports: [
        report('json'),
        report('html', {
          status: 'failed',
          sha256: null,
          size_bytes: null,
          completed_at: null,
          error_code: 'REPORT_TEMPLATE_FAILED',
          error_message: maliciousReason,
        }),
      ],
    })

    expect(wrapper.text()).toContain('1/2 已完成')
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain(
      '已完成',
    )
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain('1.1.0')
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain('1 KB')
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain(
      'a'.repeat(64),
    )
    const failed = wrapper.get('[aria-label="HTML 报告"]')
    expect(failed.text()).toContain('生成失败')
    expect(failed.text()).toContain('REPORT_TEMPLATE_FAILED')
    expect(failed.text()).toContain(maliciousReason)
    expect(failed.find('img').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('v-html')
  })

  it('only enables download for completed reports and retry for failed reports', async () => {
    const json = report('json')
    const failedHtml = report('html', {
      status: 'failed',
      sha256: null,
      size_bytes: null,
      completed_at: null,
      error_code: 'REPORT_FAILED',
      error_message: '生成器失败',
    })
    const wrapper = mountWorkspace({
      reports: [json, failedHtml],
    })

    const download = wrapper.get('button[aria-label="下载 JSON 报告"]')
    const retry = wrapper.get('button[aria-label="重试生成 HTML 报告"]')
    expect(download.attributes('disabled')).toBeUndefined()
    expect(retry.attributes('disabled')).toBeUndefined()

    await download.trigger('click')
    await retry.trigger('click')
    expect(wrapper.emitted('download')).toEqual([[json, 'identity']])
    expect(wrapper.emitted('generate')).toEqual([['html']])
  })

  it('offers original and gzip variants only for JSON and shows sample association', async () => {
    const json = report('json')
    const html = report('html')
    const wrapper = mountWorkspace({
      reports: [json, html],
      sampleRelation: 'expired',
    })

    const jsonRow = wrapper.get('[aria-label="JSON 报告"]')
    expect(jsonRow.text()).toContain('样本已到期')
    const selector = jsonRow.get('select[aria-label="JSON 下载格式"]')
    expect(selector.findAll('option').map((option) => option.text())).toEqual([
      '原始 .json',
      '压缩 .json.gz',
    ])
    await selector.setValue('gzip')
    await jsonRow.get('button[aria-label="下载 压缩 JSON 报告"]').trigger('click')

    expect(wrapper.emitted('download')).toEqual([[json, 'gzip']])
    expect(
      wrapper
        .get('[aria-label="HTML 报告"]')
        .find('select[aria-label="JSON 下载格式"]')
        .exists(),
    ).toBe(false)
  })

  it('locks queued, generating, downloading, and reader-only actions accessibly', () => {
    const json = report('json', {
      status: 'queued',
      sha256: null,
      size_bytes: null,
      completed_at: null,
    })
    const html = report('html')
    const wrapper = mountWorkspace({
      reports: [json, html],
      canGenerate: false,
      downloadingReportId: html.id,
      actionError: '当前角色只能查看和下载报告。',
    })

    expect(
      wrapper
        .get('[aria-label="JSON 报告"] button[aria-disabled="true"]')
        .attributes('disabled'),
    ).toBeDefined()
    const htmlDownload = wrapper.get(
      'button[aria-label="下载 HTML 报告"]',
    )
    expect(htmlDownload.attributes('disabled')).toBeDefined()
    expect(htmlDownload.attributes('aria-busy')).toBe('true')
    expect(wrapper.get('[role="alert"]').text()).toContain(
      '只能查看和下载',
    )

    const emptyReader = mountWorkspace({ canGenerate: false })
    expect(emptyReader.text()).toContain(
      '只能查看和下载已有报告',
    )
    expect(
      emptyReader
        .get('button[aria-label="生成 JSON 报告"]')
        .attributes('disabled'),
    ).toBeDefined()
  })

  it('exposes a format-specific busy state while a create request is pending', () => {
    const wrapper = mountWorkspace({
      generatingFormats: ['json'],
    })
    const jsonGenerate = wrapper.get(
      'button[aria-label="生成 JSON 报告"]',
    )
    const htmlGenerate = wrapper.get(
      'button[aria-label="生成 HTML 报告"]',
    )

    expect(jsonGenerate.attributes('disabled')).toBeDefined()
    expect(jsonGenerate.attributes('aria-busy')).toBe('true')
    expect(htmlGenerate.attributes('disabled')).toBeUndefined()
    expect(wrapper.get('[aria-label="JSON 报告"]').text()).toContain(
      '正在提交',
    )
  })

  it('opens the current task code view and exports an optional combined C archive', async () => {
    const wrapper = mountWorkspace({ reports: [report('html')] })

    await wrapper.get('button[title="查看反编译代码"]').trigger('click')
    expect(wrapper.emitted('viewSources')).toEqual([[]])

    const combined = wrapper.get(
      '.report-source-option input[type="checkbox"]',
    )
    expect((combined.element as HTMLInputElement).checked).toBe(false)
    await combined.setValue(true)
    await wrapper.get('button.report-source-action--primary').trigger('click')
    expect(wrapper.emitted('exportSources')).toEqual([[true]])

    await wrapper.setProps({ exportingSources: true })
    const exportButton = wrapper.get(
      'button.report-source-action--primary',
    )
    expect(exportButton.attributes('disabled')).toBeDefined()
    expect(exportButton.attributes('aria-busy')).toBe('true')
    expect(exportButton.text()).toContain('正在生成')
  })

  it('hides source tools when the task has no readable decompile result', () => {
    const wrapper = mountWorkspace({ hasDecompileSources: false })

    expect(wrapper.find('button[title="查看反编译代码"]').exists()).toBe(false)
    expect(wrapper.find('.report-source-option').exists()).toBe(false)
    expect(wrapper.find('button.report-source-action--primary').exists()).toBe(
      false,
    )
  })
})
