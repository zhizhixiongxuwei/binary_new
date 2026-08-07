import { createApp, h, shallowRef } from 'vue'

import type {
  ReportDownloadEncoding,
  TaskReport,
} from '@/api/types'
import '@/assets/main.css'
import ReportResultWorkspace from '@/components/tasks/results/ReportResultWorkspace.vue'

const report: TaskReport = {
  id: 'report-playwright-json',
  task_id: 'task-report-ui',
  format: 'json',
  schema_version: '1.0.0',
  status: 'complete',
  sha256: 'a'.repeat(64),
  size_bytes: 4096,
  error_code: null,
  error_message: null,
  created_at: '2026-07-30T01:00:00Z',
  completed_at: '2026-07-30T01:00:01Z',
}

createApp({
  setup() {
    const delivered = shallowRef('none')

    function recordDownload(
      selectedReport: TaskReport,
      encoding: ReportDownloadEncoding,
    ): void {
      delivered.value = `${selectedReport.format}:${encoding}`
    }

    return () =>
      h('main', { class: 'page-view', style: { containerType: 'inline-size' } }, [
        h(ReportResultWorkspace, {
          taskId: 'task-report-ui',
          reports: [report],
          canGenerate: true,
          generationHint: 'JSON 与 HTML 使用独立生成状态。',
          generatingFormats: [],
          downloadingReportKey: '',
          sampleRelation: 'expired',
          actionError: '',
          onDownload: recordDownload,
        }),
        h(
          'output',
          {
            'aria-label': '报告下载选择结果',
            class: 'sr-only',
          },
          delivered.value,
        ),
      ])
  },
}).mount('#app')
