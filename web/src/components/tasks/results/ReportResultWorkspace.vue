<script setup lang="ts">
import {
  Braces,
  Code2,
  FileArchive,
  FileCode2,
  FilePlus2,
  FileText,
  LoaderCircle,
  RotateCw,
  ShieldAlert,
} from 'lucide-vue-next'
import { computed, shallowRef, type Component } from 'vue'

import type {
  ReportDownloadEncoding,
  ReportFormat,
  TaskReport,
  TaskReportSampleRelation,
} from '@/api/types'
import ReportDownloadControl from '@/components/tasks/results/ReportDownloadControl.vue'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  taskId: string
  reports: readonly TaskReport[]
  canGenerate: boolean
  generationHint: string
  generatingFormats: readonly ReportFormat[]
  downloadingReportKey: string
  sampleRelation: TaskReportSampleRelation | 'unknown'
  actionError: string
  exportingSources: boolean
  hasDecompileSources: boolean
}>()

const emit = defineEmits<{
  generate: [format: ReportFormat]
  download: [report: TaskReport, encoding: ReportDownloadEncoding]
  viewSources: []
  exportSources: [includeCombined: boolean]
}>()

const includeCombined = shallowRef(false)

interface FormatDefinition {
  format: ReportFormat
  label: string
  description: string
  icon: Component
}

interface ReportRow extends FormatDefinition {
  report: TaskReport | undefined
}

const formatDefinitions: readonly FormatDefinition[] = [
  {
    format: 'json',
    label: 'JSON 报告',
    description: '完整机器可读检测结果',
    icon: Braces,
  },
  {
    format: 'html',
    label: 'HTML 报告',
    description: '可离线打开的审阅报告',
    icon: FileCode2,
  },
  {
    format: 'docx',
    label: 'Word 报告',
    description: '可编辑的 Word 文档',
    icon: FileText,
  },
]

const rows = computed<readonly ReportRow[]>(() =>
  formatDefinitions.map((definition) => ({
    ...definition,
    report: props.reports.find(
      (report) => report.format === definition.format,
    ),
  })),
)
const completeCount = computed(
  () => props.reports.filter((report) => report.status === 'complete').length,
)
function statusLabel(report: TaskReport | undefined): string {
  if (!report) return '未生成'
  switch (report.status) {
    case 'queued':
      return '等待生成'
    case 'generating':
      return '生成中'
    case 'complete':
      return '已完成'
    case 'failed':
      return '生成失败'
    default:
      return '已删除'
  }
}

function isGenerating(format: ReportFormat): boolean {
  return props.generatingFormats.includes(format)
}

function isServerPending(report: TaskReport | undefined): boolean {
  return report?.status === 'queued' || report?.status === 'generating'
}

function canRequestGeneration(row: ReportRow): boolean {
  return (
    props.canGenerate &&
    (!row.report || row.report.status === 'failed') &&
    !isGenerating(row.format)
  )
}

function handleDownload(
  report: TaskReport,
  encoding: ReportDownloadEncoding,
): void {
  emit('download', report, encoding)
}

const sampleRelationLabels: Readonly<
  Record<TaskReportSampleRelation | 'unknown', string>
> = {
  retained: '样本保留中',
  expired: '样本已到期',
  deleted: '样本已清理',
  unknown: '样本关联未知',
}
</script>

<template>
  <div class="report-workspace" :data-task-id="taskId">
    <header class="report-workspace__heading">
      <div>
        <strong>报告产物</strong>
        <span>{{ generationHint }}</span>
      </div>
      <div class="report-workspace__tools">
        <span class="report-workspace__count">
          {{ completeCount }}/3 已完成
        </span>
        <button
          v-if="hasDecompileSources"
          class="report-source-action"
          type="button"
          title="查看反编译代码"
          @click="emit('viewSources')"
        >
          <Code2 :size="14" aria-hidden="true" />
          查看代码
        </button>
        <label v-if="hasDecompileSources" class="report-source-option">
          <input v-model="includeCombined" type="checkbox">
          <span>包含 all-functions.c</span>
        </label>
        <button
          v-if="hasDecompileSources"
          class="report-source-action report-source-action--primary"
          type="button"
          :disabled="exportingSources || downloadingReportKey !== ''"
          :aria-busy="exportingSources"
          title="导出当前任务源码包（不绑定报告快照）"
          @click="emit('exportSources', includeCombined)"
        >
          <LoaderCircle
            v-if="exportingSources"
            class="spin"
            :size="14"
            aria-hidden="true"
          />
          <FileArchive v-else :size="14" aria-hidden="true" />
          {{ exportingSources ? '正在生成' : '导出当前源码' }}
        </button>
      </div>
    </header>

    <p
      v-if="actionError"
      class="report-workspace__error"
      role="alert"
    >
      <ShieldAlert :size="15" aria-hidden="true" />
      <span>{{ actionError }}</span>
    </p>

    <div class="report-list" aria-label="任务报告列表">
      <section
        v-for="row in rows"
        :key="row.format"
        class="report-row"
        :aria-label="row.label"
      >
        <div class="report-row__identity">
          <component :is="row.icon" :size="20" aria-hidden="true" />
          <span>
            <strong>{{ row.label }}</strong>
            <small>{{ row.description }}</small>
          </span>
        </div>

        <div class="report-row__status">
          <span
            class="report-status"
            :class="`report-status--${row.report?.status ?? 'missing'}`"
          >
            <LoaderCircle
              v-if="isGenerating(row.format) || isServerPending(row.report)"
              class="spin"
              :size="12"
              aria-hidden="true"
            />
            {{ isGenerating(row.format) ? '正在提交' : statusLabel(row.report) }}
          </span>
          <code v-if="row.report?.error_code">{{ row.report.error_code }}</code>
          <span
            v-if="row.report"
            class="sample-relation"
            :class="`sample-relation--${sampleRelation}`"
          >
            {{ sampleRelationLabels[sampleRelation] }}
          </span>
        </div>

        <dl class="report-row__metadata">
          <div>
            <dt>Schema</dt>
            <dd>{{ row.report?.schema_version || '—' }}</dd>
          </div>
          <div>
            <dt>大小</dt>
            <dd>{{ formatBytes(row.report?.size_bytes ?? undefined) }}</dd>
          </div>
          <div>
            <dt>完成时间</dt>
            <dd>{{ formatDateTime(row.report?.completed_at ?? undefined) }}</dd>
          </div>
          <div class="report-row__hash">
            <dt>SHA-256</dt>
            <dd><code>{{ row.report?.sha256 || '—' }}</code></dd>
          </div>
        </dl>

        <div class="report-row__action">
          <ReportDownloadControl
            v-if="row.report?.status === 'complete'"
            :report="row.report"
            :pending-key="downloadingReportKey"
            @download="handleDownload"
          />
          <button
            v-else-if="!row.report || row.report.status === 'failed'"
            class="report-action"
            type="button"
            :disabled="!canRequestGeneration(row)"
            :title="
              canGenerate
                ? row.report?.status === 'failed'
                  ? `重试生成 ${row.label}`
                  : `生成 ${row.label}`
                : generationHint
            "
            :aria-busy="isGenerating(row.format)"
            :aria-label="
              row.report?.status === 'failed'
                ? `重试生成 ${row.label}`
                : `生成 ${row.label}`
            "
            @click="emit('generate', row.format)"
          >
            <LoaderCircle
              v-if="isGenerating(row.format)"
              class="spin"
              :size="14"
              aria-hidden="true"
            />
            <RotateCw
              v-else-if="row.report?.status === 'failed'"
              :size="14"
              aria-hidden="true"
            />
            <FilePlus2 v-else :size="14" aria-hidden="true" />
            {{ row.report?.status === 'failed' ? '重试' : '生成' }}
          </button>
          <button
            v-else-if="isServerPending(row.report)"
            class="report-action"
            type="button"
            disabled
            aria-disabled="true"
          >
            <LoaderCircle class="spin" :size="14" aria-hidden="true" />
            生成中
          </button>
          <span v-else class="report-row__no-action">不可下载</span>
        </div>

        <p
          v-if="row.report?.status === 'failed'"
          class="report-row__failure"
          role="status"
        >
          {{ row.report.error_message || '报告生成器未返回失败原因。' }}
        </p>
      </section>
    </div>
  </div>
</template>

<style scoped>
.report-workspace {
  min-width: 0;
}

.report-workspace__heading {
  display: flex;
  min-height: 52px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 9px 16px;
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
}

.report-workspace__heading div,
.report-row__identity span {
  display: grid;
  gap: 3px;
}

.report-workspace__heading .report-workspace__tools {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  flex-wrap: wrap;
}

.report-workspace__heading strong,
.report-row__identity strong {
  color: var(--ink-800);
  font-size: 12px;
}

.report-workspace__heading span,
.report-row__identity small,
.report-workspace__count {
  color: var(--ink-600);
  font-size: 10px;
}

.report-source-action {
  display: inline-flex;
  height: 30px;
  flex: 0 0 auto;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 0 9px;
  border: 1px solid #c8d3d2;
  border-radius: 4px;
  color: var(--teal-strong);
  background: #fff;
  cursor: pointer;
  font: inherit;
  font-size: 9px;
}

.report-source-action--primary {
  border-color: var(--teal);
  color: #fff;
  background: var(--teal-strong);
}

.report-source-action:disabled {
  cursor: wait;
  opacity: 0.6;
}

.report-source-option {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: 5px;
  color: var(--ink-600);
  font-size: 9px;
  white-space: nowrap;
}

.report-source-option input {
  width: 14px;
  height: 14px;
  accent-color: var(--teal);
}

.report-workspace__count {
  flex: 0 0 auto;
  font-family: "IBM Plex Mono", Consolas, monospace;
}

.report-workspace__error {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin: 0;
  padding: 10px 16px;
  border-bottom: 1px solid #e8b9b9;
  color: #7e3030;
  background: #fff4f4;
  font-size: 11px;
  overflow-wrap: anywhere;
}

.report-workspace__error svg {
  flex: 0 0 auto;
}

.report-list {
  display: grid;
}

.report-row {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(180px, 0.8fr) minmax(110px, 0.45fr) minmax(300px, 1.5fr) auto;
  align-items: center;
  gap: 16px;
  padding: 16px;
  border-bottom: 1px solid var(--line);
}

.report-row:last-child {
  border-bottom: 0;
}

.report-row__identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
  color: var(--teal-strong);
}

.report-row__identity svg {
  flex: 0 0 auto;
}

.report-row__status {
  display: grid;
  justify-items: start;
  gap: 5px;
}

.report-row__status code {
  color: var(--red);
  font-size: 9px;
  overflow-wrap: anywhere;
}

.sample-relation {
  color: var(--ink-600);
  font-size: 9px;
  font-weight: 700;
}

.sample-relation--expired {
  color: #73530e;
}

.sample-relation--deleted {
  color: #7e3030;
}

.report-status {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  gap: 5px;
  padding: 2px 7px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #f5f7f7;
  font-size: 9px;
  font-weight: 700;
  white-space: nowrap;
}

.report-status--complete {
  border-color: #b8d7d3;
  color: #076860;
  background: #edf8f6;
}

.report-status--failed {
  border-color: #e0b7b7;
  color: #8a3030;
  background: #fff2f2;
}

.report-status--queued,
.report-status--generating {
  border-color: #d6c58e;
  color: #73530e;
  background: #fff8e8;
}

.report-row__metadata {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(70px, 0.5fr) minmax(70px, 0.5fr) minmax(135px, 0.8fr);
  gap: 8px 14px;
  margin: 0;
}

.report-row__metadata div {
  min-width: 0;
}

.report-row__metadata dt {
  margin-bottom: 3px;
  color: var(--ink-600);
  font-size: 9px;
}

.report-row__metadata dd {
  min-width: 0;
  margin: 0;
  color: var(--ink-800);
  font-size: 10px;
  overflow-wrap: anywhere;
}

.report-row__hash {
  grid-column: 1 / -1;
}

.report-row__hash code {
  font-size: 9px;
}

.report-row__failure {
  grid-column: 1 / -1;
  margin: -5px 0 0;
  padding: 8px 10px;
  border-left: 3px solid var(--red);
  color: #7e3030;
  background: #fff5f5;
  font-size: 10px;
  overflow-wrap: anywhere;
}

.report-row__action {
  display: flex;
  min-width: 82px;
  justify-content: flex-end;
}

.report-action {
  display: inline-flex;
  min-width: 76px;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 6px 10px;
  border: 1px solid #b9c5c7;
  border-radius: 4px;
  color: var(--ink-800);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
  font-weight: 700;
}

.report-action:hover:not(:disabled) {
  border-color: var(--teal);
  color: var(--teal-strong);
  background: #f0f8f7;
}

.report-action--primary {
  border-color: var(--teal);
  color: #fff;
  background: var(--teal-strong);
}

.report-action--primary:hover:not(:disabled) {
  color: #fff;
  background: #075f59;
}

.report-action:disabled {
  cursor: not-allowed;
  opacity: 0.56;
}

.report-row__no-action {
  color: var(--ink-400);
  font-size: 10px;
}

.spin {
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  to {
    transform: rotate(360deg);
  }
}

@container (max-width: 920px) {
  .report-row {
    grid-template-columns: minmax(180px, 1fr) minmax(110px, 0.5fr) auto;
  }

  .report-row__metadata {
    grid-column: 1 / -1;
    grid-row: 2;
  }
}

@container (max-width: 620px) {
  .report-workspace__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .report-workspace__heading .report-workspace__tools {
    width: 100%;
    justify-content: flex-start;
  }

  .report-row {
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 12px;
  }

  .report-row__status {
    justify-items: end;
  }

  .report-row__metadata,
  .report-row__failure {
    grid-column: 1 / -1;
  }

  .report-row__metadata {
    grid-template-columns: 1fr 1fr;
  }

  .report-row__action {
    grid-column: 1 / -1;
    justify-content: flex-start;
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
