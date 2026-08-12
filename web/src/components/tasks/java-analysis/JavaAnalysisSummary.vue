<script setup lang="ts">
import { AlertTriangle, CircleCheck, Cpu, FileWarning } from 'lucide-vue-next'
import { computed } from 'vue'

import type { JavaAnalysisRun, JavaAnalysisSeverity } from '@/api/types'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  run: JavaAnalysisRun
}>()

const statusLabels: Readonly<Record<JavaAnalysisRun['status'], string>> = {
  queued: '排队中',
  running: '检测中',
  succeeded: '已完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '正在取消',
  cancelled: '已取消',
}
const severityMetrics: readonly {
  id: JavaAnalysisSeverity
  label: string
}[] = [
  { id: 'CRITICAL', label: '严重' },
  { id: 'HIGH', label: '高危' },
  { id: 'MEDIUM', label: '中危' },
  { id: 'LOW', label: '低危' },
]
const coveragePercent = computed(() =>
  props.run.coverage.total_files > 0
    ? Math.round(
        (props.run.coverage.analyzed_files /
          props.run.coverage.total_files) *
          100,
      )
    : 0,
)
</script>

<template>
  <section class="analysis-summary" aria-label="Java 源码检测汇总">
    <div class="analysis-summary__identity">
      <CircleCheck
        v-if="run.status === 'succeeded'"
        :size="18"
        aria-hidden="true"
      />
      <AlertTriangle v-else :size="18" aria-hidden="true" />
      <span>
        <small>检测状态</small>
        <strong>{{ statusLabels[run.status] }}</strong>
      </span>
    </div>
    <div class="analysis-summary__metric analysis-summary__metric--total">
      <small>发现总数</small>
      <strong>{{ run.finding_count }}</strong>
    </div>
    <div
      v-for="metric in severityMetrics"
      :key="metric.id"
      class="analysis-summary__metric"
      :class="`analysis-summary__metric--${metric.id.toLowerCase()}`"
    >
      <small>{{ metric.label }}</small>
      <strong>{{ run.severity_counts[metric.id] }}</strong>
    </div>
    <div class="analysis-summary__coverage">
      <Cpu :size="15" aria-hidden="true" />
      <span>
        <small>文件覆盖</small>
        <strong>{{ run.coverage.analyzed_files }}/{{ run.coverage.total_files }} · {{ coveragePercent }}%</strong>
        <small>解析 {{ run.coverage.parsed_files }} · 恢复 {{ run.coverage.recovered_files }}</small>
      </span>
    </div>
  </section>

  <section class="analysis-meta" aria-label="Java 源码检测版本信息">
    <span><small>检测器</small><code>{{ run.analyzer_name }} {{ run.analyzer_version }}</code></span>
    <span><small>规则集</small><code>{{ run.ruleset_version || '等待引擎返回' }}</code></span>
    <span><small>源码</small><code>{{ formatBytes(run.source_size_bytes) }} · {{ run.source_file_count }} 文件</code></span>
    <span><small>解析诊断</small><code>{{ run.diagnostic_count }}</code></span>
    <span><small>创建时间</small><time :datetime="run.created_at">{{ formatDateTime(run.created_at) }}</time></span>
  </section>

  <div
    v-if="run.status === 'partial' || run.findings_truncated || run.diagnostics_truncated"
    class="analysis-notice"
    role="status"
  >
    <FileWarning :size="16" aria-hidden="true" />
    <span>
      检测结果不完整：{{ run.coverage.failed_files }} 个文件未成功解析<span v-if="run.findings_truncated">，发现数量达到上限</span><span v-if="run.diagnostics_truncated">，诊断数量达到上限</span>。
    </span>
  </div>

  <div v-if="run.error_message" class="analysis-error" role="alert">
    <AlertTriangle :size="16" aria-hidden="true" />
    <span><code>{{ run.error_code || 'java_analysis_failed' }}</code>{{ run.error_message }}</span>
  </div>
</template>

<style scoped>
.analysis-summary {
  display: grid;
  grid-template-columns: minmax(128px, 1.25fr) repeat(5, minmax(74px, 0.65fr)) minmax(150px, 1.2fr);
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.analysis-summary > div {
  display: flex;
  min-width: 0;
  min-height: 70px;
  align-items: center;
  gap: 9px;
  padding: 10px 14px;
  border-right: 1px solid #e6eaeb;
}

.analysis-summary > div:last-child { border-right: 0; }
.analysis-summary span { display: grid; min-width: 0; gap: 2px; }
.analysis-summary small,
.analysis-meta small { color: var(--ink-400); font-size: 8px; font-weight: 700; }
.analysis-summary strong { color: var(--ink-800); font-size: 15px; font-variant-numeric: tabular-nums; }
.analysis-summary__identity { color: var(--teal-strong); }
.analysis-summary__metric--critical { border-top: 3px solid #9f2f36; }
.analysis-summary__metric--high { border-top: 3px solid #c55b35; }
.analysis-summary__metric--medium { border-top: 3px solid #d09a31; }
.analysis-summary__metric--low { border-top: 3px solid #3e8095; }
.analysis-summary__metric--total { border-top: 3px solid var(--ink-600); }
.analysis-summary__coverage { color: var(--blue); }
.analysis-summary__coverage strong { font-size: 11px; }

.analysis-meta {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 1px;
  border-bottom: 1px solid var(--line);
  background: var(--line);
}

.analysis-meta > span {
  display: grid;
  min-width: 0;
  gap: 3px;
  padding: 8px 14px;
  background: #fafbfb;
}

.analysis-meta code,
.analysis-meta time {
  overflow: hidden;
  color: var(--ink-600);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.analysis-notice,
.analysis-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  border-bottom: 1px solid #ead8b8;
  color: #7d581d;
  background: #fff9ee;
  font-size: 10px;
}

.analysis-error {
  border-color: #ebcccc;
  color: #873737;
  background: #fff3f3;
}

.analysis-error span { display: flex; gap: 8px; }

@container (max-width: 980px) {
  .analysis-summary { grid-template-columns: repeat(4, minmax(90px, 1fr)); }
  .analysis-summary > div { border-bottom: 1px solid #e6eaeb; }
  .analysis-meta { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@container (max-width: 560px) {
  .analysis-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .analysis-meta { grid-template-columns: minmax(0, 1fr); }
}
</style>
