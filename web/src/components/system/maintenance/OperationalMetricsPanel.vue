<script setup lang="ts">
import { Activity, Clock3, ShieldAlert } from 'lucide-vue-next'
import { computed } from 'vue'

import type { OperationalMetrics } from '@/api/types'

const props = defineProps<{
  metrics?: OperationalMetrics
}>()

const stageLabels: Readonly<Record<string, string>> = {
  VALIDATING: '校验',
  IDENTIFYING: '识别',
  EXTRACTING: '解包',
  INDEXING: '建索引',
  SCANNING: '分析',
  REPORTING: '报告',
}

const stageDurations = computed(() => props.metrics?.stage_durations ?? [])
const analyzerFailureRates = computed(
  () => props.metrics?.analyzer_failure_rates ?? [],
)
const totalRuns = computed(() =>
  analyzerFailureRates.value.reduce((total, metric) => total + metric.total_runs, 0),
)
const failedRuns = computed(() =>
  analyzerFailureRates.value.reduce(
    (total, metric) => total + metric.failed_runs,
    0,
  ),
)
const windowDays = computed(() =>
  Math.max(1, Math.round((props.metrics?.window_hours ?? 168) / 24)),
)

function formatDuration(milliseconds: number): string {
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return '—'
  if (milliseconds < 1_000) return `${Math.round(milliseconds)} ms`
  if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(1)} 秒`
  if (milliseconds < 3_600_000) {
    return `${(milliseconds / 60_000).toFixed(1)} 分钟`
  }
  return `${(milliseconds / 3_600_000).toFixed(1)} 小时`
}

function formatFailureRate(basisPoints: number): string {
  if (!Number.isFinite(basisPoints) || basisPoints < 0) return '—'
  return `${(Math.min(basisPoints, 10_000) / 100).toFixed(2)}%`
}

function failureClass(basisPoints: number): string {
  if (basisPoints >= 2_000) return 'failure-rate--critical'
  if (basisPoints > 0) return 'failure-rate--warning'
  return 'failure-rate--healthy'
}
</script>

<template>
  <section class="operational-metrics surface-panel" aria-labelledby="metrics-title">
    <header class="metrics-heading">
      <div class="metrics-title">
        <span class="metrics-kicker mono">LIVE / {{ windowDays }} DAYS</span>
        <h2 id="metrics-title">处理耗时与分析器稳定性</h2>
      </div>
      <div class="metrics-summary" aria-label="运行指标汇总">
        <span>
          <Activity :size="14" aria-hidden="true" />
          <strong class="mono">{{ totalRuns }}</strong>
          <small>分析运行</small>
        </span>
        <span>
          <ShieldAlert :size="14" aria-hidden="true" />
          <strong class="mono">{{ failedRuns }}</strong>
          <small>失败或超时</small>
        </span>
      </div>
    </header>

    <div class="metrics-body">
      <section class="metric-section" aria-labelledby="stage-duration-title">
        <div class="metric-section__title">
          <Clock3 :size="15" aria-hidden="true" />
          <h3 id="stage-duration-title">阶段平均耗时</h3>
        </div>
        <div
          v-if="stageDurations.length"
          class="metric-table"
          role="table"
          aria-label="阶段平均耗时"
        >
          <div class="metric-table__header" role="row">
            <span role="columnheader">阶段</span>
            <span role="columnheader">样本数</span>
            <span role="columnheader">平均耗时</span>
          </div>
          <div
            v-for="metric in stageDurations"
            :key="metric.stage"
            class="metric-row"
            role="row"
          >
            <strong role="cell">{{ stageLabels[metric.stage] ?? metric.stage }}</strong>
            <span class="mono" role="cell">{{ metric.sample_count }}</span>
            <code role="cell">{{ formatDuration(metric.average_duration_ms) }}</code>
          </div>
        </div>
        <p v-else class="metrics-empty">窗口内暂无完整阶段转换样本</p>
      </section>

      <section class="metric-section" aria-labelledby="analyzer-failure-title">
        <div class="metric-section__title">
          <ShieldAlert :size="15" aria-hidden="true" />
          <h3 id="analyzer-failure-title">分析器失败率</h3>
        </div>
        <div
          v-if="analyzerFailureRates.length"
          class="metric-table"
          role="table"
          aria-label="分析器失败率"
        >
          <div class="metric-table__header analyzer-columns" role="row">
            <span role="columnheader">分析器</span>
            <span role="columnheader">运行</span>
            <span role="columnheader">失败率</span>
          </div>
          <div
            v-for="metric in analyzerFailureRates"
            :key="metric.name"
            class="metric-row analyzer-columns"
            role="row"
          >
            <strong class="analyzer-name" role="cell">{{ metric.name }}</strong>
            <span class="mono" role="cell">
              {{ metric.failed_runs }} / {{ metric.total_runs }}
            </span>
            <code
              class="failure-rate"
              :class="failureClass(metric.failure_rate_basis_points)"
              role="cell"
            >
              {{ formatFailureRate(metric.failure_rate_basis_points) }}
            </code>
          </div>
        </div>
        <p v-else class="metrics-empty">窗口内暂无分析器运行记录</p>
      </section>
    </div>
  </section>
</template>

<style scoped>
.operational-metrics {
  min-width: 0;
  overflow: hidden;
}

.metrics-heading {
  display: flex;
  min-height: 66px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 17px;
  border-bottom: 1px solid var(--line);
}

.metrics-title {
  min-width: 0;
}

.metrics-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.metrics-title h2,
.metric-section__title h3 {
  margin: 0;
  color: var(--ink-800);
}

.metrics-title h2 {
  font-size: 14px;
}

.metrics-summary {
  display: flex;
  flex: 0 0 auto;
  align-items: stretch;
  border: 1px solid var(--line);
  border-radius: 4px;
}

.metrics-summary > span {
  display: grid;
  min-width: 108px;
  grid-template-columns: 18px auto;
  grid-template-rows: auto auto;
  align-content: center;
  padding: 7px 10px;
}

.metrics-summary > span + span {
  border-left: 1px solid var(--line);
}

.metrics-summary svg {
  grid-row: 1 / 3;
  align-self: center;
  color: var(--teal-strong);
}

.metrics-summary strong {
  color: var(--ink-800);
  font-size: 11px;
}

.metrics-summary small {
  color: var(--ink-400);
  font-size: 8px;
}

.metrics-body {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.metric-section {
  min-width: 0;
}

.metric-section + .metric-section {
  border-left: 1px solid var(--line);
}

.metric-section__title {
  display: flex;
  min-height: 41px;
  align-items: center;
  gap: 7px;
  padding: 9px 14px;
  border-bottom: 1px solid #e7ebeb;
  color: var(--blue);
}

.metric-section__title h3 {
  font-size: 10px;
}

.metric-table__header,
.metric-row {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(90px, 1fr) 70px minmax(90px, auto);
  align-items: center;
  gap: 10px;
  padding: 7px 14px;
}

.metric-table__header {
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 8px;
  font-weight: 700;
}

.metric-row {
  min-height: 39px;
  border-top: 1px solid #edf0f0;
  color: var(--ink-600);
  font-size: 9px;
}

.metric-table__header + .metric-row {
  border-top: 0;
}

.metric-row strong,
.metric-row span,
.metric-row code {
  min-width: 0;
  overflow-wrap: anywhere;
}

.metric-row code {
  color: var(--ink-800);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  text-align: right;
}

.analyzer-columns {
  grid-template-columns: minmax(120px, 1fr) 82px minmax(70px, auto);
}

.analyzer-name {
  font-size: 9px;
}

.failure-rate {
  font-weight: 700;
}

.failure-rate--healthy {
  color: var(--teal-strong) !important;
}

.failure-rate--warning {
  color: var(--amber) !important;
}

.failure-rate--critical {
  color: var(--red) !important;
}

.metrics-empty {
  min-height: 86px;
  margin: 0;
  padding: 31px 14px;
  color: var(--ink-400);
  font-size: 9px;
  text-align: center;
}

@media (max-width: 820px) {
  .metrics-heading {
    align-items: stretch;
    flex-direction: column;
  }

  .metrics-summary {
    align-self: stretch;
  }

  .metrics-summary > span {
    min-width: 0;
    flex: 1;
  }

  .metrics-body {
    grid-template-columns: minmax(0, 1fr);
  }

  .metric-section + .metric-section {
    border-top: 1px solid var(--line);
    border-left: 0;
  }
}

@media (max-width: 480px) {
  .metric-table__header,
  .metric-row,
  .analyzer-columns {
    grid-template-columns: minmax(80px, 1fr) 58px minmax(72px, auto);
    gap: 7px;
    padding-right: 10px;
    padding-left: 10px;
  }
}
</style>
