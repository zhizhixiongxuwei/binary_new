<script setup lang="ts">
import { Binary, CircleAlert, RadioTower, TriangleAlert } from 'lucide-vue-next'
import { useId } from 'vue'

import type {
  AnalyzerSummaryMetric,
  ParsedAnalyzerSummary,
} from '@/components/tasks/results/analyzerSummary'
import { formatBytes } from '@/utils/formatters'

const props = withDefaults(
  defineProps<{
    summary: ParsedAnalyzerSummary
    example?: boolean
  }>(),
  { example: false },
)

const titleId = useId()
const countFormatter = new Intl.NumberFormat('zh-CN')

function formatMetric(metric: AnalyzerSummaryMetric): string {
  return metric.unit === 'bytes'
    ? formatBytes(metric.value)
    : countFormatter.format(metric.value)
}
</script>

<template>
  <section
    v-if="summary.present"
    class="analyzer-summary"
    data-analyzer-summary
    :aria-labelledby="titleId"
  >
    <header class="analyzer-summary__heading">
      <div class="analyzer-summary__title">
        <Binary :size="16" aria-hidden="true" />
        <span>
          <strong :id="titleId">结构化分析摘要</strong>
          <small>diagnostics</small>
        </span>
      </div>
      <div
        class="analyzer-summary__provenance"
        role="group"
        aria-label="摘要数据来源"
      >
        <span
          class="analyzer-summary__reported"
          title="字段由当前结果的分析器 diagnostics 上报"
        >
          <RadioTower :size="12" aria-hidden="true" />
          分析器上报
        </span>
        <span
          v-if="props.example"
          class="analyzer-summary__example"
          role="note"
        >
          固定示例 · 非真实结果
        </span>
      </div>
    </header>

    <dl v-if="summary.identity.length" class="analyzer-summary__identity">
      <div v-for="field in summary.identity" :key="field.key">
        <dt>{{ field.label }}</dt>
        <dd>{{ field.value }}</dd>
      </div>
    </dl>

    <dl v-if="summary.metrics.length" class="analyzer-summary__metrics">
      <div
        v-for="metric in summary.metrics"
        :key="metric.key"
        :class="`analyzer-summary__metric--${metric.tone}`"
      >
        <dt>{{ metric.label }}</dt>
        <dd>{{ formatMetric(metric) }}</dd>
      </div>
    </dl>

    <div v-if="summary.issues.length" class="analyzer-summary__issues">
      <div
        v-for="group in summary.issues"
        :key="group.kind"
        class="analyzer-summary__issue-group"
        :class="`analyzer-summary__issue-group--${group.kind}`"
      >
        <div class="analyzer-summary__issue-title">
          <CircleAlert
            v-if="group.kind === 'error'"
            :size="14"
            aria-hidden="true"
          />
          <TriangleAlert v-else :size="14" aria-hidden="true" />
          <strong>{{ group.label }}</strong>
        </div>
        <ul>
          <li v-for="(message, index) in group.messages" :key="index">
            {{ message }}
          </li>
        </ul>
        <small v-if="group.omittedCount">
          还有 {{ group.omittedCount }} 条未在摘要中展开
        </small>
      </div>
    </div>
  </section>
</template>

<style scoped>
.analyzer-summary {
  min-width: 0;
  border-bottom: 1px solid #34464a;
  color: var(--ink-800);
  background: #f5f8f8;
}

.analyzer-summary__heading {
  display: flex;
  min-width: 0;
  min-height: 46px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 12px;
  border-bottom: 1px solid #d8e0e1;
}

.analyzer-summary__title,
.analyzer-summary__provenance,
.analyzer-summary__reported {
  display: flex;
  min-width: 0;
  align-items: center;
}

.analyzer-summary__title {
  gap: 8px;
  color: var(--teal-strong);
}

.analyzer-summary__title > span {
  display: grid;
  min-width: 0;
  gap: 1px;
}

.analyzer-summary__title strong {
  color: var(--ink-800);
  font-size: 12px;
}

.analyzer-summary__title small {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.analyzer-summary__provenance {
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 5px;
}

.analyzer-summary__reported,
.analyzer-summary__example {
  min-height: 23px;
  padding: 3px 6px;
  border: 1px solid #b9d2cc;
  border-radius: 3px;
  color: #17665f;
  background: #fff;
  font-size: 11px;
  font-weight: 700;
  line-height: 1.35;
}

.analyzer-summary__reported {
  gap: 4px;
}

.analyzer-summary__example {
  border-color: #d6a84d;
  color: #68490c;
  background: #fff6da;
}

.analyzer-summary__identity,
.analyzer-summary__metrics {
  display: grid;
  min-width: 0;
  margin: 0;
}

.analyzer-summary__identity {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-bottom: 1px solid #d8e0e1;
  background: #fff;
}

.analyzer-summary__identity > div,
.analyzer-summary__metrics > div {
  display: grid;
  min-width: 0;
  align-content: center;
  gap: 2px;
  padding: 8px 11px;
  border-right: 1px solid #e0e6e7;
}

.analyzer-summary__identity > div:last-child,
.analyzer-summary__metrics > div:last-child {
  border-right: 0;
}

.analyzer-summary__identity dt,
.analyzer-summary__metrics dt {
  color: var(--ink-600);
  font-size: 11px;
}

.analyzer-summary__identity dd,
.analyzer-summary__metrics dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: var(--ink-800);
  font-size: 12px;
  font-weight: 700;
}

.analyzer-summary__identity dd {
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.analyzer-summary__metrics {
  grid-template-columns: repeat(4, minmax(0, 1fr));
  background: #eef3f3;
}

.analyzer-summary__metric--warning dd {
  color: #76560d;
}

.analyzer-summary__metric--danger dd {
  color: #9b352a;
}

.analyzer-summary__issues {
  display: grid;
  min-width: 0;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  border-top: 1px solid #d8e0e1;
  background: #fff;
}

.analyzer-summary__issue-group {
  min-width: 0;
  padding: 8px 12px 9px;
  border-left: 3px solid #d6a84d;
}

.analyzer-summary__issue-group + .analyzer-summary__issue-group {
  border-left-width: 1px;
  border-left-color: #e0e6e7;
}

.analyzer-summary__issue-group--error:first-child {
  border-left-color: #bd574a;
}

.analyzer-summary__issue-title {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #76560d;
  font-size: 11px;
}

.analyzer-summary__issue-group--error .analyzer-summary__issue-title {
  color: #9b352a;
}

.analyzer-summary__issue-group ul {
  display: grid;
  min-width: 0;
  gap: 3px;
  margin: 5px 0 0;
  padding-left: 18px;
  color: var(--ink-700);
  font-size: 11px;
  line-height: 1.45;
}

.analyzer-summary__issue-group li {
  overflow-wrap: anywhere;
}

.analyzer-summary__issue-group small {
  display: block;
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 11px;
}

@media (max-width: 720px) {
  .analyzer-summary__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .analyzer-summary__provenance {
    justify-content: flex-start;
  }

  .analyzer-summary__identity,
  .analyzer-summary__metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .analyzer-summary__identity > div:nth-child(2n),
  .analyzer-summary__metrics > div:nth-child(2n) {
    border-right: 0;
  }

  .analyzer-summary__identity > div:nth-child(n + 3),
  .analyzer-summary__metrics > div:nth-child(n + 3) {
    border-top: 1px solid #e0e6e7;
  }
}

@media (max-width: 460px) {
  .analyzer-summary__issues {
    grid-template-columns: minmax(0, 1fr);
  }

  .analyzer-summary__issue-group + .analyzer-summary__issue-group {
    border-top: 1px solid #e0e6e7;
    border-left-width: 3px;
    border-left-color: #d6a84d;
  }
}
</style>
