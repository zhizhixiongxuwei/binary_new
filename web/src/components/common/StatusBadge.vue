<script setup lang="ts">
import { computed } from 'vue'

import type { RiskLevel, TaskStatus } from '@/api/types'

const props = defineProps<{
  value: TaskStatus | RiskLevel
  kind: 'status' | 'risk'
}>()

const statusLabels: Record<string, string> = {
  pending: '待提交',
  uploading: '上传中',
  queued: '排队中',
  validating: '校验中',
  identifying: '识别中',
  extracting: '解包中',
  indexing: '索引中',
  scanning: '扫描中',
  reporting: '报告生成中',
  running: '执行中',
  succeeded: '已完成',
  partial_succeeded: '部分完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '取消中',
  cancelled: '已取消',
  deleting: '删除中',
  deleted: '已删除',
}

const riskLabels: Record<string, string> = {
  none: '无风险',
  low: '低危',
  medium: '中危',
  high: '高危',
  critical: '严重',
  unknown: '未评估',
}

const normalizedValue = computed(() => props.value.toLowerCase())
const label = computed(
  () =>
    (props.kind === 'status'
      ? statusLabels[normalizedValue.value]
      : riskLabels[normalizedValue.value]) ?? props.value,
)
const accessibleLabel = computed(
  () => `${props.kind === 'status' ? '执行状态' : '风险等级'}：${label.value}`,
)

const tone = computed(() => {
  const value = normalizedValue.value
  if (
    [
      'uploading',
      'validating',
      'identifying',
      'extracting',
      'indexing',
      'scanning',
      'reporting',
    ].includes(value)
  ) {
    return 'running'
  }
  if (value === 'partial_succeeded') return 'partial'
  if (value === 'cancel_requested' || value === 'deleting') return 'queued'
  return value
})
</script>

<template>
  <span
    class="status-badge"
    :class="[`status-badge--${kind}`, `status-badge--${tone}`]"
    :aria-label="accessibleLabel"
  >
    <span class="status-badge__dot" aria-hidden="true" />
    {{ label }}
  </span>
</template>

<style scoped>
.status-badge {
  display: inline-flex;
  min-width: 66px;
  min-height: 24px;
  align-items: center;
  justify-content: flex-start;
  gap: 6px;
  padding: 2px 8px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #f7f8f8;
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}

.status-badge__dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ink-400);
}

.status-badge--running,
.status-badge--queued {
  border-color: #b9cde4;
  color: #245a92;
  background: #f1f6fb;
}

.status-badge--running .status-badge__dot,
.status-badge--queued .status-badge__dot {
  background: var(--blue);
}

.status-badge--succeeded,
.status-badge--none,
.status-badge--low {
  border-color: #b8d7d3;
  color: #076860;
  background: #f1f8f7;
}

.status-badge--succeeded .status-badge__dot,
.status-badge--none .status-badge__dot,
.status-badge--low .status-badge__dot {
  background: var(--teal);
}

.status-badge--failed,
.status-badge--high,
.status-badge--critical {
  border-color: #e4bebe;
  color: #a52f2f;
  background: #fff5f5;
}

.status-badge--failed .status-badge__dot,
.status-badge--high .status-badge__dot,
.status-badge--critical .status-badge__dot {
  background: var(--red);
}

.status-badge--medium,
.status-badge--partial {
  border-color: #decba7;
  color: #83551a;
  background: #fff9ef;
}

.status-badge--medium .status-badge__dot,
.status-badge--partial .status-badge__dot {
  background: var(--amber);
}
</style>
