<script setup lang="ts">
import { ArrowUpRight, CircleCheck, CircleX, Layers3, X } from 'lucide-vue-next'
import { computed } from 'vue'

import type { ArchiveTaskBatchResult } from '@/api/types'

const props = defineProps<{
  selectedCount: number
  submitting: boolean
  disabled: boolean
  result: ArchiveTaskBatchResult | null
  error: string
  entryLabels: Readonly<Record<string, string>>
}>()

const emit = defineEmits<{
  create: []
  clear: []
  openTask: [taskId: string]
}>()

const summary = computed(() => ({
  created:
    props.result?.items.filter((item) => item.outcome === 'created').length ?? 0,
  existing:
    props.result?.items.filter((item) => item.outcome === 'existing').length ?? 0,
  failed:
    props.result?.items.filter((item) => item.outcome === 'failed').length ?? 0,
}))
</script>

<template>
  <div class="batch-actions">
    <div class="batch-actions__selection" aria-live="polite">
      <Layers3 :size="17" aria-hidden="true" />
      <strong>已选 {{ selectedCount }} / 20</strong>
      <button
        v-if="selectedCount"
        type="button"
        aria-label="清空选择"
        title="清空选择"
        :disabled="submitting"
        @click="emit('clear')"
      >
        <X :size="15" aria-hidden="true" />
      </button>
    </div>
    <el-button
      type="primary"
      :loading="submitting"
      :disabled="disabled || selectedCount === 0 || selectedCount > 20"
      @click="emit('create')"
    >
      批量创建 {{ selectedCount }} 个任务
    </el-button>
  </div>

  <div v-if="error" class="batch-error" role="alert">{{ error }}</div>

  <section v-if="result" class="batch-result" aria-live="polite">
    <div class="batch-result__summary">
      <span><CircleCheck :size="14" aria-hidden="true" />新建 {{ summary.created }}</span>
      <span>已存在 {{ summary.existing }}</span>
      <span :class="{ 'batch-result__failed': summary.failed > 0 }">
        <CircleX :size="14" aria-hidden="true" />失败 {{ summary.failed }}
      </span>
    </div>
    <ul>
      <li v-for="item in result.items" :key="item.entry_id">
        <div>
          <strong :title="entryLabels[item.entry_id] ?? item.entry_id">
            {{ entryLabels[item.entry_id] ?? item.entry_id }}
          </strong>
          <small>
            {{ item.outcome === 'created' ? '任务已创建' : item.outcome === 'existing' ? item.task_id ? '任务已存在' : '已创建（任务已删除）' : item.message ?? item.error_code ?? '创建失败' }}
          </small>
        </div>
        <button
          v-if="item.task_id"
          type="button"
          aria-label="查看批量创建任务"
          title="查看任务"
          @click="emit('openTask', item.task_id)"
        >
          <ArrowUpRight :size="16" aria-hidden="true" />
        </button>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.batch-actions {
  display: flex;
  min-height: 58px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 14px;
  background: #f7f9f9;
}

.batch-actions__selection {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
  color: var(--teal-strong);
  font-size: 12px;
}

.batch-actions__selection button,
.batch-result li > button {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
}

.batch-error {
  padding: 9px 14px;
  border-top: 1px solid #ebc6c1;
  color: var(--red);
  background: #fff5f3;
  font-size: 12px;
}

.batch-result {
  border-top: 1px solid var(--line);
}

.batch-result__summary {
  display: flex;
  flex-wrap: wrap;
  gap: 14px;
  padding: 9px 14px;
  color: var(--ink-600);
  background: #f4f8f7;
  font-size: 11px;
}

.batch-result__summary span {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.batch-result__failed {
  color: var(--red);
}

.batch-result ul {
  max-height: 220px;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
}

.batch-result li {
  display: flex;
  min-height: 52px;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 14px;
  border-top: 1px solid var(--line);
}

.batch-result li:first-child {
  border-top: 0;
}

.batch-result li > div {
  min-width: 0;
}

.batch-result strong,
.batch-result small {
  display: block;
}

.batch-result strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.batch-result small {
  margin-top: 2px;
  color: var(--ink-400);
  font-size: 10px;
}

@media (max-width: 520px) {
  .batch-actions {
    align-items: stretch;
    flex-direction: column;
  }

  .batch-actions :deep(.el-button) {
    width: 100%;
    margin: 0;
  }
}
</style>
