<script setup lang="ts">
import { ArrowLeft, Code2 } from 'lucide-vue-next'
import { shallowRef, watch } from 'vue'

import type { TaskStatus, UserRole } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import ReportResultWorkspace from '@/components/tasks/results/ReportResultWorkspace.vue'
import LiveDecompileResult from '@/components/tasks/results/LiveDecompileResult.vue'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'
import { useTaskReports } from '@/composables/useTaskReports'

const props = defineProps<{
  taskId: string
  taskStatus: TaskStatus
  userRole: UserRole | null
}>()

const emit = defineEmits<{
  stateChange: [state: TaskResultState]
}>()

const results = useTaskReports({
  taskId: () => props.taskId,
  taskStatus: () => props.taskStatus,
  userRole: () => props.userRole,
})
const viewingSources = shallowRef(false)

watch(
  () => props.taskId,
  () => {
    viewingSources.value = false
  },
)

watch(
  results.state,
  (state) => emit('stateChange', state),
  { immediate: true },
)

defineExpose({
  refresh: results.refresh,
})
</script>

<template>
  <section v-if="viewingSources" class="report-source-view">
    <header class="report-source-view__heading">
      <button
        type="button"
        title="返回报告产物"
        aria-label="返回报告产物"
        @click="viewingSources = false"
      >
        <ArrowLeft :size="15" aria-hidden="true" />
      </button>
      <Code2 :size="16" aria-hidden="true" />
      <span>
        <strong>反编译代码</strong>
        <small>当前任务持久化结果</small>
      </span>
    </header>
    <LiveDecompileResult :task-id="taskId" />
  </section>
  <StatePanel
    v-else-if="
      results.state.value.status === 'loading' ||
        results.state.value.status === 'error'
    "
    :kind="
      results.state.value.status === 'loading'
        ? 'loading'
        : 'error'
    "
    :title="results.state.value.title ?? ''"
    :description="results.state.value.description ?? ''"
    :retryable="results.state.value.status === 'error'"
    @retry="results.refresh"
  />
  <ReportResultWorkspace
    v-else
    :task-id="taskId"
    :reports="results.reports.value"
    :can-generate="results.canGenerate.value"
    :generation-hint="results.generationHint.value"
    :generating-formats="results.generatingFormats.value"
    :downloading-report-key="results.downloadingReportKey.value"
    :sample-relation="results.sampleRelation.value"
    :action-error="results.actionError.value"
    :exporting-sources="results.exportingSources.value"
    :has-decompile-sources="results.hasDecompileSources.value"
    @generate="results.generate"
    @download="results.download"
    @view-sources="viewingSources = true"
    @export-sources="results.exportSources"
  />
</template>

<style scoped>
.report-source-view {
  min-width: 0;
}

.report-source-view__heading {
  display: flex;
  min-height: 48px;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
  color: var(--teal-strong);
  background: #f7f9f9;
}

.report-source-view__heading button {
  display: inline-flex;
  width: 30px;
  height: 30px;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: 1px solid #c8d3d2;
  border-radius: 4px;
  color: var(--ink-700);
  background: #fff;
  cursor: pointer;
}

.report-source-view__heading span {
  display: grid;
  gap: 2px;
}

.report-source-view__heading strong {
  color: var(--ink-800);
  font-size: 11px;
}

.report-source-view__heading small {
  color: var(--ink-600);
  font-size: 9px;
}
</style>
