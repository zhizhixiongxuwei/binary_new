<script setup lang="ts">
import { AlertTriangle, History } from 'lucide-vue-next'
import { ElMessageBox } from 'element-plus'
import { onScopeDispose, watch } from 'vue'

import type { UserRole } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import PythonAnalysisFindingDrawer from '@/components/tasks/python-analysis/PythonAnalysisFindingDrawer.vue'
import PythonAnalysisFindingFilters from '@/components/tasks/python-analysis/PythonAnalysisFindingFilters.vue'
import PythonAnalysisFindingTable from '@/components/tasks/python-analysis/PythonAnalysisFindingTable.vue'
import PythonAnalysisSummary from '@/components/tasks/python-analysis/PythonAnalysisSummary.vue'
import PythonAnalysisToolbar from '@/components/tasks/python-analysis/PythonAnalysisToolbar.vue'
import type { TaskResultState } from '@/components/tasks/taskResultTypes'
import { usePythonAnalysis } from '@/composables/usePythonAnalysis'

const props = withDefaults(
  defineProps<{
    taskId: string
    userRole: UserRole | null
    enabled?: boolean
  }>(),
  { enabled: true },
)

const emit = defineEmits<{
  stateChange: [state: TaskResultState]
  busyChange: [busy: boolean]
  openSource: [resultId: string]
}>()

const analysis = usePythonAnalysis({
  taskId: () => props.taskId,
  userRole: () => props.userRole,
  enabled: () => props.enabled,
})

watch(
  analysis.state,
  (state) => emit('stateChange', state),
  { immediate: true },
)
watch(
  analysis.busy,
  (busy) => emit('busyChange', busy),
  { immediate: true },
)
onScopeDispose(() => emit('busyChange', false))

async function confirmDeleteRun(): Promise<void> {
  const run = analysis.selectedRun.value
  if (!run) return
  try {
    await ElMessageBox.confirm(
      `将删除检测版本 ${run.id.slice(-8)} 的全部发现和关联报告，不会删除反编译源码项目。`,
      '删除 Python 源码检测记录？',
      {
        confirmButtonText: '删除记录',
        cancelButtonText: '保留记录',
        type: 'warning',
        distinguishCancelAndClose: true,
      },
    )
  } catch {
    return
  }
  await analysis.deleteRun()
}

async function startProject(projectId: string): Promise<void> {
  await analysis.selectProject(projectId)
  await analysis.createRun()
}

defineExpose({
  refresh: analysis.refresh,
  startProject,
})
</script>

<template>
  <StatePanel
    v-if="analysis.state.value.status !== 'ready'"
    :kind="
      analysis.state.value.status === 'loading'
        ? 'loading'
        : analysis.state.value.status === 'error'
          ? 'error'
          : 'empty'
    "
    :title="analysis.state.value.title ?? ''"
    :description="analysis.state.value.description ?? ''"
    :retryable="analysis.state.value.status === 'error'"
    @retry="analysis.refresh"
  />
  <div v-else class="python-analysis-workspace">
    <PythonAnalysisToolbar
      :projects="analysis.projects.value"
      :runs="analysis.runs.value"
      :selected-project-id="analysis.selectedProjectId.value"
      :selected-run-id="analysis.selectedRunId.value"
      :can-create="analysis.canCreate.value"
      :can-cancel="analysis.canCancel.value"
      :can-delete-run="analysis.canDeleteRun.value"
      :creating="analysis.creating.value"
      :cancelling="analysis.cancelling.value"
      :deleting="analysis.deleting.value"
      @project-change="analysis.selectProject"
      @run-change="analysis.selectRun"
      @create="analysis.createRun"
      @cancel="analysis.cancelRun"
      @delete-run="confirmDeleteRun"
      @refresh="analysis.refresh"
    />

    <div v-if="analysis.operationError.value" class="operation-error" role="alert">
      <AlertTriangle :size="15" aria-hidden="true" />
      <span>{{ analysis.operationError.value }}</span>
      <button type="button" @click="analysis.clearOperationError">关闭</button>
    </div>

    <template v-if="analysis.selectedRun.value">
      <PythonAnalysisSummary :run="analysis.selectedRun.value" />

      <template
        v-if="['succeeded', 'partial'].includes(analysis.selectedRun.value.status)"
      >
        <PythonAnalysisFindingFilters
          :filters="analysis.filters.value"
          :disabled="analysis.findingsLoading.value"
          @apply="analysis.applyFilters"
        />
        <PythonAnalysisFindingTable
          :findings="analysis.findings.value"
          :loading="analysis.findingsLoading.value"
          :loading-more="analysis.loadingMore.value"
          :has-more="analysis.hasMoreFindings.value"
          @select="analysis.selectFinding"
          @load-more="analysis.loadMoreFindings"
        />
      </template>
      <div v-else class="run-waiting" role="status">
        <History :size="20" aria-hidden="true" />
        <strong>该检测版本尚无可展示结果</strong>
        <span>运行完成后会在此显示 CWE、规则、文件、类型、方法位置和命中行上下文片段。</span>
      </div>
    </template>
    <div v-else class="run-waiting">
      <History :size="20" aria-hidden="true" />
      <strong>该源码项目尚未执行 Python 检测</strong>
      <span v-if="analysis.canOperate.value">选择源码项目后点击“开始检测”。</span>
      <span v-else>当前没有可查看的历史检测版本。</span>
    </div>
  </div>

  <PythonAnalysisFindingDrawer
    :finding="analysis.selectedFinding.value"
    @close="analysis.selectFinding(undefined)"
    @open-source="emit('openSource', $event)"
  />
</template>

<style scoped>
.python-analysis-workspace {
  min-width: 0;
  overflow: hidden;
  container-type: inline-size;
}

.operation-error {
  display: flex;
  min-height: 38px;
  align-items: center;
  gap: 8px;
  padding: 8px 13px;
  border-bottom: 1px solid #ebcccc;
  color: #873737;
  background: #fff3f3;
  font-size: 10px;
}

.operation-error span { min-width: 0; flex: 1; overflow-wrap: anywhere; }
.operation-error button { border: 0; color: inherit; background: transparent; cursor: pointer; font-size: 9px; }

.run-waiting {
  display: grid;
  min-height: 210px;
  place-items: center;
  align-content: center;
  gap: 8px;
  padding: 24px;
  color: var(--ink-400);
  text-align: center;
}
.run-waiting strong { color: var(--ink-600); font-size: 12px; }
.run-waiting span { max-width: 520px; font-size: 10px; line-height: 1.6; }
</style>
