<script setup lang="ts">
import {
  CheckCircle2,
  FolderCode,
  LoaderCircle,
  RotateCw,
  TriangleAlert,
  X,
} from 'lucide-vue-next'
import { shallowRef, watch } from 'vue'

import type {
  ConfirmDecompileProjectDeletionInput,
  DecompileProject,
  DecompileProjectDeletionOperation,
  DecompileProjectDeletionPreview,
  UserRole,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import DecompileProjectDeleteDialog from '@/components/tasks/decompile-projects/DecompileProjectDeleteDialog.vue'
import DecompileProjectTable from '@/components/tasks/decompile-projects/DecompileProjectTable.vue'
import { useDecompileProjects } from '@/composables/useDecompileProjects'

const props = withDefaults(
  defineProps<{
    taskId: string
    userRole: UserRole | null
    enabled?: boolean
  }>(),
  {
    enabled: true,
  },
)

const emit = defineEmits<{
  deleted: [projectId: string]
  analyze: [projectId: string]
  analyzeJava: [projectId: string]
}>()

const selectedProject = shallowRef<DecompileProject | null>(null)
const deletionPreview = shallowRef<DecompileProjectDeletionPreview>()
const projects = useDecompileProjects({
  taskId: () => props.taskId,
  userRole: () => props.userRole,
  enabled: () => props.enabled,
})

watch(
  () => props.taskId,
  () => {
    selectedProject.value = null
    deletionPreview.value = undefined
  },
)

async function openDelete(project: DecompileProject): Promise<void> {
  if (!projects.canDelete.value) return
  projects.clearOperationError()
  selectedProject.value = project
  deletionPreview.value = undefined
  deletionPreview.value = await projects.previewProjectDeletion(project.id)
}

function closeDelete(): void {
  if (
    projects.deletingProjectId.value ||
    projects.previewingProjectId.value
  ) return
  selectedProject.value = null
  deletionPreview.value = undefined
  projects.clearOperationError()
}

async function confirmDelete(
  input: ConfirmDecompileProjectDeletionInput,
): Promise<void> {
  const project = selectedProject.value
  if (!project) return
  const operation = await projects.deleteProject(project.id, input)
  if (!operation) return
  selectedProject.value = null
  deletionPreview.value = undefined
  emit('deleted', project.id)
}

function refresh(): void {
  projects.refresh()
}

function deletionStatusText(
  operation: DecompileProjectDeletionOperation,
): string {
  const project = operation.project_id.slice(-8)
  const additional = Math.max(
    0,
    projects.activeDeletionOperationCount.value - 1,
  )
  const suffix = additional ? `，另有 ${additional} 个清理操作进行中` : ''
  switch (operation.status) {
    case 'complete':
      return `源码项目 ${project} 及全部衍生结果已清理完成`
    case 'cancelling':
      return `正在停止源码项目 ${project} 的关联检测${suffix}`
    case 'deleting':
      return `正在清理源码项目 ${project} 及全部衍生结果${suffix}`
    case 'failed':
      return `源码项目 ${project} 清理暂时失败，系统正在自动重试${operation.error_message ? `：${operation.error_message}` : ''}${suffix}`
    default:
      return `源码项目 ${project} 的删除请求已受理，等待后台清理${suffix}`
  }
}

defineExpose({ refresh })
</script>

<template>
  <section class="project-panel surface-panel" aria-labelledby="decompile-project-title">
    <header class="project-panel__header">
      <div class="project-panel__title">
        <FolderCode :size="17" aria-hidden="true" />
        <h2 id="decompile-project-title">反编译源码项目</h2>
        <span v-if="projects.projects.value.length" class="project-panel__count">
          {{ projects.projects.value.length }}
        </span>
      </div>
      <button
        type="button"
        title="刷新源码项目列表"
        aria-label="刷新源码项目列表"
        :disabled="projects.loading.value || !enabled"
        @click="refresh"
      >
        <RotateCw
          :class="{ spin: projects.loading.value }"
          :size="14"
          aria-hidden="true"
        />
      </button>
    </header>

    <div
      v-if="projects.latestDeletionOperation.value"
      class="project-panel__operation"
      :class="`project-panel__operation--${projects.latestDeletionOperation.value.status}`"
      :role="projects.latestDeletionOperation.value.status === 'failed' ? 'alert' : 'status'"
      aria-live="polite"
    >
      <CheckCircle2
        v-if="projects.latestDeletionOperation.value.status === 'complete'"
        :size="14"
        aria-hidden="true"
      />
      <TriangleAlert
        v-else-if="projects.latestDeletionOperation.value.status === 'failed'"
        :size="14"
        aria-hidden="true"
      />
      <LoaderCircle v-else class="spin" :size="14" aria-hidden="true" />
      <span>{{ deletionStatusText(projects.latestDeletionOperation.value) }}</span>
    </div>

    <div
      v-if="projects.operationError.value && !selectedProject"
      class="project-panel__error"
      role="alert"
    >
      <span>{{ projects.operationError.value }}</span>
      <button
        type="button"
        title="关闭错误提示"
        aria-label="关闭错误提示"
        @click="projects.clearOperationError"
      >
        <X :size="13" aria-hidden="true" />
      </button>
    </div>
    <div
      v-if="projects.deletionPollError.value"
      class="project-panel__error"
      role="alert"
    >
      <span>{{ projects.deletionPollError.value }}</span>
      <button
        type="button"
        title="关闭进度错误提示"
        aria-label="关闭进度错误提示"
        @click="projects.clearDeletionPollError"
      >
        <X :size="13" aria-hidden="true" />
      </button>
    </div>

    <StatePanel
      v-if="projects.loading.value"
      class="project-panel__state"
      kind="loading"
      title="正在读取源码项目版本"
    />
    <StatePanel
      v-else-if="projects.error.value"
      class="project-panel__state"
      kind="error"
      title="源码项目读取失败"
      :description="projects.error.value"
      retryable
      @retry="refresh"
    />
    <StatePanel
      v-else-if="!projects.projects.value.length"
      class="project-panel__state"
      kind="empty"
      title="暂无反编译源码项目"
      description="该任务尚未保存独立的反编译源码版本。"
    />
    <template v-else>
      <DecompileProjectTable
        :projects="projects.projects.value"
        :can-delete="projects.canDelete.value"
        :loading-more="projects.loadingMore.value"
        :has-more="projects.hasMore.value"
        :downloading-project-id="projects.downloadingProjectId.value"
        :deleting-project-id="projects.deletingProjectId.value"
        :latest-c-analysis-by-project="projects.latestCAnalysisByProject.value"
        :latest-java-analysis-by-project="projects.latestJavaAnalysisByProject.value"
        :can-analyze="projects.canDelete.value"
        @download="projects.downloadProject($event.id)"
        @delete="openDelete"
        @analyze="emit('analyze', $event.id)"
        @analyze-java="emit('analyzeJava', $event.id)"
        @load-more="projects.loadMore"
      />
    </template>
  </section>

  <DecompileProjectDeleteDialog
    :project="selectedProject"
    :pending="Boolean(projects.deletingProjectId.value)"
    :preview-loading="projects.previewingProjectId.value === selectedProject?.id"
    :preview="deletionPreview"
    :error-message="selectedProject ? projects.operationError.value : ''"
    @cancel="closeDelete"
    @confirm="confirmDelete"
  />
</template>

<style scoped>
.project-panel {
  min-width: 0;
  overflow: hidden;
  container-type: inline-size;
}

.project-panel__header {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 0 12px 0 16px;
  border-bottom: 1px solid var(--line);
}

.project-panel__title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  color: var(--teal-strong);
}

.project-panel__title h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
}

.project-panel__count {
  display: inline-grid;
  min-width: 22px;
  height: 20px;
  place-items: center;
  padding: 0 5px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: #f3f6f6;
  font-size: 9px;
}

.project-panel__header > button,
.project-panel__error button {
  display: inline-grid;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.project-panel__header > button:hover:not(:disabled),
.project-panel__error button:hover:not(:disabled) {
  border-color: var(--teal);
  color: var(--teal-strong);
}

.project-panel__header > button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.project-panel__state {
  min-height: 164px;
  border: 0;
  border-radius: 0;
  box-shadow: none;
}

.project-panel__operation {
  display: flex;
  min-height: 36px;
  align-items: center;
  gap: 8px;
  padding: 7px 13px;
  border-left: 3px solid var(--teal);
  color: var(--ink-700);
  background: #eef8f6;
  font-size: 11px;
}

.project-panel__operation > svg {
  flex: 0 0 auto;
  color: var(--teal-strong);
}

.project-panel__operation > span {
  min-width: 0;
  overflow-wrap: anywhere;
}

.project-panel__operation--complete {
  border-left-color: #2f7d58;
  background: #edf8f1;
}

.project-panel__operation--failed {
  border-left-color: var(--red);
  color: #7e3030;
  background: #fff2f2;
}

.project-panel__operation--failed > svg {
  color: var(--red);
}

.project-panel__error {
  display: flex;
  min-height: 38px;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 7px 10px 7px 13px;
  border-left: 3px solid var(--red);
  color: #7e3030;
  background: #fff2f2;
  font-size: 11px;
}

.project-panel__error span {
  min-width: 0;
  overflow-wrap: anywhere;
}

.project-panel__error button {
  width: 26px;
  height: 26px;
  flex-basis: 26px;
  border-color: transparent;
  color: #7e3030;
  background: transparent;
}

.spin {
  animation: project-panel-spin 1s linear infinite;
}

@keyframes project-panel-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
