<script setup lang="ts">
import {
  CalendarPlus2,
  Command,
  RotateCcw,
  Square,
  Trash2,
} from 'lucide-vue-next'
import { computed, shallowRef } from 'vue'

import type { TaskDetail, UserRole } from '@/api/types'
import TaskDeleteDialog from '@/components/tasks/TaskDeleteDialog.vue'
import {
  extendSampleExpiry,
  getTaskActionModel,
  type TaskActionMode,
} from '@/components/tasks/taskActions'
import { formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  task: TaskDetail
  mode: TaskActionMode
  userRole: UserRole | null
  isCreator: boolean
  now?: Date
  pendingAction?: 'cancel' | 'retry' | 'delete' | 'extend' | null
}>()

const emit = defineEmits<{
  cancel: []
  retry: []
  delete: []
  extend: [sampleExpiresAt: string]
}>()

const cancelDialogOpen = shallowRef(false)
const deleteDialogOpen = shallowRef(false)

const model = computed(() =>
  getTaskActionModel({
    task: props.task,
    mode: props.mode,
    userRole: props.userRole,
    isCreator: props.isCreator,
    now: props.now,
  }),
)
const taskName = computed(() => props.task.original_filename || props.task.name)
const expiryLabel = computed(() => formatDateTime(props.task.sample_expires_at))
const operationPending = computed(() => props.pendingAction !== null && props.pendingAction !== undefined)
const modeLabel = computed(() =>
  props.mode === 'preview' ? '预览模式' : '在线操作',
)

function openCancelDialog(): void {
  if (model.value.cancel.enabled && !operationPending.value) {
    cancelDialogOpen.value = true
  }
}

function confirmCancel(): void {
  if (operationPending.value) return
  cancelDialogOpen.value = false
  emit('cancel')
}

function retryTask(): void {
  if (model.value.retry.enabled && !operationPending.value) emit('retry')
}

function openDeleteDialog(): void {
  if (!model.value.delete.enabled || operationPending.value) return
  deleteDialogOpen.value = true
}

function confirmDelete(): void {
  if (operationPending.value) return
  deleteDialogOpen.value = false
  emit('delete')
}

function extendRetention(): void {
  if (!model.value.extend.enabled || operationPending.value) return
  const nextExpiry = extendSampleExpiry(props.task.sample_expires_at)
  if (nextExpiry) emit('extend', nextExpiry)
}
</script>

<template>
  <section
    class="task-actions surface-panel"
    aria-labelledby="task-actions-title"
    :aria-busy="operationPending"
  >
    <header class="task-actions__context">
      <div class="task-actions__heading">
        <Command :size="16" aria-hidden="true" />
        <h2 id="task-actions-title">任务命令</h2>
        <span class="task-actions__mode">{{ modeLabel }}</span>
      </div>
      <div class="retention-summary">
        <span>样本到期</span>
        <strong>{{ expiryLabel }}</strong>
        <small v-if="model.sampleDeleted">任务原始样本已清理</small>
        <small v-else-if="model.sampleExpired">保留期已到，等待后台清理</small>
      </div>
    </header>

    <div class="task-actions__commands" role="group" aria-label="任务操作命令">
      <div
        class="task-action"
        :title="model.cancel.reason"
        :tabindex="!model.cancel.enabled || operationPending ? 0 : -1"
        aria-describedby="cancel-action-reason"
      >
        <el-button
          data-action="cancel"
          size="small"
          :icon="Square"
          :loading="pendingAction === 'cancel'"
          :disabled="!model.cancel.enabled || operationPending"
          :title="model.cancel.reason"
          aria-describedby="cancel-action-reason"
          @click="openCancelDialog"
        >
          取消
        </el-button>
        <span id="cancel-action-reason" class="sr-only">
          {{ model.cancel.reason }}
        </span>
      </div>

      <div
        class="task-action"
        :title="model.retry.reason"
        :tabindex="!model.retry.enabled || operationPending ? 0 : -1"
        aria-describedby="retry-action-reason"
      >
        <el-button
          data-action="retry"
          size="small"
          :icon="RotateCcw"
          :loading="pendingAction === 'retry'"
          :disabled="!model.retry.enabled || operationPending"
          :title="model.retry.reason"
          aria-describedby="retry-action-reason"
          @click="retryTask"
        >
          重检
        </el-button>
        <span id="retry-action-reason" class="sr-only">
          {{ model.retry.reason }}
        </span>
      </div>

      <div
        class="task-action"
        :title="model.extend.reason"
        :tabindex="!model.extend.enabled || operationPending ? 0 : -1"
        aria-describedby="extend-action-reason"
      >
        <el-button
          data-action="extend"
          size="small"
          :icon="CalendarPlus2"
          :loading="pendingAction === 'extend'"
          :disabled="!model.extend.enabled || operationPending"
          :title="model.extend.reason"
          aria-describedby="extend-action-reason"
          @click="extendRetention"
        >
          延期 15 天
        </el-button>
        <span id="extend-action-reason" class="sr-only">
          {{ model.extend.reason }}
        </span>
      </div>

      <div
        class="task-action task-action--danger"
        :title="model.delete.reason"
        :tabindex="!model.delete.enabled || operationPending ? 0 : -1"
        aria-describedby="delete-action-reason"
      >
        <el-button
          data-action="delete"
          size="small"
          type="danger"
          plain
          :icon="Trash2"
          :loading="pendingAction === 'delete'"
          :disabled="!model.delete.enabled || operationPending"
          :title="model.delete.reason"
          aria-describedby="delete-action-reason"
          @click="openDeleteDialog"
        >
          删除
        </el-button>
        <span id="delete-action-reason" class="sr-only">
          {{ model.delete.reason }}
        </span>
      </div>
    </div>

    <el-dialog
      v-model="cancelDialogOpen"
      title="取消当前任务？"
      width="min(440px, calc(100vw - 32px))"
      align-center
    >
      <p class="dialog-copy">
        任务将先进入“请求取消”状态，正在运行的分析步骤会被终止。已有的完整结果仍会保留。
      </p>
      <template #footer>
        <el-button @click="cancelDialogOpen = false">继续执行</el-button>
        <el-button
          type="warning"
          data-confirm="cancel"
          :disabled="operationPending"
          @click="confirmCancel"
        >
          确认取消
        </el-button>
      </template>
    </el-dialog>

    <TaskDeleteDialog
      v-model="deleteDialogOpen"
      :task-name="taskName"
      :pending="pendingAction === 'delete'"
      @confirm="confirmDelete"
    />
  </section>
</template>

<style scoped>
.task-actions {
  display: grid;
  min-height: 62px;
  grid-template-columns: minmax(300px, 1fr) auto;
  align-items: stretch;
  overflow: hidden;
}

.task-actions__context {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 18px;
  padding: 9px 14px;
}

.task-actions__heading {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
  color: var(--teal-strong);
}

.task-actions__heading h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
  white-space: nowrap;
}

.task-actions__mode {
  padding: 1px 5px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 9px;
  white-space: nowrap;
}

.retention-summary {
  display: grid;
  min-width: 0;
  flex: 0 0 auto;
  grid-template-columns: auto minmax(0, auto);
  align-items: baseline;
  column-gap: 7px;
  justify-items: end;
  margin-left: auto;
}

.retention-summary span,
.retention-summary small {
  color: var(--ink-600);
  font-size: 10px;
}

.retention-summary strong {
  min-width: 0;
  color: var(--ink-800);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.retention-summary small {
  grid-column: 1 / -1;
  color: var(--red);
  font-weight: 700;
}

.task-actions__commands {
  display: grid;
  min-width: 446px;
  grid-template-columns: repeat(4, minmax(98px, 1fr));
  align-items: center;
  gap: 6px;
  padding: 9px 12px;
  border-left: 1px solid var(--line);
  background: #f7f9f9;
}

.task-action {
  min-width: 0;
}

.task-action :deep(.el-button) {
  min-height: 32px;
  width: 100%;
  margin: 0;
}

.task-action :deep(.el-button > span) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dialog-copy {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
  line-height: 1.7;
}

@container (max-width: 920px) {
  .task-actions {
    grid-template-columns: 1fr;
  }

  .task-actions__context {
    border-bottom: 1px solid var(--line);
  }

  .task-actions__commands {
    min-width: 0;
    border-left: 0;
  }
}

@container (max-width: 540px) {
  .task-actions__context {
    align-items: flex-start;
    flex-direction: column;
    gap: 7px;
  }

  .retention-summary {
    width: 100%;
    justify-items: start;
    margin-left: 0;
  }

  .retention-summary small {
    justify-self: start;
  }

  .task-actions__commands {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    padding: 8px 10px 10px;
  }
}

@container (max-width: 360px) {
  .retention-summary {
    grid-template-columns: 1fr;
  }

  .retention-summary strong {
    white-space: normal;
  }

  .retention-summary small {
    grid-column: 1;
  }
}
</style>
