<script setup lang="ts">
import { AlertTriangle, LoaderCircle } from 'lucide-vue-next'
import { computed, reactive, shallowRef, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, ApiError } from '@/api/client'
import type { ScanTask, TaskListQuery, UserRole } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import TaskDeleteDialog from '@/components/tasks/TaskDeleteDialog.vue'
import TaskFilterBar, { type TaskFilterValue } from '@/components/tasks/TaskFilterBar.vue'
import {
  parseTaskListRouteQuery,
  serializeTaskListRouteQuery,
  taskRouteQueryIsCanonical,
  type TaskListRouteState,
} from '@/components/tasks/taskListFilters'
import TaskTable from '@/components/tasks/TaskTable.vue'
import { getTaskActionModel } from '@/components/tasks/taskActions'
import { useTaskList } from '@/composables/useTaskList'

const props = withDefaults(
  defineProps<{
    userRole?: UserRole | null
    currentUserId?: string | null
  }>(),
  {
    userRole: null,
    currentUserId: null,
  },
)

const route = useRoute()
const router = useRouter()
const query = reactive<TaskListRouteState>(parseTaskListRouteQuery(route.query))
const taskList = useTaskList()
const cursorHistory = shallowRef<string[]>([])
const deleteDialogOpen = shallowRef(false)
const deleteTarget = shallowRef<ScanTask | null>(null)
const deletingTaskId = shallowRef<string | null>(null)
const deleteError = shallowRef('')
const deleteFeedback = shallowRef('')
let lastLoadedQueryKey = ''
let paginationContextKey = ''
let expectedRouteCursor: string | undefined

const appliedFilters = computed<TaskFilterValue>(() => ({
  keyword: query.keyword,
  status: query.status,
  input_type: query.input_type,
  creator: query.creator,
  tag: query.tag,
  created_from: query.created_from,
  created_to: query.created_to,
}))

function requestQuery(state: TaskListRouteState = query): TaskListQuery {
  const value: TaskListQuery = {
    page_size: state.page_size,
  }
  if (state.cursor) value.cursor = state.cursor
  if (state.keyword) value.keyword = state.keyword
  if (state.status) value.status = state.status
  if (state.input_type) value.input_type = state.input_type
  if (state.creator) value.creator = state.creator
  if (state.tag) value.tag = state.tag
  if (state.created_from) value.created_from = state.created_from
  if (state.created_to) value.created_to = state.created_to
  return value
}

function contextKey(state: TaskListRouteState): string {
  return JSON.stringify({
    keyword: state.keyword,
    status: state.status,
    input_type: state.input_type,
    creator: state.creator,
    tag: state.tag,
    created_from: state.created_from,
    created_to: state.created_to,
    page_size: state.page_size,
  })
}

function requestKey(value: TaskListQuery): string {
  return JSON.stringify(value)
}

function loadRouteState(state: TaskListRouteState): void {
  const value = requestQuery(state)
  const key = requestKey(value)
  if (key === lastLoadedQueryKey) return
  lastLoadedQueryKey = key
  void taskList.load(value)
}

function navigate(nextState: TaskListRouteState): void {
  const nextQuery = serializeTaskListRouteQuery(nextState)
  if (taskRouteQueryIsCanonical(route.query, nextQuery)) {
    lastLoadedQueryKey = ''
    loadRouteState(nextState)
    return
  }
  void router.push({ query: nextQuery })
}

function applyFilters(value: TaskFilterValue): void {
  cursorHistory.value = []
  expectedRouteCursor = ''
  navigate({
    ...query,
    ...value,
    cursor: '',
  })
}

function resetFilters(): void {
  cursorHistory.value = []
  expectedRouteCursor = ''
  navigate({
    ...query,
    keyword: '',
    status: '',
    input_type: '',
    creator: '',
    tag: '',
    created_from: '',
    created_to: '',
    cursor: '',
  })
}

function showFirstPage(): void {
  if (!query.cursor) return
  cursorHistory.value = []
  expectedRouteCursor = ''
  navigate({ ...query, cursor: '' })
}

function showPreviousPage(): void {
  const previousCursor = cursorHistory.value[cursorHistory.value.length - 1]
  if (previousCursor === undefined) return
  cursorHistory.value = cursorHistory.value.slice(0, -1)
  expectedRouteCursor = previousCursor
  navigate({ ...query, cursor: previousCursor })
}

function showNextPage(): void {
  const nextCursor = taskList.nextCursor.value
  if (!nextCursor || nextCursor === query.cursor) return
  cursorHistory.value = [...cursorHistory.value, query.cursor]
  expectedRouteCursor = nextCursor
  navigate({ ...query, cursor: nextCursor })
}

function changePageSize(pageSize: number): void {
  if (![10, 20, 50].includes(pageSize)) return
  cursorHistory.value = []
  expectedRouteCursor = ''
  navigate({
    ...query,
    cursor: '',
    page_size: pageSize as TaskListRouteState['page_size'],
  })
}

function requestDelete(task: ScanTask): void {
  const action = getTaskActionModel({
    task,
    mode: 'live',
    userRole: props.userRole,
    isCreator: props.currentUserId === task.creator_id,
  }).delete
  if (!action.enabled || deletingTaskId.value) return
  deleteTarget.value = task
  deleteError.value = ''
  deleteDialogOpen.value = true
}

async function confirmDelete(): Promise<void> {
  const target = deleteTarget.value
  if (!target || deletingTaskId.value) return
  deletingTaskId.value = target.id
  deleteError.value = ''
  deleteFeedback.value = ''
  try {
    await api.deleteTask(target.id)
    deleteDialogOpen.value = false
    deleteFeedback.value = `“${target.name}”已进入删除流程。`
    await taskList.reload()
  } catch (error) {
    deleteError.value =
      error instanceof ApiError
        ? error.message
        : error instanceof Error
          ? error.message
          : '任务删除请求提交失败'
  } finally {
    deletingTaskId.value = null
  }
}

watch(
  () => route.query,
  (routeQuery) => {
    const nextState = parseTaskListRouteQuery(routeQuery)
    const nextContextKey = contextKey(nextState)
    if (paginationContextKey && paginationContextKey !== nextContextKey) {
      cursorHistory.value = []
    }
    paginationContextKey = nextContextKey
    if (
      nextState.cursor !== query.cursor &&
      nextState.cursor !== expectedRouteCursor
    ) {
      cursorHistory.value = []
    }
    expectedRouteCursor = undefined
    Object.assign(query, nextState)

    const canonicalQuery = serializeTaskListRouteQuery(nextState)
    if (!taskRouteQueryIsCanonical(routeQuery, canonicalQuery)) {
      void router.replace({ query: canonicalQuery })
    }
    loadRouteState(nextState)
  },
  { immediate: true, deep: true },
)
</script>

<template>
  <section class="surface-panel" aria-label="检测任务列表">
    <TaskFilterBar
      :initial-value="appliedFilters"
      @apply="applyFilters"
      @reset="resetFilters"
    />
    <StatePanel
      v-if="taskList.loading.value && taskList.items.value.length === 0"
      kind="loading"
    />
    <StatePanel
      v-else-if="taskList.errorMessage.value && taskList.items.value.length === 0"
      kind="error"
      title="任务列表读取失败"
      :description="taskList.errorMessage.value"
      retryable
      @retry="taskList.reload"
    />
    <StatePanel
      v-else-if="taskList.items.value.length === 0 && !query.cursor"
      kind="empty"
      title="暂无检测任务"
    />
    <div
      v-else
      class="task-list__results"
      :aria-busy="taskList.loading.value ? 'true' : 'false'"
    >
      <div
        v-if="deleteFeedback"
        class="task-list__notice task-list__notice--success"
        role="status"
        aria-live="polite"
      >
        {{ deleteFeedback }}
      </div>
      <div
        v-if="taskList.loading.value"
        class="task-list__notice task-list__notice--loading"
        role="status"
        aria-live="polite"
      >
        <LoaderCircle class="spin" :size="15" />
        正在刷新任务列表
      </div>
      <div
        v-if="taskList.errorMessage.value"
        class="task-list__notice task-list__notice--error"
        role="alert"
      >
        <AlertTriangle :size="15" />
        <span>{{ taskList.errorMessage.value }}</span>
        <el-button plain size="small" @click="taskList.reload">重试</el-button>
      </div>
      <TaskTable
        :items="taskList.items.value"
        :page-size="query.page_size"
        :has-previous="cursorHistory.length > 0"
        :has-next="Boolean(
          taskList.nextCursor.value && taskList.nextCursor.value !== query.cursor
        )"
        :can-reset="Boolean(query.cursor)"
        :loading="taskList.loading.value"
        :user-role="userRole"
        :current-user-id="currentUserId"
        :pending-task-id="deletingTaskId"
        @open="router.push({ name: 'task-detail', params: { id: $event } })"
        @delete="requestDelete"
        @first-page="showFirstPage"
        @previous-page="showPreviousPage"
        @next-page="showNextPage"
        @page-size-change="changePageSize"
      />
    </div>
    <TaskDeleteDialog
      v-if="deleteTarget"
      v-model="deleteDialogOpen"
      :task-name="deleteTarget.name"
      :pending="deletingTaskId === deleteTarget.id"
      :error-message="deleteError"
      @confirm="confirmDelete"
    />
  </section>
</template>

<style scoped>
.task-list__results {
  min-width: 0;
}

.task-list__notice {
  display: flex;
  min-height: 38px;
  align-items: center;
  gap: 8px;
  padding: 7px 14px;
  border-bottom: 1px solid var(--line);
  font-size: 12px;
}

.task-list__notice--loading {
  color: var(--ink-600);
  background: #f4f8fa;
}

.task-list__notice--error {
  color: #8d2929;
  background: #fff5f5;
}

.task-list__notice--success {
  color: #165f54;
  background: #eef8f6;
}

.task-list__notice--error span {
  min-width: 0;
  flex: 1;
}

.spin {
  flex: 0 0 auto;
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 540px) {
  .task-list__notice {
    align-items: flex-start;
    flex-wrap: wrap;
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
