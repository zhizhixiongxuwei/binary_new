<script setup lang="ts">
import {
  CodeXml,
  FileArchive,
  FileJson2,
  ShieldCheck,
} from 'lucide-vue-next'
import {
  computed,
  nextTick,
  useId,
  useTemplateRef,
  watch,
  type CSSProperties,
  type Component,
} from 'vue'

import TaskResultPane from '@/components/tasks/TaskResultPane.vue'
import {
  TASK_RESULT_TABS,
  type TaskResultCommand,
  type TaskResultCommandStates,
  type TaskResultMode,
  type TaskResultPaneAction,
  type TaskResultState,
  type TaskResultStates,
  type TaskResultTab,
} from '@/components/tasks/taskResultTypes'

const props = withDefaults(
  defineProps<{
    taskId: string
    mode?: TaskResultMode
    states?: TaskResultStates
    commands?: TaskResultCommandStates
    managedTabs?: readonly TaskResultTab[]
    visibleTabs?: readonly TaskResultTab[]
  }>(),
  {
    mode: 'live',
    states: () => ({}),
    commands: () => ({}),
    managedTabs: () => [],
    visibleTabs: () => TASK_RESULT_TABS,
  },
)

const activeTab = defineModel<TaskResultTab>('activeTab', {
  default: 'files',
})

const emit = defineEmits<{
  tabChange: [tab: TaskResultTab]
  command: [command: TaskResultCommand]
}>()

const slots = defineSlots<{
  files?: (props: {
    taskId: string
    state: TaskResultState
    mode: TaskResultMode
  }) => unknown
  decompile?: (props: {
    taskId: string
    state: TaskResultState
    mode: TaskResultMode
  }) => unknown
  vulnerabilities?: (props: {
    taskId: string
    state: TaskResultState
    mode: TaskResultMode
  }) => unknown
  reports?: (props: {
    taskId: string
    state: TaskResultState
    mode: TaskResultMode
  }) => unknown
}>()

interface TabDefinition {
  id: TaskResultTab
  label: string
  icon: Component
}

const tabDefinitions: readonly TabDefinition[] = [
  { id: 'files', label: '文件结构', icon: FileArchive },
  { id: 'decompile', label: '反编译', icon: CodeXml },
  { id: 'vulnerabilities', label: '容器漏洞', icon: ShieldCheck },
  { id: 'reports', label: '报告', icon: FileJson2 },
]

const tabs = computed<readonly TabDefinition[]>(() => {
  const requested = new Set(props.visibleTabs)
  const selected = tabDefinitions.filter((tab) => requested.has(tab.id))
  return selected.length > 0 ? selected : [tabDefinitions[0]!]
})

const tabListStyle = computed<CSSProperties>(() => ({
  gridTemplateColumns: `repeat(${tabs.value.length}, minmax(140px, 1fr))`,
  minWidth: `${tabs.value.length * 140}px`,
}))

const unavailableStates: Readonly<Record<TaskResultTab, TaskResultState>> = {
  files: {
    status: 'unavailable',
    title: '文件结构视图未接入',
    description: '当前页面没有可用的文件结构数据源。',
  },
  decompile: {
    status: 'unavailable',
    title: '反编译结果未接入',
    description: '当前任务没有可读取的反编译结果。',
  },
  vulnerabilities: {
    status: 'unavailable',
    title: '容器漏洞结果未接入',
    description: '当前任务没有可读取的容器漏洞结果。',
  },
  reports: {
    status: 'unavailable',
    title: '报告结果未接入',
    description: '当前任务没有可读取的 JSON 或 HTML 报告。',
  },
}

const workspaceId = `task-result-${useId().replace(/:/g, '')}`
const tabList = useTemplateRef<HTMLElement>('tabList')

function hasSlot(tab: TaskResultTab): boolean {
  return Boolean(slots[tab])
}

function contentOwnsState(tab: TaskResultTab): boolean {
  return props.managedTabs.includes(tab)
}

function resolveState(tab: TaskResultTab): TaskResultState {
  const provided = props.states[tab]
  if (provided?.status === 'ready' && !hasSlot(tab)) {
    return unavailableStates[tab]
  }
  if (provided) return provided
  if (hasSlot(tab)) return { status: 'ready' }
  return unavailableStates[tab]
}

const paneStates = computed<Readonly<Record<TaskResultTab, TaskResultState>>>(() => ({
  files: resolveState('files'),
  decompile: resolveState('decompile'),
  vulnerabilities: resolveState('vulnerabilities'),
  reports: resolveState('reports'),
}))

function commandState(command: TaskResultCommand): {
  enabled: boolean
  pending: boolean
} {
  const state = props.commands[command]
  return {
    enabled: state?.enabled ?? false,
    pending: state?.pending ?? false,
  }
}

function action(
  id: TaskResultCommand,
  label: string,
  icon: TaskResultPaneAction['icon'],
  options: {
    shortLabel?: string
    requiresReady?: boolean
  } = {},
): TaskResultPaneAction {
  const state = commandState(id)
  return {
    id,
    label,
    icon,
    requiresReady: options.requiresReady ?? false,
    ...(options.shortLabel ? { shortLabel: options.shortLabel } : {}),
    ...state,
  }
}

const actions = computed<Readonly<Record<TaskResultTab, readonly TaskResultPaneAction[]>>>(() => ({
  files: [],
  decompile: [
    action('refresh-decompile', '刷新反编译历史结果', 'refresh'),
    action('download-decompile', '下载反编译结果', 'download', {
      requiresReady: true,
    }),
  ],
  vulnerabilities: [
    action('refresh-vulnerabilities', '刷新容器漏洞结果', 'refresh'),
    action('export-vulnerabilities', '导出容器漏洞结果', 'download', {
      requiresReady: true,
    }),
  ],
  reports:
    props.mode === 'preview'
      ? [
          action('download-report-json', '下载 JSON 报告', 'download', {
            shortLabel: 'JSON',
            requiresReady: true,
          }),
          action('download-report-html', '下载 HTML 报告', 'download', {
            shortLabel: 'HTML',
            requiresReady: true,
          }),
        ]
      : [action('refresh-reports', '刷新报告状态', 'refresh')],
}))

function tabId(tab: TaskResultTab): string {
  return `${workspaceId}-tab-${tab}`
}

function panelId(tab: TaskResultTab): string {
  return `${workspaceId}-panel-${tab}`
}

function selectTab(tab: TaskResultTab): void {
  if (!tabs.value.some((candidate) => candidate.id === tab)) return
  if (activeTab.value === tab) return
  activeTab.value = tab
  emit('tabChange', tab)
}

function focusTab(tab: TaskResultTab): void {
  void nextTick(() => {
    tabList.value
      ?.querySelector<HTMLButtonElement>(`[data-result-tab="${tab}"]`)
      ?.focus()
  })
}

function handleTabKeydown(event: KeyboardEvent, tab: TaskResultTab): void {
  const visibleTabIds = tabs.value.map((candidate) => candidate.id)
  const currentIndex = visibleTabIds.indexOf(tab)
  if (currentIndex < 0) return
  let nextIndex: number | undefined

  if (event.key === 'ArrowRight') {
    nextIndex = (currentIndex + 1) % visibleTabIds.length
  } else if (event.key === 'ArrowLeft') {
    nextIndex =
      (currentIndex - 1 + visibleTabIds.length) % visibleTabIds.length
  } else if (event.key === 'Home') {
    nextIndex = 0
  } else if (event.key === 'End') {
    nextIndex = visibleTabIds.length - 1
  }

  if (nextIndex === undefined) return
  event.preventDefault()
  const nextTab = visibleTabIds[nextIndex]
  if (!nextTab) return
  selectTab(nextTab)
  focusTab(nextTab)
}

watch(
  tabs,
  (visibleTabs) => {
    if (visibleTabs.some((tab) => tab.id === activeTab.value)) return
    const fallback = visibleTabs[0]?.id
    if (fallback) selectTab(fallback)
  },
  { immediate: true },
)
</script>

<template>
  <section class="task-result-workspace" aria-label="任务检测结果">
    <div class="task-result-workspace__tab-scroll">
      <div
        ref="tabList"
        class="task-result-workspace__tabs"
        :style="tabListStyle"
        role="tablist"
        aria-label="检测结果视图"
      >
        <button
          v-for="tab in tabs"
          :id="tabId(tab.id)"
          :key="tab.id"
          class="task-result-workspace__tab"
          :class="{ 'task-result-workspace__tab--active': activeTab === tab.id }"
          type="button"
          role="tab"
          :data-result-tab="tab.id"
          :aria-selected="activeTab === tab.id"
          :aria-controls="panelId(tab.id)"
          :tabindex="activeTab === tab.id ? 0 : -1"
          @click="selectTab(tab.id)"
          @keydown="handleTabKeydown($event, tab.id)"
        >
          <component :is="tab.icon" :size="15" aria-hidden="true" />
          <span>{{ tab.label }}</span>
        </button>
      </div>
    </div>

    <div
      :id="panelId(activeTab)"
      class="task-result-workspace__panel"
      role="tabpanel"
      tabindex="0"
      :aria-labelledby="tabId(activeTab)"
    >
      <TaskResultPane
        v-if="activeTab === 'files'"
        kind="files"
        :state="paneStates.files"
        :actions="actions.files"
        :preview="mode === 'preview'"
        :content-owns-state="contentOwnsState('files')"
        @command="emit('command', $event)"
      >
        <slot
          v-if="slots.files"
          name="files"
          :task-id="taskId"
          :state="paneStates.files"
          :mode="mode"
        />
      </TaskResultPane>

      <TaskResultPane
        v-else-if="activeTab === 'decompile'"
        kind="decompile"
        :state="paneStates.decompile"
        :actions="actions.decompile"
        :preview="mode === 'preview'"
        :content-owns-state="contentOwnsState('decompile')"
        @command="emit('command', $event)"
      >
        <slot
          v-if="slots.decompile"
          name="decompile"
          :task-id="taskId"
          :state="paneStates.decompile"
          :mode="mode"
        />
      </TaskResultPane>

      <TaskResultPane
        v-else-if="activeTab === 'vulnerabilities'"
        kind="vulnerabilities"
        :state="paneStates.vulnerabilities"
        :actions="actions.vulnerabilities"
        :preview="mode === 'preview'"
        :content-owns-state="contentOwnsState('vulnerabilities')"
        @command="emit('command', $event)"
      >
        <slot
          v-if="slots.vulnerabilities"
          name="vulnerabilities"
          :task-id="taskId"
          :state="paneStates.vulnerabilities"
          :mode="mode"
        />
      </TaskResultPane>

      <TaskResultPane
        v-else
        kind="reports"
        :state="paneStates.reports"
        :actions="actions.reports"
        :preview="mode === 'preview'"
        :content-owns-state="contentOwnsState('reports')"
        @command="emit('command', $event)"
      >
        <slot
          v-if="slots.reports"
          name="reports"
          :task-id="taskId"
          :state="paneStates.reports"
          :mode="mode"
        />
      </TaskResultPane>
    </div>
  </section>
</template>

<style scoped>
.task-result-workspace {
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--surface);
  box-shadow: 0 1px 2px rgb(23 36 39 / 5%);
  container-type: inline-size;
}

.task-result-workspace__tab-scroll {
  overflow-x: auto;
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
  scrollbar-width: thin;
}

.task-result-workspace__tabs {
  display: grid;
}

.task-result-workspace__tab {
  position: relative;
  display: inline-flex;
  min-width: 0;
  min-height: 46px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  padding: 8px 14px;
  border: 0;
  border-right: 1px solid #e4e8e9;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.task-result-workspace__tab:last-child {
  border-right: 0;
}

.task-result-workspace__tab::after {
  position: absolute;
  right: 16px;
  bottom: 0;
  left: 16px;
  height: 2px;
  background: transparent;
  content: "";
}

.task-result-workspace__tab:hover {
  color: var(--teal-strong);
  background: #f0f6f5;
}

.task-result-workspace__tab--active {
  color: var(--teal-strong);
  background: var(--surface);
}

.task-result-workspace__tab--active::after {
  background: var(--teal);
}

.task-result-workspace__panel {
  min-width: 0;
}

</style>
