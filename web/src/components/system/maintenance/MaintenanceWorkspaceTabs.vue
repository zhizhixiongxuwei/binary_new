<script setup lang="ts">
import {
  Activity,
  DatabaseZap,
  FolderCog,
  ScrollText,
  ShieldCheck,
} from 'lucide-vue-next'
import {
  nextTick,
  shallowRef,
  useId,
  useTemplateRef,
  type Component,
} from 'vue'

import {
  MAINTENANCE_TABS,
  type MaintenanceTab,
} from '@/components/system/maintenance/maintenanceTypes'

defineSlots<{
  runtime: () => unknown
  storage: () => unknown
  analyzers: () => unknown
  access: () => unknown
  audit: () => unknown
}>()

interface MaintenanceTabDefinition {
  id: MaintenanceTab
  label: string
  caption: string
  icon: Component
}

const tabs: readonly MaintenanceTabDefinition[] = [
  { id: 'runtime', label: '运行状态', caption: '服务与任务', icon: Activity },
  { id: 'storage', label: '存储路径', caption: '挂载与容量', icon: FolderCog },
  { id: 'analyzers', label: '分析器 / 离线库', caption: '工具与数据批次', icon: DatabaseZap },
  { id: 'access', label: '用户与角色', caption: '本地权限边界', icon: ShieldCheck },
  { id: 'audit', label: '审计日志', caption: '操作事件', icon: ScrollText },
]

const activeTab = shallowRef<MaintenanceTab>('runtime')
const workspaceId = `system-maintenance-${useId().replace(/:/g, '')}`
const tabList = useTemplateRef<HTMLElement>('tabList')

function tabId(tab: MaintenanceTab): string {
  return `${workspaceId}-tab-${tab}`
}

function panelId(tab: MaintenanceTab): string {
  return `${workspaceId}-panel-${tab}`
}

function selectTab(tab: MaintenanceTab): void {
  activeTab.value = tab
}

function focusTab(tab: MaintenanceTab): void {
  void nextTick(() => {
    tabList.value
      ?.querySelector<HTMLButtonElement>(`[data-maintenance-tab="${tab}"]`)
      ?.focus()
  })
}

function handleTabKeydown(event: KeyboardEvent, tab: MaintenanceTab): void {
  const currentIndex = MAINTENANCE_TABS.indexOf(tab)
  let nextIndex: number | undefined

  if (event.key === 'ArrowRight') {
    nextIndex = (currentIndex + 1) % MAINTENANCE_TABS.length
  } else if (event.key === 'ArrowLeft') {
    nextIndex =
      (currentIndex - 1 + MAINTENANCE_TABS.length) % MAINTENANCE_TABS.length
  } else if (event.key === 'Home') {
    nextIndex = 0
  } else if (event.key === 'End') {
    nextIndex = MAINTENANCE_TABS.length - 1
  }

  if (nextIndex === undefined) return
  event.preventDefault()
  const nextTab = MAINTENANCE_TABS[nextIndex]
  if (!nextTab) return
  selectTab(nextTab)
  focusTab(nextTab)
}
</script>

<template>
  <div class="maintenance-tabs-workspace">
    <div class="maintenance-navigation surface-panel">
      <div class="maintenance-navigation__scroll">
        <div
          ref="tabList"
          class="maintenance-tabs"
          role="tablist"
          aria-label="系统维护视图"
        >
          <button
            v-for="tab in tabs"
            :id="tabId(tab.id)"
            :key="tab.id"
            class="maintenance-tab"
            :class="{ 'maintenance-tab--active': activeTab === tab.id }"
            type="button"
            role="tab"
            :data-maintenance-tab="tab.id"
            :aria-selected="activeTab === tab.id"
            :aria-controls="panelId(tab.id)"
            :tabindex="activeTab === tab.id ? 0 : -1"
            @click="selectTab(tab.id)"
            @keydown="handleTabKeydown($event, tab.id)"
          >
            <component :is="tab.icon" :size="16" aria-hidden="true" />
            <span>
              <strong>{{ tab.label }}</strong>
              <small>{{ tab.caption }}</small>
            </span>
          </button>
        </div>
      </div>
      <span class="navigation-scope mono">LOCAL / ADMIN</span>
    </div>

    <div
      :id="panelId(activeTab)"
      class="maintenance-workspace__panel"
      role="tabpanel"
      tabindex="0"
      :aria-labelledby="tabId(activeTab)"
    >
      <slot v-if="activeTab === 'runtime'" name="runtime" />
      <slot v-else-if="activeTab === 'storage'" name="storage" />
      <slot v-else-if="activeTab === 'analyzers'" name="analyzers" />
      <slot v-else-if="activeTab === 'access'" name="access" />
      <slot v-else name="audit" />
    </div>
  </div>
</template>

<style scoped>
.maintenance-tabs-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}

.maintenance-navigation {
  display: flex;
  min-width: 0;
  align-items: stretch;
  overflow: hidden;
}

.maintenance-navigation__scroll {
  min-width: 0;
  flex: 1;
  overflow-x: auto;
  scrollbar-width: thin;
}

.maintenance-tabs {
  display: grid;
  width: 100%;
  min-width: 710px;
  grid-template-columns: repeat(5, minmax(132px, 1fr));
}

.maintenance-tab {
  display: flex;
  min-width: 0;
  min-height: 58px;
  align-items: center;
  gap: 9px;
  padding: 9px 12px;
  border: 0;
  border-right: 1px solid var(--line);
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  text-align: left;
}

.maintenance-tab:hover {
  color: var(--ink-800);
  background: #f5f8f8;
}

.maintenance-tab--active {
  position: relative;
  color: var(--teal-strong);
  background: #f1f8f7;
  box-shadow: inset 0 -3px var(--teal);
}

.maintenance-tab > svg {
  flex: 0 0 auto;
}

.maintenance-tab > span {
  min-width: 0;
}

.maintenance-tab strong,
.maintenance-tab small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.maintenance-tab strong {
  font-size: 10px;
}

.maintenance-tab small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 8px;
}

.navigation-scope {
  display: grid;
  min-width: 92px;
  place-items: center;
  padding: 0 10px;
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 8px;
  white-space: nowrap;
}

.maintenance-workspace__panel {
  min-width: 0;
}

@media (max-width: 560px) {
  .navigation-scope {
    display: none;
  }

  .maintenance-tab {
    min-height: 54px;
    padding: 8px 10px;
  }
}
</style>
