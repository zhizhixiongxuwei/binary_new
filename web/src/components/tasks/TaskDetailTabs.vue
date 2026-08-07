<script setup lang="ts">
import { Activity, Info, ScanSearch } from 'lucide-vue-next'
import { nextTick, useId, useTemplateRef, type Component } from 'vue'

export type TaskDetailTab = 'progress' | 'results' | 'information'

const activeTab = defineModel<TaskDetailTab>('activeTab', {
  default: 'progress',
})

const tabs: readonly {
  id: TaskDetailTab
  label: string
  icon: Component
}[] = [
  { id: 'progress', label: '执行进度', icon: Activity },
  { id: 'results', label: '检测结果', icon: ScanSearch },
  { id: 'information', label: '任务信息', icon: Info },
]

const componentId = `task-detail-tabs-${useId().replace(/:/g, '')}`
const tabList = useTemplateRef<HTMLElement>('tabList')

function tabId(tab: TaskDetailTab): string {
  return `${componentId}-tab-${tab}`
}

function panelId(tab: TaskDetailTab): string {
  return `${componentId}-panel-${tab}`
}

function select(tab: TaskDetailTab): void {
  activeTab.value = tab
}

function focus(tab: TaskDetailTab): void {
  void nextTick(() => {
    tabList.value
      ?.querySelector<HTMLButtonElement>(`[data-detail-tab="${tab}"]`)
      ?.focus()
  })
}

function handleKeydown(event: KeyboardEvent, tab: TaskDetailTab): void {
  const current = tabs.findIndex((item) => item.id === tab)
  let next: number | null = null
  if (event.key === 'ArrowRight') next = (current + 1) % tabs.length
  if (event.key === 'ArrowLeft') next = (current - 1 + tabs.length) % tabs.length
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = tabs.length - 1
  if (next === null) return
  event.preventDefault()
  const nextTab = tabs[next]?.id
  if (!nextTab) return
  select(nextTab)
  focus(nextTab)
}
</script>

<template>
  <section class="detail-tabs" aria-label="任务详情视图">
    <div
      ref="tabList"
      class="detail-tabs__list"
      role="tablist"
      aria-label="任务详情分区"
    >
      <button
        v-for="tab in tabs"
        :id="tabId(tab.id)"
        :key="tab.id"
        class="detail-tabs__tab"
        :class="{ 'detail-tabs__tab--active': activeTab === tab.id }"
        type="button"
        role="tab"
        :data-detail-tab="tab.id"
        :aria-selected="activeTab === tab.id"
        :aria-controls="panelId(tab.id)"
        :tabindex="activeTab === tab.id ? 0 : -1"
        @click="select(tab.id)"
        @keydown="handleKeydown($event, tab.id)"
      >
        <component :is="tab.icon" :size="15" aria-hidden="true" />
        <span>{{ tab.label }}</span>
      </button>
    </div>

    <div
      :id="panelId('progress')"
      class="detail-tabs__panel"
      :hidden="activeTab !== 'progress'"
      role="tabpanel"
      :aria-labelledby="tabId('progress')"
    >
      <slot name="progress" />
    </div>
    <div
      :id="panelId('results')"
      class="detail-tabs__panel"
      :hidden="activeTab !== 'results'"
      role="tabpanel"
      :aria-labelledby="tabId('results')"
    >
      <slot name="results" />
    </div>
    <div
      :id="panelId('information')"
      class="detail-tabs__panel"
      :hidden="activeTab !== 'information'"
      role="tabpanel"
      :aria-labelledby="tabId('information')"
    >
      <slot name="information" />
    </div>
  </section>
</template>

<style scoped>
.detail-tabs {
  min-width: 0;
}

.detail-tabs__list {
  display: flex;
  min-width: 0;
  gap: 2px;
  border-bottom: 1px solid var(--line);
}

.detail-tabs__tab {
  position: relative;
  display: inline-flex;
  min-width: 132px;
  min-height: 42px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  padding: 8px 16px;
  border: 0;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  font-size: 12px;
  font-weight: 700;
}

.detail-tabs__tab::after {
  position: absolute;
  right: 14px;
  bottom: -1px;
  left: 14px;
  height: 2px;
  background: transparent;
  content: "";
}

.detail-tabs__tab:hover {
  color: var(--teal-strong);
  background: #f4f8f8;
}

.detail-tabs__tab--active {
  color: var(--teal-strong);
}

.detail-tabs__tab--active::after {
  background: var(--teal);
}

.detail-tabs__panel {
  display: grid;
  min-width: 0;
  gap: 12px;
  padding-top: 12px;
}

.detail-tabs__panel[hidden] {
  display: none;
}

@media (max-width: 480px) {
  .detail-tabs__tab {
    min-width: 0;
    flex: 1;
    padding-inline: 8px;
  }
}
</style>
