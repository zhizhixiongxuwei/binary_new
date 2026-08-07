<script setup lang="ts">
import { Download, Filter, ScrollText } from 'lucide-vue-next'
import { computed, shallowRef } from 'vue'

import MaintenanceUnavailable from '@/components/system/maintenance/MaintenanceUnavailable.vue'
import {
  auditLogPreviews,
  type AuditEventType,
  type AuditLogPreview,
  type MaintenanceViewMode,
} from '@/components/system/maintenance/maintenanceFixtures'

defineProps<{
  mode: MaintenanceViewMode
}>()

type AuditFilter = 'all' | AuditEventType

const selectedType = shallowRef<AuditFilter>('all')

const typeLabels: Readonly<Record<AuditEventType, string>> = {
  authentication: '认证',
  task: '任务',
  maintenance: '维护',
  system: '系统',
}

const resultLabels: Readonly<Record<AuditLogPreview['result'], string>> = {
  success: '成功',
  denied: '拒绝',
}

const filteredLogs = computed(() => {
  if (selectedType.value === 'all') return auditLogPreviews
  return auditLogPreviews.filter((log) => log.type === selectedType.value)
})

function onFilterChange(event: Event): void {
  selectedType.value = (event.target as HTMLSelectElement).value as AuditFilter
}
</script>

<template>
  <MaintenanceUnavailable
    v-if="mode === 'live'"
    title="审计日志接口未接入"
    description="后端尚未提供审计日志查询和导出接口，本页不会读取服务日志或数据库记录。"
  />

  <section v-else class="audit-panel surface-panel" aria-labelledby="audit-title">
    <header class="audit-toolbar">
      <div>
        <span class="preview-kicker mono">FIXED PREVIEW / LOCAL AUDIT</span>
        <h2 id="audit-title">审计日志预览</h2>
        <p>下列事件均为固定示例；类型筛选只在浏览器内执行。</p>
      </div>
      <div class="audit-toolbar__actions">
        <label class="type-filter">
          <Filter :size="14" aria-hidden="true" />
          <span>事件类型</span>
          <select
            :value="selectedType"
            aria-label="按审计事件类型筛选"
            @change="onFilterChange"
          >
            <option value="all">全部类型</option>
            <option value="authentication">认证</option>
            <option value="task">任务</option>
            <option value="maintenance">维护</option>
            <option value="system">系统</option>
          </select>
        </label>
        <button type="button" disabled title="后端未接入">
          <Download :size="15" aria-hidden="true" />
          导出
        </button>
      </div>
    </header>

    <div class="audit-meta">
      <span>
        显示 <strong class="mono">{{ filteredLogs.length }}</strong> 条固定示例
      </span>
      <span>导出不可用：后端未接入</span>
    </div>

    <ol class="audit-list" aria-label="固定示例审计事件">
      <li v-for="log in filteredLogs" :key="log.id" class="audit-row">
        <span class="audit-row__icon" aria-hidden="true">
          <ScrollText :size="16" />
        </span>
        <div class="audit-row__time">
          <strong class="mono">{{ log.timestamp }}</strong>
          <span class="mono">{{ log.id }}</span>
        </div>
        <div class="audit-row__event">
          <div>
            <span class="event-type">{{ typeLabels[log.type] }}</span>
            <strong>{{ log.action }}</strong>
          </div>
          <span>
            操作者 <code>{{ log.actor }}</code>
            · 对象 <code>{{ log.target }}</code>
          </span>
        </div>
        <span class="audit-result" :class="`audit-result--${log.result}`">
          <i aria-hidden="true" />
          {{ resultLabels[log.result] }}
        </span>
      </li>
    </ol>
  </section>
</template>

<style scoped>
.audit-panel {
  min-width: 0;
  container: audit-panel / inline-size;
}

.audit-toolbar {
  display: flex;
  min-height: 78px;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--line);
}

.audit-toolbar > div {
  min-width: 0;
}

.preview-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.audit-toolbar h2,
.audit-toolbar p {
  margin: 0;
}

.audit-toolbar h2 {
  color: var(--ink-800);
  font-size: 14px;
}

.audit-toolbar p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.6;
}

.audit-toolbar__actions {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 8px;
}

.type-filter {
  display: flex;
  min-height: 34px;
  align-items: center;
  gap: 7px;
  padding-left: 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  font-size: 10px;
}

.type-filter span {
  white-space: nowrap;
}

.type-filter select {
  min-height: 32px;
  padding: 0 26px 0 7px;
  border: 0;
  border-left: 1px solid var(--line);
  color: var(--ink-800);
  background: var(--surface-raised);
  font-size: 10px;
}

.audit-toolbar__actions button {
  display: inline-flex;
  min-height: 34px;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-400);
  background: #eef1f1;
  font-size: 10px;
  cursor: not-allowed;
}

.audit-meta {
  display: flex;
  min-height: 36px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 17px;
  border-bottom: 1px solid #e7ebeb;
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 9px;
}

.audit-meta strong {
  color: var(--ink-600);
}

.audit-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.audit-row {
  display: grid;
  min-width: 0;
  grid-template-columns: 32px minmax(145px, 0.7fr) minmax(260px, 1.8fr) auto;
  align-items: center;
  gap: 12px;
  min-height: 66px;
  padding: 10px 17px;
  border-bottom: 1px solid #e7ebeb;
}

.audit-row:last-child {
  border-bottom: 0;
}

.audit-row__icon {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface-raised);
}

.audit-row__time,
.audit-row__event {
  min-width: 0;
}

.audit-row__time strong,
.audit-row__time span {
  display: block;
  overflow-wrap: anywhere;
}

.audit-row__time strong {
  color: var(--ink-800);
  font-size: 9px;
}

.audit-row__time span {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 9px;
}

.audit-row__event > div {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
}

.audit-row__event strong {
  color: var(--ink-800);
  font-size: 10px;
  overflow-wrap: anywhere;
}

.audit-row__event > span {
  display: block;
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 9px;
  overflow-wrap: anywhere;
}

.audit-row__event code {
  color: var(--ink-800);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.event-type {
  flex: 0 0 auto;
  padding: 2px 5px;
  border: 1px solid #c0d1e4;
  border-radius: 3px;
  color: var(--blue);
  background: #f2f6fa;
  font-size: 9px;
}

.audit-result {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  gap: 5px;
  padding: 2px 6px;
  border: 1px solid #b8d7d3;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  font-size: 9px;
  font-weight: 700;
  white-space: nowrap;
}

.audit-result i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

.audit-result--denied {
  border-color: #e4bebe;
  color: var(--red);
  background: #fff5f5;
}

.audit-result--denied i {
  background: var(--red);
}

@container audit-panel (max-width: 720px) {
  .audit-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .audit-toolbar__actions {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .type-filter {
    min-width: 0;
  }

  .type-filter select {
    min-width: 0;
    flex: 1;
  }

  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr) auto;
  }

  .audit-row__time {
    grid-column: 2;
  }

  .audit-row__event {
    grid-column: 2 / -1;
  }

  .audit-result {
    grid-row: 1;
    grid-column: 3;
  }
}

@container audit-panel (max-width: 480px) {
  .audit-toolbar {
    padding: 13px;
  }

  .audit-toolbar__actions {
    grid-template-columns: 1fr;
  }

  .audit-toolbar__actions button {
    justify-content: center;
  }

  .audit-meta {
    align-items: flex-start;
    flex-direction: column;
    padding: 9px 13px;
  }

  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr);
    gap: 9px;
    padding: 12px 13px;
  }

  .audit-result {
    grid-row: auto;
    grid-column: 2;
    justify-self: start;
  }
}
</style>
