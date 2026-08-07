<script setup lang="ts">
import { Download, Filter, RefreshCw, ScrollText, Search } from 'lucide-vue-next'
import { reactive } from 'vue'

import type { AuditLog, AuditLogListQuery } from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import { formatDateTime } from '@/utils/formatters'

defineProps<{
  logs: readonly AuditLog[]
  loading: boolean
  loadingMore: boolean
  errorMessage: string
  hasMore: boolean
}>()

const emit = defineEmits<{
  search: [query: AuditLogListQuery]
  retry: []
  loadMore: []
}>()

const filters = reactive({
  action: '',
  outcome: '',
  actor: '',
  createdFrom: '',
  createdTo: '',
})

function toIso(value: string, endOfMinute = false): string | undefined {
  if (!value) return undefined
  const date = new Date(`${value}:${endOfMinute ? '59.999' : '00.000'}`)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

function submitFilters(): void {
  const action = filters.action.trim()
  const actor = filters.actor.trim()
  const createdFrom = toIso(filters.createdFrom)
  const createdTo = toIso(filters.createdTo, true)
  emit('search', {
    ...(action ? { action } : {}),
    ...(filters.outcome ? { outcome: filters.outcome } : {}),
    ...(actor ? { actor } : {}),
    ...(createdFrom ? { created_from: createdFrom } : {}),
    ...(createdTo ? { created_to: createdTo } : {}),
  })
}

function clearFilters(): void {
  filters.action = ''
  filters.outcome = ''
  filters.actor = ''
  filters.createdFrom = ''
  filters.createdTo = ''
  emit('search', {})
}

function outcomeLabel(value: string): string {
  const labels: Readonly<Record<string, string>> = {
    success: '成功',
    denied: '拒绝',
    failure: '失败',
  }
  return labels[value] ?? value
}

function actorLabel(log: AuditLog): string {
  return log.actor?.display_name || log.actor?.username || '系统'
}
</script>

<template>
  <section
    class="audit-live surface-panel"
    aria-labelledby="audit-live-title"
  >
    <header class="section-heading">
      <div>
        <span class="section-kicker mono">LIVE / AUDIT EVENTS</span>
        <h2 id="audit-live-title">审计日志</h2>
        <p>从数据库按游标查询受控事件字段，不读取或解析服务日志文件。</p>
      </div>
      <div class="heading-actions">
        <button
          type="button"
          title="刷新审计日志"
          aria-label="刷新审计日志"
          :disabled="loading"
          @click="$emit('retry')"
        >
          <RefreshCw :size="15" aria-hidden="true" />
        </button>
        <button
          type="button"
          disabled
          title="本批后端未提供审计导出接口"
        >
          <Download :size="15" aria-hidden="true" />
          <span>导出</span>
        </button>
      </div>
    </header>

    <form class="audit-filters" @submit.prevent="submitFilters">
      <span class="filter-mark" aria-hidden="true">
        <Filter :size="15" />
      </span>
      <label>
        <span>操作</span>
        <input
          v-model="filters.action"
          placeholder="如 task.create"
          maxlength="100"
        >
      </label>
      <label>
        <span>结果</span>
        <select v-model="filters.outcome">
          <option value="">全部结果</option>
          <option value="success">成功</option>
          <option value="denied">拒绝</option>
          <option value="failure">失败</option>
        </select>
      </label>
      <label>
        <span>操作者</span>
        <input
          v-model="filters.actor"
          placeholder="用户名"
          maxlength="64"
        >
      </label>
      <label>
        <span>起始时间</span>
        <input v-model="filters.createdFrom" type="datetime-local">
      </label>
      <label>
        <span>结束时间</span>
        <input v-model="filters.createdTo" type="datetime-local">
      </label>
      <div class="filter-actions">
        <button type="button" :disabled="loading" @click="clearFilters">
          清除
        </button>
        <button class="search-command" type="submit" :disabled="loading">
          <Search :size="14" aria-hidden="true" />
          查询
        </button>
      </div>
    </form>

    <StatePanel v-if="loading" kind="loading" />
    <StatePanel
      v-else-if="errorMessage"
      kind="error"
      :description="errorMessage"
      retryable
      @retry="$emit('retry')"
    />
    <StatePanel
      v-else-if="!logs.length"
      kind="empty"
      title="没有匹配的审计事件"
      description="可清除筛选条件后重新查询。"
    />
    <ol v-else class="audit-list" aria-label="审计事件列表">
      <li v-for="log in logs" :key="log.id" class="audit-row">
        <span class="audit-icon" aria-hidden="true">
          <ScrollText :size="16" />
        </span>
        <div class="event-time">
          <strong class="mono">{{ formatDateTime(log.created_at) }}</strong>
          <span class="mono">{{ log.id }}</span>
        </div>
        <div class="event-main">
          <div>
            <span class="action-label mono">{{ log.action }}</span>
            <strong>{{ actorLabel(log) }}</strong>
          </div>
          <span>
            <code>{{ log.actor?.username || 'system' }}</code>
            · {{ log.object_type }}
            <code v-if="log.object_id">{{ log.object_id }}</code>
          </span>
        </div>
        <div class="request-meta">
          <span>请求标识</span>
          <code>{{ log.request_id || '—' }}</code>
        </div>
        <span
          class="outcome-label"
          :class="`outcome-label--${log.outcome}`"
        >
          <i aria-hidden="true" />
          {{ outcomeLabel(log.outcome) }}
        </span>
      </li>
    </ol>

    <footer class="audit-footer">
      <span>
        当前已加载 <strong class="mono">{{ logs.length }}</strong> 条
      </span>
      <button
        v-if="hasMore"
        type="button"
        :disabled="loadingMore"
        @click="$emit('loadMore')"
      >
        {{ loadingMore ? '正在加载…' : '加载更早事件' }}
      </button>
      <span v-else>已到达当前查询末尾</span>
    </footer>
  </section>
</template>

<style scoped>
.audit-live {
  min-width: 0;
  overflow: hidden;
  container: audit-live / inline-size;
}

.section-heading {
  display: flex;
  min-height: 76px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 17px;
  border-bottom: 1px solid var(--line);
}

.section-heading > div {
  min-width: 0;
}

.section-kicker {
  display: block;
  margin-bottom: 5px;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.section-heading h2,
.section-heading p {
  margin: 0;
}

.section-heading h2 {
  color: var(--ink-800);
  font-size: 14px;
}

.section-heading p {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 10px;
}

.heading-actions {
  display: flex;
  flex: 0 0 auto;
  gap: 7px;
}

.heading-actions button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
}

.heading-actions button:first-child {
  width: 32px;
  justify-content: center;
  padding: 0;
}

button:disabled {
  color: var(--ink-400);
  background: #eef1f1;
  cursor: not-allowed;
}

.audit-filters {
  display: grid;
  min-width: 0;
  grid-template-columns:
    28px minmax(120px, 0.8fr) minmax(100px, 0.55fr)
    minmax(110px, 0.65fr) minmax(168px, 0.9fr) minmax(168px, 0.9fr) auto;
  align-items: end;
  gap: 9px;
  padding: 11px 17px;
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
}

.filter-mark {
  display: grid;
  width: 28px;
  height: 32px;
  place-items: center;
  color: var(--ink-400);
}

.audit-filters label {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.audit-filters label > span {
  color: var(--ink-600);
  font-size: 8px;
  font-weight: 700;
}

.audit-filters input,
.audit-filters select {
  width: 100%;
  min-width: 0;
  min-height: 32px;
  padding: 5px 7px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-800);
  background: var(--surface);
  font-size: 9px;
}

.filter-actions {
  display: flex;
  gap: 6px;
}

.filter-actions button,
.audit-footer button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 5px 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 9px;
  white-space: nowrap;
}

.filter-actions .search-command {
  border-color: var(--teal);
  color: #fff;
  background: var(--teal);
}

.audit-list {
  padding: 0;
  margin: 0;
  list-style: none;
}

.audit-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    32px minmax(145px, 0.7fr) minmax(250px, 1.5fr)
    minmax(130px, 0.7fr) auto;
  align-items: center;
  gap: 12px;
  min-height: 68px;
  padding: 10px 17px;
  border-bottom: 1px solid #e7ebeb;
}

.audit-icon {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface-raised);
}

.event-time,
.event-main,
.request-meta {
  min-width: 0;
}

.event-time strong,
.event-time span,
.request-meta span,
.request-meta code {
  display: block;
  overflow-wrap: anywhere;
}

.event-time strong {
  color: var(--ink-800);
  font-size: 9px;
}

.event-time span,
.request-meta span {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 8px;
}

.event-main > div {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
}

.event-main strong {
  color: var(--ink-800);
  font-size: 10px;
  overflow-wrap: anywhere;
}

.event-main > span {
  display: block;
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 9px;
  overflow-wrap: anywhere;
}

.action-label {
  flex: 0 0 auto;
  padding: 2px 5px;
  border: 1px solid #c0d1e4;
  border-radius: 3px;
  color: var(--blue);
  background: #f2f6fa;
  font-size: 8px;
}

.event-main code,
.request-meta code {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
}

.outcome-label {
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

.outcome-label i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

.outcome-label--denied,
.outcome-label--failure {
  border-color: #e4bebe;
  color: var(--red);
  background: #fff5f5;
}

.outcome-label--denied i,
.outcome-label--failure i {
  background: var(--red);
}

.audit-footer {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 17px;
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 9px;
}

@container audit-live (max-width: 1050px) {
  .audit-filters {
    grid-template-columns: 28px repeat(3, minmax(100px, 1fr)) auto;
  }

  .audit-filters label:nth-of-type(4),
  .audit-filters label:nth-of-type(5) {
    grid-row: 2;
  }

  .audit-filters label:nth-of-type(4) {
    grid-column: 2 / 4;
  }

  .audit-filters label:nth-of-type(5) {
    grid-column: 4 / 6;
  }
}

@container audit-live (max-width: 760px) {
  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr) auto;
  }

  .event-main,
  .request-meta {
    grid-column: 2 / -1;
  }

  .outcome-label {
    grid-row: 1;
    grid-column: 3;
  }
}

@container audit-live (max-width: 620px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .audit-filters {
    grid-template-columns: 1fr;
    padding: 13px;
  }

  .filter-mark {
    display: none;
  }

  .audit-filters label:nth-of-type(4),
  .audit-filters label:nth-of-type(5) {
    grid-row: auto;
    grid-column: auto;
  }

  .filter-actions {
    justify-content: flex-end;
  }
}

@container audit-live (max-width: 440px) {
  .audit-row {
    grid-template-columns: 30px minmax(0, 1fr);
    padding: 12px 13px;
  }

  .outcome-label {
    grid-row: auto;
    grid-column: 2;
    justify-self: start;
  }

  .audit-footer {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
