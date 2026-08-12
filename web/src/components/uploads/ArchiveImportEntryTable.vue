<script setup lang="ts">
import {
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  FileArchive,
} from 'lucide-vue-next'
import { computed } from 'vue'

import type { ArchiveImportEntry } from '@/api/types'
import { formatBytes } from '@/utils/formatters'

const props = defineProps<{
  entries: readonly ArchiveImportEntry[]
  selectedIds: ReadonlySet<string>
  selectedCount: number
  loading: boolean
  submitting: boolean
  creationEnabled: boolean
  hasPreviousPage: boolean
  hasNextPage: boolean
  pageIndex: number
}>()

const emit = defineEmits<{
  toggle: [entry: ArchiveImportEntry, checked: boolean]
  toggleVisible: [checked: boolean]
  previousPage: []
  nextPage: []
  openTask: [taskId: string]
}>()

const visibleEligible = computed(() =>
  props.entries.filter((entry) => entry.status === 'eligible'),
)
const allVisibleSelected = computed(
  () =>
    visibleEligible.value.length > 0 &&
    visibleEligible.value.every((entry) => props.selectedIds.has(entry.id)),
)
const visibleSelectedCount = computed(
  () =>
    visibleEligible.value.filter((entry) => props.selectedIds.has(entry.id))
      .length,
)
const someVisibleSelected = computed(
  () =>
    visibleSelectedCount.value > 0 &&
    visibleSelectedCount.value < visibleEligible.value.length,
)
const visibleToggleDisabled = computed(
  () =>
    visibleEligible.value.length === 0 ||
    props.submitting ||
    !props.creationEnabled ||
    (props.selectedCount >= 20 && visibleSelectedCount.value === 0),
)

const statusLabels = {
  eligible: '可创建',
  skipped: '已跳过',
  created: '已创建',
  failed: '创建失败',
} as const

function toggleVisible(): void {
  const canAdd = props.selectedCount < 20
  emit('toggleVisible', !allVisibleSelected.value && canAdd)
}

function toggleEntry(entry: ArchiveImportEntry, event: Event): void {
  emit('toggle', entry, (event.target as HTMLInputElement).checked)
}

function disabled(entry: ArchiveImportEntry): boolean {
  return (
    (entry.status !== 'eligible' && entry.status !== 'failed') ||
    !props.creationEnabled ||
    props.submitting ||
    (props.selectedCount >= 20 && !props.selectedIds.has(entry.id))
  )
}

function entryStatusLabel(entry: ArchiveImportEntry): string {
  if (entry.status === 'created' && !entry.task_id) {
    return '已创建（任务已删除）'
  }
  return statusLabels[entry.status]
}
</script>

<template>
  <div class="entry-table-wrap" :aria-busy="loading">
    <table class="entry-table">
      <thead>
        <tr>
          <th class="entry-table__select">
            <input
              type="checkbox"
              aria-label="选择当前页可创建条目"
              :checked="allVisibleSelected"
              :indeterminate="someVisibleSelected"
              :disabled="visibleToggleDisabled"
              @change="toggleVisible"
            >
          </th>
          <th>内部路径</th>
          <th>格式</th>
          <th>类别</th>
          <th class="entry-table__size">大小</th>
          <th>状态</th>
          <th class="entry-table__command"><span class="sr-only">操作</span></th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="loading && entries.length === 0">
          <td colspan="7" class="entry-table__empty">正在读取条目…</td>
        </tr>
        <tr v-else-if="entries.length === 0">
          <td colspan="7" class="entry-table__empty">当前筛选没有条目</td>
        </tr>
        <template v-else>
          <tr v-for="entry in entries" :key="entry.id">
            <td class="entry-table__select">
              <input
                type="checkbox"
                :aria-label="`选择 ${entry.path}`"
                :checked="selectedIds.has(entry.id)"
                :disabled="disabled(entry)"
                @change="toggleEntry(entry, $event)"
              >
            </td>
            <td class="entry-table__path">
              <FileArchive :size="14" aria-hidden="true" />
              <span :title="entry.path">{{ entry.path }}</span>
            </td>
            <td class="mono">{{ entry.detected_format ?? '—' }}</td>
            <td>{{ entry.detected_category === 'container' ? '容器镜像' : entry.detected_category === 'binary' ? '二进制' : '—' }}</td>
            <td class="entry-table__size mono">{{ formatBytes(entry.size_bytes) }}</td>
            <td>
              <span
                class="entry-status"
                :class="`entry-status--${entry.status}`"
                :title="entry.skip_reason ?? ''"
              >
                {{ entryStatusLabel(entry) }}
              </span>
              <small v-if="entry.skip_reason" class="entry-table__reason">
                {{ entry.skip_reason }}
              </small>
            </td>
            <td class="entry-table__command">
              <button
                v-if="entry.task_id"
                type="button"
                aria-label="查看已创建任务"
                title="查看已创建任务"
                @click="emit('openTask', entry.task_id)"
              >
                <ArrowUpRight :size="16" aria-hidden="true" />
              </button>
            </td>
          </tr>
        </template>
      </tbody>
    </table>

    <div class="entry-pagination" aria-label="归档条目分页">
      <span class="mono">PAGE {{ pageIndex + 1 }}</span>
      <div>
        <button
          type="button"
          aria-label="上一页"
          title="上一页"
          :disabled="!hasPreviousPage || loading"
          @click="emit('previousPage')"
        >
          <ChevronLeft :size="17" aria-hidden="true" />
        </button>
        <button
          type="button"
          aria-label="下一页"
          title="下一页"
          :disabled="!hasNextPage || loading"
          @click="emit('nextPage')"
        >
          <ChevronRight :size="17" aria-hidden="true" />
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.entry-table-wrap {
  width: 100%;
  min-width: 0;
  overflow-x: auto;
  border-block: 1px solid var(--line);
}

.entry-table {
  width: 100%;
  min-width: 850px;
  border-collapse: collapse;
  table-layout: fixed;
}

.entry-table th,
.entry-table td {
  padding: 10px 9px;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 11px;
  text-align: left;
  vertical-align: top;
}

.entry-table th {
  color: var(--ink-400);
  background: #f4f7f7;
  font-size: 10px;
  font-weight: 700;
}

.entry-table tbody tr:last-child td {
  border-bottom: 0;
}

.entry-table th:nth-child(2) {
  width: 31%;
}

.entry-table th:nth-child(3),
.entry-table th:nth-child(4) {
  width: 12%;
}

.entry-table th:nth-child(6) {
  width: 18%;
}

.entry-table__select {
  width: 38px;
  text-align: center !important;
}

.entry-table__select input {
  width: 15px;
  height: 15px;
  accent-color: var(--teal);
}

.entry-table__path {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 6px;
  color: var(--ink-800) !important;
}

.entry-table__path svg {
  flex: 0 0 auto;
  margin-top: 1px;
  color: var(--teal-strong);
}

.entry-table__path span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.entry-table__size {
  width: 90px;
  text-align: right !important;
  white-space: nowrap;
}

.entry-table__command {
  width: 44px;
  text-align: center !important;
}

.entry-table__command button,
.entry-pagination button {
  display: inline-grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
}

.entry-table__command button:hover,
.entry-pagination button:hover:not(:disabled) {
  color: var(--teal-strong);
  background: #f1f8f7;
}

.entry-pagination button:disabled {
  color: var(--ink-400);
  background: #f2f4f4;
  cursor: not-allowed;
}

.entry-status {
  color: var(--ink-600);
  font-weight: 700;
}

.entry-status--eligible,
.entry-status--created {
  color: var(--teal-strong);
}

.entry-status--failed {
  color: var(--red);
}

.entry-table__reason {
  display: block;
  margin-top: 3px;
  overflow-wrap: anywhere;
  color: var(--ink-400);
  line-height: 1.4;
}

.entry-table__empty {
  height: 88px;
  color: var(--ink-400) !important;
  text-align: center !important;
  vertical-align: middle !important;
}

.entry-pagination {
  position: sticky;
  left: 0;
  display: flex;
  min-width: 100%;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  border-top: 1px solid var(--line);
  background: #fafcfc;
}

.entry-pagination > span {
  color: var(--ink-400);
  font-size: 10px;
}

.entry-pagination > div {
  display: flex;
  gap: 5px;
}
</style>
