<script setup lang="ts">
import { ElMessageBox } from 'element-plus'
import {
  Archive,
  CircleAlert,
  RefreshCw,
  Trash2,
} from 'lucide-vue-next'
import { computed, watch } from 'vue'

import type { ArchiveImportEntryFilter } from '@/api/types'
import ArchiveImportBatchActions from '@/components/uploads/ArchiveImportBatchActions.vue'
import ArchiveImportEntryTable from '@/components/uploads/ArchiveImportEntryTable.vue'
import { useArchiveImport } from '@/composables/useArchiveImport'

const props = withDefaults(
  defineProps<{
    importId: string
    uploadId: string
    filename: string
    applyInitialSelection?: boolean
    initialSelectedIds?: readonly string[]
  }>(),
  {
    applyInitialSelection: true,
    initialSelectedIds: () => [],
  },
)

const emit = defineEmits<{
  deleted: []
  openTask: [taskId: string]
  selectionChange: [entryIds: string[]]
}>()

const model = useArchiveImport({
  importId: props.importId,
  uploadId: props.uploadId,
  applyInitialSelection: props.applyInitialSelection,
  initialSelectedIds: props.initialSelectedIds,
})
let deletionEmitted = false

const statusLabels = {
  queued: '等待解析',
  running: '正在解析',
  ready: '解析完成',
  failed: '解析失败',
  deleting: '正在删除',
  deleted: '已删除',
} as const

const filterOptions: { label: string; value: ArchiveImportEntryFilter }[] = [
  { label: '全部条目', value: 'all' },
  { label: '可创建', value: 'eligible' },
  { label: '已创建', value: 'created' },
  { label: '已跳过', value: 'skipped' },
  { label: '创建失败', value: 'failed' },
]

const statusLabel = computed(() => {
  const status = model.archiveImport.value?.status
  return status ? statusLabels[status] : '读取中'
})

const showEntries = computed(() => {
  const status = model.archiveImport.value?.status
  return status === 'ready' || status === 'failed'
})

function setFilter(value: unknown): void {
  if (
    value === 'all' ||
    value === 'eligible' ||
    value === 'created' ||
    value === 'skipped' ||
    value === 'failed'
  ) {
    void model.setFilter(value)
  }
}

async function deleteArchive(): Promise<void> {
  const current = model.archiveImport.value
  if (!current) return
  const uncreatedCandidates = Math.max(
    0,
    current.eligible_entries - current.created_tasks,
  )
  try {
    await ElMessageBox.confirm(
      `将清理 ${uncreatedCandidates} 个尚未创建任务的候选和 ${current.skipped_entries} 个已跳过条目；已创建的 ${current.created_tasks} 个任务及其样本会保留。`,
      '删除外层归档上传？',
      {
        confirmButtonText: '删除归档上传',
        cancelButtonText: '保留归档',
        type: 'warning',
        distinguishCancelAndClose: true,
      },
    )
  } catch {
    return
  }
  await model.deleteUpload()
}

watch(
  model.deleted,
  (deleted) => {
    if (!deleted || deletionEmitted) return
    deletionEmitted = true
    emit('deleted')
  },
  { immediate: true },
)

watch(
  model.selectedIds,
  (entryIds) => emit('selectionChange', [...entryIds]),
  { immediate: true },
)
</script>

<template>
  <article class="archive-import">
    <header class="archive-import__header">
      <div class="archive-import__identity">
        <span class="archive-import__icon" aria-hidden="true">
          <Archive :size="19" />
        </span>
        <div>
          <strong :title="filename">{{ filename }}</strong>
          <small class="mono">{{ importId }}</small>
        </div>
      </div>
      <div class="archive-import__commands">
        <span
          class="archive-import__status"
          :class="`archive-import__status--${model.archiveImport.value?.status ?? 'loading'}`"
          aria-live="polite"
        >
          {{ statusLabel }}
        </span>
        <button
          type="button"
          aria-label="刷新归档状态"
          title="刷新归档状态"
          :disabled="model.loadingImport.value || model.deleting.value"
          @click="model.refreshImport"
        >
          <RefreshCw :size="16" aria-hidden="true" />
        </button>
        <button
          v-if="model.canDelete.value"
          type="button"
          aria-label="删除归档上传"
          title="删除归档上传"
          :disabled="model.deleting.value"
          @click="deleteArchive"
        >
          <Trash2 :size="16" aria-hidden="true" />
        </button>
      </div>
    </header>

    <div
      v-if="model.archiveImport.value"
      class="archive-import__metrics"
      aria-label="归档解析统计"
    >
      <span><strong>{{ model.archiveImport.value.scanned_entries }}</strong> 已检查</span>
      <span><strong>{{ model.archiveImport.value.eligible_entries }}</strong> 可创建</span>
      <span><strong>{{ model.archiveImport.value.skipped_entries }}</strong> 已跳过</span>
      <span><strong>{{ model.archiveImport.value.created_tasks }}</strong> 已建任务</span>
    </div>

    <div
      v-if="model.isPolling.value"
      class="archive-import__progress"
      aria-live="polite"
    >
      <el-progress :percentage="model.progress.value" :stroke-width="5" />
      <span>{{ model.archiveImport.value?.status === 'deleting' ? '归档上传正在删除' : '归档成员正在进行安全检查' }}</span>
    </div>

    <div
      v-if="model.importError.value || model.deletionError.value"
      class="archive-import__error"
      role="alert"
    >
      <CircleAlert :size="16" aria-hidden="true" />
      <span>{{ model.deletionError.value || model.importError.value }}</span>
    </div>

    <div
      v-if="model.archiveImport.value?.status === 'failed'"
      class="archive-import__failure"
      role="alert"
    >
      <CircleAlert :size="17" aria-hidden="true" />
      <div>
        <strong>{{ model.archiveImport.value.error_code ?? 'ARCHIVE_IMPORT_FAILED' }}</strong>
        <span>{{ model.archiveImport.value.error_message ?? '归档无法完成安全解析' }}</span>
      </div>
    </div>

    <div v-if="model.isEmpty.value" class="archive-import__empty">
      <strong>没有可创建任务的成员</strong>
    </div>

    <template v-if="showEntries">
      <div class="archive-import__toolbar">
        <span>归档成员</span>
        <el-select
          :model-value="model.filter.value"
          size="small"
          aria-label="筛选归档条目"
          @update:model-value="setFilter"
        >
          <el-option
            v-for="option in filterOptions"
            :key="option.value"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
      </div>

      <div v-if="model.entriesError.value" class="archive-import__error" role="alert">
        <CircleAlert :size="16" aria-hidden="true" />
        <span>{{ model.entriesError.value }}</span>
      </div>

      <ArchiveImportEntryTable
        :entries="model.entries.value"
        :selected-ids="model.selectedIds.value"
        :selected-count="model.selectedCount.value"
        :loading="model.loadingEntries.value"
        :submitting="model.submitting.value"
        :creation-enabled="model.isReady.value"
        :has-previous-page="model.hasPreviousPage.value"
        :has-next-page="model.hasNextPage.value"
        :page-index="model.pageIndex.value"
        @toggle="model.toggleEntry"
        @toggle-visible="model.toggleVisibleEligible"
        @previous-page="model.previousPage"
        @next-page="model.nextPage"
        @open-task="emit('openTask', $event)"
      />

      <ArchiveImportBatchActions
        :selected-count="model.selectedCount.value"
        :submitting="model.submitting.value"
        :disabled="!model.isReady.value"
        :result="model.batchResult.value"
        :error="model.batchError.value"
        :entry-labels="model.entryLabels.value"
        @create="model.createTasks"
        @clear="model.clearSelection"
        @open-task="emit('openTask', $event)"
      />
    </template>
  </article>
</template>

<style scoped>
.archive-import {
  min-width: 0;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #fff;
}

.archive-import__header {
  display: flex;
  min-height: 62px;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 10px 14px;
}

.archive-import__identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 10px;
}

.archive-import__icon {
  display: grid;
  width: 36px;
  height: 36px;
  flex: 0 0 36px;
  place-items: center;
  border: 1px solid #b8d2cf;
  border-radius: 4px;
  color: var(--teal-strong);
  background: #f2f8f7;
}

.archive-import__identity > div {
  min-width: 0;
}

.archive-import__identity strong,
.archive-import__identity small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.archive-import__identity strong {
  color: var(--ink-800);
  font-size: 13px;
}

.archive-import__identity small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 9px;
}

.archive-import__commands {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 5px;
}

.archive-import__commands button {
  display: grid;
  width: 31px;
  height: 31px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
}

.archive-import__commands button:hover:not(:disabled) {
  color: var(--teal-strong);
  background: #f2f8f7;
}

.archive-import__commands button:disabled {
  color: var(--ink-400);
  cursor: wait;
}

.archive-import__status {
  margin-right: 4px;
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.archive-import__status--ready {
  color: var(--teal-strong);
}

.archive-import__status--failed {
  color: var(--red);
}

.archive-import__metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-block: 1px solid var(--line);
  background: #f7f9f9;
}

.archive-import__metrics span {
  min-width: 0;
  padding: 9px 12px;
  border-right: 1px solid var(--line);
  color: var(--ink-400);
  font-size: 10px;
  text-align: center;
}

.archive-import__metrics span:last-child {
  border-right: 0;
}

.archive-import__metrics strong {
  color: var(--ink-800);
  font-size: 12px;
}

.archive-import__progress,
.archive-import__failure,
.archive-import__empty,
.archive-import__error {
  padding: 13px 14px;
}

.archive-import__progress span {
  display: block;
  margin-top: 6px;
  color: var(--ink-400);
  font-size: 10px;
}

.archive-import__error,
.archive-import__failure {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  border-top: 1px solid #ebc6c1;
  color: var(--red);
  background: #fff5f3;
  font-size: 11px;
}

.archive-import__error svg,
.archive-import__failure svg {
  flex: 0 0 auto;
}

.archive-import__failure strong,
.archive-import__failure span,
.archive-import__empty strong {
  display: block;
}

.archive-import__failure span {
  margin-top: 3px;
}

.archive-import__empty {
  color: var(--ink-600);
  background: #fafcfc;
}

.archive-import__empty strong {
  color: var(--ink-800);
  font-size: 12px;
}

.archive-import__toolbar {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-top: 1px solid var(--line);
}

.archive-import__toolbar > span {
  color: var(--ink-800);
  font-size: 12px;
  font-weight: 700;
}

.archive-import__toolbar :deep(.el-select) {
  width: 132px;
}

@media (max-width: 620px) {
  .archive-import__header {
    align-items: flex-start;
    flex-direction: column;
  }

  .archive-import__commands {
    width: 100%;
    justify-content: flex-end;
  }

  .archive-import__status {
    margin-right: auto;
  }

  .archive-import__metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .archive-import__metrics span:nth-child(2) {
    border-right: 0;
  }

  .archive-import__metrics span:nth-child(-n + 2) {
    border-bottom: 1px solid var(--line);
  }
}
</style>
