<script setup lang="ts">
import { AlertTriangle, ChevronDown, RefreshCw, Upload } from 'lucide-vue-next'
import { computed, shallowRef, watch } from 'vue'
import { useRouter } from 'vue-router'

import type { ArchiveImport, InputCategory } from '@/api/types'
import ArchiveImportWorkspace from '@/components/uploads/ArchiveImportWorkspace.vue'
import FileDropzone from '@/components/uploads/FileDropzone.vue'
import SupportedUploadTypes from '@/components/uploads/SupportedUploadTypes.vue'
import UploadQueue from '@/components/uploads/UploadQueue.vue'
import { useArchiveImportList } from '@/composables/useArchiveImportList'
import { useCategorizedUpload } from '@/composables/useCategorizedUpload'
import { inputCategoryLabels } from '@/utils/uploadPreflight'

const props = defineProps<{
  category: InputCategory
}>()

const emit = defineEmits<{
  lockChange: [locked: boolean]
}>()

const router = useRouter()
const uploads = useCategorizedUpload(props.category)
const recoveredImports = useArchiveImportList({
  enabled: props.category === 'archive',
})
const warningMessage = shallowRef('')
const expandedImportId = shallowRef<string | null>(null)
const expandedInitialSelection = shallowRef(false)
const knownLocalImportIds = new Set<string>()
const openedImportIds = new Set<string>()
const archiveSelections = new Map<string, string[]>()

interface ArchiveWorkspaceItem {
  importId: string
  uploadId: string
  filename: string
  localId?: string
  summary?: ArchiveImport
}

const archiveStatusLabels = {
  queued: '等待解析',
  running: '正在解析',
  ready: '解析完成',
  failed: '解析失败',
  deleting: '正在删除',
  deleted: '已删除',
} as const

const archiveWorkspaces = computed<ArchiveWorkspaceItem[]>(() => {
  const imports = new Map<string, ArchiveWorkspaceItem>()
  for (const item of recoveredImports.items.value) {
    imports.set(item.id, {
      importId: item.id,
      uploadId: item.upload_id,
      filename: item.filename,
      summary: item,
    })
  }
  for (const item of uploads.archiveItems.value) {
    const recovered = imports.get(item.archiveImportId)
    imports.set(item.archiveImportId, {
      importId: item.archiveImportId,
      uploadId: item.uploadId,
      filename: item.file.name,
      localId: item.localId,
      ...(recovered?.summary ? { summary: recovered.summary } : {}),
    })
  }
  return [...imports.values()]
})

const showArchiveList = computed(
  () =>
    props.category === 'archive' &&
    (archiveWorkspaces.value.length > 0 ||
      recoveredImports.loading.value ||
      Boolean(recoveredImports.error.value)),
)

const expandedArchive = computed(
  () =>
    archiveWorkspaces.value.find(
      (item) => item.importId === expandedImportId.value,
    ) ?? null,
)

watch(
  uploads.categoryLocked,
  (locked) => emit('lockChange', locked),
  { immediate: true },
)

watch(
  uploads.archiveItems,
  (items) => {
    for (const item of items) {
      if (knownLocalImportIds.has(item.archiveImportId)) continue
      knownLocalImportIds.add(item.archiveImportId)
      expandArchive(item.archiveImportId)
    }
  },
  { immediate: true },
)

function addFiles(files: File[]): void {
  const rejected = uploads.addFiles(files)
  warningMessage.value = rejected.join('；')
}

function showRejected(messages: string[]): void {
  warningMessage.value = messages.join('；')
}

function openTask(taskId: string): void {
  void router.push({ name: 'task-detail', params: { id: taskId } })
}

function forgetArchive(item: ArchiveWorkspaceItem): void {
  if (expandedImportId.value === item.importId) expandedImportId.value = null
  archiveSelections.delete(item.importId)
  recoveredImports.remove(item.importId)
  if (item.localId) uploads.forgetDeletedArchive(item.localId)
}

function toggleArchive(item: ArchiveWorkspaceItem): void {
  if (expandedImportId.value === item.importId) {
    expandedImportId.value = null
    expandedInitialSelection.value = false
    return
  }
  expandArchive(item.importId)
}

function expandArchive(importId: string): void {
  expandedInitialSelection.value = !openedImportIds.has(importId)
  openedImportIds.add(importId)
  expandedImportId.value = importId
}

function archiveStatus(item: ArchiveWorkspaceItem): string {
  return item.summary
    ? archiveStatusLabels[item.summary.status]
    : '等待状态同步'
}

function rememberedSelection(importId: string): readonly string[] {
  return archiveSelections.get(importId) ?? []
}

function rememberSelection(importId: string, entryIds: string[]): void {
  archiveSelections.set(importId, entryIds)
}
</script>

<template>
  <section class="categorized-upload surface-panel">
    <header class="categorized-upload__header">
      <div>
        <span class="mono">{{ category.toUpperCase() }}</span>
        <h2>{{ inputCategoryLabels[category] }}</h2>
      </div>
      <div class="categorized-upload__summary">
        <span class="mono" aria-live="polite">{{ uploads.queue.value.length }} FILES</span>
        <el-button
          type="primary"
          :icon="Upload"
          :loading="uploads.isUploading.value"
          :disabled="uploads.readyCount.value === 0"
          @click="uploads.startAll"
        >
          开始上传
        </el-button>
      </div>
    </header>

    <div class="categorized-upload__body">
      <SupportedUploadTypes :category="category" />
      <div v-if="warningMessage" class="upload-warning" role="alert">
        <AlertTriangle :size="16" aria-hidden="true" />
        <span>{{ warningMessage }}</span>
      </div>
      <FileDropzone
        :category="category"
        :disabled="uploads.isUploading.value"
        @selected="addFiles"
        @rejected="showRejected"
      />
      <UploadQueue
        v-if="uploads.queue.value.length"
        :items="uploads.queue.value"
        :active-id="uploads.activeId.value"
        @remove="uploads.remove"
        @pause="uploads.pause"
        @resume="uploads.uploadItem"
        @retry="uploads.uploadItem"
        @open-task="openTask"
        @clear-completed="uploads.clearCompleted"
      />
    </div>
  </section>

  <section
    v-if="showArchiveList"
    class="archive-list"
    aria-label="归档导入列表"
  >
    <header class="archive-list__header">
      <h2>归档解析与任务创建</h2>
      <div class="archive-list__commands">
        <span class="mono">{{ archiveWorkspaces.length }} IMPORTS</span>
        <button
          type="button"
          aria-label="刷新待处理归档导入"
          title="刷新待处理归档导入"
          :disabled="recoveredImports.loading.value"
          @click="recoveredImports.refresh"
        >
          <RefreshCw :size="16" aria-hidden="true" />
        </button>
      </div>
    </header>
    <div
      v-if="recoveredImports.error.value"
      class="upload-warning"
      role="alert"
    >
      <AlertTriangle :size="16" aria-hidden="true" />
      <span>{{ recoveredImports.error.value }}</span>
    </div>
    <div
      v-if="recoveredImports.loading.value && archiveWorkspaces.length === 0"
      class="archive-list__loading"
      role="status"
    >
      正在读取待处理归档导入
    </div>
    <div v-if="archiveWorkspaces.length" class="archive-list__rows">
      <button
        v-for="item in archiveWorkspaces"
        :key="item.importId"
        class="archive-list-row"
        type="button"
        :aria-expanded="expandedImportId === item.importId"
        :aria-controls="`archive-detail-${item.importId}`"
        @click="toggleArchive(item)"
      >
        <span class="archive-list-row__identity">
          <strong :title="item.filename">{{ item.filename }}</strong>
          <small class="mono">{{ item.importId }}</small>
        </span>
        <span
          class="archive-list-row__status"
          :class="`archive-list-row__status--${item.summary?.status ?? 'unknown'}`"
        >
          {{ archiveStatus(item) }}
        </span>
        <span v-if="item.summary" class="archive-list-row__metrics mono">
          {{ item.summary.eligible_entries }} 可创建 ·
          {{ item.summary.created_tasks }} 已建 ·
          {{ item.summary.skipped_entries }} 跳过
        </span>
        <span v-else class="archive-list-row__metrics">正在同步计数</span>
        <ChevronDown
          class="archive-list-row__chevron"
          :class="{
            'archive-list-row__chevron--expanded':
              expandedImportId === item.importId,
          }"
          :size="16"
          aria-hidden="true"
        />
      </button>
    </div>
    <ArchiveImportWorkspace
      v-if="expandedArchive"
      :id="`archive-detail-${expandedArchive.importId}`"
      :key="expandedArchive.importId"
      :import-id="expandedArchive.importId"
      :upload-id="expandedArchive.uploadId"
      :filename="expandedArchive.filename"
      :apply-initial-selection="expandedInitialSelection"
      :initial-selected-ids="rememberedSelection(expandedArchive.importId)"
      @deleted="forgetArchive(expandedArchive)"
      @open-task="openTask"
      @selection-change="rememberSelection(expandedArchive.importId, $event)"
    />
    <el-button
      v-if="recoveredImports.nextCursor.value"
      class="archive-list__more"
      :icon="ChevronDown"
      :loading="recoveredImports.loadingMore.value"
      @click="recoveredImports.loadMore"
    >
      加载更多归档导入
    </el-button>
  </section>
</template>

<style scoped>
.categorized-upload__header,
.archive-list__header {
  display: flex;
  min-height: 58px;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 9px 18px;
  border-bottom: 1px solid var(--line);
}

.categorized-upload__header > div:first-child span,
.categorized-upload__header h2,
.archive-list__header h2 {
  display: block;
  margin: 0;
}

.categorized-upload__header > div:first-child span {
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
}

.categorized-upload__header h2,
.archive-list__header h2 {
  margin-top: 2px;
  color: var(--ink-800);
  font-size: 14px;
  letter-spacing: 0;
}

.categorized-upload__summary {
  display: flex;
  align-items: center;
  gap: 12px;
}

.categorized-upload__summary > span,
.archive-list__commands > span {
  color: var(--ink-400);
  font-size: 9px;
  white-space: nowrap;
}

.categorized-upload__body {
  padding: 18px;
}

.upload-warning {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 12px;
  padding: 9px 12px;
  border: 1px solid #dfc8a2;
  border-left: 3px solid var(--amber);
  border-radius: 4px;
  color: #7f541b;
  background: #fffaf1;
  font-size: 12px;
}

.upload-warning svg {
  flex: 0 0 auto;
  margin-top: 1px;
}

.upload-warning span {
  min-width: 0;
  overflow-wrap: anywhere;
}

.archive-list {
  display: grid;
  gap: 12px;
  margin-top: 18px;
}

.archive-list__header {
  min-height: 42px;
  padding: 0;
  border-bottom: 0;
}

.archive-list__header h2 {
  margin: 0;
}

.archive-list__commands {
  display: flex;
  align-items: center;
  gap: 7px;
}

.archive-list__commands button {
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

.archive-list__commands button:disabled {
  color: var(--ink-400);
  cursor: wait;
}

.archive-list__rows {
  border-block: 1px solid var(--line);
}

.archive-list-row {
  display: grid;
  width: 100%;
  min-height: 52px;
  grid-template-columns: minmax(150px, 1fr) auto minmax(180px, auto) 24px;
  align-items: center;
  gap: 14px;
  padding: 8px 10px;
  border: 0;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.archive-list-row:last-child {
  border-bottom: 0;
}

.archive-list-row:hover,
.archive-list-row[aria-expanded='true'] {
  background: #f3f8f7;
}

.archive-list-row:focus-visible {
  outline: 2px solid var(--teal);
  outline-offset: -2px;
}

.archive-list-row__identity {
  min-width: 0;
}

.archive-list-row__identity strong,
.archive-list-row__identity small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.archive-list-row__identity strong {
  color: var(--ink-800);
  font-size: 12px;
}

.archive-list-row__identity small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 9px;
}

.archive-list-row__status {
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.archive-list-row__status--ready {
  color: var(--teal-strong);
}

.archive-list-row__status--failed {
  color: var(--red);
}

.archive-list-row__metrics {
  color: var(--ink-400);
  font-size: 10px;
  text-align: right;
  white-space: nowrap;
}

.archive-list-row__chevron {
  transition: transform 160ms ease;
}

.archive-list-row__chevron--expanded {
  transform: rotate(180deg);
}

.archive-list > .upload-warning {
  margin: 0;
}

.archive-list__loading {
  padding: 18px;
  border: 1px solid var(--line);
  color: var(--ink-400);
  background: #fff;
  font-size: 12px;
}

.archive-list__more {
  justify-self: center;
}

@media (max-width: 620px) {
  .categorized-upload__header {
    align-items: flex-start;
    flex-direction: column;
    padding: 12px 14px;
  }

  .categorized-upload__summary {
    width: 100%;
    justify-content: space-between;
  }

  .categorized-upload__body {
    padding: 14px;
  }

  .archive-list-row {
    grid-template-columns: minmax(0, 1fr) auto 24px;
  }

  .archive-list-row__metrics {
    display: none;
  }
}

@media (max-width: 380px) {
  .categorized-upload__summary {
    align-items: stretch;
    flex-direction: column;
  }

  .categorized-upload__body {
    padding: 10px;
  }
}
</style>
