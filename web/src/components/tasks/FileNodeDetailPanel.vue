<script setup lang="ts">
import {
  AlertTriangle,
  Archive,
  ExternalLink,
  FileSearch,
  X,
} from 'lucide-vue-next'
import { computed, watch } from 'vue'

import type {
  FileNodeDetail,
  JsonValue,
  FileNodeSourceContainer,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import SampleRetentionNotice from '@/components/tasks/SampleRetentionNotice.vue'
import { useFileNodeDetail } from '@/composables/useFileNodeDetail'
import { formatBytes } from '@/utils/formatters'
import {
  fileNodeExtractionLabel,
  fileNodeStatusTone,
  fileNodeTypeLabel,
} from '@/utils/fileNodes'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

interface MetadataEntry {
  key: string
  value: JsonValue
}

const props = withDefaults(
  defineProps<{
    taskId: string
    fileId: string | null
    fileName: string
    sampleRetention?: SampleRetentionSnapshot | null
  }>(),
  {
    sampleRetention: null,
  },
)

const emit = defineEmits<{
  close: []
  openSourceContainer: [source: FileNodeSourceContainer]
  detailChange: [detail: FileNodeDetail | null]
}>()

const { detail, loading, errorMessage, reload } = useFileNodeDetail(
  () => props.taskId,
  () => props.fileId,
)

const integerFormat = new Intl.NumberFormat('zh-CN')
const hiddenMetadataKeys = new Set(['storage_key', 'storagekey'])

const heading = computed(() => detail.value?.display_name || props.fileName || '节点详情')
const extractionTone = computed(() =>
  detail.value ? fileNodeStatusTone(detail.value.extraction_status) : 'muted',
)
const metadataEntries = computed<MetadataEntry[]>(() => {
  if (!detail.value) return []
  const metadata = sanitizeMetadata(detail.value.metadata_json)
  if (metadata === null) return []
  if (isMetadataObject(metadata)) {
    return Object.entries(metadata).map(([key, value]) => ({ key, value }))
  }
  return [{ key: Array.isArray(metadata) ? 'items' : 'value', value: metadata }]
})

function isMetadataObject(value: JsonValue): value is Readonly<Record<string, JsonValue>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function sanitizeMetadata(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map((item) => sanitizeMetadata(item))
  if (!isMetadataObject(value)) return value

  const sanitized: Record<string, JsonValue> = {}
  for (const [key, nested] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/-/g, '_')
    if (hiddenMetadataKeys.has(normalizedKey)) continue
    sanitized[key] = sanitizeMetadata(nested)
  }
  return sanitized
}

function isCompositeMetadata(value: JsonValue): boolean {
  return typeof value === 'object' && value !== null
}

function metadataText(value: JsonValue): string {
  if (isCompositeMetadata(value)) return JSON.stringify(value, null, 2)
  if (value === null) return 'null'
  if (value === '') return '（空字符串）'
  return String(value)
}

function formatFileSize(value: number | null): string {
  if (value === null) return '—'
  return `${formatBytes(value)} · ${integerFormat.format(value)} B`
}

watch(
  [() => props.taskId, () => props.fileId],
  () => emit('detailChange', null),
)

watch(
  detail,
  (current) => emit('detailChange', current),
  { immediate: true },
)
</script>

<template>
  <aside class="file-detail-panel" aria-label="文件节点详情">
    <header class="file-detail-toolbar">
      <div class="file-detail-toolbar__heading">
        <FileSearch :size="16" aria-hidden="true" />
        <div>
          <small>节点详情</small>
          <strong :title="heading">{{ heading }}</strong>
        </div>
      </div>
      <button
        v-if="fileId"
        class="close-command"
        type="button"
        aria-label="关闭文件详情"
        title="关闭文件详情"
        @click="emit('close')"
      >
        <X :size="16" />
      </button>
    </header>

    <SampleRetentionNotice
      v-if="sampleRetention && !sampleRetention.canReuseSample"
      :retention="sampleRetention"
      history-label="文件详情"
    />

    <StatePanel
      v-if="!fileId"
      class="file-detail-state"
      kind="empty"
      title="未选择文件节点"
    />
    <StatePanel
      v-else-if="loading"
      class="file-detail-state"
      kind="loading"
      title="正在读取节点详情"
    />
    <StatePanel
      v-else-if="errorMessage"
      class="file-detail-state"
      kind="error"
      :description="errorMessage"
      retryable
      @retry="reload"
    />

    <div v-else-if="detail" class="file-detail-content">
      <section class="identity-section">
        <strong>{{ detail.display_name || detail.logical_path || '/' }}</strong>
        <span class="mono">{{ detail.logical_path || '/' }}</span>
        <span
          class="extraction-status"
          :class="`extraction-status--${extractionTone}`"
        >
          {{ fileNodeExtractionLabel(detail.extraction_status) }}
        </span>
      </section>

      <section class="detail-section">
        <h3>文件属性</h3>
        <dl class="attribute-list">
          <div>
            <dt>节点编号</dt>
            <dd class="mono">{{ detail.id }}</dd>
          </div>
          <div>
            <dt>节点类型</dt>
            <dd>{{ fileNodeTypeLabel(detail.node_type) }}</dd>
          </div>
          <div>
            <dt>格式</dt>
            <dd class="format-value">{{ detail.format || '—' }}</dd>
          </div>
          <div>
            <dt>MIME</dt>
            <dd class="mono">{{ detail.mime_type || '—' }}</dd>
          </div>
          <div>
            <dt>架构</dt>
            <dd>{{ detail.architecture || '—' }}</dd>
          </div>
          <div>
            <dt>大小</dt>
            <dd class="mono">{{ formatFileSize(detail.size_bytes) }}</dd>
          </div>
          <div class="attribute-list__wide">
            <dt>SHA-256</dt>
            <dd class="mono hash-value">{{ detail.sha256 || '—' }}</dd>
          </div>
        </dl>
      </section>

      <section class="detail-section provenance-section">
        <h3>来源容器</h3>
        <div v-if="detail.source_container" class="source-container">
          <Archive class="source-container__icon" :size="17" aria-hidden="true" />
          <div class="source-container__identity">
            <span class="source-container__format mono">
              {{ detail.source_container.format }}
            </span>
            <strong
              class="mono"
              :title="detail.source_container.logical_path"
            >
              {{ detail.source_container.logical_path }}
            </strong>
            <small class="mono">节点 {{ detail.source_container.id }}</small>
          </div>
          <button
            class="source-container__command"
            type="button"
            :aria-label="`打开来源容器 ${detail.source_container.logical_path}`"
            :title="`打开来源容器节点：${detail.source_container.logical_path}`"
            @click="emit('openSourceContainer', detail.source_container)"
          >
            <ExternalLink :size="14" aria-hidden="true" />
            <span>打开节点</span>
          </button>
        </div>
        <div v-else class="source-container source-container--root">
          <Archive class="source-container__icon" :size="17" aria-hidden="true" />
          <div class="source-container__identity">
            <strong>根输入样本</strong>
            <small>无来源容器</small>
          </div>
        </div>
      </section>

      <section class="detail-section">
        <h3>父来源</h3>
        <div v-if="detail.source_parent" class="source-parent">
          <strong class="mono">{{ detail.source_parent.logical_path }}</strong>
          <span class="mono">节点 {{ detail.source_parent.id }}</span>
        </div>
        <div v-else class="source-parent">
          <strong>根输入</strong>
          <span>无父文件节点</span>
        </div>
      </section>

      <section
        v-if="detail.error_code || detail.error_message"
        class="diagnostic-section"
        role="alert"
      >
        <AlertTriangle :size="16" aria-hidden="true" />
        <div>
          <strong class="mono">{{ detail.error_code || 'EXTRACTION_ERROR' }}</strong>
          <span>{{ detail.error_message || '该节点处理失败，未提供更多信息。' }}</span>
        </div>
      </section>

      <section class="detail-section metadata-section">
        <h3>结构化元数据</h3>
        <dl v-if="metadataEntries.length" class="metadata-list">
          <div v-for="entry in metadataEntries" :key="entry.key">
            <dt class="mono">{{ entry.key }}</dt>
            <dd>
              <pre v-if="isCompositeMetadata(entry.value)" class="mono">{{ metadataText(entry.value) }}</pre>
              <span v-else>{{ metadataText(entry.value) }}</span>
            </dd>
          </div>
        </dl>
        <p v-else class="metadata-empty">无附加元数据</p>
      </section>
    </div>
  </aside>
</template>

<style scoped>
.file-detail-panel {
  min-width: 0;
  border-left: 1px solid var(--line);
  background: #fafbfb;
}

.file-detail-toolbar {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 12px;
  border-bottom: 1px solid var(--line);
  background: #f5f7f7;
}

.file-detail-toolbar__heading {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  color: var(--teal-strong);
}

.file-detail-toolbar__heading div {
  min-width: 0;
}

.file-detail-toolbar__heading small,
.file-detail-toolbar__heading strong {
  display: block;
}

.file-detail-toolbar__heading small {
  color: var(--ink-400);
  font-size: 9px;
}

.file-detail-toolbar__heading strong {
  max-width: 240px;
  margin-top: 2px;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.close-command {
  display: grid;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  padding: 0;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.close-command:hover {
  color: var(--red);
  background: #fff5f5;
}

.file-detail-state {
  min-height: 300px;
}

.file-detail-content {
  max-height: min(720px, calc(100vh - 150px));
  overflow: auto;
  overscroll-behavior: contain;
}

.identity-section {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 4px 10px;
  padding: 13px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.identity-section > strong,
.identity-section > span:not(.extraction-status) {
  min-width: 0;
  overflow-wrap: anywhere;
}

.identity-section > strong {
  color: var(--ink-950);
  font-size: 13px;
}

.identity-section > span:not(.extraction-status) {
  grid-column: 1 / -1;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.45;
}

.extraction-status {
  display: inline-flex;
  min-height: 23px;
  align-items: center;
  align-self: start;
  padding: 2px 7px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #f7f8f8;
  font-size: 10px;
  white-space: nowrap;
}

.extraction-status--success {
  border-color: #b8d7d3;
  color: #076860;
  background: #f1f8f7;
}

.extraction-status--warning {
  border-color: #decba7;
  color: #83551a;
  background: #fff9ef;
}

.extraction-status--failed {
  border-color: #e4bebe;
  color: #a52f2f;
  background: #fff5f5;
}

.detail-section {
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}

.detail-section h3 {
  min-height: 34px;
  margin: 0;
  padding: 10px 14px 7px;
  color: var(--ink-600);
  font-size: 10px;
  text-transform: uppercase;
}

.attribute-list,
.metadata-list {
  margin: 0;
}

.attribute-list {
  display: grid;
  grid-template-columns: 1fr 1fr;
}

.attribute-list > div {
  min-width: 0;
  padding: 8px 14px 10px;
  border-top: 1px solid #edf0f0;
}

.attribute-list > div:nth-child(odd):not(.attribute-list__wide) {
  border-right: 1px solid #edf0f0;
}

.attribute-list__wide {
  grid-column: 1 / -1;
}

.attribute-list dt,
.metadata-list dt {
  color: var(--ink-400);
  font-size: 9px;
}

.attribute-list dd,
.metadata-list dd {
  min-width: 0;
  margin: 4px 0 0;
  color: var(--ink-800);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.format-value {
  text-transform: uppercase;
}

.hash-value {
  font-size: 9px !important;
  line-height: 1.45;
}

.source-parent {
  display: grid;
  gap: 5px;
  padding: 2px 14px 13px;
}

.source-parent strong {
  color: var(--ink-800);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.source-parent span {
  color: var(--ink-400);
  font-size: 9px;
}

.source-container {
  display: grid;
  min-width: 0;
  grid-template-columns: 26px minmax(0, 1fr) auto;
  align-items: center;
  gap: 9px;
  padding: 3px 14px 13px;
}

.source-container__icon {
  color: var(--teal-strong);
}

.source-container__identity {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.source-container__identity strong {
  display: -webkit-box;
  min-width: 0;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 10px;
  line-height: 1.45;
  overflow-wrap: anywhere;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.source-container__identity small {
  overflow: hidden;
  color: var(--ink-400);
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.source-container__format {
  width: max-content;
  max-width: 100%;
  overflow: hidden;
  color: var(--teal-strong);
  font-size: 9px;
  font-weight: 700;
  text-overflow: ellipsis;
  text-transform: uppercase;
  white-space: nowrap;
}

.source-container__command {
  display: inline-flex;
  min-height: 30px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 4px 8px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  font-size: 10px;
  cursor: pointer;
}

.source-container__command:hover,
.source-container__command:focus-visible {
  border-color: #91bbb6;
  color: var(--teal-strong);
  background: #edf6f5;
}

.source-container--root {
  grid-template-columns: 26px minmax(0, 1fr);
}

.diagnostic-section {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 12px 14px;
  border-bottom: 1px solid #e3bcbc;
  color: var(--red);
  background: #fff7f7;
}

.diagnostic-section div {
  min-width: 0;
}

.diagnostic-section strong,
.diagnostic-section span {
  display: block;
  overflow-wrap: anywhere;
}

.diagnostic-section strong {
  font-size: 10px;
}

.diagnostic-section span {
  margin-top: 4px;
  color: #7e4040;
  font-size: 11px;
  line-height: 1.5;
}

.metadata-list > div {
  padding: 8px 14px 10px;
  border-top: 1px solid #edf0f0;
}

.metadata-list pre {
  max-width: 100%;
  max-height: 240px;
  margin: 0;
  overflow: auto;
  color: var(--ink-800);
  font-size: 9px;
  line-height: 1.55;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.metadata-list span {
  white-space: pre-wrap;
}

.metadata-empty {
  margin: 0;
  padding: 2px 14px 14px;
  color: var(--ink-400);
  font-size: 11px;
}

@container (max-width: 960px) {
  .file-detail-panel {
    border-top: 1px solid var(--line);
    border-left: 0;
  }

  .file-detail-content {
    max-height: none;
  }

  .file-detail-toolbar__heading strong {
    max-width: min(520px, 70vw);
  }
}

@container (max-width: 460px) {
  .attribute-list {
    grid-template-columns: 1fr;
  }

  .attribute-list > div:nth-child(odd):not(.attribute-list__wide) {
    border-right: 0;
  }

  .source-container {
    grid-template-columns: 22px minmax(0, 1fr);
  }

  .source-container__command {
    grid-column: 2;
    justify-self: start;
  }
}
</style>
