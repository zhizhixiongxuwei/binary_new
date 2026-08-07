<script setup lang="ts">
import {
  AlertTriangle,
  Archive,
  ChevronRight,
  File,
  FileCode2,
  Folder,
  Link2,
  LoaderCircle,
  Plus,
  RotateCw,
} from 'lucide-vue-next'
import type { Component } from 'vue'

import type { FileNode } from '@/api/types'
import { fileBranchKey, isExpandableFileNode } from '@/composables/useFileTree'
import { formatBytes } from '@/utils/formatters'
import {
  fileNodeDisplayName,
  fileNodeExtractionLabel,
  fileNodeStatusTone,
  fileNodeTypeLabel,
} from '@/utils/fileNodes'

interface FileTreeBranchViewState {
  readonly items: readonly FileNode[]
  readonly nextCursor: string | undefined
  readonly loading: boolean
  readonly loaded: boolean
  readonly errorMessage: string
  readonly errorAction: 'initial' | 'more' | undefined
}

const props = defineProps<{
  nodes: readonly FileNode[]
  branches: Readonly<Record<string, FileTreeBranchViewState>>
  expandedNodeIds: ReadonlySet<string>
  selectedNodeId: string | null
}>()

const emit = defineEmits<{
  toggle: [node: FileNode]
  select: [node: FileNode]
  loadMore: [parentId: string]
  retry: [parentId: string]
}>()

const archiveFormats = new Set([
  'zip',
  'jar',
  'war',
  'ear',
  'apk',
  'tar',
  'docker-tar',
  'oci-tar',
  'gzip',
  'bzip2',
  'xz',
  'zstd',
  '7z',
  'rar',
])

function branchState(nodeId: string): FileTreeBranchViewState | undefined {
  return props.branches[fileBranchKey(nodeId)]
}

function isExpanded(nodeId: string): boolean {
  return props.expandedNodeIds.has(nodeId)
}

function nodeIcon(node: FileNode): Component {
  if (node.node_type === 'directory') return Folder
  if (node.node_type === 'symlink' || node.node_type === 'hardlink') return Link2
  if (archiveFormats.has(node.format.toLowerCase())) return Archive
  if (node.format) return FileCode2
  return File
}

function formatNodeSize(size: number | null): string {
  return formatBytes(size ?? undefined)
}

function nodeType(node: FileNode): string {
  return node.format || fileNodeTypeLabel(node.node_type)
}

function sourceHintTitle(node: FileNode): string {
  const source = node.source_container
  return source
    ? `来源容器：${source.logical_path}（${source.format}）`
    : ''
}
</script>

<template>
  <ul class="file-tree-branch">
    <li v-for="node in nodes" :key="node.id" class="file-node">
      <div
        class="file-node__row"
        :class="{ 'file-node__row--selected': selectedNodeId === node.id }"
      >
        <button
          v-if="isExpandableFileNode(node)"
          class="tree-command"
          type="button"
          :aria-label="`${isExpanded(node.id) ? '折叠' : '展开'} ${fileNodeDisplayName(node)}`"
          :aria-expanded="isExpanded(node.id)"
          @click="emit('toggle', node)"
        >
          <ChevronRight
            class="tree-command__chevron"
            :class="{ 'tree-command__chevron--open': isExpanded(node.id) }"
            :size="16"
          />
        </button>
        <span v-else class="tree-command tree-command--placeholder" aria-hidden="true" />

        <span class="file-node__icon" aria-hidden="true">
          <component :is="nodeIcon(node)" :size="17" />
        </span>

        <button
          class="file-node__identity"
          type="button"
          :aria-label="`查看 ${fileNodeDisplayName(node)} 的节点详情`"
          :aria-current="selectedNodeId === node.id ? 'true' : 'false'"
          @click="emit('select', node)"
        >
          <strong :title="node.logical_path">{{ fileNodeDisplayName(node) }}</strong>
          <small class="mono" :title="node.logical_path">{{ node.logical_path }}</small>
        </button>

        <span class="file-node__type">
          <strong>{{ nodeType(node) }}</strong>
          <small :title="sourceHintTitle(node)">
            {{ fileNodeTypeLabel(node.node_type) }}
            <span v-if="node.source_container" class="source-format-hint">
              · 来源 {{ node.source_container.format }}
            </span>
          </small>
        </span>

        <span class="file-node__size mono">{{ formatNodeSize(node.size_bytes) }}</span>

        <span class="file-node__result">
          <span
            class="extraction-status"
            :class="`extraction-status--${fileNodeStatusTone(node.extraction_status)}`"
          >
            {{ fileNodeExtractionLabel(node.extraction_status) }}
          </span>
          <details
            v-if="node.error_code || node.error_message"
            class="node-error"
            @click.stop
          >
            <summary
              :aria-label="`查看 ${fileNodeDisplayName(node)} 的错误原因`"
              :title="`查看 ${fileNodeDisplayName(node)} 的错误原因`"
            >
              <AlertTriangle :size="16" />
            </summary>
            <span class="node-error__content" role="alert">
              <strong class="mono">{{ node.error_code || 'EXTRACTION_ERROR' }}</strong>
              <span>{{ node.error_message || '该节点处理失败，未提供更多信息。' }}</span>
            </span>
          </details>
        </span>
      </div>

      <div v-if="isExpanded(node.id)" class="file-node__children">
        <div
          v-if="branchState(node.id)?.loading && !branchState(node.id)?.loaded"
          class="branch-state"
          role="status"
        >
          <LoaderCircle class="spin" :size="16" />
          <span>正在读取子项</span>
        </div>

        <div
          v-else-if="
            branchState(node.id)?.errorMessage && !branchState(node.id)?.items.length
          "
          class="branch-state branch-state--error"
          role="alert"
        >
          <AlertTriangle :size="16" />
          <span>{{ branchState(node.id)?.errorMessage }}</span>
          <button
            class="inline-command"
            type="button"
            :aria-label="`重试读取 ${fileNodeDisplayName(node)} 的子项`"
            @click="emit('retry', node.id)"
          >
            <RotateCw :size="14" />
            重试
          </button>
        </div>

        <template v-else-if="branchState(node.id)?.loaded">
          <FileTreeBranch
            v-if="branchState(node.id)?.items.length"
            :nodes="branchState(node.id)?.items ?? []"
            :branches="branches"
            :expanded-node-ids="expandedNodeIds"
            :selected-node-id="selectedNodeId"
            @toggle="emit('toggle', $event)"
            @select="emit('select', $event)"
            @load-more="emit('loadMore', $event)"
            @retry="emit('retry', $event)"
          />
          <div v-else class="branch-state branch-state--empty" role="status">
            <span>该节点没有子项</span>
          </div>
        </template>

        <div
          v-if="
            branchState(node.id)?.errorMessage && branchState(node.id)?.items.length
          "
          class="branch-state branch-state--error branch-state--compact"
          role="alert"
        >
          <AlertTriangle :size="15" />
          <span>{{ branchState(node.id)?.errorMessage }}</span>
          <button
            class="inline-command"
            type="button"
            :aria-label="`重试加载 ${fileNodeDisplayName(node)} 的更多子项`"
            @click="emit('retry', node.id)"
          >
            <RotateCw :size="14" />
            重试
          </button>
        </div>

        <div
          v-if="branchState(node.id)?.loading && branchState(node.id)?.loaded"
          class="branch-state branch-state--compact"
          role="status"
        >
          <LoaderCircle class="spin" :size="15" />
          <span>正在加载更多</span>
        </div>

        <button
          v-else-if="
            branchState(node.id)?.nextCursor && !branchState(node.id)?.errorMessage
          "
          class="load-more-command"
          type="button"
          @click="emit('loadMore', node.id)"
        >
          <Plus :size="15" />
          加载更多
        </button>
      </div>
    </li>
  </ul>
</template>

<style scoped>
.file-tree-branch {
  min-width: 0;
  margin: 0;
  padding: 0;
  list-style: none;
}

.file-node {
  min-width: 0;
}

.file-node__row {
  position: relative;
  display: grid;
  min-height: 54px;
  grid-template-columns: 28px 30px minmax(210px, 1fr) minmax(118px, 0.32fr) 104px 132px;
  align-items: center;
  gap: 7px;
  border-bottom: 1px solid #e8ebec;
  color: var(--ink-800);
}

.file-node__row:hover {
  background: #f7f9f9;
}

.file-node__row--selected {
  background: #edf6f5;
  box-shadow: 3px 0 0 var(--teal) inset;
}

.file-node__row--selected:hover {
  background: #e7f2f1;
}

.tree-command {
  display: grid;
  width: 28px;
  height: 28px;
  padding: 0;
  place-items: center;
  border: 0;
  border-radius: 4px;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
}

.tree-command:hover {
  color: var(--teal-strong);
  background: #eaf3f2;
}

.tree-command--placeholder {
  cursor: default;
}

.tree-command__chevron {
  transition: transform 140ms ease;
}

.tree-command__chevron--open {
  transform: rotate(90deg);
}

.file-node__icon {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 1px solid #dce2e3;
  border-radius: 4px;
  color: var(--blue);
  background: #f5f8fa;
}

.file-node__identity,
.file-node__type {
  min-width: 0;
}

.file-node__identity {
  width: 100%;
  padding: 5px 4px;
  border: 0;
  border-radius: 3px;
  color: inherit;
  background: transparent;
  text-align: left;
  cursor: pointer;
}

.file-node__identity:hover {
  background: #eaf3f2;
}

.file-node__identity strong,
.file-node__identity small,
.file-node__type strong,
.file-node__type small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-node__identity strong,
.file-node__type strong {
  font-size: 12px;
}

.file-node__identity small,
.file-node__type small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 9px;
}

.file-node__type strong {
  text-transform: uppercase;
}

.source-format-hint {
  color: var(--teal-strong);
  text-transform: uppercase;
}

.file-node__size {
  color: var(--ink-600);
  font-size: 10px;
}

.file-node__result {
  position: relative;
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 6px;
}

.extraction-status {
  display: inline-flex;
  min-height: 23px;
  align-items: center;
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

.node-error {
  position: relative;
}

.node-error summary {
  display: grid;
  width: 26px;
  height: 26px;
  place-items: center;
  border-radius: 4px;
  color: var(--red);
  cursor: pointer;
  list-style: none;
}

.node-error summary::-webkit-details-marker {
  display: none;
}

.node-error summary:hover {
  background: #fff0f0;
}

.node-error__content {
  position: absolute;
  z-index: 5;
  top: 31px;
  right: 0;
  width: min(320px, 70vw);
  padding: 11px 12px;
  border: 1px solid #e3bcbc;
  border-radius: 5px;
  color: #7e4040;
  background: #fffafa;
  box-shadow: 0 5px 18px rgb(23 36 39 / 14%);
  max-height: min(360px, calc(100vh - 64px));
  overflow-y: auto;
}

.node-error__content strong,
.node-error__content span {
  display: block;
  overflow-wrap: anywhere;
}

.node-error__content strong {
  color: var(--red);
  font-size: 10px;
}

.node-error__content span {
  margin-top: 5px;
  font-size: 11px;
  line-height: 1.5;
}

.file-node__children {
  margin-left: 27px;
  padding-left: 16px;
  border-left: 1px solid #cfd8da;
}

.branch-state {
  display: flex;
  min-height: 50px;
  align-items: center;
  gap: 8px;
  padding: 9px 12px;
  border-bottom: 1px solid #e8ebec;
  color: var(--ink-600);
  font-size: 11px;
}

.branch-state--error {
  color: var(--red);
  background: #fffafa;
}

.branch-state--empty {
  color: var(--ink-400);
}

.branch-state--compact {
  min-height: 42px;
}

.inline-command,
.load-more-command {
  display: inline-flex;
  min-height: 28px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  font-size: 11px;
  cursor: pointer;
}

.inline-command {
  margin-left: auto;
  padding: 3px 8px;
}

.load-more-command {
  width: 100%;
  border-width: 0 0 1px;
  border-color: #e8ebec;
  border-radius: 0;
  background: #f9fafa;
}

.inline-command:hover,
.load-more-command:hover {
  color: var(--teal-strong);
  background: #edf5f4;
}

.spin {
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  to {
    transform: rotate(360deg);
  }
}

@container (max-width: 700px) {
  .file-node__row {
    min-height: 68px;
    grid-template-columns: 28px 30px minmax(0, 1fr) auto;
    grid-template-rows: 32px 24px;
    gap: 0 7px;
    padding: 5px 0;
  }

  .tree-command,
  .file-node__icon {
    grid-row: 1 / 3;
  }

  .file-node__identity {
    grid-column: 3;
    grid-row: 1;
  }

  .file-node__type {
    grid-column: 3;
    grid-row: 2;
  }

  .file-node__type strong,
  .file-node__type small {
    display: inline;
    margin: 0 6px 0 0;
    font-size: 9px;
  }

  .file-node__size {
    grid-column: 4;
    grid-row: 1;
    text-align: right;
  }

  .file-node__result {
    grid-column: 4;
    grid-row: 2;
    justify-content: flex-end;
  }

  .file-node__children {
    margin-left: 0;
    padding-left: 4px;
  }

  .node-error__content {
    position: fixed;
    top: auto;
    right: 16px;
    bottom: 16px;
    left: 16px;
    width: auto;
    max-height: calc(100vh - 32px);
  }
}

@media (prefers-reduced-motion: reduce) {
  .tree-command__chevron {
    transition: none;
  }

  .spin {
    animation: none;
  }
}
</style>
