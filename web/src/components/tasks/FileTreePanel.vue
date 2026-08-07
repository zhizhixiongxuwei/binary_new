<script setup lang="ts">
import { AlertTriangle, LoaderCircle, Plus, RefreshCw, RotateCw } from 'lucide-vue-next'
import { computed, shallowRef, watch } from 'vue'

import type {
  FileNode,
  FileNodeDetail,
  FileNodeSourceContainer,
} from '@/api/types'
import StatePanel from '@/components/common/StatePanel.vue'
import FileNodeDetailPanel from '@/components/tasks/FileNodeDetailPanel.vue'
import FileTreeBranch from '@/components/tasks/FileTreeBranch.vue'
import {
  ROOT_FILE_BRANCH,
  useFileTree,
  type FileTreeBranchState,
} from '@/composables/useFileTree'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

const props = withDefaults(
  defineProps<{
    taskId: string
    sampleRetention?: SampleRetentionSnapshot | null
  }>(),
  {
    sampleRetention: null,
  },
)

const emit = defineEmits<{
  nodeDetailChange: [detail: FileNodeDetail | null]
}>()

const {
  branches,
  expandedNodeIds,
  toggleNode,
  loadMore,
  retryBranch,
  reload,
} = useFileTree(() => props.taskId)

const emptyRoot: Readonly<FileTreeBranchState> = {
  items: [],
  nextCursor: undefined,
  loading: true,
  loaded: false,
  errorMessage: '',
  errorAction: undefined,
}

const root = computed(() => branches[ROOT_FILE_BRANCH] ?? emptyRoot)
const selectedNodeId = shallowRef<string | null>(null)
const selectedNodeName = shallowRef('')

function selectNode(node: FileNode): void {
  selectedNodeId.value = node.id
  selectedNodeName.value = node.display_name || node.logical_path || '/'
}

function openSourceContainer(source: FileNodeSourceContainer): void {
  const pathSegments = source.logical_path.split('/').filter(Boolean)
  selectedNodeId.value = source.id
  selectedNodeName.value =
    pathSegments[pathSegments.length - 1] ?? source.logical_path
}

function clearSelection(): void {
  selectedNodeId.value = null
  selectedNodeName.value = ''
}

function reloadAll(): void {
  clearSelection()
  reload()
}

watch(
  () => props.taskId,
  () => clearSelection(),
)

watch(
  () => ({
    loaded: root.value.loaded,
    loading: root.value.loading,
    nextCursor: root.value.nextCursor,
    items: root.value.items,
  }),
  ({ loaded, loading, nextCursor, items }) => {
    if (
      selectedNodeId.value === null &&
      loaded &&
      !loading &&
      !nextCursor &&
      items.length === 1 &&
      items[0]?.node_type === 'file'
    ) {
      selectNode(items[0])
    }
  },
)
</script>

<template>
  <div class="file-tree-panel" aria-label="任务文件结构">
    <header class="file-tree-toolbar">
      <div class="file-tree-toolbar__summary">
        <strong>文件索引</strong>
        <span v-if="root.loaded">根节点已载入 {{ root.items.length }} 项</span>
      </div>
      <button
        class="refresh-command"
        type="button"
        aria-label="刷新文件结构"
        title="刷新文件结构"
        @click="reloadAll"
      >
        <RefreshCw :class="{ spin: root.loading }" :size="16" />
      </button>
    </header>

    <div class="file-explorer">
      <section class="file-tree-pane" aria-label="文件节点索引">
        <StatePanel
          v-if="root.loading && !root.loaded"
          class="file-tree-state"
          kind="loading"
          title="正在读取文件结构"
        />
        <StatePanel
          v-else-if="root.errorMessage && !root.items.length"
          class="file-tree-state"
          kind="error"
          :description="root.errorMessage"
          retryable
          @retry="retryBranch(null)"
        />
        <StatePanel
          v-else-if="root.loaded && !root.items.length"
          class="file-tree-state"
          kind="empty"
          title="文件结构尚未生成"
        />

        <div v-else class="file-tree-content">
          <div class="file-tree-columns" aria-hidden="true">
            <span>名称</span>
            <span>类型 / 格式</span>
            <span>大小</span>
            <span>提取状态</span>
          </div>

          <div class="file-tree" aria-label="文件节点">
            <FileTreeBranch
              :nodes="root.items"
              :branches="branches"
              :expanded-node-ids="expandedNodeIds"
              :selected-node-id="selectedNodeId"
              @toggle="toggleNode"
              @select="selectNode"
              @load-more="loadMore"
              @retry="retryBranch"
            />
          </div>

          <div
            v-if="root.errorMessage && root.items.length"
            class="root-page-state root-page-state--error"
            role="alert"
          >
            <AlertTriangle :size="15" />
            <span>{{ root.errorMessage }}</span>
            <button type="button" @click="retryBranch(null)">
              <RotateCw :size="14" />
              重试
            </button>
          </div>

          <div
            v-if="root.loading && root.loaded"
            class="root-page-state"
            role="status"
          >
            <LoaderCircle class="spin" :size="15" />
            <span>正在加载更多</span>
          </div>
          <button
            v-else-if="root.nextCursor && !root.errorMessage"
            class="root-load-more"
            type="button"
            @click="loadMore(null)"
          >
            <Plus :size="15" />
            加载更多
          </button>
        </div>
      </section>

      <FileNodeDetailPanel
        :task-id="taskId"
        :file-id="selectedNodeId"
        :file-name="selectedNodeName"
        :sample-retention="sampleRetention"
        @close="clearSelection"
        @open-source-container="openSourceContainer"
        @detail-change="emit('nodeDetailChange', $event)"
      />
    </div>
  </div>
</template>

<style scoped>
.file-tree-panel {
  min-width: 0;
  container-type: inline-size;
}

.file-explorer {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1.65fr) minmax(320px, 0.75fr);
}

.file-tree-pane {
  min-width: 0;
  container-type: inline-size;
}

.file-tree-toolbar {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--line);
  background: #fbfcfc;
}

.file-tree-toolbar__summary {
  display: flex;
  min-width: 0;
  align-items: baseline;
  gap: 10px;
}

.file-tree-toolbar__summary strong {
  color: var(--ink-800);
  font-size: 12px;
}

.file-tree-toolbar__summary span {
  color: var(--ink-400);
  font-size: 10px;
}

.refresh-command {
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

.refresh-command:hover {
  color: var(--teal-strong);
  background: #edf5f4;
}

.file-tree-state {
  min-height: 290px;
}

.file-tree-content {
  min-width: 0;
  padding: 0 14px 12px;
}

.file-tree-columns {
  display: grid;
  min-height: 35px;
  grid-template-columns: 65px minmax(210px, 1fr) minmax(118px, 0.32fr) 104px 132px;
  align-items: center;
  gap: 7px;
  border-bottom: 1px solid var(--line-strong);
  color: var(--ink-600);
  font-size: 10px;
  font-weight: 700;
}

.file-tree-columns span:first-child {
  grid-column: 2;
}

.file-tree {
  min-width: 0;
}

.root-page-state {
  display: flex;
  min-height: 42px;
  align-items: center;
  justify-content: center;
  gap: 7px;
  border-bottom: 1px solid #e8ebec;
  color: var(--ink-600);
  background: #f9fafa;
  font-size: 11px;
}

.root-page-state--error {
  color: var(--red);
  background: #fffafa;
}

.root-page-state button,
.root-load-more {
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

.root-page-state button {
  padding: 3px 8px;
}

.root-load-more {
  width: 100%;
  border-width: 0 0 1px;
  border-color: #e8ebec;
  border-radius: 0;
  background: #f9fafa;
}

.root-page-state button:hover,
.root-load-more:hover {
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
  .file-tree-content {
    padding: 0 8px 10px;
  }

  .file-tree-columns {
    display: none;
  }

  .file-tree-toolbar__summary {
    align-items: flex-start;
    flex-direction: column;
    gap: 2px;
  }
}

@container (max-width: 960px) {
  .file-explorer {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
