<script setup lang="ts">
import { CodeXml, Files, ScanSearch, ShieldCheck } from 'lucide-vue-next'
import { computed } from 'vue'

import type {
  FileDecompileRequest,
  FileNodeDetail,
  TaskDetail,
  UserRole,
} from '@/api/types'
import FileNodeDecompileAction from '@/components/tasks/FileNodeDecompileAction.vue'
import FileNodeImageScanAction from '@/components/tasks/FileNodeImageScanAction.vue'
import { getFileNodeDecompileActionModel } from '@/components/tasks/fileNodeDecompile'
import { getFileNodeImageScanActionModel } from '@/components/tasks/fileNodeImageScan'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { isContainerImageInputType } from '@/components/tasks/taskResultProfile'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

const props = defineProps<{
  task: TaskDetail
  node: FileNodeDetail | null
  userRole: UserRole | null
  mode: TaskActionMode
  sampleRetention: SampleRetentionSnapshot
}>()

const emit = defineEmits<{
  openFiles: []
  openVulnerabilities: []
  decompileCompleted: [request: FileDecompileRequest]
}>()

const canOperate = computed(
  () => props.userRole === 'administrator' || props.userRole === 'operator',
)
const containerTask = computed(() => isContainerImageInputType(props.task.input_type))
const decompileModel = computed(() =>
  props.node
    ? getFileNodeDecompileActionModel({
        node: props.node,
        taskStatus: props.task.status,
        userRole: props.userRole,
        mode: props.mode,
        sampleRetention: props.sampleRetention,
      })
    : null,
)
const imageScanModel = computed(() =>
  props.node
    ? getFileNodeImageScanActionModel({
        node: props.node,
        taskStatus: props.task.status,
        userRole: props.userRole,
        mode: props.mode,
        sampleRetention: props.sampleRetention,
      })
    : null,
)
const hasNodeAction = computed(
  () => Boolean(decompileModel.value?.visible || imageScanModel.value?.visible),
)
const selectedNodeLabel = computed(
  () => props.node?.display_name || props.node?.logical_path || '',
)
</script>

<template>
  <section
    v-if="canOperate"
    class="analysis-actions surface-panel"
    aria-labelledby="analysis-actions-title"
  >
    <header class="analysis-actions__header">
      <span class="analysis-actions__icon" aria-hidden="true">
        <ShieldCheck :size="17" />
      </span>
      <div class="analysis-actions__heading">
        <h2 id="analysis-actions-title">分析操作</h2>
        <span v-if="selectedNodeLabel" :title="selectedNodeLabel">
          {{ selectedNodeLabel }}
        </span>
      </div>
      <div
        v-if="!hasNodeAction"
        class="analysis-actions__commands"
        role="group"
        aria-label="任务分析操作"
      >
        <el-button
          v-if="containerTask"
          type="primary"
          :icon="ScanSearch"
          @click="emit('openVulnerabilities')"
        >
          查看 Trivy 检测
        </el-button>
        <el-button
          :type="containerTask ? 'default' : 'primary'"
          :icon="containerTask ? Files : CodeXml"
          @click="emit('openFiles')"
        >
          {{ containerTask ? '选择嵌套镜像' : '选择文件并发起反编译' }}
        </el-button>
      </div>
    </header>

    <FileNodeDecompileAction
      v-if="node && decompileModel?.visible"
      :task-id="task.id"
      :task-status="task.status"
      :node="node"
      :user-role="userRole"
      :mode="mode"
      :sample-retention="sampleRetention"
      @completed="emit('decompileCompleted', $event)"
    />

    <FileNodeImageScanAction
      v-if="node && imageScanModel?.visible"
      :task-id="task.id"
      :task-status="task.status"
      :node="node"
      :user-role="userRole"
      :mode="mode"
      :sample-retention="sampleRetention"
    />
  </section>
</template>

<style scoped>
.analysis-actions {
  min-width: 0;
  overflow: hidden;
  border-left: 3px solid var(--teal);
}

.analysis-actions__header {
  display: flex;
  min-height: 62px;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  background: #f7fbfa;
}

.analysis-actions__icon {
  display: grid;
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
  place-items: center;
  border: 1px solid #afd2cd;
  border-radius: 4px;
  color: var(--teal-strong);
  background: var(--surface);
}

.analysis-actions__heading {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.analysis-actions__heading h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
}

.analysis-actions__heading span {
  max-width: min(36vw, 420px);
  overflow: hidden;
  color: var(--ink-600);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.analysis-actions__commands {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  margin-left: auto;
}

.analysis-actions :deep(.decompile-command),
.analysis-actions :deep(.image-scan-command) {
  border-top: 1px solid var(--line);
  border-bottom: 0;
}

@container (max-width: 620px) {
  .analysis-actions__header {
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .analysis-actions__commands {
    width: 100%;
    justify-content: stretch;
    margin-left: 42px;
  }

  .analysis-actions__commands :deep(.el-button) {
    min-width: 0;
    flex: 1;
    margin: 0;
  }
}

@container (max-width: 440px) {
  .analysis-actions__commands {
    align-items: stretch;
    flex-direction: column;
    margin-left: 0;
  }

  .analysis-actions__commands :deep(.el-button) {
    width: 100%;
  }
}
</style>
