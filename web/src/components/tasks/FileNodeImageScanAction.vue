<script setup lang="ts">
import { ScanSearch } from 'lucide-vue-next'
import { computed, useId } from 'vue'

import type {
  FileNodeDetail,
  TaskStatus,
  UserRole,
} from '@/api/types'
import {
  getFileNodeImageScanActionModel,
} from '@/components/tasks/fileNodeImageScan'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { useManualImageScan } from '@/composables/useManualImageScan'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

const props = defineProps<{
  taskId: string
  taskStatus: TaskStatus
  node: FileNodeDetail
  userRole: UserRole | null
  mode: TaskActionMode
  sampleRetention: SampleRetentionSnapshot
}>()

const componentId = useId().replace(/:/g, '')
const titleId = `file-image-scan-title-${componentId}`
const reasonId = `file-image-scan-reason-${componentId}`
const model = computed(() =>
  getFileNodeImageScanActionModel({
    node: props.node,
    taskStatus: props.taskStatus,
    userRole: props.userRole,
    mode: props.mode,
    sampleRetention: props.sampleRetention,
  }),
)
const imageScan = useManualImageScan({
  taskId: () => props.taskId,
  fileNodeId: () => props.node.id,
  mode: () => props.mode,
  enabled: () => model.value.enabled,
  disabledReason: () => model.value.reason,
})
const commandDisabled = computed(
  () =>
    !model.value.enabled ||
    imageScan.pending.value ||
    imageScan.request.value !== undefined,
)
const rootImage = computed(() => props.node.parent_id === null)
const taskActive = computed(
  () => !['SUCCEEDED', 'PARTIAL', 'PARTIAL_SUCCEEDED', 'FAILED', 'CANCELLED']
    .includes(props.taskStatus.trim().toUpperCase()),
)
const commandTitle = computed(() => {
  if (imageScan.pending.value) return '正在提交镜像检测请求。'
  if (imageScan.request.value) return '该镜像检测请求已进入队列。'
  return model.value.reason
})
</script>

<template>
  <section
    v-if="model.visible"
    class="image-scan-command"
    :aria-labelledby="titleId"
  >
    <div class="image-scan-command__copy">
      <span class="image-scan-command__icon" aria-hidden="true">
        <ScanSearch :size="16" />
      </span>
      <span>
        <strong :id="titleId">
          {{ rootImage ? 'Trivy 镜像检测' : '单独检测嵌套镜像' }}
        </strong>
        <small :id="reasonId">{{ commandTitle }}</small>
      </span>
    </div>
    <el-button
      :data-action="rootImage ? 'scan-root-image' : 'scan-nested-image'"
      :icon="ScanSearch"
      :loading="imageScan.pending.value"
      :disabled="commandDisabled"
      :title="commandTitle"
      :aria-describedby="reasonId"
      @click="imageScan.submit"
    >
      {{
        imageScan.request.value
          ? '请求已排队'
          : imageScan.pending.value
            ? '正在提交'
            : rootImage
              ? taskActive
                ? '检测已排队'
                : '开始 Trivy 检测'
              : '单独检测'
      }}
    </el-button>

    <div
      v-if="imageScan.request.value"
      class="image-scan-command__feedback"
      role="status"
      aria-live="polite"
    >
      <strong>{{ imageScan.feedbackMessage.value }}</strong>
      <span>仅表示请求已排队，尚未完成 Trivy 检测。</span>
      <dl>
        <div>
          <dt>Job</dt>
          <dd class="mono">{{ imageScan.request.value.job_id }}</dd>
        </div>
        <div>
          <dt>节点</dt>
          <dd class="mono">{{ imageScan.request.value.file_node_id }}</dd>
        </div>
        <div>
          <dt>状态</dt>
          <dd class="mono">{{ imageScan.request.value.status }}</dd>
        </div>
      </dl>
    </div>
    <p
      v-else-if="imageScan.errorMessage.value"
      class="image-scan-command__error"
      role="alert"
    >
      {{ imageScan.errorMessage.value }}
    </p>
  </section>
</template>

<style scoped>
.image-scan-command {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px 12px;
  padding: 11px 14px;
  border-bottom: 1px solid var(--line);
  background: #fffaf0;
}

.image-scan-command__copy {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
}

.image-scan-command__copy > span:last-child {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.image-scan-command__copy strong {
  color: var(--ink-800);
  font-size: 11px;
}

.image-scan-command__copy small {
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.4;
}

.image-scan-command__icon {
  display: grid;
  width: 29px;
  height: 29px;
  flex: 0 0 29px;
  place-items: center;
  border: 1px solid #e5c77c;
  border-radius: 4px;
  color: #8a5a00;
  background: #fff5d9;
}

.image-scan-command :deep(.el-button) {
  min-width: 112px;
  margin: 0;
}

.image-scan-command__feedback,
.image-scan-command__error {
  min-width: 0;
  grid-column: 1 / -1;
  margin: 0;
  padding-top: 9px;
  border-top: 1px solid var(--line);
}

.image-scan-command__feedback {
  display: grid;
  gap: 5px;
  color: var(--ink-600);
  font-size: 10px;
}

.image-scan-command__feedback > strong {
  color: #7b5200;
}

.image-scan-command__feedback dl {
  display: grid;
  min-width: 0;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin: 3px 0 0;
}

.image-scan-command__feedback dl > div {
  min-width: 0;
  padding: 6px 7px;
  border: 1px solid var(--line);
  border-radius: 3px;
  background: var(--surface);
}

.image-scan-command__feedback dt {
  color: var(--ink-400);
  font-size: 8px;
}

.image-scan-command__feedback dd {
  min-width: 0;
  margin: 3px 0 0;
  overflow-wrap: anywhere;
  color: var(--ink-800);
  font-size: 9px;
}

.image-scan-command__error {
  color: var(--red);
  font-size: 10px;
  line-height: 1.45;
}

@container (max-width: 430px) {
  .image-scan-command {
    grid-template-columns: 1fr;
  }

  .image-scan-command :deep(.el-button) {
    width: 100%;
  }

  .image-scan-command__feedback dl {
    grid-template-columns: 1fr;
  }
}
</style>
