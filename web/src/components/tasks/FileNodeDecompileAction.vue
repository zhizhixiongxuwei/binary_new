<script setup lang="ts">
import { CodeXml } from 'lucide-vue-next'
import { computed, useId, watch } from 'vue'

import type {
  FileDecompileRequest,
  FileNodeDetail,
  TaskStatus,
  UserRole,
} from '@/api/types'
import {
  getFileNodeDecompileActionModel,
} from '@/components/tasks/fileNodeDecompile'
import type { TaskActionMode } from '@/components/tasks/taskActions'
import { useFileNodeDecompile } from '@/composables/useFileNodeDecompile'
import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

const props = defineProps<{
  taskId: string
  taskStatus: TaskStatus
  node: FileNodeDetail
  userRole: UserRole | null
  mode: TaskActionMode
  sampleRetention: SampleRetentionSnapshot
}>()

const emit = defineEmits<{
  completed: [request: FileDecompileRequest]
}>()

const componentId = useId().replace(/:/g, '')
const titleId = `file-decompile-title-${componentId}`
const reasonId = `file-decompile-reason-${componentId}`
const model = computed(() =>
  getFileNodeDecompileActionModel({
    node: props.node,
    taskStatus: props.taskStatus,
    userRole: props.userRole,
    mode: props.mode,
    sampleRetention: props.sampleRetention,
  }),
)
const decompile = useFileNodeDecompile({
  taskId: () => props.taskId,
  fileNodeId: () => props.node.id,
  mode: () => props.mode,
  enabled: () => model.value.enabled,
  disabledReason: () => model.value.reason,
})
const activeRequest = computed(() =>
  ['queued', 'leased', 'running', 'cancel_requested'].includes(
    decompile.request.value?.status ?? '',
  ),
)
const failedRequest = computed(() =>
  ['failed', 'cancelled'].includes(decompile.request.value?.status ?? ''),
)
const commandDisabled = computed(
  () =>
    !model.value.enabled ||
    decompile.pending.value ||
    activeRequest.value,
)
const commandTitle = computed(() => {
  if (decompile.pending.value) return '正在提交反编译请求。'
  if (decompile.request.value?.status === 'succeeded') {
    return '反编译已完成，打开已刷新结果。'
  }
  if (failedRequest.value) return '再次提交该文件节点的反编译请求。'
  if (activeRequest.value) return decompile.feedbackMessage.value
  return model.value.reason
})
const commandLabel = computed(() => {
  if (decompile.pending.value) return '正在提交'
  switch (decompile.request.value?.status) {
    case 'queued':
      return '等待处理'
    case 'leased':
      return '准备处理'
    case 'running':
      return '正在反编译'
    case 'cancel_requested':
      return '正在取消'
    case 'succeeded':
      return '查看结果'
    case 'failed':
    case 'cancelled':
      return '重新反编译'
    default:
      return '发起反编译'
  }
})
const statusLabel = computed(() => {
  switch (decompile.request.value?.status) {
    case 'queued':
      return '已排队'
    case 'leased':
      return 'Worker 已领取'
    case 'running':
      return '正在运行'
    case 'succeeded':
      return '已完成'
    case 'failed':
      return '失败'
    case 'cancel_requested':
      return '取消中'
    case 'cancelled':
      return '已取消'
    default:
      return '未知'
  }
})
let completedJobId = ''

function handleCommand(): void {
  const current = decompile.request.value
  if (current?.status === 'succeeded') {
    emit('completed', current)
  } else if (failedRequest.value) {
    decompile.retry()
  } else {
    void decompile.submit()
  }
}

watch(
  () => decompile.request.value,
  (current) => {
    if (
      current?.status === 'succeeded' &&
      completedJobId !== current.job_id
    ) {
      completedJobId = current.job_id
      emit('completed', current)
    }
  },
)
</script>

<template>
  <section
    v-if="model.visible"
    class="decompile-command"
    :aria-labelledby="titleId"
  >
    <div class="decompile-command__copy">
      <span class="decompile-command__icon" aria-hidden="true">
        <CodeXml :size="16" />
      </span>
      <span>
        <strong :id="titleId">反编译</strong>
        <small :id="reasonId">{{ commandTitle }}</small>
      </span>
    </div>
    <el-button
      data-action="decompile-file"
      :icon="CodeXml"
      :loading="decompile.pending.value"
      :disabled="commandDisabled"
      :title="commandTitle"
      :aria-describedby="reasonId"
      @click="handleCommand"
    >
      {{ commandLabel }}
    </el-button>

    <div
      v-if="decompile.request.value"
      class="decompile-command__feedback"
      role="status"
      aria-live="polite"
    >
      <strong>{{ decompile.feedbackMessage.value }}</strong>
      <span v-if="activeRequest">状态将自动刷新，完成后会打开反编译结果。</span>
      <span v-else-if="decompile.request.value.status === 'succeeded'">
        Ghidra 已完成处理，反编译结果现在可以阅读。
      </span>
      <span v-else>该请求已结束，可以重新发起反编译。</span>
      <dl>
        <div>
          <dt>Request</dt>
          <dd class="mono">{{ decompile.request.value.request_id }}</dd>
        </div>
        <div>
          <dt>Job</dt>
          <dd class="mono">{{ decompile.request.value.job_id }}</dd>
        </div>
        <div>
          <dt>状态</dt>
          <dd>{{ statusLabel }}</dd>
        </div>
      </dl>
      <p
        v-if="decompile.statusRefreshError.value"
        class="decompile-command__refresh-error"
        role="alert"
      >
        {{ decompile.statusRefreshError.value }}，系统将继续重试。
      </p>
      <p
        v-if="failedRequest && decompile.errorMessage.value"
        class="decompile-command__refresh-error"
        role="alert"
      >
        {{ decompile.errorMessage.value }}
      </p>
    </div>
    <p
      v-else-if="decompile.errorMessage.value"
      class="decompile-command__error"
      role="alert"
    >
      {{ decompile.errorMessage.value }}
    </p>
  </section>
</template>

<style scoped>
.decompile-command {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px 12px;
  padding: 11px 14px;
  border-bottom: 1px solid var(--line);
  background: #f8fafa;
}

.decompile-command__copy {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
}

.decompile-command__copy > span:last-child {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.decompile-command__copy strong {
  color: var(--ink-800);
  font-size: 11px;
}

.decompile-command__copy small {
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.4;
}

.decompile-command__icon {
  display: grid;
  width: 29px;
  height: 29px;
  flex: 0 0 29px;
  place-items: center;
  border: 1px solid #b8d7d3;
  border-radius: 4px;
  color: var(--teal-strong);
  background: #f1f8f7;
}

.decompile-command :deep(.el-button) {
  min-width: 112px;
  margin: 0;
}

.decompile-command__feedback,
.decompile-command__error {
  min-width: 0;
  grid-column: 1 / -1;
  margin: 0;
  padding-top: 9px;
  border-top: 1px solid var(--line);
}

.decompile-command__feedback {
  display: grid;
  gap: 5px;
  color: var(--ink-600);
  font-size: 10px;
}

.decompile-command__feedback > strong {
  color: var(--teal-strong);
}

.decompile-command__feedback dl {
  display: grid;
  min-width: 0;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin: 3px 0 0;
}

.decompile-command__feedback dl > div {
  min-width: 0;
  padding: 6px 7px;
  border: 1px solid var(--line);
  border-radius: 3px;
  background: var(--surface);
}

.decompile-command__feedback dt {
  color: var(--ink-400);
  font-size: 8px;
}

.decompile-command__feedback dd {
  min-width: 0;
  margin: 3px 0 0;
  overflow-wrap: anywhere;
  color: var(--ink-800);
  font-size: 9px;
}

.decompile-command__refresh-error {
  margin: 2px 0 0;
  color: var(--red);
  overflow-wrap: anywhere;
}

.decompile-command__error {
  color: var(--red);
  font-size: 10px;
  line-height: 1.45;
}

@container (max-width: 430px) {
  .decompile-command {
    grid-template-columns: 1fr;
  }

  .decompile-command :deep(.el-button) {
    width: 100%;
  }

  .decompile-command__feedback dl {
    grid-template-columns: 1fr;
  }
}
</style>
