<script setup lang="ts">
import {
  ArrowUpRight,
  CircleCheck,
  Pause,
  Play,
  RotateCw,
  Trash2,
  X,
} from 'lucide-vue-next'

import type { UploadQueueDisplayItem } from '@/components/uploads/uploadQueueTypes'
import { formatBytes } from '@/utils/formatters'

defineProps<{
  items: readonly UploadQueueDisplayItem[]
  activeId: string | null
}>()

const emit = defineEmits<{
  remove: [id: string]
  pause: [id: string]
  resume: [id: string]
  retry: [id: string]
  openTask: [taskId: string]
  clearCompleted: [id: string]
}>()

const labels = {
  ready: '等待上传',
  uploading: '上传中',
  paused: '已暂停',
  completed: '任务已创建',
  archive: '归档已上传',
  failed: '上传失败',
} as const
</script>

<template>
  <div class="upload-queue" role="list" aria-label="上传队列">
    <div
      v-for="item in items"
      :key="item.localId"
      class="upload-row"
      role="listitem"
    >
      <div class="upload-row__main">
        <div class="upload-row__heading">
          <strong :title="item.file.name">{{ item.file.name }}</strong>
          <span class="upload-row__size">{{ formatBytes(item.file.size) }}</span>
        </div>
        <el-progress
          :percentage="item.progress"
          :stroke-width="5"
          :status="item.status === 'failed' ? 'exception' : item.status === 'completed' || item.status === 'archive' ? 'success' : undefined"
          :aria-label="`${item.file.name} 上传进度 ${item.progress}%`"
        />
        <div class="upload-row__state" aria-live="polite">
          <span
            class="upload-row__status"
            :class="`upload-row__status--${item.status}`"
          >
            <CircleCheck
              v-if="item.status === 'completed'"
              :size="13"
              aria-hidden="true"
            />
            {{ labels[item.status] }}
          </span>
          <span v-if="item.errorMessage" class="upload-row__error">{{ item.errorMessage }}</span>
          <span
            v-else-if="item.detectedFormat"
            class="upload-row__format mono"
          >
            {{ item.detectedFormat }}
          </span>
        </div>
      </div>
      <div class="upload-row__commands">
        <button
          v-if="item.status === 'completed' && item.taskId"
          class="upload-row__open-task"
          type="button"
          aria-label="查看任务"
          title="查看任务"
          @click="emit('openTask', item.taskId)"
        >
          <ArrowUpRight :size="17" aria-hidden="true" />
          <span>查看任务</span>
        </button>
        <button
          v-if="item.status === 'completed' && item.taskId"
          type="button"
          aria-label="从列表清除"
          title="从列表清除"
          @click="emit('clearCompleted', item.localId)"
        >
          <X :size="17" aria-hidden="true" />
        </button>
        <button
          v-if="item.status === 'uploading'"
          type="button"
          aria-label="暂停上传"
          title="暂停上传"
          @click="emit('pause', item.localId)"
        >
          <Pause :size="17" aria-hidden="true" />
        </button>
        <button
          v-if="item.status === 'paused'"
          type="button"
          aria-label="继续上传"
          title="继续上传"
          @click="emit('resume', item.localId)"
        >
          <Play :size="17" aria-hidden="true" />
        </button>
        <button
          v-if="item.status === 'failed' && item.canRetry"
          type="button"
          aria-label="重试上传"
          title="重试上传"
          :disabled="activeId !== null"
          @click="emit('retry', item.localId)"
        >
          <RotateCw :size="17" aria-hidden="true" />
        </button>
        <button
          v-if="item.status !== 'uploading' && item.status !== 'completed' && item.status !== 'archive'"
          type="button"
          :aria-label="item.removing ? '正在移除文件' : '移除文件'"
          :title="item.removing ? '正在移除文件' : '移除文件'"
          :disabled="Boolean(item.removing)"
          :aria-busy="item.removing ? 'true' : 'false'"
          @click="emit('remove', item.localId)"
        >
          <RotateCw
            v-if="item.removing"
            class="upload-row__spinner"
            :size="17"
            aria-hidden="true"
          />
          <Trash2 v-else :size="17" aria-hidden="true" />
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.upload-queue {
  display: grid;
  width: 100%;
  min-width: 0;
  max-width: 100%;
  margin-top: 14px;
  border: 1px solid var(--line);
  border-radius: 5px;
  background: #fff;
}

.upload-row {
  display: flex;
  min-height: 94px;
  align-items: center;
  gap: 16px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
}

.upload-row:last-child {
  border-bottom: 0;
}

.upload-row__main {
  min-width: 0;
  flex: 1;
}

.upload-row__heading,
.upload-row__state {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.upload-row__heading {
  margin-bottom: 9px;
}

.upload-row__heading strong {
  min-width: 0;
  flex: 1;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 13px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.upload-row__size {
  flex: 0 0 auto;
  white-space: nowrap;
}

.upload-row__heading span,
.upload-row__state {
  color: var(--ink-600);
  font-size: 11px;
}

.upload-row__state {
  margin-top: 6px;
}

.upload-row__status {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 4px;
}

.upload-row__error {
  display: block;
  min-width: 0;
  max-width: 65%;
  overflow-wrap: anywhere;
  text-align: right;
}

.upload-row__format {
  color: var(--ink-400);
  font-size: 10px;
}

.upload-row__status--archive,
.upload-row__status--completed {
  color: var(--teal-strong);
}

.upload-row__status--failed,
.upload-row__error {
  color: var(--red);
}

.upload-row__commands {
  display: flex;
  flex: 0 0 auto;
  min-width: 70px;
  justify-content: flex-end;
  gap: 5px;
}

.upload-row__commands button {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
}

.upload-row__commands .upload-row__open-task {
  width: auto;
  min-width: 92px;
  padding: 0 10px;
  grid-template-columns: auto auto;
  gap: 6px;
  color: var(--teal-strong);
  font-size: 11px;
  font-weight: 700;
}

.upload-row__commands button:hover {
  border-color: var(--line-strong);
  color: var(--teal-strong);
  background: #f4f8f8;
}

.upload-row__commands button:disabled {
  color: var(--ink-400);
  background: #f4f5f5;
  cursor: not-allowed;
}

.upload-row__commands button:focus-visible {
  outline: 2px solid var(--teal);
  outline-offset: 1px;
}

.upload-row__spinner {
  animation: upload-row-spin 0.8s linear infinite;
}

@keyframes upload-row-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .upload-row__spinner {
    animation: none;
  }
}

@media (max-width: 540px) {
  .upload-row {
    min-height: 0;
    align-items: stretch;
    flex-direction: column;
    gap: 10px;
    padding: 12px;
  }

  .upload-row__heading {
    align-items: flex-start;
  }

  .upload-row__heading strong {
    overflow: visible;
    overflow-wrap: anywhere;
    text-overflow: clip;
    white-space: normal;
  }

  .upload-row__state {
    align-items: flex-start;
    flex-direction: column;
    gap: 5px;
  }

  .upload-row__error {
    max-width: 100%;
    text-align: left;
  }

  .upload-row__commands {
    width: 100%;
    min-width: 0;
    justify-content: flex-end;
    padding-top: 2px;
  }
}
</style>
