<script setup lang="ts">
import { AlertTriangle, Upload } from 'lucide-vue-next'
import { shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import PageHeader from '@/components/common/PageHeader.vue'
import FileDropzone from '@/components/uploads/FileDropzone.vue'
import SupportedUploadTypes from '@/components/uploads/SupportedUploadTypes.vue'
import UploadQueue from '@/components/uploads/UploadQueue.vue'
import { useChunkUpload } from '@/composables/useChunkUpload'

const uploads = useChunkUpload()
const router = useRouter()
const warningMessage = shallowRef('')

function addFiles(files: File[]): void {
  const rejected = uploads.addFiles(files)
  warningMessage.value = rejected.join('；')
}
</script>

<template>
  <div class="page-view">
    <PageHeader title="新建任务" eyebrow="TASKS / CREATE">
      <template #actions>
        <el-button
          type="primary"
          :icon="Upload"
          :loading="uploads.isUploading.value"
          :disabled="uploads.readyCount.value === 0"
          @click="uploads.startAll"
        >
          开始上传
        </el-button>
      </template>
    </PageHeader>

    <section class="upload-workspace surface-panel">
      <div class="upload-workspace__header">
        <h2>待检测文件</h2>
        <span class="mono" aria-live="polite">
          {{ uploads.queue.value.length }} 个文件
        </span>
      </div>
      <div class="upload-workspace__body">
        <SupportedUploadTypes />
        <div v-if="warningMessage" class="upload-warning" role="alert">
          <AlertTriangle :size="16" aria-hidden="true" />
          <span>{{ warningMessage }}</span>
        </div>
        <FileDropzone @selected="addFiles" />
        <UploadQueue
          v-if="uploads.queue.value.length"
          :items="uploads.queue.value"
          :active-id="uploads.activeId.value"
          @remove="uploads.remove"
          @pause="uploads.pause"
          @resume="uploads.uploadItem"
          @retry="uploads.uploadItem"
          @open-task="router.push({ name: 'task-detail', params: { id: $event } })"
        />
      </div>
    </section>
  </div>
</template>

<style scoped>
.upload-workspace__header {
  display: flex;
  min-height: 52px;
  align-items: center;
  justify-content: space-between;
  padding: 0 18px;
  border-bottom: 1px solid var(--line);
}

.upload-workspace__header h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 14px;
}

.upload-workspace__header span {
  color: var(--ink-400);
  font-size: 10px;
  white-space: nowrap;
}

.upload-workspace__body {
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

@media (max-width: 620px) {
  .upload-workspace__header {
    min-height: 48px;
    padding: 0 14px;
  }

  .upload-workspace__body {
    padding: 14px;
  }
}

@media (max-width: 380px) {
  .upload-workspace__body {
    padding: 10px;
  }
}
</style>
