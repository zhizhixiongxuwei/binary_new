<script setup lang="ts">
import { FileUp } from 'lucide-vue-next'
import { shallowRef, useTemplateRef } from 'vue'

const emit = defineEmits<{
  selected: [files: File[]]
}>()

const input = useTemplateRef<HTMLInputElement>('input')
const dragging = shallowRef(false)

function emitFiles(fileList: FileList | null): void {
  if (!fileList?.length) return
  emit('selected', Array.from(fileList))
  if (input.value) input.value.value = ''
}

function onDrop(event: DragEvent): void {
  dragging.value = false
  emitFiles(event.dataTransfer?.files ?? null)
}

function openFilePicker(): void {
  input.value?.click()
}
</script>

<template>
  <div
    class="dropzone"
    :class="{ 'dropzone--dragging': dragging }"
    role="group"
    aria-label="待检测文件选择"
    @dragenter.prevent="dragging = true"
    @dragover.prevent="dragging = true"
    @dragleave.prevent="dragging = false"
    @drop.prevent="onDrop"
  >
    <input
      ref="input"
      class="sr-only"
      type="file"
      multiple
      tabindex="-1"
      aria-label="选择待检测文件"
      @change="emitFiles(($event.target as HTMLInputElement).files)"
    >
    <span class="dropzone__icon" aria-hidden="true">
      <FileUp :size="25" aria-hidden="true" />
    </span>
    <div class="dropzone__copy">
      <strong>选择待检测文件</strong>
      <span>系统按文件内容识别格式，可多选；单文件上限 10 GB</span>
    </div>
    <el-button
      class="dropzone__button"
      type="primary"
      native-type="button"
      plain
      @click="openFilePicker"
    >
      选择文件
    </el-button>
  </div>
</template>

<style scoped>
.dropzone {
  display: flex;
  width: 100%;
  min-height: 112px;
  min-width: 0;
  max-width: 100%;
  align-items: center;
  gap: 16px;
  padding: 22px;
  border: 1px dashed var(--line-strong);
  border-radius: 5px;
  background: #f8fafa;
  transition: border-color 140ms ease, background-color 140ms ease;
}

.dropzone--dragging {
  border-color: var(--teal);
  background: #eff7f6;
}

.dropzone__icon {
  display: grid;
  width: 48px;
  height: 48px;
  flex: 0 0 48px;
  place-items: center;
  border: 1px solid #bad3d0;
  border-radius: 5px;
  color: var(--teal);
  background: #fff;
}

.dropzone__copy {
  min-width: 0;
  flex: 1;
}

.dropzone__copy strong,
.dropzone__copy span {
  display: block;
}

.dropzone__copy strong {
  color: var(--ink-800);
  font-size: 14px;
  overflow-wrap: anywhere;
}

.dropzone__copy span {
  margin-top: 5px;
  color: var(--ink-600);
  font-size: 12px;
}

@media (max-width: 540px) {
  .dropzone {
    align-items: stretch;
    flex-direction: column;
    gap: 12px;
    min-height: 0;
    padding: 16px;
  }

  .dropzone__icon {
    display: none;
  }

  .dropzone__button {
    width: 100%;
    min-height: 40px;
    margin: 0;
  }
}
</style>
