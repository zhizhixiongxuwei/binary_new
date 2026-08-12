<script setup lang="ts">
import { FileUp } from 'lucide-vue-next'
import { onScopeDispose, shallowRef, useTemplateRef, watch } from 'vue'

import type { InputCategory } from '@/api/types'
import {
  inputCategoryAccept,
  inputCategoryLabels,
  preflightUploadFile,
} from '@/utils/uploadPreflight'

const props = withDefaults(
  defineProps<{
    category?: InputCategory
    disabled?: boolean
  }>(),
  {
    category: 'binary',
    disabled: false,
  },
)

const emit = defineEmits<{
  selected: [files: File[]]
  rejected: [messages: string[]]
}>()

const input = useTemplateRef<HTMLInputElement>('input')
const dragging = shallowRef(false)
const prechecking = shallowRef(false)
let generation = 0

async function emitFiles(fileList: FileList | null): Promise<void> {
  if (!fileList?.length || props.disabled || prechecking.value) return
  const files = Array.from(fileList)
  const category = props.category
  const requestGeneration = ++generation
  prechecking.value = true
  try {
    const settled = await Promise.allSettled(
      files.map((file) => preflightUploadFile(file, category)),
    )
    if (requestGeneration !== generation || category !== props.category) return
    const results = settled.map((result) =>
      result.status === 'fulfilled' ? result.value : { accepted: true },
    )
    const accepted = files.filter((_, index) => results[index]?.accepted)
    const rejected = results.flatMap((result) =>
      result.message ? [result.message] : [],
    )
    if (accepted.length) emit('selected', accepted)
    if (rejected.length) emit('rejected', rejected)
  } finally {
    if (requestGeneration === generation) {
      prechecking.value = false
      if (input.value) input.value.value = ''
    }
  }
}

function onDrop(event: DragEvent): void {
  dragging.value = false
  emitFiles(event.dataTransfer?.files ?? null)
}

function openFilePicker(): void {
  if (props.disabled || prechecking.value) return
  input.value?.click()
}

watch(
  () => props.category,
  () => {
    generation += 1
    prechecking.value = false
    dragging.value = false
    if (input.value) input.value.value = ''
  },
)

onScopeDispose(() => {
  generation += 1
})
</script>

<template>
  <div
    class="dropzone"
    :class="{
      'dropzone--dragging': dragging,
      'dropzone--disabled': disabled,
    }"
    role="group"
    aria-label="待检测文件选择"
    @dragenter.prevent="dragging = !disabled"
    @dragover.prevent="dragging = !disabled"
    @dragleave.prevent="dragging = false"
    @drop.prevent="onDrop"
  >
    <input
      ref="input"
      class="sr-only"
      type="file"
      multiple
      :data-accept-hint="inputCategoryAccept[category]"
      :disabled="disabled || prechecking"
      tabindex="-1"
      aria-label="选择待检测文件"
      @change="emitFiles(($event.target as HTMLInputElement).files)"
    >
    <span class="dropzone__icon" aria-hidden="true">
      <FileUp :size="25" aria-hidden="true" />
    </span>
    <div class="dropzone__copy">
      <strong>{{ inputCategoryLabels[category] }}</strong>
      <span>单文件上限 2 GiB</span>
    </div>
    <el-button
      class="dropzone__button"
      type="primary"
      native-type="button"
      plain
      :loading="prechecking"
      :disabled="disabled || prechecking"
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

.dropzone--disabled {
  color: var(--ink-400);
  background: #f2f4f4;
  cursor: not-allowed;
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
