<script setup lang="ts">
import { Archive, Binary, Box } from 'lucide-vue-next'
import { shallowRef, watch } from 'vue'

import type { InputCategory } from '@/api/types'

const props = withDefaults(
  defineProps<{
    currentCategory?: InputCategory | null
    required?: boolean
    locked?: boolean
  }>(),
  {
    currentCategory: null,
    required: false,
    locked: false,
  },
)

const open = defineModel<boolean>({ required: true })
const emit = defineEmits<{
  select: [category: InputCategory]
  cancel: []
}>()

const selected = shallowRef<InputCategory | null>(props.currentCategory)
const categories = [
  {
    value: 'binary',
    number: '01',
    title: '二进制格式',
    formats: 'PE · ELF · Mach-O · CLASS · JAR · DEX · APK · PYC',
    icon: Binary,
  },
  {
    value: 'archive',
    number: '02',
    title: '压缩包格式',
    formats: 'ZIP · 7Z · RAR · TAR · GZIP · XZ · DEB · RPM',
    icon: Archive,
  },
  {
    value: 'container',
    number: '03',
    title: '容器镜像格式',
    formats: 'Docker Save TAR · OCI Image Layout TAR',
    icon: Box,
  },
] as const

watch(open, (visible) => {
  if (visible) selected.value = props.currentCategory
})

watch(
  () => props.currentCategory,
  (category) => {
    if (open.value) selected.value = category
  },
)

function confirmSelection(): void {
  if (!selected.value || props.locked) return
  emit('select', selected.value)
  open.value = false
}

function cancel(): void {
  emit('cancel')
  open.value = false
}
</script>

<template>
  <el-dialog
    v-model="open"
    class="task-category-dialog"
    width="min(680px, calc(100vw - 28px))"
    :show-close="!required"
    :close-on-click-modal="false"
    :close-on-press-escape="!required"
    :before-close="required ? undefined : (done: () => void) => done()"
    destroy-on-close
  >
    <template #header>
      <div class="category-dialog__heading">
        <span class="mono">TASK INPUT</span>
        <h2>选择输入类别</h2>
      </div>
    </template>

    <div class="category-options" role="radiogroup" aria-label="任务输入类别">
      <label
        v-for="category in categories"
        :key="category.value"
        class="category-option"
        :class="{
          'category-option--selected': selected === category.value,
          'category-option--disabled': locked,
        }"
        @dblclick="confirmSelection"
      >
        <input
          v-model="selected"
          class="sr-only"
          type="radio"
          name="task-input-category"
          :value="category.value"
          :disabled="locked"
        >
        <span class="category-option__number mono">{{ category.number }}</span>
        <span class="category-option__icon" aria-hidden="true">
          <component :is="category.icon" :size="21" />
        </span>
        <span class="category-option__body">
          <strong>{{ category.title }}</strong>
          <small>{{ category.formats }}</small>
        </span>
      </label>
    </div>

    <p v-if="locked" class="category-dialog__lock" role="status">
      上传队列非空时不能切换输入类别。
    </p>

    <template #footer>
      <div class="category-dialog__actions">
        <el-button @click="cancel">取消</el-button>
        <el-button
          type="primary"
          :disabled="!selected || locked"
          @click="confirmSelection"
        >
          确认类别
        </el-button>
      </div>
    </template>
  </el-dialog>
</template>

<style scoped>
.category-dialog__heading span,
.category-dialog__heading h2 {
  display: block;
  margin: 0;
}

.category-dialog__heading span {
  color: var(--teal-strong);
  font-size: 10px;
  font-weight: 700;
}

.category-dialog__heading h2 {
  margin-top: 4px;
  color: var(--ink-950);
  font-size: 18px;
  letter-spacing: 0;
}

.category-options {
  display: grid;
  border: 1px solid var(--line);
  border-radius: 5px;
  overflow: hidden;
}

.category-option {
  display: grid;
  width: 100%;
  min-height: 76px;
  grid-template-columns: 34px 42px minmax(0, 1fr);
  align-items: center;
  gap: 10px;
  padding: 12px 14px;
  border: 0;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  background: #fff;
  cursor: pointer;
  text-align: left;
}

.category-option:last-child {
  border-bottom: 0;
}

.category-option:hover {
  background: #f5f9f8;
}

.category-option--selected {
  box-shadow: inset 3px 0 var(--teal);
  color: var(--teal-strong);
  background: #eef7f6;
}

.category-option:focus-within {
  position: relative;
  z-index: 1;
  outline: 2px solid var(--teal);
  outline-offset: -2px;
}

.category-option--disabled {
  color: var(--ink-400);
  background: #f3f5f5;
  cursor: not-allowed;
}

.category-option__number {
  color: inherit;
  font-size: 11px;
  font-weight: 700;
}

.category-option__icon {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border: 1px solid currentColor;
  border-radius: 4px;
}

.category-option__body {
  min-width: 0;
}

.category-option__body strong,
.category-option__body small {
  display: block;
  overflow-wrap: anywhere;
}

.category-option__body strong {
  color: var(--ink-800);
  font-size: 14px;
}

.category-option__body small {
  margin-top: 4px;
  color: var(--ink-600);
  font-size: 11px;
  line-height: 1.45;
}

.category-dialog__lock {
  margin: 12px 0 0;
  color: #7f541b;
  font-size: 12px;
}

.category-dialog__actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

@media (max-width: 520px) {
  .category-option {
    min-height: 84px;
    grid-template-columns: 28px minmax(0, 1fr);
  }

  .category-option__icon {
    display: none;
  }
}
</style>
