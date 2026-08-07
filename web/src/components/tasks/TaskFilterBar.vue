<script setup lang="ts">
import {
  ChevronDown,
  RotateCcw,
  Search,
  SlidersHorizontal,
} from 'lucide-vue-next'
import { computed, reactive, shallowRef, watch } from 'vue'

import {
  INPUT_FORMAT_GROUPS,
  normalizeInputFormat,
  normalizeTaskCreator,
  normalizeTaskDate,
  normalizeTaskKeyword,
  normalizeTaskTag,
  taskDateRangeIsValid,
  USER_TASK_STATUS_OPTIONS,
  type TaskFilterValue,
} from '@/components/tasks/taskListFilters'

export type { TaskFilterValue } from '@/components/tasks/taskListFilters'

const props = defineProps<{
  initialValue: TaskFilterValue
}>()

const emit = defineEmits<{
  apply: [value: TaskFilterValue]
  reset: []
}>()

const form = reactive<TaskFilterValue>({ ...props.initialValue })
const advancedOpen = shallowRef(hasAdvancedFilters(props.initialValue))
const errors = reactive({
  keyword: '',
  input_type: '',
  creator: '',
  tag: '',
  created_at: '',
})

const activeAdvancedFilterCount = computed(
  () =>
    [
      form.creator,
      form.tag,
      form.created_from,
      form.created_to,
    ].filter(Boolean).length,
)

function hasAdvancedFilters(value: TaskFilterValue): boolean {
  return Boolean(
    value.creator ||
      value.tag ||
      value.created_from ||
      value.created_to,
  )
}

function clearErrors(): void {
  errors.keyword = ''
  errors.input_type = ''
  errors.creator = ''
  errors.tag = ''
  errors.created_at = ''
}

watch(
  () =>
    [
      props.initialValue.keyword,
      props.initialValue.status,
      props.initialValue.input_type,
      props.initialValue.creator,
      props.initialValue.tag,
      props.initialValue.created_from,
      props.initialValue.created_to,
    ] as const,
  ([keyword, status, inputType, creator, tag, createdFrom, createdTo]) => {
    form.keyword = keyword
    form.status = status
    form.input_type = inputType
    form.creator = creator
    form.tag = tag
    form.created_from = createdFrom
    form.created_to = createdTo
    if (hasAdvancedFilters(props.initialValue)) advancedOpen.value = true
    clearErrors()
  },
)

function submit(): void {
  clearErrors()
  const keyword = normalizeTaskKeyword(form.keyword)
  const inputType = normalizeInputFormat(form.input_type)
  const creator = normalizeTaskCreator(form.creator)
  const tag = normalizeTaskTag(form.tag)
  const createdFrom = normalizeTaskDate(form.created_from)
  const createdTo = normalizeTaskDate(form.created_to)

  if (keyword === null) {
    errors.keyword = '关键词不能包含控制字符，且不能超过 255 个字符'
  }
  if (inputType === null) {
    errors.input_type = '格式值仅支持字母、数字、点、下划线、加号和连字符'
  }
  if (creator === null) {
    errors.creator = '创建者不能包含控制字符，且不能超过 128 个字符'
  }
  if (tag === null) {
    errors.tag = '标签不能包含控制字符，且不能超过 64 个字符'
  }
  if (createdFrom === null || createdTo === null) {
    errors.created_at = '创建日期必须使用有效的 YYYY-MM-DD 日期'
  } else if (!taskDateRangeIsValid(createdFrom, createdTo)) {
    errors.created_at = '开始日期不能晚于结束日期'
  }

  if (Object.values(errors).some(Boolean)) return
  if (
    keyword === null ||
    inputType === null ||
    creator === null ||
    tag === null ||
    createdFrom === null ||
    createdTo === null
  ) {
    return
  }

  form.keyword = keyword
  form.input_type = inputType
  form.creator = creator
  form.tag = tag
  form.created_from = createdFrom
  form.created_to = createdTo
  emit('apply', {
    ...form,
  })
}

function reset(): void {
  form.keyword = ''
  form.status = ''
  form.input_type = ''
  form.creator = ''
  form.tag = ''
  form.created_from = ''
  form.created_to = ''
  advancedOpen.value = false
  clearErrors()
  emit('reset')
}
</script>

<template>
  <form class="task-filters" aria-label="任务筛选" @submit.prevent="submit">
    <div class="task-filters__primary">
      <div class="task-filters__control">
        <el-input
          v-model="form.keyword"
          class="task-filters__search"
          clearable
          maxlength="255"
          :aria-invalid="errors.keyword ? 'true' : 'false'"
          placeholder="任务名称或文件名"
          aria-label="任务名称或文件名"
        >
          <template #prefix><Search :size="15" /></template>
        </el-input>
        <span v-if="errors.keyword" class="task-filters__error" role="alert">
          {{ errors.keyword }}
        </span>
      </div>

      <el-select
        v-model="form.status"
        class="task-filters__select"
        clearable
        aria-label="执行状态"
        placeholder="全部状态"
      >
        <el-option label="全部状态" value="" />
        <el-option
          v-for="option in USER_TASK_STATUS_OPTIONS"
          :key="option.value"
          :label="option.label"
          :value="option.value"
        />
      </el-select>

      <div class="task-filters__control">
        <el-select
          v-model="form.input_type"
          class="task-filters__select"
          filterable
          allow-create
          clearable
          default-first-option
          :aria-invalid="errors.input_type ? 'true' : 'false'"
          aria-label="输入格式"
          placeholder="全部输入格式"
        >
          <el-option label="全部输入格式" value="" />
          <el-option-group
            v-for="group in INPUT_FORMAT_GROUPS"
            :key="group.label"
            :label="group.label"
          >
            <el-option
              v-for="format in group.options"
              :key="format"
              :label="format"
              :value="format"
            />
          </el-option-group>
        </el-select>
        <span v-if="errors.input_type" class="task-filters__error" role="alert">
          {{ errors.input_type }}
        </span>
      </div>

      <div class="task-filters__actions">
        <el-button
          class="task-filters__advanced-trigger"
          native-type="button"
          :aria-expanded="advancedOpen ? 'true' : 'false'"
          aria-controls="task-advanced-filters"
          @click="advancedOpen = !advancedOpen"
        >
          <SlidersHorizontal :size="15" aria-hidden="true" />
          <span>高级筛选</span>
          <span
            v-if="activeAdvancedFilterCount"
            class="task-filters__count"
            aria-label="已启用高级筛选数量"
          >
            {{ activeAdvancedFilterCount }}
          </span>
          <ChevronDown
            class="task-filters__chevron"
            :class="{ 'task-filters__chevron--open': advancedOpen }"
            :size="14"
            aria-hidden="true"
          />
        </el-button>
        <el-button native-type="submit" type="primary" :icon="Search">
          查询
        </el-button>
        <el-button
          native-type="button"
          :icon="RotateCcw"
          aria-label="重置筛选"
          title="重置筛选"
          @click="reset"
        />
      </div>
    </div>

    <div
      v-show="advancedOpen"
      id="task-advanced-filters"
      class="task-filters__advanced"
    >
      <label class="task-filters__field">
        <span class="task-filters__label">创建者</span>
        <el-input
          v-model="form.creator"
          clearable
          maxlength="128"
          :aria-invalid="errors.creator ? 'true' : 'false'"
          aria-label="创建者"
          placeholder="名称或账号"
        />
        <span v-if="errors.creator" class="task-filters__error" role="alert">
          {{ errors.creator }}
        </span>
      </label>

      <label class="task-filters__field">
        <span class="task-filters__label">标签</span>
        <el-input
          v-model="form.tag"
          clearable
          maxlength="64"
          :aria-invalid="errors.tag ? 'true' : 'false'"
          aria-label="标签"
          placeholder="精确匹配"
        />
        <span v-if="errors.tag" class="task-filters__error" role="alert">
          {{ errors.tag }}
        </span>
      </label>

      <fieldset class="task-filters__date-field">
        <legend class="task-filters__label">创建日期</legend>
        <div class="task-filters__date-range">
          <input
            v-model="form.created_from"
            class="task-filters__date-input"
            type="date"
            aria-label="创建日期开始"
          >
          <span class="task-filters__date-separator" aria-hidden="true">至</span>
          <input
            v-model="form.created_to"
            class="task-filters__date-input"
            type="date"
            aria-label="创建日期结束"
          >
        </div>
        <span v-if="errors.created_at" class="task-filters__error" role="alert">
          {{ errors.created_at }}
        </span>
      </fieldset>
    </div>
  </form>
</template>

<style scoped>
.task-filters {
  padding: 14px;
  border-bottom: 1px solid var(--line);
  background: var(--surface-raised);
}

.task-filters__primary {
  display: grid;
  grid-template-columns: minmax(220px, 1fr) 150px 160px auto;
  gap: 9px;
  align-items: start;
}

.task-filters__control,
.task-filters__field,
.task-filters__date-field {
  min-width: 0;
}

.task-filters__search,
.task-filters__select {
  width: 100%;
}

.task-filters__actions {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 8px;
}

.task-filters__actions :deep(.el-button + .el-button) {
  margin-left: 0;
}

.task-filters__advanced-trigger {
  min-width: 0;
}

.task-filters__advanced-trigger :deep(span) {
  gap: 5px;
}

.task-filters__count {
  min-width: 18px;
  height: 18px;
  padding: 0 4px;
  border: 1px solid #a9cdca;
  border-radius: 4px;
  color: var(--teal-strong);
  background: #edf7f6;
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  line-height: 16px;
  text-align: center;
}

.task-filters__chevron {
  flex: 0 0 auto;
  transition: transform 160ms ease;
}

.task-filters__chevron--open {
  transform: rotate(180deg);
}

.task-filters__advanced {
  display: grid;
  grid-template-columns: minmax(150px, 0.7fr) minmax(150px, 0.7fr) minmax(320px, 1.4fr);
  gap: 12px;
  padding-top: 12px;
  margin-top: 12px;
  border-top: 1px solid var(--line);
}

.task-filters__field {
  display: grid;
  align-content: start;
  gap: 5px;
}

.task-filters__date-field {
  padding: 0;
  margin: 0;
  border: 0;
}

.task-filters__label {
  display: block;
  padding: 0;
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  line-height: 1.4;
}

.task-filters__date-range {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
  gap: 7px;
  align-items: center;
  margin-top: 5px;
}

.task-filters__date-input {
  width: 100%;
  min-width: 0;
  height: 32px;
  padding: 0 10px;
  border: 1px solid var(--line-strong);
  border-radius: 5px;
  color: var(--ink-800);
  background: var(--surface);
  font-size: 13px;
}

.task-filters__date-input:hover {
  border-color: var(--ink-400);
}

.task-filters__date-input:focus {
  border-color: var(--blue);
  outline: 1px solid var(--blue);
  outline-offset: 0;
}

.task-filters__date-separator {
  color: var(--ink-400);
  font-size: 12px;
}

.task-filters__error {
  display: block;
  margin-top: 5px;
  color: var(--red);
  font-size: 11px;
  line-height: 1.4;
}

@media (max-width: 920px) {
  .task-filters__primary {
    grid-template-columns: 1fr 1fr;
  }

  .task-filters__control:first-child,
  .task-filters__actions {
    grid-column: 1 / -1;
  }

  .task-filters__advanced {
    grid-template-columns: 1fr 1fr;
  }

  .task-filters__date-field {
    grid-column: 1 / -1;
  }
}

@media (max-width: 540px) {
  .task-filters {
    padding: 10px;
  }

  .task-filters__primary,
  .task-filters__advanced {
    grid-template-columns: minmax(0, 1fr);
  }

  .task-filters__control:first-child,
  .task-filters__actions,
  .task-filters__date-field {
    grid-column: auto;
  }

  .task-filters__actions {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto 34px;
    gap: 6px;
  }

  .task-filters__actions .task-filters__advanced-trigger {
    width: 100%;
    margin-right: 0;
  }

  .task-filters__actions :deep(.el-button) {
    min-width: 0;
    padding-right: 10px;
    padding-left: 10px;
  }
}

@media (max-width: 420px) {
  .task-filters__date-range {
    grid-template-columns: minmax(0, 1fr);
  }

  .task-filters__date-separator {
    display: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .task-filters__chevron {
    transition: none;
  }
}
</style>
