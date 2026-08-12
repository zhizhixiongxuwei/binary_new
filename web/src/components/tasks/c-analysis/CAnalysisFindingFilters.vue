<script setup lang="ts">
import { Filter, RotateCcw } from 'lucide-vue-next'
import { shallowRef, watch } from 'vue'

import type { CAnalysisSeverity } from '@/api/types'
import type { CAnalysisFilters } from '@/composables/useCAnalysis'

const props = defineProps<{
  filters: CAnalysisFilters
  disabled: boolean
}>()

const emit = defineEmits<{
  apply: [filters: CAnalysisFilters]
}>()

const cwe = shallowRef('')
const severity = shallowRef<CAnalysisSeverity>()
const functionName = shallowRef('')

watch(
  () => props.filters,
  (filters) => {
    cwe.value = filters.cwe
    severity.value = filters.severity
    functionName.value = filters.function
  },
  { immediate: true },
)

function apply(): void {
  emit('apply', {
    cwe: cwe.value,
    ...(severity.value ? { severity: severity.value } : {}),
    function: functionName.value,
  })
}

function reset(): void {
  cwe.value = ''
  severity.value = undefined
  functionName.value = ''
  apply()
}
</script>

<template>
  <form class="finding-filters" aria-label="筛选 C 源码检测结果" @submit.prevent="apply">
    <div class="finding-filters__title">
      <Filter :size="15" aria-hidden="true" />
      <strong>检测明细</strong>
    </div>
    <el-input
      v-model="cwe"
      class="finding-filters__cwe"
      placeholder="CWE，例如 CWE-120"
      aria-label="按 CWE 筛选"
      :disabled="disabled"
      maxlength="16"
      clearable
    />
    <el-select
      v-model="severity"
      class="finding-filters__severity"
      placeholder="全部严重度"
      aria-label="按严重度筛选"
      :disabled="disabled"
      clearable
    >
      <el-option label="严重" value="CRITICAL" />
      <el-option label="高危" value="HIGH" />
      <el-option label="中危" value="MEDIUM" />
      <el-option label="低危" value="LOW" />
    </el-select>
    <el-input
      v-model="functionName"
      class="finding-filters__function"
      placeholder="函数名包含"
      aria-label="按函数名筛选"
      :disabled="disabled"
      maxlength="512"
      clearable
    />
    <el-button native-type="submit" :disabled="disabled">应用筛选</el-button>
    <button
      class="finding-filters__reset"
      type="button"
      title="重置筛选"
      aria-label="重置 C 源码检测筛选"
      :disabled="disabled"
      @click="reset"
    >
      <RotateCcw :size="14" aria-hidden="true" />
    </button>
  </form>
</template>

<style scoped>
.finding-filters {
  display: grid;
  grid-template-columns: auto minmax(150px, 0.7fr) minmax(130px, 0.55fr) minmax(180px, 1fr) auto 32px;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
}

.finding-filters__title {
  display: flex;
  align-items: center;
  gap: 7px;
  padding-right: 6px;
  color: var(--teal-strong);
  font-size: 10px;
  white-space: nowrap;
}

.finding-filters__reset {
  display: inline-grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.finding-filters__reset:hover:not(:disabled) {
  border-color: var(--teal);
  color: var(--teal-strong);
}

.finding-filters__reset:disabled { cursor: not-allowed; opacity: 0.55; }

@container (max-width: 820px) {
  .finding-filters {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .finding-filters__title { grid-column: 1 / -1; }
  .finding-filters__function { grid-column: 1 / -1; }
}
</style>
