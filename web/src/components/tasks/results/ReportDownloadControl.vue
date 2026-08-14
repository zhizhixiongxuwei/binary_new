<script setup lang="ts">
import { Download, LoaderCircle } from 'lucide-vue-next'
import { computed, shallowRef, watch } from 'vue'

import type {
  ReportDownloadEncoding,
  TaskReport,
} from '@/api/types'
import { reportDownloadKey } from '@/composables/useReportDownload'

const props = defineProps<{
  report: TaskReport
  pendingKey: string
}>()

const emit = defineEmits<{
  download: [report: TaskReport, encoding: ReportDownloadEncoding]
}>()

const encoding = shallowRef<ReportDownloadEncoding>('identity')
const currentKey = computed(() =>
  reportDownloadKey(props.report.id, encoding.value),
)
const pending = computed(() => props.pendingKey === currentKey.value)
const disabled = computed(() => props.pendingKey !== '')
const downloadLabel = computed(() => {
  if (props.report.format === 'docx') return '下载 Word 报告'
  const suffix = encoding.value === 'gzip' ? '压缩 JSON 报告' : `${props.report.format.toUpperCase()} 报告`
  return `下载 ${suffix}`
})

watch(
  () => props.report.id,
  () => {
    encoding.value = 'identity'
  },
)

function submit(): void {
  if (disabled.value) return
  emit('download', props.report, encoding.value)
}
</script>

<template>
  <div class="report-download">
    <label v-if="report.format === 'json'" class="report-download__variant">
      <span class="sr-only">JSON 下载格式</span>
      <select
        v-model="encoding"
        aria-label="JSON 下载格式"
        :disabled="disabled"
      >
        <option value="identity">原始 .json</option>
        <option value="gzip">压缩 .json.gz</option>
      </select>
    </label>
    <button
      class="report-download__command"
      type="button"
      :disabled="disabled"
      :aria-busy="pending"
      :aria-label="downloadLabel"
      @click="submit"
    >
      <LoaderCircle
        v-if="pending"
        class="spin"
        :size="14"
        aria-hidden="true"
      />
      <Download v-else :size="14" aria-hidden="true" />
      下载
    </button>
  </div>
</template>

<style scoped>
.report-download {
  display: flex;
  min-width: 0;
  align-items: stretch;
  justify-content: flex-end;
  gap: 6px;
}

.report-download__variant {
  min-width: 124px;
}

.report-download__variant select {
  width: 100%;
  min-height: 32px;
  padding: 5px 26px 5px 8px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-800);
  background: var(--surface);
  font-size: 10px;
}

.report-download__variant select:focus-visible,
.report-download__command:focus-visible {
  outline: 2px solid var(--teal);
  outline-offset: 1px;
}

.report-download__command {
  display: inline-flex;
  min-width: 76px;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 6px 10px;
  border: 1px solid var(--teal);
  border-radius: 4px;
  color: #fff;
  background: var(--teal-strong);
  cursor: pointer;
  font-size: 10px;
  font-weight: 700;
}

.report-download__command:hover:not(:disabled) {
  background: #075f59;
}

.report-download__command:disabled,
.report-download__variant select:disabled {
  cursor: not-allowed;
  opacity: 0.56;
}

.spin {
  animation: report-download-spin 1s linear infinite;
}

@keyframes report-download-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 480px) {
  .report-download {
    width: 100%;
  }

  .report-download__variant {
    min-width: 0;
    flex: 1;
  }

  .report-download__command {
    flex: 0 0 84px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
