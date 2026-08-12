<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue'

import type {
  ConfirmDecompileProjectDeletionInput,
  DecompileProject,
  DecompileProjectDeletionPreview,
} from '@/api/types'
import { formatBytes, formatDateTime } from '@/utils/formatters'

const props = withDefaults(
  defineProps<{
    project: DecompileProject | null
    pending?: boolean
    previewLoading?: boolean
    preview: DecompileProjectDeletionPreview | undefined
    errorMessage?: string
  }>(),
  {
    pending: false,
    previewLoading: false,
    errorMessage: '',
  },
)

const emit = defineEmits<{
  cancel: []
  confirm: [input: ConfirmDecompileProjectDeletionInput]
}>()

const cascadeAcknowledged = shallowRef(false)
const typedSuffix = shallowRef('')
const canConfirm = computed(
  () =>
    Boolean(props.preview) &&
    cascadeAcknowledged.value &&
    typedSuffix.value === props.preview?.typed_suffix &&
    !props.pending &&
    !props.previewLoading,
)

watch(
  [() => props.project?.id, () => props.preview?.confirmation_token],
  () => {
    cascadeAcknowledged.value = false
    typedSuffix.value = ''
  },
)

function handleVisibilityChange(visible: boolean): void {
  if (!visible && !props.pending) emit('cancel')
}

function confirm(): void {
  if (!canConfirm.value || !props.preview) return
  emit('confirm', {
    confirmation_token: props.preview.confirmation_token,
    cascade: true,
    typed_suffix: typedSuffix.value,
  })
}
</script>

<template>
  <el-dialog
    :model-value="project !== null"
    title="级联删除反编译源码版本？"
    width="min(620px, calc(100vw - 32px))"
    align-center
    :close-on-click-modal="!pending"
    :close-on-press-escape="!pending"
    :show-close="!pending"
    @update:model-value="handleVisibilityChange"
  >
    <div v-if="project" class="delete-project">
      <p class="delete-project__warning">
        该操作会取消正在执行的源码检测，并删除源码目录、全部 C / Java 检测版本、检测发现和引用它们的报告。删除完成后不能恢复。
      </p>
      <dl>
        <div>
          <dt>项目标识</dt>
          <dd class="mono">{{ project.id }}</dd>
        </div>
        <div>
          <dt>目标文件</dt>
          <dd>{{ project.target_path }}</dd>
        </div>
        <div>
          <dt>目录内容</dt>
          <dd>
            {{ project.source_file_count }} 个源码文件，{{ formatBytes(project.source_size_bytes) }}
          </dd>
        </div>
      </dl>
      <div v-if="previewLoading" class="delete-project__preview-state" role="status">
        正在计算源码和衍生证据的影响范围…
      </div>
      <template v-else-if="preview">
        <section class="delete-project__impact" aria-labelledby="delete-impact-title">
          <h3 id="delete-impact-title">将被删除</h3>
          <dl>
            <div><dt>源码文件</dt><dd>{{ preview.counts.source_files }}</dd></div>
            <div><dt>反编译索引</dt><dd>{{ preview.counts.decompile_results }}</dd></div>
            <div><dt>C 检测版本</dt><dd>{{ preview.counts.c_analysis_runs }}</dd></div>
            <div><dt>C 检测发现</dt><dd>{{ preview.counts.c_analysis_findings }}</dd></div>
            <div><dt>Java 检测版本</dt><dd>{{ preview.counts.java_analysis_runs }}</dd></div>
            <div><dt>Java 检测发现</dt><dd>{{ preview.counts.java_analysis_findings }}</dd></div>
            <div><dt>关联报告</dt><dd>{{ preview.counts.reports }}</dd></div>
            <div><dt>报告文件/产物</dt><dd>{{ preview.counts.report_files + preview.counts.artifacts }}</dd></div>
          </dl>
        </section>
        <el-checkbox v-model="cascadeAcknowledged" :disabled="pending">
          我确认级联清除上述源码及所有衍生检测证据
        </el-checkbox>
        <label class="delete-project__typed-confirmation">
          <span>输入项目 ID 后 8 位 <code>{{ preview.typed_suffix }}</code></span>
          <el-input
            v-model="typedSuffix"
            :disabled="pending"
            :placeholder="preview.typed_suffix"
            maxlength="8"
            autocomplete="off"
            aria-label="输入项目 ID 后 8 位确认删除"
          />
        </label>
        <small class="delete-project__expiry">
          本次服务器确认令牌有效至 {{ formatDateTime(preview.expires_at) }}，且只能使用一次。
        </small>
      </template>
      <p v-if="errorMessage" class="delete-project__error" role="alert">
        {{ errorMessage }}
      </p>
    </div>
    <template #footer>
      <el-button :disabled="pending" @click="emit('cancel')">保留版本</el-button>
      <el-button
        type="danger"
        :loading="pending"
        data-confirm="delete-project"
        :disabled="!canConfirm"
        @click="confirm"
      >
        级联删除
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.delete-project {
  display: grid;
  gap: 12px;
}

.delete-project p {
  margin: 0;
  color: var(--ink-600);
  font-size: 12px;
  line-height: 1.65;
}

.delete-project__warning {
  padding: 10px 12px;
  border-left: 3px solid var(--red);
  color: #7e3030 !important;
  background: #fff2f2;
}

.delete-project dl {
  margin: 0;
  border: 1px solid var(--line);
  border-radius: 4px;
}

.delete-project dl div {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  gap: 10px;
  padding: 9px 10px;
  border-bottom: 1px solid var(--line);
}

.delete-project dl div:last-child {
  border-bottom: 0;
}

.delete-project dt {
  color: var(--ink-600);
  font-size: 10px;
}

.delete-project dd {
  min-width: 0;
  margin: 0;
  color: var(--ink-800);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.delete-project__error {
  color: var(--red) !important;
}

.delete-project__preview-state {
  min-height: 70px;
  display: grid;
  place-items: center;
  color: var(--ink-400);
  background: #f7f9f9;
  font-size: 11px;
}

.delete-project__impact {
  display: grid;
  gap: 7px;
}

.delete-project__impact h3 {
  margin: 0;
  color: var(--ink-800);
  font-size: 11px;
}

.delete-project__impact dl {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.delete-project__impact dl div {
  grid-template-columns: minmax(0, 1fr) auto;
}

.delete-project__typed-confirmation {
  display: grid;
  gap: 6px;
  color: var(--ink-600);
  font-size: 10px;
}

.delete-project__typed-confirmation code {
  color: var(--red);
  font-size: 10px;
  font-weight: 700;
}

.delete-project__expiry {
  color: var(--ink-400);
  font-size: 9px;
}

@media (max-width: 560px) {
  .delete-project__impact dl {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
