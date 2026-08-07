<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    taskName: string
    pending?: boolean
    errorMessage?: string
  }>(),
  {
    pending: false,
    errorMessage: '',
  },
)

const emit = defineEmits<{
  confirm: []
}>()

const open = defineModel<boolean>({ default: false })
const confirmation = shallowRef('')
const confirmed = computed(
  () => confirmation.value === props.taskName,
)

function close(): void {
  if (props.pending) return
  open.value = false
}

function confirm(): void {
  if (!confirmed.value || props.pending) return
  emit('confirm')
}

watch(open, (visible) => {
  if (!visible) confirmation.value = ''
})
</script>

<template>
  <el-dialog
    v-model="open"
    title="删除任务？"
    width="min(520px, calc(100vw - 32px))"
    align-center
    :close-on-click-modal="!pending"
    :close-on-press-escape="!pending"
    :show-close="!pending"
  >
    <div class="delete-confirmation">
      <p>
        提交后任务进入删除流程。后台将清理挂载目录中的样本引用、提取文件、反编译结果、Trivy 检测结果和生成报告；任务审计记录继续保留。
      </p>
      <code>{{ taskName }}</code>
      <label for="delete-task-name">输入任务名确认</label>
      <el-input
        id="delete-task-name"
        v-model="confirmation"
        autocomplete="off"
        :disabled="pending"
        :placeholder="taskName"
        @keyup.enter="confirm"
      />
      <p v-if="errorMessage" class="delete-confirmation__error" role="alert">
        {{ errorMessage }}
      </p>
    </div>
    <template #footer>
      <el-button :disabled="pending" @click="close">保留任务</el-button>
      <el-button
        type="danger"
        data-confirm="delete"
        :loading="pending"
        :disabled="!confirmed || pending"
        @click="confirm"
      >
        提交删除
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.delete-confirmation {
  display: grid;
  gap: 10px;
}

.delete-confirmation p {
  margin: 0;
  color: var(--ink-600);
  font-size: 12px;
  line-height: 1.65;
}

.delete-confirmation code {
  display: block;
  overflow-wrap: anywhere;
  padding: 9px 10px;
  border-left: 3px solid var(--red);
  color: var(--ink-800);
  background: #fff5f5;
  font-size: 11px;
}

.delete-confirmation label {
  color: var(--ink-800);
  font-size: 11px;
  font-weight: 700;
}

.delete-confirmation__error {
  color: var(--red) !important;
}
</style>
