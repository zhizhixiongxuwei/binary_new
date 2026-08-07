<script setup lang="ts">
import { LockKeyhole, ShieldCheck } from 'lucide-vue-next'
import { computed, reactive } from 'vue'

import type { ChangePasswordInput } from '@/api/types'
import {
  type PasswordChangeErrors,
  validatePasswordChange,
} from '@/utils/password'

defineProps<{
  loading: boolean
  errorMessage?: string
}>()

const emit = defineEmits<{
  submit: [value: ChangePasswordInput]
}>()

const form = reactive({
  currentPassword: '',
  newPassword: '',
  confirmation: '',
})
const errors = reactive<PasswordChangeErrors>({})
const canSubmit = computed(
  () =>
    Boolean(form.currentPassword) &&
    Boolean(form.newPassword) &&
    Boolean(form.confirmation),
)

function clearErrors(): void {
  delete errors.currentPassword
  delete errors.newPassword
  delete errors.confirmation
}

function submit(): void {
  clearErrors()
  Object.assign(errors, validatePasswordChange(form))
  if (Object.keys(errors).length) return

  emit('submit', {
    current_password: form.currentPassword,
    new_password: form.newPassword,
  })
}
</script>

<template>
  <form class="password-form" @submit.prevent="submit">
    <label class="field-label" for="current-password">当前密码</label>
    <el-input
      id="current-password"
      v-model="form.currentPassword"
      size="large"
      type="password"
      show-password
      autocomplete="current-password"
      :prefix-icon="LockKeyhole"
      :class="{ 'field-input--error': errors.currentPassword }"
      @input="delete errors.currentPassword"
    />
    <span v-if="errors.currentPassword" class="field-error" role="alert">
      {{ errors.currentPassword }}
    </span>

    <label class="field-label field-label--spaced" for="new-password">新密码</label>
    <el-input
      id="new-password"
      v-model="form.newPassword"
      size="large"
      type="password"
      show-password
      autocomplete="new-password"
      :prefix-icon="ShieldCheck"
      :class="{ 'field-input--error': errors.newPassword }"
      @input="delete errors.newPassword"
    />
    <span v-if="errors.newPassword" class="field-error" role="alert">
      {{ errors.newPassword }}
    </span>

    <label class="field-label field-label--spaced" for="confirm-password">确认新密码</label>
    <el-input
      id="confirm-password"
      v-model="form.confirmation"
      size="large"
      type="password"
      show-password
      autocomplete="new-password"
      :prefix-icon="ShieldCheck"
      :class="{ 'field-input--error': errors.confirmation }"
      @input="delete errors.confirmation"
    />
    <span v-if="errors.confirmation" class="field-error" role="alert">
      {{ errors.confirmation }}
    </span>

    <div v-if="errorMessage" class="submit-error" role="alert">{{ errorMessage }}</div>

    <el-button
      class="submit-command"
      type="primary"
      size="large"
      native-type="submit"
      :loading="loading"
      :disabled="!canSubmit"
    >
      更新密码
    </el-button>
  </form>
</template>

<style scoped>
.password-form {
  padding: 24px;
}

.field-label {
  display: block;
  margin-bottom: 8px;
  color: var(--ink-800);
  font-size: 12px;
  font-weight: 700;
}

.field-label--spaced {
  margin-top: 18px;
}

.field-error {
  display: block;
  margin-top: 6px;
  color: var(--red);
  font-size: 11px;
}

.field-input--error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--red) inset;
}

.submit-error {
  margin-top: 16px;
  padding: 10px 12px;
  border-left: 3px solid var(--red);
  color: #9d3030;
  background: #fff3f3;
  font-size: 12px;
}

.submit-command {
  width: 100%;
  margin-top: 22px;
}
</style>
