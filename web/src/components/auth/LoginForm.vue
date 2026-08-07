<script setup lang="ts">
import { LockKeyhole, User } from 'lucide-vue-next'
import { computed, reactive } from 'vue'

import type { LoginInput } from '@/api/types'
import LoginRateLimitAlert from '@/components/auth/LoginRateLimitAlert.vue'

const props = defineProps<{
  loading: boolean
  errorMessage?: string
  retryAfterSeconds?: number
}>()

const emit = defineEmits<{
  submit: [value: LoginInput]
}>()

const form = reactive<LoginInput>({
  username: '',
  password: '',
})
const isRateLimited = computed(
  () =>
    Number.isSafeInteger(props.retryAfterSeconds) &&
    (props.retryAfterSeconds ?? 0) > 0,
)
const canSubmit = computed(
  () =>
    !props.loading &&
    !isRateLimited.value &&
    Boolean(form.username.trim()) &&
    Boolean(form.password),
)

function submit(): void {
  if (!canSubmit.value) return
  emit('submit', {
    username: form.username.trim(),
    password: form.password,
  })
}
</script>

<template>
  <form class="login-form" @submit.prevent="submit">
    <label class="field-label" for="username">用户名</label>
    <el-input
      id="username"
      v-model="form.username"
      size="large"
      autocomplete="username"
      placeholder="请输入用户名"
      :prefix-icon="User"
    />

    <label class="field-label field-label--spaced" for="password">密码</label>
    <el-input
      id="password"
      v-model="form.password"
      size="large"
      type="password"
      show-password
      autocomplete="current-password"
      placeholder="请输入密码"
      :prefix-icon="LockKeyhole"
    />

    <div class="login-feedback">
      <LoginRateLimitAlert
        v-if="isRateLimited"
        :remaining-seconds="retryAfterSeconds ?? 1"
      />
      <div v-else-if="errorMessage" class="login-error" role="alert">
        {{ errorMessage }}
      </div>
      <div v-else class="login-feedback__placeholder" aria-hidden="true" />
    </div>

    <el-button
      class="login-command"
      type="primary"
      size="large"
      native-type="submit"
      :loading="loading"
      :disabled="!canSubmit"
      :aria-describedby="isRateLimited ? 'login-rate-limit-status' : undefined"
    >
      登录
    </el-button>
  </form>
</template>

<style scoped>
.login-form {
  margin-top: 30px;
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

.login-feedback {
  margin-top: 15px;
  min-height: 64px;
}

.login-feedback__placeholder {
  min-height: 64px;
}

.login-error {
  min-height: 64px;
  padding: 10px 12px;
  border-left: 3px solid var(--red);
  display: flex;
  align-items: center;
  color: #9d3030;
  background: #fff3f3;
  font-size: 12px;
  line-height: 1.5;
}

.login-command {
  width: 100%;
  margin-top: 12px;
}
</style>
