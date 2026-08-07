<script setup lang="ts">
import { shallowRef } from 'vue'
import { useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import type { ChangePasswordInput } from '@/api/types'
import ChangePasswordForm from '@/components/auth/ChangePasswordForm.vue'
import PageHeader from '@/components/common/PageHeader.vue'
import { useSessionStore } from '@/stores/session'

const router = useRouter()
const session = useSessionStore()
const loading = shallowRef(false)
const errorMessage = shallowRef('')

async function handleSubmit(input: ChangePasswordInput): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    await session.changePassword(input)
    await router.replace({ name: 'overview' })
  } catch (error) {
    errorMessage.value = error instanceof ApiError ? error.message : '密码更新失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="password-view">
    <PageHeader title="更新密码" eyebrow="ACCOUNT / PASSWORD" />
    <section class="password-panel surface-panel">
      <header class="password-panel__header">
        <span class="mono">{{ session.user?.username }}</span>
      </header>
      <ChangePasswordForm
        :loading="loading"
        :error-message="errorMessage"
        @submit="handleSubmit"
      />
    </section>
  </div>
</template>

<style scoped>
.password-view {
  width: min(100%, 520px);
  margin: 0 auto;
}

.password-panel__header {
  display: flex;
  min-height: 46px;
  align-items: center;
  padding: 0 24px;
  border-bottom: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 11px;
}
</style>
