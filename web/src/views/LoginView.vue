<script setup lang="ts">
import { Binary, CheckCircle2, Database, HardDrive } from 'lucide-vue-next'
import { shallowRef } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import { isDemoMode } from '@/api/runtime'
import type { LoginInput } from '@/api/types'
import LoginForm from '@/components/auth/LoginForm.vue'
import { useLoginRateLimit } from '@/composables/useLoginRateLimit'
import { PRODUCT_NAME } from '@/config/branding'
import { useSessionStore } from '@/stores/session'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const loading = shallowRef(false)
const errorMessage = shallowRef('')
const {
  remainingSeconds,
  isRateLimited,
  start: startRateLimit,
} = useLoginRateLimit()

function isRateLimitError(error: unknown): error is ApiError {
  return (
    error instanceof ApiError &&
    error.status === 429 &&
    error.code === 'login_rate_limited'
  )
}

function safeLoginErrorMessage(error: unknown): string {
  if (
    error instanceof ApiError &&
    (error.status === 401 ||
      error.code?.toLocaleLowerCase('en-US') === 'invalid_credentials')
  ) {
    return '用户名或密码错误'
  }
  return error instanceof ApiError ? error.message : '登录服务暂不可用'
}

async function handleLogin(input: LoginInput): Promise<void> {
  if (loading.value || isRateLimited.value) return
  loading.value = true
  errorMessage.value = ''
  try {
    await session.login(input)
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/'
    await router.replace(redirect)
  } catch (error) {
    if (isRateLimitError(error)) {
      startRateLimit(error.retryAfterSeconds)
      errorMessage.value = ''
    } else {
      errorMessage.value = safeLoginErrorMessage(error)
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <main class="login-page">
    <section class="identity-panel" aria-label="系统标识">
      <div class="identity-grid" aria-hidden="true">
        <span v-for="index in 54" :key="index" :class="{ active: index % 7 === 0 || index % 11 === 0 }" />
      </div>
      <div class="identity-content">
        <div class="identity-mark"><Binary :size="31" /></div>
        <p class="identity-kicker mono">OFFLINE ANALYSIS CONSOLE</p>
        <h1>{{ PRODUCT_NAME }}</h1>
        <p class="identity-subtitle">离线二进制、归档与镜像检测</p>
        <div class="identity-status">
          <span><CheckCircle2 :size="15" />服务节点</span>
          <strong>LOCAL</strong>
        </div>
        <div class="identity-meta">
          <span><HardDrive :size="15" />文件仓库</span>
          <span><Database :size="15" />漏洞库</span>
        </div>
      </div>
    </section>

    <section class="login-panel">
      <div class="login-box">
        <div class="login-heading">
          <span class="mono">AUTH / 01</span>
          <h2>登录操作台</h2>
        </div>
        <p v-if="isDemoMode" class="demo-login-note">
          使用 demo-reader 或 demo-operator 可预览对应权限，其他非空用户名使用管理员权限。
        </p>
        <LoginForm
          :loading="loading"
          :error-message="errorMessage"
          :retry-after-seconds="remainingSeconds"
          @submit="handleLogin"
        />
        <footer class="login-footer">
          <span class="status-dot" />
          <span>内网节点</span>
          <strong>{{ PRODUCT_NAME }}</strong>
        </footer>
      </div>
    </section>
  </main>
</template>

<style scoped>
.login-page {
  display: grid;
  min-height: 100vh;
  grid-template-columns: minmax(360px, 0.9fr) minmax(420px, 1.1fr);
  background: #eef1f1;
}

.identity-panel {
  position: relative;
  display: flex;
  min-height: 100vh;
  align-items: center;
  overflow: hidden;
  border-right: 1px solid #314347;
  color: #e5eeee;
  background: #142326;
}

.identity-grid {
  position: absolute;
  inset: 24px;
  display: grid;
  grid-template-columns: repeat(9, 1fr);
  gap: 12px;
  opacity: 0.28;
}

.identity-grid span {
  border: 1px solid #32474a;
}

.identity-grid span.active {
  border-color: #188f86;
  background: #176e68;
}

.identity-content {
  position: relative;
  z-index: 1;
  width: min(440px, 80%);
  margin: 0 auto;
  padding: 32px;
  background: #142326;
}

.identity-mark {
  display: grid;
  width: 58px;
  height: 58px;
  place-items: center;
  border: 1px solid #456266;
  border-radius: 5px;
  color: #53c8be;
  background: #1c3033;
}

.identity-kicker {
  margin: 56px 0 14px;
  color: #55b8b0;
  font-size: 10px;
  font-weight: 700;
}

.identity-content h1 {
  margin: 0;
  color: #fff;
  font-family: "DIN Alternate", "Noto Sans SC", sans-serif;
  font-size: 36px;
  line-height: 1.18;
  overflow-wrap: anywhere;
}

.identity-subtitle {
  margin: 15px 0 50px;
  color: #9badaf;
  font-size: 15px;
}

.identity-status {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 13px 0;
  border-top: 1px solid #35484b;
  border-bottom: 1px solid #35484b;
  font-size: 12px;
}

.identity-status span,
.identity-meta span {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: #9badaf;
}

.identity-status strong {
  color: #58c8bf;
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 11px;
}

.identity-meta {
  display: flex;
  gap: 28px;
  margin-top: 14px;
  font-size: 11px;
}

.login-panel {
  display: grid;
  min-height: 100vh;
  place-items: center;
  padding: 40px;
}

.login-box {
  width: min(410px, 100%);
  padding: 36px 38px 24px;
  border: 1px solid var(--line);
  border-top: 3px solid var(--teal);
  border-radius: 5px;
  background: #fff;
  box-shadow: 0 12px 32px rgb(28 45 49 / 8%);
}

.login-heading span {
  color: var(--teal-strong);
  font-size: 10px;
  font-weight: 700;
}

.login-heading h2 {
  margin: 10px 0 0;
  color: var(--ink-950);
  font-family: "DIN Alternate", "Noto Sans SC", sans-serif;
  font-size: 27px;
}

.demo-login-note {
  margin: 18px 0 -12px;
  padding: 9px 11px;
  border: 1px solid #ddc28d;
  border-left: 3px solid var(--amber);
  border-radius: 4px;
  color: #6e4d1b;
  background: #fff8e9;
  font-size: 11px;
  line-height: 1.5;
}

.login-footer {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 30px -38px -24px;
  padding: 14px 38px;
  border-top: 1px solid var(--line);
  color: var(--ink-400);
  font-size: 10px;
}

.login-footer strong {
  margin-left: auto;
  color: var(--ink-600);
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--teal);
}

@media (max-width: 820px) {
  .login-page {
    grid-template-columns: 1fr;
  }

  .identity-panel {
    min-height: 210px;
  }

  .identity-content {
    width: 100%;
    padding: 28px;
  }

  .identity-mark,
  .identity-status,
  .identity-meta {
    display: none;
  }

  .identity-kicker {
    margin: 0 0 10px;
  }

  .identity-content h1 {
    font-size: 38px;
  }

  .identity-subtitle {
    margin: 10px 0 0;
  }

  .login-panel {
    min-height: auto;
    padding: 26px 16px;
  }
}
</style>
