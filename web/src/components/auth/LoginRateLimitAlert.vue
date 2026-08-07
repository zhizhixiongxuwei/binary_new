<script setup lang="ts">
import { Clock3, ShieldAlert } from 'lucide-vue-next'
import { computed } from 'vue'

const props = defineProps<{
  remainingSeconds: number
}>()

const seconds = computed(() =>
  Math.min(86_400, Math.max(1, Math.trunc(props.remainingSeconds))),
)
</script>

<template>
  <div
    id="login-rate-limit-status"
    class="rate-limit-alert"
    role="status"
    aria-live="polite"
    aria-atomic="true"
  >
    <ShieldAlert class="rate-limit-alert__icon" :size="18" aria-hidden="true" />
    <div class="rate-limit-alert__copy">
      <strong>登录尝试过于频繁</strong>
      <span>为保护系统，请稍后再试。</span>
    </div>
    <span
      class="rate-limit-alert__countdown mono"
      :aria-label="`${seconds} 秒后可再次登录`"
    >
      <Clock3 :size="13" aria-hidden="true" />
      <b>{{ seconds }}</b>
      <span>秒</span>
    </span>
  </div>
</template>

<style scoped>
.rate-limit-alert {
  display: grid;
  min-height: 64px;
  grid-template-columns: 20px minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 9px 11px;
  border-left: 3px solid var(--amber);
  color: #674817;
  background: #fff8e9;
  font-size: 11px;
  line-height: 1.45;
}

.rate-limit-alert__icon {
  color: #a46d17;
}

.rate-limit-alert__copy {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.rate-limit-alert__copy strong {
  color: #51370e;
  font-size: 12px;
}

.rate-limit-alert__countdown {
  display: inline-grid;
  min-width: 56px;
  min-height: 32px;
  grid-template-columns: 14px minmax(18px, auto) 12px;
  align-items: center;
  justify-content: center;
  gap: 2px;
  border-left: 1px solid #e7cf9f;
  color: #6e4d1b;
}

.rate-limit-alert__countdown b {
  min-width: 2ch;
  color: #8f5e12;
  font-size: 15px;
  text-align: right;
}

@media (max-width: 380px) {
  .rate-limit-alert {
    grid-template-columns: 18px minmax(0, 1fr);
  }

  .rate-limit-alert__countdown {
    grid-column: 2;
    justify-content: start;
    border-left: 0;
  }
}
</style>
