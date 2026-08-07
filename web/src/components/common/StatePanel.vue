<script setup lang="ts">
import { AlertTriangle, Inbox, LoaderCircle, RotateCw } from 'lucide-vue-next'
import { computed } from 'vue'

type StateKind = 'loading' | 'empty' | 'error'

const props = defineProps<{
  kind: StateKind
  title?: string
  description?: string
  retryable?: boolean
}>()

const emit = defineEmits<{
  retry: []
}>()

const icon = computed(() => {
  if (props.kind === 'loading') return LoaderCircle
  if (props.kind === 'error') return AlertTriangle
  return Inbox
})

const defaultTitle = computed(() => {
  if (props.kind === 'loading') return '正在读取数据'
  if (props.kind === 'error') return '数据读取失败'
  return '暂无数据'
})

const liveRole = computed(() => (props.kind === 'error' ? 'alert' : 'status'))
</script>

<template>
  <div
    class="state-panel"
    :class="`state-panel--${kind}`"
    :role="liveRole"
    aria-atomic="true"
    :aria-busy="kind === 'loading'"
  >
    <component
      :is="icon"
      class="state-panel__icon"
      :class="{ spin: kind === 'loading' }"
      :size="25"
      aria-hidden="true"
    />
    <strong class="state-panel__title">{{ title ?? defaultTitle }}</strong>
    <span v-if="description" class="state-panel__description">{{ description }}</span>
    <el-button
      v-if="kind === 'error' && retryable"
      plain
      size="small"
      :icon="RotateCw"
      @click="emit('retry')"
    >
      重试
    </el-button>
  </div>
</template>

<style scoped>
.state-panel {
  display: flex;
  min-height: 220px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 10px;
  padding: 36px 24px;
  color: var(--ink-600);
  text-align: center;
}

.state-panel__icon {
  color: var(--ink-400);
}

.state-panel--error .state-panel__icon {
  color: var(--red);
}

.state-panel__title {
  color: var(--ink-800);
  font-size: 14px;
  overflow-wrap: anywhere;
}

.state-panel__description {
  max-width: 480px;
  color: var(--ink-600);
  font-size: 12px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.spin {
  animation: rotate 1s linear infinite;
}

@keyframes rotate {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
