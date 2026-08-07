<script setup lang="ts">
import { AlertCircle, X } from 'lucide-vue-next'

defineProps<{
  message: string
}>()

const emit = defineEmits<{
  dismiss: []
}>()
</script>

<template>
  <div class="logout-alert" role="alert">
    <AlertCircle :size="15" aria-hidden="true" />
    <span>{{ message }}</span>
    <button
      type="button"
      aria-label="关闭退出错误"
      title="关闭"
      @click="emit('dismiss')"
    >
      <X :size="14" />
    </button>
  </div>
</template>

<style scoped>
.logout-alert {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
  color: #9f3030;
  font-size: 11px;
}

.logout-alert > span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.logout-alert button {
  display: grid;
  width: 26px;
  height: 26px;
  flex: 0 0 26px;
  place-items: center;
  border: 0;
  border-radius: 4px;
  color: #9f3030;
  background: transparent;
  cursor: pointer;
}

.logout-alert button:hover {
  background: #fff0f0;
}
</style>
