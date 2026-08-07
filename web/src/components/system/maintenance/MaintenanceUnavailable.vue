<script setup lang="ts">
import { Cable } from 'lucide-vue-next'

defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <div class="maintenance-unavailable surface-panel" role="status">
    <span class="maintenance-unavailable__icon" aria-hidden="true">
      <Cable :size="24" />
    </span>
    <strong>{{ title }}</strong>
    <p>{{ description }}</p>
    <span class="maintenance-unavailable__state mono">BACKEND NOT CONNECTED</span>
  </div>
</template>

<style scoped>
.maintenance-unavailable {
  display: grid;
  min-height: 260px;
  place-items: center;
  align-content: center;
  gap: 10px;
  padding: 34px 20px;
  text-align: center;
}

.maintenance-unavailable__icon {
  display: grid;
  width: 46px;
  height: 46px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--ink-400);
  background: var(--surface-raised);
}

.maintenance-unavailable strong {
  color: var(--ink-800);
  font-size: 14px;
}

.maintenance-unavailable p {
  max-width: 520px;
  margin: 0;
  color: var(--ink-600);
  font-size: 12px;
  line-height: 1.7;
  overflow-wrap: anywhere;
}

.maintenance-unavailable__state {
  padding: 3px 7px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-400);
  background: #f6f8f8;
  font-size: 9px;
}
</style>
