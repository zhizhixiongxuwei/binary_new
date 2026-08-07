<script setup lang="ts">
import { LockKeyhole } from 'lucide-vue-next'

import type { SampleRetentionSnapshot } from '@/utils/sampleRetention'

defineProps<{
  retention: SampleRetentionSnapshot
  historyLabel: string
}>()
</script>

<template>
  <div
    class="sample-retention-notice"
    :class="`sample-retention-notice--${retention.status}`"
    role="note"
    :title="retention.actionReason"
  >
    <LockKeyhole :size="15" aria-hidden="true" />
    <span>
      <strong>{{ retention.statusLabel }}</strong>
      {{ retention.actionReason }} 当前仍可查看已保存的{{ historyLabel }}。
    </span>
  </div>
</template>

<style scoped>
.sample-retention-notice {
  display: flex;
  min-width: 0;
  min-height: 38px;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid #decba7;
  color: #71511f;
  background: #fff9ef;
  font-size: 10px;
  line-height: 1.5;
}

.sample-retention-notice svg {
  flex: 0 0 auto;
}

.sample-retention-notice span {
  min-width: 0;
}

.sample-retention-notice strong {
  margin-right: 5px;
  color: #664312;
}

.sample-retention-notice--deleted {
  border-color: #e4bebe;
  color: #8b3434;
  background: #fff5f5;
}

.sample-retention-notice--deleted strong {
  color: #922b2b;
}

.sample-retention-notice--unavailable {
  border-color: #c9d2d4;
  color: var(--ink-600);
  background: #f5f7f7;
}

.sample-retention-notice--unavailable strong {
  color: var(--ink-800);
}
</style>
