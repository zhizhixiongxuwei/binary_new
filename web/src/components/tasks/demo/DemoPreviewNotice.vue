<script setup lang="ts">
import { Eye } from 'lucide-vue-next'

withDefaults(
  defineProps<{
    subject?: string
  }>(),
  {
    subject: '结果',
  },
)
</script>

<template>
  <div class="preview-notice" role="note">
    <Eye class="preview-notice__icon" :size="16" aria-hidden="true" />
    <div class="preview-notice__copy">
      <strong>{{ subject }}界面预览</strong>
      <span>以下为固定示例数据，不来自扫描引擎，也不代表当前任务的真实检测结论。</span>
    </div>
  </div>
</template>

<style scoped>
.preview-notice {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  padding: 10px 14px;
  border-bottom: 1px solid #dfd7bc;
  color: #624d20;
  background: #fffaf0;
}

.preview-notice__icon {
  flex: 0 0 auto;
  margin-top: 1px;
  color: #8a671b;
}

.preview-notice__copy {
  display: flex;
  min-width: 0;
  align-items: baseline;
  gap: 8px;
  flex-wrap: wrap;
}

.preview-notice__copy strong {
  color: #574316;
  font-size: 11px;
}

.preview-notice__copy span {
  color: #735f30;
  font-size: 10px;
  line-height: 1.55;
}
</style>
