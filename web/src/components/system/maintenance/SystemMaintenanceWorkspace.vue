<script setup lang="ts">
import SystemMaintenanceLiveWorkspace from '@/components/system/maintenance/SystemMaintenanceLiveWorkspace.vue'
</script>

<template>
  <section class="maintenance-workspace" aria-label="系统维护工作台">
    <div class="preview-notice" role="status">
      <span class="preview-notice__mark mono">UI PREVIEW</span>
      <div>
        <strong>界面预览 · 固定示例数据</strong>
        <span>维护命令不会执行，也不会写入主机、数据库或离线数据目录。</span>
      </div>
    </div>

    <SystemMaintenanceLiveWorkspace />
  </section>
</template>

<style scoped>
.maintenance-workspace {
  display: grid;
  min-width: 0;
  gap: 14px;
}

.preview-notice {
  display: flex;
  min-width: 0;
  min-height: 48px;
  align-items: center;
  gap: 11px;
  padding: 9px 13px;
  border: 1px solid #b8d7d3;
  border-left: 3px solid var(--teal);
  border-radius: 5px;
  color: var(--ink-600);
  background: #f3f9f8;
}

.preview-notice__mark {
  flex: 0 0 auto;
  padding: 3px 6px;
  border: 1px solid #a8cbc6;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #e7f4f2;
  font-size: 9px;
  font-weight: 700;
}

.preview-notice > div {
  min-width: 0;
}

.preview-notice strong,
.preview-notice span {
  display: block;
}

.preview-notice strong {
  color: var(--ink-800);
  font-size: 11px;
}

.preview-notice > div span {
  margin-top: 2px;
  font-size: 9px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}

@media (max-width: 560px) {
  .preview-notice {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
