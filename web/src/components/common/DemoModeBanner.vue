<script setup lang="ts">
import { MonitorDot } from 'lucide-vue-next'
</script>

<template>
  <div class="demo-mode-banner" role="status" aria-label="界面预览模式">
    <MonitorDot :size="15" aria-hidden="true" />
    <strong>界面预览</strong>
    <span>示例数据</span>
    <small>不连接后端，不执行真实检测</small>
  </div>
</template>

<style scoped>
.demo-mode-banner {
  position: fixed;
  inset: 0 0 auto;
  z-index: 100;
  display: flex;
  min-height: 34px;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 6px 14px;
  border-bottom: 1px solid #9a6419;
  color: #573b14;
  background: #fff1cf;
  box-shadow: 0 1px 4px rgb(57 43 15 / 18%);
  font-size: 11px;
}

.demo-mode-banner strong {
  font-size: 12px;
}

.demo-mode-banner span {
  padding-left: 8px;
  border-left: 1px solid #cda866;
  font-weight: 700;
}

.demo-mode-banner small {
  color: #755320;
  font-size: 10px;
}

@media (max-width: 520px) {
  .demo-mode-banner {
    justify-content: flex-start;
  }

  .demo-mode-banner small {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}
</style>
