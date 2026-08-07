<script setup lang="ts">
import { ArrowLeft, Binary } from 'lucide-vue-next'
</script>

<template>
  <main class="not-found">
    <div class="not-found__code mono">HTTP / 404</div>
    <Binary :size="42" />
    <h1>页面不存在</h1>
    <el-button type="primary" :icon="ArrowLeft" @click="$router.push('/')">返回操作台</el-button>
  </main>
</template>

<style scoped>
.not-found {
  display: flex;
  min-height: 100vh;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 16px;
  color: var(--ink-800);
  background: var(--surface-muted);
}

.not-found__code {
  padding: 5px 8px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--red);
  background: #fff;
  font-size: 10px;
}

.not-found svg {
  color: var(--teal);
}

.not-found h1 {
  margin: 0 0 6px;
  font-size: 24px;
}
</style>
