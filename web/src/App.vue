<script setup lang="ts">
import { defineAsyncComponent } from 'vue'

import { isDemoMode } from '@/api/runtime'

const DemoModeBanner = isDemoMode
  ? defineAsyncComponent(() => import('@/components/common/DemoModeBanner.vue'))
  : null
</script>

<template>
  <div :class="{ 'demo-runtime': isDemoMode }">
    <DemoModeBanner v-if="DemoModeBanner" />
    <RouterView />
  </div>
</template>

<style scoped>
.demo-runtime {
  padding-top: 34px;
}

.demo-runtime :deep(.sidebar) {
  top: 34px;
}

.demo-runtime :deep(.mobile-menu),
.demo-runtime :deep(.skip-link) {
  top: 42px;
}

.demo-runtime :deep(.login-page),
.demo-runtime :deep(.identity-panel),
.demo-runtime :deep(.login-panel) {
  min-height: calc(100vh - 34px);
}
</style>
