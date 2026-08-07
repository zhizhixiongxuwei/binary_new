<script setup lang="ts">
import { defineAsyncComponent } from 'vue'

import PageHeader from '@/components/common/PageHeader.vue'
import SystemMaintenanceLiveWorkspace from '@/components/system/maintenance/SystemMaintenanceLiveWorkspace.vue'

const workspaceComponent =
  import.meta.env.VITE_APP_MODE === 'demo'
    ? defineAsyncComponent(
        () =>
          import(
            '@/components/system/maintenance/SystemMaintenanceWorkspace.vue'
          ),
      )
    : SystemMaintenanceLiveWorkspace
</script>

<template>
  <div class="page-view">
    <PageHeader
      title="系统维护"
      eyebrow="SYSTEM / MAINTENANCE"
      description="查看本地节点、持久化目录、离线工具、用户权限与审计事件。"
    />
    <component :is="workspaceComponent" />
  </div>
</template>
