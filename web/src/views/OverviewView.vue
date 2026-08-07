<script setup lang="ts">
import { Plus } from 'lucide-vue-next'

import PageHeader from '@/components/common/PageHeader.vue'
import OverviewPanel from '@/components/overview/OverviewPanel.vue'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
</script>

<template>
  <div class="page-view">
    <PageHeader title="系统概览" eyebrow="OVERVIEW / LIVE">
      <template #actions>
        <el-button
          v-if="session.user?.role !== 'reader'"
          type="primary"
          :icon="Plus"
          @click="$router.push({ name: 'task-create' })"
        >
          新建任务
        </el-button>
      </template>
    </PageHeader>
    <OverviewPanel />
  </div>
</template>
