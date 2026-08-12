<script setup lang="ts">
import { Plus } from 'lucide-vue-next'

import PageHeader from '@/components/common/PageHeader.vue'
import OverviewPanel from '@/components/overview/OverviewPanel.vue'
import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const { launchTaskCreation } = useTaskCreationLauncher()
</script>

<template>
  <div class="page-view">
    <PageHeader title="系统概览" eyebrow="OVERVIEW / LIVE">
      <template #actions>
        <el-button
          v-if="session.user?.role !== 'reader'"
          type="primary"
          :icon="Plus"
          @click="launchTaskCreation"
        >
          新建任务
        </el-button>
      </template>
    </PageHeader>
    <OverviewPanel />
  </div>
</template>
