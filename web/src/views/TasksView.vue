<script setup lang="ts">
import { Plus } from 'lucide-vue-next'

import PageHeader from '@/components/common/PageHeader.vue'
import TaskListPanel from '@/components/tasks/TaskListPanel.vue'
import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
const { launchTaskCreation } = useTaskCreationLauncher()
</script>

<template>
  <div class="page-view">
    <PageHeader title="检测任务" eyebrow="TASKS / INDEX">
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
    <TaskListPanel
      :user-role="session.user?.role ?? null"
      :current-user-id="session.user?.id ?? null"
    />
  </div>
</template>
