<script setup lang="ts">
import { Plus } from 'lucide-vue-next'

import PageHeader from '@/components/common/PageHeader.vue'
import TaskListPanel from '@/components/tasks/TaskListPanel.vue'
import { useSessionStore } from '@/stores/session'

const session = useSessionStore()
</script>

<template>
  <div class="page-view">
    <PageHeader title="检测任务" eyebrow="TASKS / INDEX">
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
    <TaskListPanel
      :user-role="session.user?.role ?? null"
      :current-user-id="session.user?.id ?? null"
    />
  </div>
</template>
