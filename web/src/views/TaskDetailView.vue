<script setup lang="ts">
import { ArrowLeft } from 'lucide-vue-next'
import { computed } from 'vue'
import { useRoute } from 'vue-router'

import PageHeader from '@/components/common/PageHeader.vue'
import TaskDetailPanel from '@/components/tasks/TaskDetailPanel.vue'

const route = useRoute()
const taskId = computed(() => String(route.params.id))
</script>

<template>
  <div class="page-view">
    <PageHeader title="任务详情" :eyebrow="`TASKS / ${taskId}`">
      <template #actions>
        <el-button :icon="ArrowLeft" @click="$router.push({ name: 'tasks' })">返回列表</el-button>
      </template>
    </PageHeader>
    <TaskDetailPanel
      :task-id="taskId"
      @return-list="$router.push({ name: 'tasks' })"
    />
  </div>
</template>
