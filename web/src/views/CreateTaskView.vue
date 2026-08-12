<script setup lang="ts">
import { Replace } from 'lucide-vue-next'
import {
  computed,
  onScopeDispose,
  shallowRef,
  watch,
} from 'vue'
import { useRoute, useRouter } from 'vue-router'

import type { InputCategory } from '@/api/types'
import PageHeader from '@/components/common/PageHeader.vue'
import TaskInputCategoryDialog from '@/components/tasks/TaskInputCategoryDialog.vue'
import CategorizedUploadWorkspace from '@/components/uploads/CategorizedUploadWorkspace.vue'
import { useTaskCreationLauncher } from '@/composables/useTaskCreationLauncher'

const route = useRoute()
const router = useRouter()
const { cancelTaskCreation } = useTaskCreationLauncher()
const categoryDialogOpen = shallowRef(false)
const categoryLocked = shallowRef(false)
let navigationGeneration = 0

const routeCategory = computed<InputCategory | null>(() => {
  const value = route.query.category
  return value === 'binary' || value === 'archive' || value === 'container'
    ? value
    : null
})
const category = shallowRef<InputCategory | null>(routeCategory.value)

watch(
  routeCategory,
  (value) => {
    if (
      categoryLocked.value &&
      category.value !== null &&
      value !== category.value
    ) {
      const protectedCategory = category.value
      const requestGeneration = ++navigationGeneration
      void router
        .replace({
          name: 'task-create',
          query: { ...route.query, category: protectedCategory },
        })
        .catch(() => {
          if (requestGeneration === navigationGeneration) {
            categoryDialogOpen.value = false
          }
        })
      return
    }
    if (value !== category.value) categoryLocked.value = false
    category.value = value
    categoryDialogOpen.value = value === null
  },
  { immediate: true },
)

async function selectCategory(value: InputCategory): Promise<void> {
  if (categoryLocked.value && category.value !== null) return
  const requestGeneration = ++navigationGeneration
  try {
    await router.replace({
      name: 'task-create',
      query: { ...route.query, category: value },
    })
  } catch {
    if (requestGeneration === navigationGeneration) {
      categoryDialogOpen.value = true
    }
  }
}

function requestCategoryChange(): void {
  if (categoryLocked.value) return
  categoryDialogOpen.value = true
}

function cancelCategorySelection(): void {
  if (category.value === null) {
    void cancelTaskCreation()
    return
  }
  categoryDialogOpen.value = false
}

onScopeDispose(() => {
  navigationGeneration += 1
})
</script>

<template>
  <div class="page-view">
    <PageHeader title="新建任务" eyebrow="TASKS / CREATE">
      <template #actions>
        <el-button
          v-if="category"
          :icon="Replace"
          :disabled="categoryLocked"
          @click="requestCategoryChange"
        >
          更换类别
        </el-button>
      </template>
    </PageHeader>

    <CategorizedUploadWorkspace
      v-if="category"
      :key="category"
      :category="category"
      @lock-change="categoryLocked = $event"
    />

    <TaskInputCategoryDialog
      v-model="categoryDialogOpen"
      :current-category="category"
      :required="category === null"
      :locked="categoryLocked"
      @select="selectCategory"
      @cancel="cancelCategorySelection"
    />
  </div>
</template>
