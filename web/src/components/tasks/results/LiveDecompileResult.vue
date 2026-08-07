<script setup lang="ts">
import { watch } from 'vue'

import type { TaskResultState } from '@/components/tasks/taskResultTypes'
import StatePanel from '@/components/common/StatePanel.vue'
import DecompileResultWorkspace from '@/components/tasks/results/DecompileResultWorkspace.vue'
import { useDecompileResults } from '@/composables/useDecompileResults'

const props = defineProps<{
  taskId: string
}>()

const emit = defineEmits<{
  stateChange: [state: TaskResultState]
}>()

const results = useDecompileResults({
  taskId: () => props.taskId,
})

watch(
  results.state,
  (state) => emit('stateChange', state),
  { immediate: true },
)

defineExpose({
  refresh: results.refresh,
})
</script>

<template>
  <StatePanel
    v-if="results.state.value.status !== 'ready'"
    :kind="
      results.state.value.status === 'loading'
        ? 'loading'
        : results.state.value.status === 'error'
          ? 'error'
          : 'empty'
    "
    :title="results.state.value.title ?? ''"
    :description="results.state.value.description ?? ''"
    :retryable="results.state.value.status === 'error'"
    @retry="results.refresh"
  />
  <DecompileResultWorkspace
    v-else
    :task-id="taskId"
    :items="results.items.value"
    :selected-id="results.selectedResultId.value"
    :source="results.source.value"
    :source-loading="results.sourceLoading.value"
    :source-error="results.sourceError.value"
    :has-more-results="results.hasMoreResults.value"
    :loading-more-results="results.loadingMore.value"
    :has-more-source="results.hasMoreSource.value"
    @select="results.selectResult"
    @load-more-results="results.loadMoreResults"
    @load-more-source="results.loadMoreSource"
  />
</template>
