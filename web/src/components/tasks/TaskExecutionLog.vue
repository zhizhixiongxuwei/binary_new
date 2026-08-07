<script setup lang="ts">
import { Activity, Wifi } from 'lucide-vue-next'
import { computed, nextTick, useTemplateRef, watch } from 'vue'

import type { TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'
import type { TaskEventConnectionStatus } from '@/composables/useTaskEvents'
import { formatDateTime } from '@/utils/formatters'

const props = defineProps<{
  entries: readonly TaskExecutionLogEntry[]
  connectionStatus: TaskEventConnectionStatus
  connectionLabel: string
  connectionTitle: string
}>()

const connectionClasses = computed(() => [
  'execution-log__connection',
  `execution-log__connection--${props.connectionStatus}`,
])
const connectionBusy = computed(
  () => props.connectionStatus === 'connecting'
    || props.connectionStatus === 'reconnecting',
)
const logList = useTemplateRef<HTMLOListElement>('logList')
const newestEntryKey = computed(
  () => props.entries[props.entries.length - 1]?.key ?? '',
)

watch(
  newestEntryKey,
  async () => {
    await nextTick()
    if (logList.value) logList.value.scrollTop = logList.value.scrollHeight
  },
  { flush: 'post' },
)
</script>

<template>
  <section
    class="execution-log surface-panel"
    aria-labelledby="execution-log-title"
    :aria-busy="connectionBusy"
  >
    <header class="execution-log__header">
      <div class="execution-log__heading">
        <Activity :size="16" aria-hidden="true" />
        <h2 id="execution-log-title">执行日志</h2>
        <span class="execution-log__count">{{ entries.length }} 条</span>
      </div>
      <span
        :class="connectionClasses"
        :title="connectionTitle"
        role="status"
        aria-live="polite"
      >
        <Wifi :size="12" aria-hidden="true" />
        {{ connectionLabel }}
      </span>
    </header>

    <div v-if="entries.length === 0" class="execution-log__empty">
      等待任务执行事件
    </div>
    <ol
      v-else
      ref="logList"
      class="execution-log__list"
      role="log"
      aria-live="polite"
      aria-relevant="additions"
    >
      <li
        v-for="entry in entries"
        :key="entry.key"
        class="execution-log__item"
        :class="`execution-log__item--${entry.tone}`"
      >
        <time :datetime="entry.createdAt">
          {{ formatDateTime(entry.createdAt) }}
        </time>
        <span class="execution-log__marker" aria-hidden="true" />
        <div class="execution-log__event">
          <div class="execution-log__event-title">
            <strong>{{ entry.title }}</strong>
            <span v-if="entry.stageLabel">{{ entry.stageLabel }}</span>
          </div>
          <small v-if="entry.detailLabel">{{ entry.detailLabel }}</small>
        </div>
        <span v-if="entry.progressLabel" class="execution-log__progress mono">
          {{ entry.progressLabel }}
        </span>
        <span class="execution-log__severity">{{ entry.severityLabel }}</span>
        <small class="execution-log__sequence mono">#{{ entry.sequence }}</small>
      </li>
    </ol>
  </section>
</template>

<style scoped>
.execution-log {
  container: execution-log / inline-size;
  overflow: hidden;
}

.execution-log__header {
  display: flex;
  min-height: 46px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--line);
}

.execution-log__heading,
.execution-log__connection,
.execution-log__event-title {
  min-width: 0;
  display: flex;
  align-items: center;
}

.execution-log__heading {
  gap: 7px;
  color: var(--teal-strong);
}

.execution-log__heading h2 {
  margin: 0;
  color: var(--ink-800);
  font-size: 13px;
}

.execution-log__count {
  padding-left: 7px;
  border-left: 1px solid var(--line);
  color: var(--ink-600);
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}

.execution-log__connection {
  flex: 0 1 auto;
  gap: 5px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.3;
}

.execution-log__connection svg {
  flex: 0 0 auto;
}

.execution-log__connection--connected {
  color: var(--teal-strong);
}

.execution-log__connection--reconnecting {
  color: var(--amber);
}

.execution-log__list {
  max-height: 254px;
  padding: 0;
  margin: 0;
  overflow: auto;
  list-style: none;
  scrollbar-gutter: stable;
}

.execution-log__item {
  display: grid;
  min-height: 46px;
  grid-template-columns: 132px 8px minmax(150px, 1fr) 64px 46px 52px;
  align-items: center;
  gap: 10px;
  padding: 7px 14px;
  border-bottom: 1px solid #e8ebec;
}

.execution-log__item:last-child {
  border-bottom: 0;
}

.execution-log__item time,
.execution-log__sequence {
  color: var(--ink-600);
  font-size: 10px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.execution-log__marker {
  width: 7px;
  height: 7px;
  border: 1px solid var(--ink-400);
  border-radius: 50%;
  background: var(--surface);
}

.execution-log__item--info .execution-log__marker {
  border-color: var(--teal);
  background: #bfe3df;
}

.execution-log__item--warning .execution-log__marker {
  border-color: var(--amber);
  background: #f4dba7;
}

.execution-log__item--error .execution-log__marker {
  border-color: var(--red);
  background: #f2bcbc;
}

.execution-log__event {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.execution-log__event-title {
  gap: 8px;
}

.execution-log__event-title strong {
  min-width: 0;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-log__event-title span,
.execution-log__severity {
  flex: 0 0 auto;
  padding: 1px 5px;
  border: 1px solid var(--line);
  border-radius: 3px;
  color: var(--ink-600);
  background: var(--surface-raised);
  font-size: 9px;
  white-space: nowrap;
}

.execution-log__event > small {
  min-width: 0;
  overflow: hidden;
  color: var(--ink-600);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.execution-log__progress {
  color: var(--ink-800);
  font-size: 10px;
  text-align: right;
}

.execution-log__severity {
  justify-self: end;
}

.execution-log__item--warning .execution-log__severity {
  border-color: #d9c992;
  color: #7c5b12;
  background: #fffaf0;
}

.execution-log__item--error .execution-log__severity {
  border-color: #e3bcbc;
  color: #8c3131;
  background: #fff5f5;
}

.execution-log__sequence {
  justify-self: end;
}

.execution-log__empty {
  display: grid;
  min-height: 76px;
  place-items: center;
  padding: 12px;
  color: var(--ink-600);
  font-size: 11px;
}

@container execution-log (max-width: 700px) {
  .execution-log__item {
    grid-template-columns: 8px minmax(130px, 1fr) 56px 42px;
  }

  .execution-log__item time,
  .execution-log__sequence {
    display: none;
  }
}

@container execution-log (max-width: 430px) {
  .execution-log__header {
    align-items: flex-start;
    flex-direction: column;
    gap: 4px;
  }

  .execution-log__item {
    grid-template-columns: 8px minmax(0, 1fr) auto;
    gap: 8px;
  }

  .execution-log__event-title {
    align-items: flex-start;
    flex-direction: column;
    gap: 3px;
  }

  .execution-log__event-title strong {
    max-width: 100%;
  }

  .execution-log__severity {
    display: none;
  }
}
</style>
