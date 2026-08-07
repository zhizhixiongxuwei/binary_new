<script setup lang="ts">
import {
  Ban,
  Circle,
  CircleCheck,
  CircleX,
  CodeXml,
  Database,
  FileCheck2,
  LoaderCircle,
  PackageCheck,
  Save,
  ScanSearch,
  ServerCog,
  Timer,
} from 'lucide-vue-next'
import { computed } from 'vue'
import type { Component } from 'vue'

import type { TaskExecutionLogEntry } from '@/components/tasks/taskExecutionLog'
import type { TaskStageSource } from '@/utils/taskStages'
import {
  deriveTaskStageProgress,
  type TaskStageId,
  type TaskStageState,
} from '@/utils/taskStages'

const props = defineProps<{
  task: TaskStageSource
  entries?: readonly TaskExecutionLogEntry[]
}>()

const model = computed(() => deriveTaskStageProgress(props.task, props.entries ?? []))
const progressAriaAttributes = computed<Readonly<Record<string, string>>>(() =>
  model.value.indeterminate
    ? {}
    : { 'aria-valuenow': String(model.value.progress) },
)

const stageIcons: Readonly<Record<TaskStageId, Component>> = {
  queued: Timer,
  preparing: FileCheck2,
  starting: ServerCog,
  running: CodeXml,
  verifying: PackageCheck,
  database_ready: Database,
  targets_ready: FileCheck2,
  scanning: ScanSearch,
  publishing: Save,
  completed: CircleCheck,
}

const stateIcons: Readonly<Record<TaskStageState, Component>> = {
  completed: CircleCheck,
  current: LoaderCircle,
  pending: Circle,
  failed: CircleX,
  cancelled: Ban,
}
</script>

<template>
  <section
    class="task-stages surface-panel"
    :class="`task-stages--${model.outcome}`"
    aria-label="阶段进度"
  >
    <header class="task-stages__header">
      <div class="task-stages__heading">
        <div class="task-stages__title-line">
          <h2>阶段进度</h2>
          <span>{{ model.workflowLabel }}</span>
        </div>
        <p role="status" aria-live="polite">{{ model.summary }}</p>
      </div>
      <strong
        class="task-stages__percentage"
        :aria-label="model.indeterminate ? '任务总进度计算中' : `任务总进度 ${model.progress}%`"
      >
        {{ model.indeterminate ? '计算中' : `${model.progress}%` }}
      </strong>
    </header>

    <div
      class="task-stages__meter"
      :class="{ 'task-stages__meter--indeterminate': model.indeterminate }"
      role="progressbar"
      :data-progress-mode="model.indeterminate ? 'indeterminate' : 'determinate'"
      aria-label="任务总进度"
      aria-valuemin="0"
      aria-valuemax="100"
      v-bind="progressAriaAttributes"
    >
      <span
        :style="{ width: model.indeterminate ? '36%' : `${model.progress}%` }"
      />
    </div>

    <ol class="task-stages__list">
      <li
        v-for="stage in model.stages"
        :key="stage.id"
        class="task-stages__item"
        :class="`task-stages__item--${stage.state}`"
        :data-stage="stage.id"
        :data-state="stage.state"
        :aria-current="stage.state === 'current' ? 'step' : false"
        :aria-label="`${stage.label}：${stage.stateLabel}`"
      >
        <component
          :is="stateIcons[stage.state]"
          class="task-stages__state-icon"
          :size="19"
          aria-hidden="true"
        />
        <div class="task-stages__label">
          <span>
            <component :is="stageIcons[stage.id]" :size="14" aria-hidden="true" />
            {{ stage.label }}
          </span>
          <small>{{ stage.stateLabel }}</small>
        </div>
      </li>
    </ol>
  </section>
</template>

<style scoped>
.task-stages {
  container: task-stages / inline-size;
  overflow: hidden;
}

.task-stages__header {
  display: flex;
  min-height: 58px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
}

.task-stages__heading {
  min-width: 0;
}

.task-stages__heading h2,
.task-stages__heading p {
  margin: 0;
}

.task-stages__title-line {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}

.task-stages__title-line span {
  padding: 1px 6px;
  border: 1px solid #bad3d0;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  font-size: 9px;
  font-weight: 700;
  white-space: nowrap;
}

.task-stages__heading h2 {
  color: var(--ink-800);
  font-size: 13px;
}

.task-stages__heading p {
  margin-top: 3px;
  color: var(--ink-600);
  font-size: 11px;
  overflow-wrap: anywhere;
}

.task-stages__percentage {
  flex: 0 0 auto;
  color: var(--teal-strong);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 13px;
}

.task-stages--partial .task-stages__percentage {
  color: var(--amber);
}

.task-stages--failed .task-stages__percentage {
  color: var(--red);
}

.task-stages__meter {
  height: 3px;
  overflow: hidden;
  background: #e5e9ea;
}

.task-stages__meter span {
  display: block;
  width: 0;
  height: 100%;
  background: var(--teal);
  transition: width 180ms ease-out;
}

.task-stages__meter--indeterminate span {
  width: 36%;
  background: repeating-linear-gradient(
    90deg,
    var(--blue) 0,
    var(--blue) 8px,
    #86aebc 8px,
    #86aebc 16px
  );
  animation: task-progress-indeterminate 1.2s ease-in-out infinite alternate;
}

@keyframes task-progress-indeterminate {
  from {
    transform: translateX(-30%);
  }
  to {
    transform: translateX(210%);
  }
}

.task-stages--partial .task-stages__meter span {
  background: var(--amber);
}

.task-stages--failed .task-stages__meter span {
  background: var(--red);
}

.task-stages__list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
  gap: 12px;
  padding: 14px 16px 16px;
  margin: 0;
  list-style: none;
}

.task-stages__item {
  display: grid;
  min-width: 0;
  min-height: 68px;
  grid-template-columns: 22px minmax(0, 1fr);
  align-content: center;
  gap: 8px;
  padding: 10px 4px 7px;
  border-top: 3px solid var(--line);
  color: var(--ink-400);
}

.task-stages__state-icon {
  align-self: start;
  margin-top: 1px;
}

.task-stages__label {
  min-width: 0;
}

.task-stages__label span {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 5px;
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}

.task-stages__label span svg {
  flex: 0 0 auto;
}

.task-stages__label small {
  display: block;
  margin-top: 5px;
  color: var(--ink-400);
  font-size: 10px;
}

.task-stages__item--completed {
  border-top-color: var(--teal);
  color: var(--teal);
}

.task-stages__item--current {
  border-top-color: var(--blue);
  color: var(--blue);
}

.task-stages__item--failed {
  border-top-color: var(--red);
  color: var(--red);
}

.task-stages__item--cancelled {
  border-top-color: var(--ink-600);
  color: var(--ink-600);
}

.task-stages__item--completed .task-stages__label span,
.task-stages__item--completed .task-stages__label small {
  color: var(--teal-strong);
}

.task-stages__item--current .task-stages__label span,
.task-stages__item--current .task-stages__label small {
  color: var(--blue);
}

.task-stages__item--failed .task-stages__label span,
.task-stages__item--failed .task-stages__label small {
  color: var(--red);
}

.task-stages__item--cancelled .task-stages__label span,
.task-stages__item--cancelled .task-stages__label small {
  color: var(--ink-600);
}

@container task-stages (max-width: 500px) {
  .task-stages__header {
    align-items: flex-start;
  }

  .task-stages__list {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px 12px;
  }

  .task-stages__item {
    min-height: 62px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .task-stages__meter span {
    transition: none;
  }

  .task-stages__meter--indeterminate span {
    animation: none;
    transform: translateX(90%);
  }
}
</style>
