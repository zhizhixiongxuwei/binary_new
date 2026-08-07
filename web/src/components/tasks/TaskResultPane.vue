<script setup lang="ts">
import {
  AlertTriangle,
  CircleOff,
  CodeXml,
  Download,
  FileArchive,
  FileJson2,
  Inbox,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
} from 'lucide-vue-next'
import { computed, type Component } from 'vue'

import type {
  TaskResultPaneAction,
  TaskResultState,
  TaskResultTab,
} from '@/components/tasks/taskResultTypes'

const props = defineProps<{
  kind: TaskResultTab
  state: TaskResultState
  actions?: readonly TaskResultPaneAction[]
  preview?: boolean
  contentOwnsState?: boolean
}>()

const emit = defineEmits<{
  command: [command: TaskResultPaneAction['id']]
}>()

defineSlots<{
  default?: () => unknown
}>()

interface PaneDefinition {
  title: string
  icon: Component
  loadingTitle: string
  emptyTitle: string
  unavailableTitle: string
  errorTitle: string
}

const paneDefinitions: Record<TaskResultTab, PaneDefinition> = {
  files: {
    title: '文件结构',
    icon: FileArchive,
    loadingTitle: '正在读取文件结构',
    emptyTitle: '文件结构尚未生成',
    unavailableTitle: '文件结构视图未接入',
    errorTitle: '文件结构读取失败',
  },
  decompile: {
    title: '反编译',
    icon: CodeXml,
    loadingTitle: '正在读取反编译结果',
    emptyTitle: '暂无反编译结果',
    unavailableTitle: '反编译结果未接入',
    errorTitle: '反编译结果读取失败',
  },
  vulnerabilities: {
    title: '容器漏洞',
    icon: ShieldCheck,
    loadingTitle: '正在读取容器漏洞结果',
    emptyTitle: '暂无容器漏洞结果',
    unavailableTitle: '容器漏洞结果未接入',
    errorTitle: '容器漏洞结果读取失败',
  },
  reports: {
    title: '报告',
    icon: FileJson2,
    loadingTitle: '正在读取报告',
    emptyTitle: '暂无可用报告',
    unavailableTitle: '报告结果未接入',
    errorTitle: '报告读取失败',
  },
}

const definition = computed(() => paneDefinitions[props.kind])

const statusLabel = computed(() => {
  switch (props.state.status) {
    case 'loading':
      return '读取中'
    case 'ready':
      return '已就绪'
    case 'empty':
      return '无结果'
    case 'error':
      return '异常'
    default:
      return '未接入'
  }
})

const stateTitle = computed(() => {
  if (props.state.title) return props.state.title
  switch (props.state.status) {
    case 'loading':
      return definition.value.loadingTitle
    case 'empty':
      return definition.value.emptyTitle
    case 'error':
      return definition.value.errorTitle
    case 'unavailable':
      return definition.value.unavailableTitle
    default:
      return ''
  }
})

const stateIcon = computed<Component>(() => {
  switch (props.state.status) {
    case 'loading':
      return LoaderCircle
    case 'error':
      return AlertTriangle
    case 'unavailable':
      return CircleOff
    default:
      return Inbox
  }
})

function actionIcon(action: TaskResultPaneAction): Component {
  return action.icon === 'refresh' ? RefreshCw : Download
}

function actionDisabled(action: TaskResultPaneAction): boolean {
  if (!action.enabled || action.pending) return true
  if (props.state.status === 'loading' || props.state.status === 'unavailable') {
    return true
  }
  return action.requiresReady && props.state.status !== 'ready'
}

function runAction(action: TaskResultPaneAction): void {
  if (!actionDisabled(action)) emit('command', action.id)
}
</script>

<template>
  <section
    class="result-pane"
    :aria-busy="state.status === 'loading'"
    :aria-label="`${definition.title}结果`"
  >
    <header class="result-pane__toolbar">
      <div class="result-pane__identity">
        <component :is="definition.icon" :size="17" aria-hidden="true" />
        <strong>{{ definition.title }}</strong>
        <span
          class="result-pane__status"
          :class="`result-pane__status--${state.status}`"
        >
          {{ statusLabel }}
        </span>
        <span v-if="preview" class="result-pane__preview">界面预览</span>
      </div>

      <div v-if="actions?.length" class="result-pane__commands" aria-label="结果操作">
        <button
          v-for="action in actions"
          :key="action.id"
          class="result-pane__command"
          type="button"
          :disabled="actionDisabled(action)"
          :aria-label="action.label"
          :title="action.label"
          :aria-busy="action.pending"
          @click="runAction(action)"
        >
          <LoaderCircle
            v-if="action.pending"
            class="result-pane__command-icon spin"
            :size="14"
            aria-hidden="true"
          />
          <component
            :is="actionIcon(action)"
            v-else
            class="result-pane__command-icon"
            :size="14"
            aria-hidden="true"
          />
          <span v-if="action.shortLabel">{{ action.shortLabel }}</span>
        </button>
      </div>
    </header>

    <div
      v-if="$slots.default && (state.status === 'ready' || contentOwnsState)"
      class="result-pane__content"
    >
      <slot />
    </div>
    <div
      v-else
      class="result-pane__state"
      :class="`result-pane__state--${state.status}`"
      :role="state.status === 'error' ? 'alert' : 'status'"
      :aria-live="state.status === 'loading' ? 'polite' : 'off'"
    >
      <component
        :is="stateIcon"
        class="result-pane__state-icon"
        :class="{ spin: state.status === 'loading' }"
        :size="27"
        aria-hidden="true"
      />
      <strong>{{ stateTitle || definition.unavailableTitle }}</strong>
      <code v-if="state.errorCode" class="result-pane__error-code">
        {{ state.errorCode }}
      </code>
      <span v-if="state.description" class="result-pane__description">
        {{ state.description }}
      </span>
    </div>
  </section>
</template>

<style scoped>
.result-pane {
  min-width: 0;
  min-height: 350px;
  background: var(--surface);
}

.result-pane__toolbar {
  display: flex;
  min-height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 7px 14px;
  border-bottom: 1px solid var(--line);
  background: #fbfcfc;
}

.result-pane__identity,
.result-pane__commands {
  display: flex;
  min-width: 0;
  align-items: center;
}

.result-pane__identity {
  gap: 8px;
  color: var(--teal-strong);
}

.result-pane__identity strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.result-pane__status,
.result-pane__preview {
  display: inline-flex;
  min-height: 20px;
  align-items: center;
  padding: 1px 6px;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: var(--ink-600);
  background: #f5f7f7;
  font-size: 9px;
  font-weight: 700;
  white-space: nowrap;
}

.result-pane__status--ready {
  border-color: #b8d7d3;
  color: #076860;
  background: #f1f8f7;
}

.result-pane__status--loading {
  border-color: #b9cde4;
  color: #245a92;
  background: #f1f6fb;
}

.result-pane__status--error {
  border-color: #e4bebe;
  color: #a52f2f;
  background: #fff5f5;
}

.result-pane__preview {
  border-color: #d7c894;
  color: #73571d;
  background: #fffaf0;
}

.result-pane__commands {
  flex: 0 0 auto;
  gap: 6px;
}

.result-pane__command {
  display: inline-flex;
  min-width: 30px;
  height: 30px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 0 8px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
  font-size: 10px;
  font-weight: 700;
}

.result-pane__command:hover:not(:disabled) {
  border-color: #9fc5c1;
  color: var(--teal-strong);
  background: #edf5f4;
}

.result-pane__command:disabled {
  color: #a4adaf;
  background: #f2f4f4;
  cursor: not-allowed;
}

.result-pane__command-icon {
  flex: 0 0 auto;
}

.result-pane__content {
  min-width: 0;
}

.result-pane__state {
  display: flex;
  min-height: 300px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 9px;
  padding: 32px 22px;
  color: var(--ink-600);
  text-align: center;
}

.result-pane__state-icon {
  color: var(--ink-400);
}

.result-pane__state--error .result-pane__state-icon {
  color: var(--red);
}

.result-pane__state strong {
  color: var(--ink-800);
  font-size: 13px;
}

.result-pane__error-code {
  padding: 2px 5px;
  border-radius: 3px;
  color: #9b3030;
  background: #fff0f0;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 10px;
}

.result-pane__description {
  max-width: 520px;
  color: var(--ink-600);
  font-size: 11px;
  line-height: 1.6;
}

.spin {
  animation: result-pane-spin 1s linear infinite;
}

@keyframes result-pane-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 620px) {
  .result-pane__toolbar {
    align-items: flex-start;
    flex-direction: column;
  }

  .result-pane__commands {
    width: 100%;
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
