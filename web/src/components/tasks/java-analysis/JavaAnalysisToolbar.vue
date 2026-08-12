<script setup lang="ts">
import { LoaderCircle, Play, RefreshCw, Square, Trash2 } from 'lucide-vue-next'

import type { JavaAnalysisRun, DecompileProject } from '@/api/types'
import { formatDateTime } from '@/utils/formatters'

defineProps<{
  projects: readonly DecompileProject[]
  runs: readonly JavaAnalysisRun[]
  selectedProjectId: string
  selectedRunId: string
  canCreate: boolean
  canCancel: boolean
  canDeleteRun: boolean
  creating: boolean
  cancelling: boolean
  deleting: boolean
}>()

defineEmits<{
  projectChange: [projectId: string]
  runChange: [runId: string]
  create: []
  cancel: []
  deleteRun: []
  refresh: []
}>()

const statusLabels: Readonly<Record<JavaAnalysisRun['status'], string>> = {
  queued: '排队中',
  running: '检测中',
  succeeded: '已完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '正在取消',
  cancelled: '已取消',
}

function projectLabel(project: DecompileProject): string {
  return `${project.target_path} · ${project.id.slice(-8)}`
}

function runLabel(run: JavaAnalysisRun): string {
  return `${formatDateTime(run.created_at)} · ${statusLabels[run.status]} · ${run.id.slice(-8)}`
}
</script>

<template>
  <header class="analysis-toolbar">
    <div class="analysis-toolbar__selectors">
      <label>
        <span>源码项目</span>
        <el-select
          :model-value="selectedProjectId"
          :disabled="creating || cancelling || deleting"
          aria-label="选择 Java 源码项目"
          @update:model-value="$emit('projectChange', String($event))"
        >
          <el-option
            v-for="project in projects"
            :key="project.id"
            :label="projectLabel(project)"
            :value="project.id"
          />
        </el-select>
      </label>
      <label>
        <span>检测版本</span>
        <el-select
          :model-value="selectedRunId"
          :disabled="creating || cancelling || deleting"
          clearable
          placeholder="尚未检测"
          aria-label="选择 Java 源码检测版本"
          @update:model-value="$emit('runChange', String($event ?? ''))"
        >
          <el-option
            v-for="run in runs"
            :key="run.id"
            :label="runLabel(run)"
            :value="run.id"
          />
        </el-select>
      </label>
    </div>

    <div class="analysis-toolbar__actions" aria-label="Java 源码检测操作">
      <el-button
        type="primary"
        :disabled="!canCreate"
        :loading="creating"
        @click="$emit('create')"
      >
        <Play v-if="!creating" :size="14" aria-hidden="true" />
        开始检测
      </el-button>
      <el-button
        v-if="canCancel || cancelling"
        :disabled="!canCancel"
        :loading="cancelling"
        @click="$emit('cancel')"
      >
        <Square v-if="!cancelling" :size="13" aria-hidden="true" />
        取消
      </el-button>
      <el-button
        v-if="canDeleteRun || deleting"
        type="danger"
        plain
        :disabled="!canDeleteRun"
        :loading="deleting"
        @click="$emit('deleteRun')"
      >
        <Trash2 v-if="!deleting" :size="14" aria-hidden="true" />
        删除记录
      </el-button>
      <button
        class="analysis-toolbar__refresh"
        type="button"
        title="刷新 Java 源码检测"
        aria-label="刷新 Java 源码检测"
        :disabled="creating || cancelling || deleting"
        @click="$emit('refresh')"
      >
        <LoaderCircle
          v-if="creating || cancelling || deleting"
          class="spin"
          :size="15"
          aria-hidden="true"
        />
        <RefreshCw v-else :size="15" aria-hidden="true" />
      </button>
    </div>
  </header>
</template>

<style scoped>
.analysis-toolbar {
  display: flex;
  min-width: 0;
  align-items: end;
  justify-content: space-between;
  gap: 14px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  background: #f7f9f9;
}

.analysis-toolbar__selectors {
  display: grid;
  min-width: 0;
  flex: 1;
  grid-template-columns: minmax(220px, 1.25fr) minmax(210px, 1fr);
  gap: 12px;
}

.analysis-toolbar__selectors label {
  display: grid;
  min-width: 0;
  gap: 5px;
}

.analysis-toolbar__selectors label > span {
  color: var(--ink-600);
  font-size: 9px;
  font-weight: 700;
}

.analysis-toolbar__actions {
  display: flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 8px;
}

.analysis-toolbar__refresh {
  display: inline-grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.analysis-toolbar__refresh:hover:not(:disabled) {
  border-color: var(--teal);
  color: var(--teal-strong);
}

.analysis-toolbar__refresh:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.spin {
  animation: toolbar-spin 1s linear infinite;
}

@keyframes toolbar-spin {
  to { transform: rotate(360deg); }
}

@container (max-width: 760px) {
  .analysis-toolbar {
    align-items: stretch;
    flex-direction: column;
  }

  .analysis-toolbar__selectors {
    grid-template-columns: minmax(0, 1fr);
  }

  .analysis-toolbar__actions {
    flex-wrap: wrap;
  }
}
</style>
