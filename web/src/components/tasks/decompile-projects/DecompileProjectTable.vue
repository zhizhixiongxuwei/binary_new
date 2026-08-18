<script setup lang="ts">
import { Download, FileCode2, LoaderCircle, ScanSearch, Trash2 } from 'lucide-vue-next'

import type {
  DecompileProject,
  DecompileProjectSourceKind,
  DecompileProjectStatus,
  CAnalysisRun,
  JavaAnalysisRun,
  PythonAnalysisRun,
} from '@/api/types'
import { formatBytes, formatDateTime } from '@/utils/formatters'

defineProps<{
  projects: readonly DecompileProject[]
  canDelete: boolean
  loadingMore: boolean
  hasMore: boolean
  downloadingProjectId: string
  deletingProjectId: string
  latestCAnalysisByProject: Readonly<Record<string, CAnalysisRun>>
  latestJavaAnalysisByProject: Readonly<Record<string, JavaAnalysisRun>>
  latestPythonAnalysisByProject: Readonly<Record<string, PythonAnalysisRun>>
  canAnalyze: boolean
}>()

defineEmits<{
  download: [project: DecompileProject]
  delete: [project: DecompileProject]
  analyze: [project: DecompileProject]
  analyzeJava: [project: DecompileProject]
  analyzePython: [project: DecompileProject]
  loadMore: []
}>()

const sourceKindLabels: Readonly<Record<DecompileProjectSourceKind, string>> = {
  'ghidra-pseudoc': 'Ghidra 伪 C',
  java: 'Java',
  kotlin: 'Kotlin',
  python: 'Python',
  bytecode: '字节码',
}

const statusLabels: Readonly<Record<DecompileProjectStatus, string>> = {
  complete: '完整',
  partial: '部分完成',
  bytecode_only: '仅字节码',
}

const analysisStatusLabels: Readonly<Record<CAnalysisRun['status'], string>> = {
  queued: '排队中',
  running: '检测中',
  succeeded: '已完成',
  partial: '部分完成',
  failed: '失败',
  cancel_requested: '正在取消',
  cancelled: '已取消',
}

const javaAnalysisStatusLabels: Readonly<
  Record<JavaAnalysisRun['status'], string>
> = analysisStatusLabels

const pythonAnalysisStatusLabels: Readonly<
  Record<PythonAnalysisRun['status'], string>
> = analysisStatusLabels

function supportsCAnalysis(project: DecompileProject): boolean {
  return project.layout_version === 'project-v1' &&
    project.source_kind === 'ghidra-pseudoc' &&
    project.language.toLowerCase() === 'c' &&
    (project.status === 'complete' || project.status === 'partial')
}

function supportsJavaAnalysis(project: DecompileProject): boolean {
  return project.layout_version === 'project-v1' &&
    project.manifest_available &&
    project.source_kind === 'java' &&
    (project.language === 'java' || project.language === 'mixed') &&
    (project.status === 'complete' || project.status === 'partial')
}

function supportsPythonAnalysis(project: DecompileProject): boolean {
  return project.layout_version === 'project-v1' &&
    project.manifest_available &&
    project.source_kind === 'python' &&
    (project.language === 'python' || project.language === 'mixed') &&
    (project.status === 'complete' || project.status === 'partial')
}

function analysisActive(run: CAnalysisRun | undefined): boolean {
  return Boolean(run && ['queued', 'running', 'cancel_requested'].includes(run.status))
}

function javaAnalysisActive(run: JavaAnalysisRun | undefined): boolean {
  return Boolean(run && ['queued', 'running', 'cancel_requested'].includes(run.status))
}

function pythonAnalysisActive(run: PythonAnalysisRun | undefined): boolean {
  return Boolean(run && ['queued', 'running', 'cancel_requested'].includes(run.status))
}

function sourceLabel(project: DecompileProject): string {
  return sourceKindLabels[project.source_kind]
}

function engineLabel(project: DecompileProject): string {
  return [project.engine_name, project.engine_version].filter(Boolean).join(' ')
}
</script>

<template>
  <div class="project-table" role="table" aria-label="反编译源码项目版本">
    <div class="project-table__header" role="row">
      <span role="columnheader">版本标识</span>
      <span role="columnheader">目标文件</span>
      <span role="columnheader">源码</span>
      <span role="columnheader">引擎</span>
      <span role="columnheader">状态</span>
      <span role="columnheader">规模</span>
      <span role="columnheader">完成时间</span>
      <span role="columnheader">操作</span>
    </div>

    <div
      v-for="project in projects"
      :key="project.id"
      class="project-row"
      role="row"
      :data-project-id="project.id"
    >
      <div class="project-version" role="cell" data-label="版本标识">
        <code :title="project.id">{{ project.id }}</code>
        <small>{{ project.layout_version === 'legacy-v1' ? '旧布局' : '独立目录' }}</small>
      </div>
      <div class="project-target" role="cell" data-label="目标文件">
        <strong :title="project.target_path">{{ project.target_path }}</strong>
        <code>{{ project.file_node_id }}</code>
      </div>
      <div role="cell" data-label="源码">
        <strong class="source-kind">{{ sourceLabel(project) }}</strong>
        <small class="secondary">{{ project.language }}</small>
      </div>
      <div role="cell" data-label="引擎">
        <span class="engine" :title="engineLabel(project)">
          {{ engineLabel(project) }}
        </span>
      </div>
      <div role="cell" data-label="状态">
        <span class="project-status" :class="`project-status--${project.status}`">
          {{ statusLabels[project.status] }}
        </span>
        <small v-if="supportsCAnalysis(project)" class="analysis-status">
          C 检测：{{ latestCAnalysisByProject[project.id]
            ? analysisStatusLabels[latestCAnalysisByProject[project.id]!.status]
            : '未执行' }}
        </small>
        <small v-else-if="supportsJavaAnalysis(project)" class="analysis-status">
          Java 检测：{{ latestJavaAnalysisByProject[project.id]
            ? javaAnalysisStatusLabels[latestJavaAnalysisByProject[project.id]!.status]
            : '未执行' }}
        </small>
        <small v-else-if="supportsPythonAnalysis(project)" class="analysis-status">
          Python 检测：{{ latestPythonAnalysisByProject[project.id]
            ? pythonAnalysisStatusLabels[latestPythonAnalysisByProject[project.id]!.status]
            : '未执行' }}
        </small>
        <small v-else class="analysis-status">
          源码检测：不适用
        </small>
      </div>
      <div class="project-scale" role="cell" data-label="规模">
        <span>{{ project.source_file_count }} 文件</span>
        <small>{{ project.symbol_count }} 符号 · {{ formatBytes(project.source_size_bytes) }}</small>
      </div>
      <time
        role="cell"
        data-label="完成时间"
        :datetime="project.completed_at || project.created_at"
      >
        {{ formatDateTime(project.completed_at || project.created_at) }}
      </time>
      <div class="project-actions" role="cell" data-label="操作">
        <button
          v-if="canAnalyze && supportsCAnalysis(project)"
          type="button"
          title="对该源码项目执行 C 检测"
          :aria-label="`对源码项目 ${project.id} 执行 C 检测`"
          :disabled="
            analysisActive(latestCAnalysisByProject[project.id]) ||
              Boolean(deletingProjectId) ||
              Boolean(downloadingProjectId)
          "
          @click="$emit('analyze', project)"
        >
          <ScanSearch :size="14" aria-hidden="true" />
        </button>
        <button
          v-if="canAnalyze && supportsJavaAnalysis(project)"
          type="button"
          title="对该源码项目执行 Java 检测"
          :aria-label="`对源码项目 ${project.id} 执行 Java 检测`"
          :disabled="
            javaAnalysisActive(latestJavaAnalysisByProject[project.id]) ||
              Boolean(deletingProjectId) ||
              Boolean(downloadingProjectId)
          "
          @click="$emit('analyzeJava', project)"
        >
          <FileCode2 :size="14" aria-hidden="true" />
        </button>
        <button
          v-if="canAnalyze && supportsPythonAnalysis(project)"
          type="button"
          title="对该源码项目执行 Python 检测"
          :aria-label="`对源码项目 ${project.id} 执行 Python 检测`"
          :disabled="
            pythonAnalysisActive(latestPythonAnalysisByProject[project.id]) ||
              Boolean(deletingProjectId) ||
              Boolean(downloadingProjectId)
          "
          @click="$emit('analyzePython', project)"
        >
          <FileCode2 :size="14" aria-hidden="true" />
        </button>
        <button
          type="button"
          title="下载源码项目"
          :aria-label="`下载源码项目 ${project.id}`"
          :aria-busy="downloadingProjectId === project.id"
          :disabled="Boolean(downloadingProjectId) || deletingProjectId === project.id"
          @click="$emit('download', project)"
        >
          <LoaderCircle
            v-if="downloadingProjectId === project.id"
            class="spin"
            :size="14"
            aria-hidden="true"
          />
          <Download v-else :size="14" aria-hidden="true" />
        </button>
        <button
          v-if="canDelete"
          type="button"
          class="project-actions__delete"
          title="删除源码项目版本"
          :aria-label="`删除源码项目版本 ${project.id}`"
          :aria-busy="deletingProjectId === project.id"
          :disabled="Boolean(deletingProjectId) || downloadingProjectId === project.id"
          @click="$emit('delete', project)"
        >
          <LoaderCircle
            v-if="deletingProjectId === project.id"
            class="spin"
            :size="14"
            aria-hidden="true"
          />
          <Trash2 v-else :size="14" aria-hidden="true" />
        </button>
      </div>
    </div>
  </div>

  <footer v-if="hasMore" class="load-more">
    <el-button :loading="loadingMore" :disabled="loadingMore" @click="$emit('loadMore')">
      加载更多版本
    </el-button>
  </footer>
</template>

<style scoped>
.project-table__header,
.project-row {
  display: grid;
  min-width: 0;
  grid-template-columns:
    minmax(180px, 1.2fr) minmax(170px, 1.1fr) minmax(90px, 0.58fr)
    minmax(110px, 0.7fr) minmax(82px, 0.5fr) minmax(112px, 0.66fr)
    minmax(132px, 0.72fr) 104px;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
}

.project-table__header {
  color: var(--ink-600);
  background: #f3f6f6;
  font-size: 9px;
  font-weight: 700;
}

.project-row {
  min-height: 68px;
  border-top: 1px solid #e7ebeb;
  color: var(--ink-600);
  font-size: 10px;
}

.project-row > * {
  min-width: 0;
}

.project-version code,
.project-target strong,
.project-target code,
.project-scale span,
.project-scale small,
.secondary {
  display: block;
}

.project-version code {
  overflow: hidden;
  color: var(--ink-800);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.project-version small,
.secondary,
.project-target code,
.project-scale small {
  margin-top: 3px;
  color: var(--ink-400);
  font-size: 8px;
}

.project-target strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.project-target code {
  overflow: hidden;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.source-kind {
  color: var(--ink-800);
  font-size: 10px;
}

.engine {
  display: block;
  overflow: hidden;
  color: var(--ink-800);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.project-status {
  display: inline-flex;
  min-height: 22px;
  align-items: center;
  padding: 2px 6px;
  border: 1px solid #b8d7d3;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #f1f8f7;
  white-space: nowrap;
}

.project-status--partial,
.project-status--bytecode_only {
  border-color: #decba7;
  color: var(--amber);
  background: #fff9ef;
}

.analysis-status {
  display: block;
  margin-top: 4px;
  color: var(--ink-400);
  font-size: 8px;
  white-space: nowrap;
}

.project-scale span {
  color: var(--ink-800);
}

.project-actions {
  display: flex;
  gap: 5px;
}

.project-actions button {
  display: inline-grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-600);
  background: var(--surface);
  cursor: pointer;
}

.project-actions button:hover:not(:disabled) {
  border-color: var(--teal);
  color: var(--teal-strong);
}

.project-actions .project-actions__delete:hover:not(:disabled) {
  border-color: var(--red);
  color: var(--red);
}

.project-actions button:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.load-more {
  display: grid;
  place-items: center;
  padding: 10px;
  border-top: 1px solid var(--line);
}

.spin {
  animation: project-spin 1s linear infinite;
}

@keyframes project-spin {
  to {
    transform: rotate(360deg);
  }
}

@container (max-width: 1060px) {
  .project-table__header {
    display: none;
  }

  .project-row {
    grid-template-columns: minmax(180px, 1fr) minmax(180px, 1fr) repeat(2, minmax(100px, 0.55fr));
    align-items: start;
    padding: 14px 16px;
  }

  .project-row > [role="cell"]::before {
    display: block;
    margin-bottom: 5px;
    color: var(--ink-400);
    content: attr(data-label);
    font-size: 8px;
  }
}

@container (max-width: 640px) {
  .project-row {
    grid-template-columns: 1fr 1fr;
  }
}

@container (max-width: 410px) {
  .project-row {
    grid-template-columns: 1fr;
  }
}

@media (prefers-reduced-motion: reduce) {
  .spin {
    animation: none;
  }
}
</style>
