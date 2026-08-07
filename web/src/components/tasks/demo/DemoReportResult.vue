<script setup lang="ts">
import {
  Braces,
  Download,
  FileCode2,
  FileJson2,
  Gauge,
  ListTree,
  LockKeyhole,
} from 'lucide-vue-next'
import { computed, type Component } from 'vue'

import {
  DEMO_REPORT_ARTIFACTS,
  DEMO_HTML_REPORT_SECTIONS,
  type DemoReportArtifact,
} from '@/components/tasks/demo/demoResultFixtures'
import DemoPreviewNotice from '@/components/tasks/demo/DemoPreviewNotice.vue'

const props = defineProps<{
  taskId: string
  taskName: string
  inputType: string
  taskStatus: string
}>()

const artifactIcons: Readonly<Record<DemoReportArtifact['format'], Component>> = {
  JSON: FileJson2,
  HTML: FileCode2,
}

const taskSnapshot = computed(() => [
  { label: '任务名称', value: props.taskName },
  { label: '任务编号', value: props.taskId, mono: true },
  { label: '输入格式', value: props.inputType },
  { label: '任务状态', value: props.taskStatus },
])

interface DemoJsonReportPreview {
  schema: string
  task: {
    id: string
    name: string
    input_type: string
    status: string
  }
  summary: {
    files_indexed: number
    decompile_view: string
    vulnerability_records: number
  }
  limitations: readonly string[]
}

const jsonPreview = computed<DemoJsonReportPreview>(() => ({
  schema: 'binaryscan.demo.report/v1',
  task: {
    id: props.taskId,
    name: props.taskName,
    input_type: props.inputType,
    status: props.taskStatus,
  },
  summary: {
    files_indexed: 128,
    decompile_view: 'fixed-demo-only',
    vulnerability_records: 6,
  },
  limitations: [
    'fixed example data',
    'no backend report generated',
  ],
}))
const jsonPreviewText = computed(() => JSON.stringify(jsonPreview.value, null, 2))

const limitSnapshot = [
  { label: '单文件上限', value: '10 GB' },
  { label: '解包后上限', value: '50 GB' },
  { label: '嵌套深度', value: '10 层' },
  { label: '文件数量', value: '20,000' },
  { label: '膨胀比', value: '100 倍' },
  { label: '样本保留', value: '15 天' },
] as const
</script>

<template>
  <div class="report-preview">
    <DemoPreviewNotice subject="报告" />

    <section class="artifact-section" aria-labelledby="demo-artifacts-title">
      <header class="section-heading">
        <div>
          <FileJson2 :size="16" aria-hidden="true" />
          <h3 id="demo-artifacts-title">报告产物示例</h3>
        </div>
        <span>JSON + HTML</span>
      </header>
      <div class="artifact-list">
        <article
          v-for="artifact in DEMO_REPORT_ARTIFACTS"
          :key="artifact.format"
          class="artifact-row"
        >
          <component
            :is="artifactIcons[artifact.format]"
            class="artifact-row__icon"
            :size="19"
            aria-hidden="true"
          />
          <div class="artifact-row__identity">
            <strong>{{ artifact.filename }}</strong>
            <span>{{ artifact.description }}</span>
          </div>
          <div class="artifact-row__meta">
            <span>{{ artifact.format }}</span>
            <code>{{ artifact.size }}</code>
            <span class="artifact-row__ready">示例就绪</span>
          </div>
          <button
            class="artifact-row__download"
            type="button"
            disabled
            :aria-label="`下载 ${artifact.format} 报告（后端未接入）`"
            title="界面预览中不执行下载，后端接入后启用"
          >
            <Download :size="15" aria-hidden="true" />
          </button>
        </article>
      </div>
    </section>

    <section class="document-preview-section" aria-labelledby="demo-document-preview-title">
      <header class="section-heading">
        <div>
          <Braces :size="16" aria-hidden="true" />
          <h3 id="demo-document-preview-title">报告内容预览</h3>
        </div>
        <span>固定结构 · 只读</span>
      </header>

      <div class="document-preview-grid">
        <article class="document-preview document-preview--json">
          <header class="document-preview__heading">
            <span>
              <FileJson2 :size="15" aria-hidden="true" />
              <strong>JSON 结构</strong>
            </span>
            <code>application/json</code>
          </header>
          <pre
            class="json-preview"
            tabindex="0"
            aria-label="只读 JSON 报告固定结构预览"
          ><code>{{ jsonPreviewText }}</code></pre>
        </article>

        <article class="document-preview document-preview--html">
          <header class="document-preview__heading">
            <span>
              <ListTree :size="15" aria-hidden="true" />
              <strong>HTML 报告目录</strong>
            </span>
            <code>text/html</code>
          </header>
          <nav class="html-toc" aria-label="HTML 报告固定目录预览">
            <ol>
              <li
                v-for="section in DEMO_HTML_REPORT_SECTIONS"
                :key="section.id"
                :data-report-section="section.id"
              >
                <span class="html-toc__number">{{ section.number }}</span>
                <span class="html-toc__content">
                  <strong>{{ section.title }}</strong>
                  <small>{{ section.summary }}</small>
                </span>
              </li>
            </ol>
          </nav>
          <footer class="html-toc__footnote">
            目录用于展示离线 HTML 报告的信息层级，不生成页面或执行跳转。
          </footer>
        </article>
      </div>
    </section>

    <div class="snapshot-grid">
      <section class="snapshot-section" aria-labelledby="demo-task-snapshot-title">
        <header class="section-heading">
          <div>
            <LockKeyhole :size="16" aria-hidden="true" />
            <h3 id="demo-task-snapshot-title">任务快照</h3>
          </div>
          <span>写入报告头</span>
        </header>
        <dl class="snapshot-list">
          <div v-for="item in taskSnapshot" :key="item.label">
            <dt>{{ item.label }}</dt>
            <dd :class="{ mono: item.mono }" :title="item.value">{{ item.value }}</dd>
          </div>
        </dl>
      </section>

      <section class="snapshot-section" aria-labelledby="demo-limit-snapshot-title">
        <header class="section-heading">
          <div>
            <Gauge :size="16" aria-hidden="true" />
            <h3 id="demo-limit-snapshot-title">安全限制快照</h3>
          </div>
          <span>随报告固化</span>
        </header>
        <dl class="limit-grid">
          <div v-for="item in limitSnapshot" :key="item.label">
            <dt>{{ item.label }}</dt>
            <dd>{{ item.value }}</dd>
          </div>
        </dl>
      </section>
    </div>

    <footer class="report-footnote">
      下载控件保持禁用；界面预览不会生成、写入或导出任何报告文件。
    </footer>
  </div>
</template>

<style scoped>
.report-preview {
  min-width: 0;
}

.artifact-section,
.document-preview-section,
.snapshot-section {
  min-width: 0;
}

.artifact-section,
.document-preview-section {
  border-bottom: 1px solid var(--line);
}

.section-heading {
  display: flex;
  min-height: 46px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--line);
  background: #f8fafa;
}

.section-heading > div {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  color: var(--teal-strong);
}

.section-heading h3 {
  margin: 0;
  color: var(--ink-800);
  font-size: 11px;
}

.section-heading > span {
  color: var(--ink-600);
  font-size: 9px;
  white-space: nowrap;
}

.artifact-list {
  display: grid;
}

.artifact-row {
  display: grid;
  min-width: 0;
  min-height: 72px;
  grid-template-columns: 28px minmax(240px, 1fr) auto 34px;
  align-items: center;
  gap: 11px;
  padding: 11px 14px;
  border-bottom: 1px solid #e5e9ea;
}

.artifact-row:last-child {
  border-bottom: 0;
}

.artifact-row__icon {
  color: var(--teal);
}

.artifact-row__identity {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.artifact-row__identity strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.artifact-row__identity span {
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.5;
}

.artifact-row__meta {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 7px;
  color: var(--ink-600);
  font-size: 9px;
}

.artifact-row__meta code {
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.artifact-row__meta > span:first-child,
.artifact-row__ready {
  padding: 2px 5px;
  border: 1px solid var(--line);
  border-radius: 3px;
  font-size: 8px;
  font-weight: 700;
}

.artifact-row__ready {
  border-color: #b8d7d3;
  color: #076860;
  background: #f1f8f7;
}

.artifact-row__download {
  display: inline-flex;
  width: 32px;
  height: 32px;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: 1px solid var(--line);
  border-radius: 4px;
  color: #a4adaf;
  background: #f2f4f4;
  cursor: not-allowed;
}

.document-preview-grid {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(0, 1.05fr) minmax(280px, 0.95fr);
}

.document-preview {
  min-width: 0;
}

.document-preview:first-child {
  border-right: 1px solid var(--line);
}

.document-preview__heading {
  display: flex;
  min-height: 40px;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 7px 12px;
  border-bottom: 1px solid var(--line);
  background: #fbfcfc;
}

.document-preview__heading > span {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--teal-strong);
}

.document-preview__heading strong {
  color: var(--ink-800);
  font-size: 10px;
}

.document-preview__heading code {
  color: var(--ink-600);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
}

.json-preview {
  min-width: 0;
  height: 292px;
  margin: 0;
  overflow: auto;
  padding: 14px;
  color: #d8e7e7;
  background: #172427;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
  line-height: 1.65;
  tab-size: 2;
}

.json-preview:focus-visible {
  outline: 2px solid #58a9cf;
  outline-offset: -3px;
}

.html-toc {
  min-width: 0;
}

.html-toc ol {
  display: grid;
  margin: 0;
  padding: 0;
  list-style: none;
}

.html-toc li {
  display: grid;
  min-width: 0;
  min-height: 60px;
  grid-template-columns: 34px minmax(0, 1fr);
  align-items: center;
  gap: 9px;
  padding: 8px 12px;
  border-bottom: 1px solid #e5e9ea;
}

.html-toc__number {
  color: var(--teal);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 13px;
  font-weight: 700;
}

.html-toc__content {
  display: grid;
  min-width: 0;
  gap: 4px;
}

.html-toc__content strong {
  color: var(--ink-800);
  font-size: 10px;
}

.html-toc__content small {
  color: var(--ink-600);
  font-size: 8px;
  line-height: 1.45;
}

.html-toc__footnote {
  min-height: 52px;
  padding: 10px 12px;
  color: var(--ink-600);
  background: #f8fafa;
  font-size: 8px;
  line-height: 1.55;
}

.snapshot-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
}

.snapshot-section:first-child {
  border-right: 1px solid var(--line);
}

.snapshot-list {
  margin: 0;
}

.snapshot-list > div {
  display: grid;
  min-height: 42px;
  grid-template-columns: 92px minmax(0, 1fr);
  align-items: center;
  padding: 7px 14px;
  border-bottom: 1px solid #e5e9ea;
}

.snapshot-list > div:last-child {
  border-bottom: 0;
}

.snapshot-list dt,
.limit-grid dt {
  color: var(--ink-600);
  font-size: 9px;
}

.snapshot-list dd {
  min-width: 0;
  margin: 0;
  overflow: hidden;
  color: var(--ink-800);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.limit-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  margin: 0;
}

.limit-grid > div {
  display: flex;
  min-width: 0;
  min-height: 84px;
  align-items: flex-start;
  justify-content: center;
  flex-direction: column;
  gap: 6px;
  padding: 12px 14px;
  border-right: 1px solid #e5e9ea;
  border-bottom: 1px solid #e5e9ea;
}

.limit-grid > div:nth-child(3n) {
  border-right: 0;
}

.limit-grid > div:nth-last-child(-n + 3) {
  border-bottom: 0;
}

.limit-grid dd {
  margin: 0;
  color: var(--ink-800);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 14px;
  font-weight: 700;
  white-space: nowrap;
}

.report-footnote {
  min-height: 38px;
  padding: 10px 14px;
  border-top: 1px solid var(--line);
  color: var(--ink-600);
  background: #f8fafa;
  font-size: 9px;
  line-height: 1.5;
}

@media (max-width: 760px) {
  .artifact-row {
    grid-template-columns: 24px minmax(0, 1fr) 34px;
  }

  .artifact-row__meta {
    grid-column: 2 / -1;
    grid-row: 2;
    justify-content: flex-start;
    flex-wrap: wrap;
  }

  .artifact-row__download {
    grid-column: 3;
    grid-row: 1;
  }

  .snapshot-grid {
    grid-template-columns: 1fr;
  }

  .document-preview-grid {
    grid-template-columns: 1fr;
  }

  .document-preview:first-child {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }

  .snapshot-section:first-child {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }
}

@media (max-width: 480px) {
  .document-preview__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .json-preview {
    height: 260px;
    padding: 12px 10px;
    font-size: 8px;
  }

  .limit-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  .limit-grid > div:nth-child(3n) {
    border-right: 1px solid #e5e9ea;
  }

  .limit-grid > div:nth-child(2n) {
    border-right: 0;
  }

  .limit-grid > div:nth-last-child(3) {
    border-bottom: 1px solid #e5e9ea;
  }
}
</style>
