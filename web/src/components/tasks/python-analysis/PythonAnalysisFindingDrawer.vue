<script setup lang="ts">
import { Code2, ExternalLink, FileCode2, MapPin, ShieldAlert } from 'lucide-vue-next'
import { computed, onBeforeUnmount, onMounted, shallowRef } from 'vue'

import type { PythonAnalysisFinding } from '@/api/types'
import { javaFindingMessage } from '@/utils/analyzerMessages'

const props = defineProps<{
  finding: PythonAnalysisFinding | undefined
}>()

const emit = defineEmits<{
  close: []
  openSource: [resultId: string]
}>()

const MAX_DRAWER_WIDTH = 620
const VIEWPORT_WIDTH_RATIO = 0.92
const drawerSize = shallowRef(MAX_DRAWER_WIDTH)

function updateDrawerSize(): void {
  const viewportWidth =
    document.documentElement.clientWidth || globalThis.innerWidth || MAX_DRAWER_WIDTH
  drawerSize.value = Math.max(
    1,
    Math.min(MAX_DRAWER_WIDTH, Math.floor(viewportWidth * VIEWPORT_WIDTH_RATIO)),
  )
}

onMounted(() => {
  updateDrawerSize()
  globalThis.addEventListener('resize', updateDrawerSize, { passive: true })
})

onBeforeUnmount(() => {
  globalThis.removeEventListener('resize', updateDrawerSize)
})

function handleVisibility(visible: boolean): void {
  if (!visible) emit('close')
}

function locationLabel(finding: PythonAnalysisFinding): string {
  const value = finding.location
  return `${value.start_line}:${value.start_column} - ${value.end_line}:${value.end_column}`
}

interface SnippetLine {
  key: number
  label: string
  labelTitle: string
  text: string
  hit: boolean
}

const snippetLines = computed<readonly SnippetLine[]>(() => {
  const finding = props.finding
  if (!finding?.snippet) return []

  const snippetStartLine = finding.snippet_start_line
  if (!snippetStartLine) return []

  return finding.snippet.split(/\r\n|\n|\r/).map((text, index) => {
    const sourceLine = snippetStartLine + index
    return {
      key: sourceLine,
      label: String(sourceLine),
      labelTitle: `源码第 ${sourceLine} 行`,
      text,
      hit:
        sourceLine >= finding.location.start_line &&
        sourceLine <= finding.location.end_line,
    }
  })
})
</script>

<template>
  <el-drawer
    :model-value="finding !== undefined"
    title="Java 源码检测详情"
    :size="drawerSize"
    append-to-body
    @update:model-value="handleVisibility"
  >
    <article v-if="finding" class="finding-detail">
      <header class="finding-detail__header">
        <span class="severity" :class="`severity--${finding.severity.toLowerCase()}`">
          {{ finding.severity }}
        </span>
        <code>{{ finding.cwe }}</code>
        <code>{{ finding.rule_id }}</code>
      </header>

      <section>
        <h3><ShieldAlert :size="15" aria-hidden="true" />检测结论</h3>
        <p>{{ javaFindingMessage(finding.rule_id, finding.message) }}</p>
      </section>

      <dl>
        <div>
          <dt><FileCode2 :size="13" aria-hidden="true" />文件</dt>
          <dd>
            <strong>{{ finding.file.logical_path }}</strong>
            <code>{{ finding.file.binary_name }}</code>
          </dd>
        </div>
        <div>
          <dt><Code2 :size="13" aria-hidden="true" />类型 / 方法</dt>
          <dd>
            <strong>{{ finding.callable.type_name }}</strong>
            <code>{{ finding.callable.kind }} {{ finding.callable.name }}</code>
            <code v-if="finding.callable.signature">{{ finding.callable.signature }}</code>
          </dd>
        </div>
        <div>
          <dt><MapPin :size="13" aria-hidden="true" />源码位置</dt>
          <dd><code>{{ locationLabel(finding) }}</code></dd>
        </div>
      </dl>

      <section class="snippet-section">
        <div class="snippet-heading">
          <h3><Code2 :size="15" aria-hidden="true" />检测片段</h3>
          <span class="snippet-hit-location">
            <MapPin :size="12" aria-hidden="true" />
            命中 <code>{{ locationLabel(finding) }}</code>
          </span>
        </div>
        <div
          v-if="snippetLines.length > 0"
          class="snippet-code"
          role="region"
          tabindex="0"
          aria-label="Java 源码检测片段"
        >
          <div
            v-for="line in snippetLines"
            :key="line.key"
            class="snippet-line"
            :class="{ 'snippet-line--hit': line.hit }"
            :aria-current="line.hit ? 'location' : false"
          >
            <span class="snippet-gutter" :title="line.labelTitle">{{ line.label }}</span>
            <code>{{ line.text }}</code>
          </div>
        </div>
        <p v-else class="snippet-empty">该发现没有保存源码片段。</p>
      </section>

      <el-button
        type="primary"
        plain
        @click="emit('openSource', finding.file.result_id)"
      >
        <ExternalLink :size="14" aria-hidden="true" />
        打开 Java 源码
      </el-button>
    </article>
  </el-drawer>
</template>

<style scoped>
.finding-detail { display: grid; gap: 18px; color: var(--ink-600); }
.finding-detail__header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
.finding-detail__header code { color: var(--ink-800); font-size: 10px; }
.finding-detail section { display: grid; gap: 8px; }
.finding-detail h3 { display: flex; align-items: center; gap: 7px; margin: 0; color: var(--ink-800); font-size: 12px; }
.finding-detail p { margin: 0; line-height: 1.7; font-size: 11px; }
.finding-detail dl { margin: 0; border: 1px solid var(--line); border-radius: 4px; }
.finding-detail dl div { display: grid; grid-template-columns: 105px minmax(0, 1fr); gap: 12px; padding: 10px 12px; border-bottom: 1px solid var(--line); }
.finding-detail dl div:last-child { border-bottom: 0; }
.finding-detail dt { display: flex; align-items: center; gap: 6px; font-size: 9px; }
.finding-detail dd { display: grid; min-width: 0; gap: 3px; margin: 0; color: var(--ink-800); font-size: 10px; }
.finding-detail dd code { overflow-wrap: anywhere; }
.snippet-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
.snippet-hit-location { display: inline-flex; align-items: center; gap: 5px; color: var(--ink-500); font-size: 9px; }
.snippet-hit-location code { color: var(--ink-800); font-size: 9px; }
.snippet-code { max-height: 340px; overflow: auto; border: 1px solid #344549; border-radius: 4px; color: #d9e5e3; background: #172427; font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; font-size: 10px; line-height: 1.65; }
.snippet-line { display: grid; min-width: max-content; grid-template-columns: 48px minmax(0, 1fr); }
.snippet-line code { display: block; min-height: 1.65em; padding: 2px 14px; color: inherit; white-space: pre; }
.snippet-line--hit { background: #263d3c; box-shadow: inset 3px 0 #62b7ad; }
.snippet-line--hit code { color: #f2fbf9; }
.snippet-gutter { display: block; padding: 2px 9px; border-right: 1px solid #344549; color: #77908e; text-align: right; user-select: none; }
.snippet-line--hit .snippet-gutter { color: #9edbd4; }
.snippet-empty { margin: 0; padding: 14px; border: 1px solid #344549; border-radius: 4px; color: #aabbb9; background: #172427; font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace; font-size: 10px; }
.severity { display: inline-flex; min-height: 23px; align-items: center; padding: 2px 7px; border: 1px solid var(--line-strong); border-radius: 3px; font-size: 8px; font-weight: 800; }
.severity--critical { border-color: #ce9599; color: #8f252d; background: #fff1f2; }
.severity--high { border-color: #d9a18c; color: #9a4428; background: #fff4ef; }
.severity--medium { border-color: #dcc18b; color: #815c13; background: #fff9eb; }
.severity--low { border-color: #9dc5d1; color: #28697b; background: #f0f9fb; }
</style>
