<script setup lang="ts">
import {
  Box,
  Braces,
  ChevronDown,
  Code2,
  FileCode2,
  ListTree,
  LoaderCircle,
  Search,
  TriangleAlert,
} from 'lucide-vue-next'
import { computed, shallowRef, watch, type Component } from 'vue'

import type {
  DecompileResult,
  DecompileSymbolKind,
  JsonValue,
} from '@/api/types'
import ReadOnlyCodeEditor from '@/components/code-editor/ReadOnlyCodeEditor.vue'
import type { ReadOnlyCodeLanguage } from '@/components/code-editor/monacoLoader'
import BytecodeAnalyzerSummary from '@/components/tasks/results/BytecodeAnalyzerSummary.vue'
import BytecodeMethodIndexPanel from '@/components/tasks/results/BytecodeMethodIndexPanel.vue'
import { parseAnalyzerSummary } from '@/components/tasks/results/analyzerSummary'
import { neutralizeUnsafeDisplayCharacters } from '@/components/tasks/results/displayText'
import { parseBytecodeMethodIndex } from '@/components/tasks/results/jvmMethodIndex'

const props = defineProps<{
  taskId: string
  items: readonly DecompileResult[]
  selectedId: string
  source: string
  sourceLoading: boolean
  sourceError: string
  hasMoreResults: boolean
  loadingMoreResults: boolean
  hasMoreSource: boolean
}>()

const emit = defineEmits<{
  select: [resultId: string]
  loadMoreResults: []
  loadMoreSource: []
}>()

interface ResultGroup {
  name: string
  items: readonly DecompileResult[]
}

type ResultFilter = 'all' | 'source' | 'bytecode' | 'issues'
const MAX_DIAGNOSTIC_PREVIEW_LENGTH = 4_096

const query = shallowRef('')
const resultFilter = shallowRef<ResultFilter>('all')
const selectedBytecodeMethodKey = shallowRef('')
const normalizedQuery = computed(() =>
  query.value.trim().toLocaleLowerCase('zh-CN'),
)
const selectedResult = computed(() =>
  props.items.find((item) => item.id === props.selectedId),
)
const isJvmBytecodeResult = computed(() => {
  const language = selectedResult.value?.language.trim().toLocaleLowerCase('en-US') ?? ''
  return language.includes('java') && language.includes('bytecode')
})
const bytecodeMethodIndex = computed(() =>
  parseBytecodeMethodIndex(selectedResult.value?.diagnostics),
)
const analyzerSummary = computed(() =>
  parseAnalyzerSummary(selectedResult.value?.diagnostics),
)
const activeBytecodeMethodKey = computed(() => {
  const methods = bytecodeMethodIndex.value.methods
  return methods.some((method) => method.key === selectedBytecodeMethodKey.value)
    ? selectedBytecodeMethodKey.value
    : methods[0]?.key ?? ''
})
const filterCounts = computed<Record<ResultFilter, number>>(() => ({
  all: props.items.length,
  source: props.items.filter((item) =>
    item.status === 'complete' || item.status === 'partial',
  ).length,
  bytecode: props.items.filter((item) => item.status === 'bytecode_only').length,
  issues: props.items.filter((item) =>
    ['unsupported', 'failed', 'cancelled'].includes(item.status),
  ).length,
}))
const filteredItems = computed(() => {
  const statusFiltered = props.items.filter((item) =>
    matchesResultFilter(item, resultFilter.value),
  )
  if (!normalizedQuery.value) return statusFiltered
  return statusFiltered.filter((item) => {
    const searchable = [
      item.display_name,
      item.group_name,
      item.location,
      item.signature,
      item.detail,
      item.language,
      item.engine_name,
      item.symbol_key,
      item.id === props.selectedId ? props.source : '',
    ]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
    return searchable.includes(normalizedQuery.value)
  })
})
const groupedItems = computed<readonly ResultGroup[]>(() => {
  const groups = new Map<string, DecompileResult[]>()
  filteredItems.value.forEach((item) => {
    const groupName = item.group_name || '未分组符号'
    const group = groups.get(groupName) ?? []
    group.push(item)
    groups.set(groupName, group)
  })
  return [...groups].map(([name, items]) => ({ name, items }))
})
const sourceMatchCount = computed(() => {
  if (!normalizedQuery.value || !props.source) return 0
  const escaped = normalizedQuery.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return (
    props.source
      .toLocaleLowerCase('zh-CN')
      .match(new RegExp(escaped, 'g'))?.length ?? 0
  )
})
const editorLanguage = computed<ReadOnlyCodeLanguage>(() => {
  const language = selectedResult.value?.language.trim().toLowerCase() ?? ''
  if (language.includes('java') && language.includes('bytecode')) {
    return 'jvm-bytecode'
  }
  if (language.includes('java')) return 'java'
  if (language.includes('smali') || language.includes('dex')) return 'smali'
  if (language.includes('pyc') || language.includes('bytecode')) {
    return 'python-bytecode'
  }
  return 'c'
})
const languageLabel = computed(() => {
  const language = selectedResult.value?.language.trim()
  if (!language) return '反编译文本'
  const normalized = language.toLowerCase()
  if (normalized.includes('java') && normalized.includes('bytecode')) {
    return 'JVM 字节码索引'
  }
  if (normalized.includes('smali') || normalized.includes('dex')) return 'Smali'
  if (normalized.includes('pyc') || normalized.includes('python')) {
    return 'Python 字节码'
  }
  if (normalized.includes('java')) return 'Java 形态'
  if (normalized.includes('c')) return '伪 C'
  return language
})
const capabilityMessage = computed(() => {
  const result = selectedResult.value
  if (!result) return ''
  switch (result.status) {
    case 'partial':
      return '分析器仅生成部分输出；符号、类型或控制流可能缺失。'
    case 'bytecode_only':
      return '能力已降级为字节码视图，未恢复为高层语言。'
    case 'unsupported':
      return '当前分析器不支持该符号或输入格式。'
    case 'failed':
      return '分析器处理失败，请结合诊断信息定位原因。'
    case 'cancelled':
      return '反编译任务已取消，已完成的输出仍可阅读。'
    case 'queued':
      return '该反编译单元正在排队，暂时没有源码输出。'
    case 'running':
      return '该反编译单元仍在处理中，结果可能继续更新。'
    default:
      return '反编译输出不是原始源码；变量名、类型、注释和控制流可能失真。'
  }
})
const diagnosticMessage = computed(() =>
  diagnosticText(selectedResult.value?.diagnostics),
)

watch(
  () => props.selectedId,
  () => {
    selectedBytecodeMethodKey.value = ''
  },
)

const unitIcons: Readonly<Record<DecompileSymbolKind, Component>> = {
  function: Braces,
  class: Box,
  method: Code2,
  module: FileCode2,
  unknown: FileCode2,
}

const unitLabels: Readonly<Record<DecompileSymbolKind, string>> = {
  function: '函数',
  class: '类',
  method: '方法',
  module: '模块',
  unknown: '符号',
}

const resultFilters: readonly {
  value: ResultFilter
  label: string
  icon: Component
}[] = [
  { value: 'all', label: '全部', icon: ListTree },
  { value: 'source', label: '源码形态', icon: FileCode2 },
  { value: 'bytecode', label: '仅字节码', icon: Code2 },
  { value: 'issues', label: '异常', icon: TriangleAlert },
]

function diagnosticText(value: JsonValue | undefined): string {
  if (typeof value === 'string') return diagnosticPreview(value)
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ''
  const record = value as Readonly<Record<string, JsonValue>>
  for (const key of ['message', 'warning', 'limitation', 'detail']) {
    const candidate = record[key]
    if (typeof candidate === 'string' && candidate.trim()) {
      return diagnosticPreview(candidate)
    }
  }
  return ''
}

function diagnosticPreview(value: string): string {
  const truncated = value.length > MAX_DIAGNOSTIC_PREVIEW_LENGTH
  const safeValue = neutralizeUnsafeDisplayCharacters(
    value.slice(0, MAX_DIAGNOSTIC_PREVIEW_LENGTH),
  ).trim()
  return truncated && safeValue ? `${safeValue}...` : safeValue
}

function matchesResultFilter(
  item: DecompileResult,
  filter: ResultFilter,
): boolean {
  switch (filter) {
    case 'source':
      return item.status === 'complete' || item.status === 'partial'
    case 'bytecode':
      return item.status === 'bytecode_only'
    case 'issues':
      return ['unsupported', 'failed', 'cancelled'].includes(item.status)
    default:
      return true
  }
}

function selectFilter(filter: ResultFilter): void {
  resultFilter.value = filter
  const selected = selectedResult.value
  if (selected && matchesResultFilter(selected, filter)) return
  const firstVisible = props.items.find((item) => matchesResultFilter(item, filter))
  if (firstVisible) emit('select', firstVisible.id)
}

function selectBytecodeMethod(methodKey: string): void {
  selectedBytecodeMethodKey.value = methodKey
}
</script>

<template>
  <div class="decompile-workspace">
    <section class="capability-strip" aria-labelledby="capability-title">
      <div class="capability-strip__identity">
        <Code2 :size="17" aria-hidden="true" />
        <span>
          <small id="capability-title">反编译能力</small>
          <strong>{{ languageLabel }}</strong>
        </span>
      </div>
      <p>{{ capabilityMessage }}</p>
      <span
        v-if="selectedResult"
        class="capability-strip__engine"
        :class="`capability-strip__engine--${selectedResult.status}`"
      >
        {{ selectedResult.engine_name || '未知引擎' }}
        {{ selectedResult.engine_version }}
        · {{ selectedResult.status }}
      </span>
    </section>

    <div
      v-if="diagnosticMessage"
      class="capability-warning"
      role="note"
    >
      <TriangleAlert :size="16" aria-hidden="true" />
      <strong>分析器诊断</strong>
      <span>{{ diagnosticMessage }}</span>
    </div>

    <div class="decompile-workspace__body">
      <aside class="symbol-panel" aria-label="反编译符号列表">
        <div class="symbol-panel__heading">
          <div>
            <strong>函数 / 类 / 方法</strong>
            <span>{{ filteredItems.length }} / {{ items.length }}</span>
          </div>
          <label class="symbol-search">
            <span class="sr-only">搜索已加载的名称、签名或代码</span>
            <Search :size="14" aria-hidden="true" />
            <input
              v-model="query"
              type="search"
              autocomplete="off"
              placeholder="搜索已加载的名称、签名或代码"
            >
          </label>
          <div class="result-filters" role="group" aria-label="按反编译能力筛选">
            <button
              v-for="filter in resultFilters"
              :key="filter.value"
              type="button"
              :class="{ 'result-filter--active': resultFilter === filter.value }"
              :aria-pressed="resultFilter === filter.value"
              @click="selectFilter(filter.value)"
            >
              <component :is="filter.icon" :size="12" aria-hidden="true" />
              <span>{{ filter.label }}</span>
              <code>{{ filterCounts[filter.value] }}</code>
            </button>
          </div>
        </div>

        <div
          v-if="groupedItems.length"
          class="symbol-tree"
          role="tree"
          aria-label="反编译符号"
        >
          <section
            v-for="group in groupedItems"
            :key="group.name"
            class="symbol-group"
            role="group"
            :aria-label="group.name"
          >
            <h4>{{ group.name }}</h4>
            <button
              v-for="item in group.items"
              :key="item.id"
              class="symbol-row"
              :class="{ 'symbol-row--active': selectedId === item.id }"
              type="button"
              role="treeitem"
              :aria-selected="selectedId === item.id"
              @click="emit('select', item.id)"
            >
              <component
                :is="unitIcons[item.symbol_kind] ?? FileCode2"
                :size="14"
                aria-hidden="true"
              />
              <span class="symbol-row__main">
                <strong>{{ item.display_name || item.symbol_key }}</strong>
                <small class="mono">{{ item.location || '位置未知' }}</small>
              </span>
              <span class="symbol-row__kind">
                {{ unitLabels[item.symbol_kind] ?? '符号' }}
              </span>
            </button>
          </section>
        </div>
        <div v-else class="symbol-panel__empty" role="status">
          没有匹配的函数、类、方法或已加载代码
        </div>
        <button
          v-if="hasMoreResults"
          class="load-more"
          type="button"
          :disabled="loadingMoreResults"
          :aria-busy="loadingMoreResults"
          @click="emit('loadMoreResults')"
        >
          <LoaderCircle
            v-if="loadingMoreResults"
            class="spin"
            :size="14"
            aria-hidden="true"
          />
          <ChevronDown v-else :size="14" aria-hidden="true" />
          加载更多符号
        </button>
      </aside>

      <section class="code-panel" aria-label="只读反编译输出">
        <template v-if="selectedResult">
          <header class="code-panel__heading">
            <div class="code-panel__title">
              <span>
                <strong>
                  {{ selectedResult.display_name || selectedResult.symbol_key }}
                </strong>
                <small>
                  {{ unitLabels[selectedResult.symbol_kind] ?? '符号' }}
                </small>
              </span>
              <code>{{ selectedResult.signature || '签名不可用' }}</code>
            </div>
            <div class="code-panel__badges" aria-label="代码属性">
              <span>{{ languageLabel }}</span>
              <span>只读</span>
              <span>非原始源码</span>
            </div>
          </header>

          <div class="code-panel__meta">
            <span>位置 <code>{{ selectedResult.location || '未知' }}</code></span>
            <span>{{ selectedResult.detail || '无附加符号信息' }}</span>
            <span v-if="normalizedQuery" aria-live="polite">
              已加载代码命中 <code>{{ sourceMatchCount }}</code> 处
            </span>
            <span class="mono">task: {{ taskId }}</span>
          </div>

          <BytecodeAnalyzerSummary
            v-if="analyzerSummary.present"
            :summary="analyzerSummary"
          />

          <BytecodeMethodIndexPanel
            v-if="isJvmBytecodeResult && bytecodeMethodIndex.present"
            :key="selectedResult.id"
            :index="bytecodeMethodIndex"
            :selected-key="activeBytecodeMethodKey"
            @select="selectBytecodeMethod"
          />

          <div
            v-if="sourceLoading && !source"
            class="code-panel__state"
            role="status"
          >
            <LoaderCircle class="spin" :size="22" aria-hidden="true" />
            <strong>正在安全读取反编译输出</strong>
          </div>
          <div
            v-else-if="sourceError && !source"
            class="code-panel__state code-panel__state--error"
            role="alert"
          >
            <TriangleAlert :size="22" aria-hidden="true" />
            <strong>{{ sourceError }}</strong>
          </div>
          <ReadOnlyCodeEditor
            v-else-if="source"
            :source="source"
            :language="editorLanguage"
            :label="`只读${languageLabel}反编译输出`"
          />
          <div v-else class="code-panel__state" role="status">
            <FileCode2 :size="24" aria-hidden="true" />
            <strong>该单元没有可读取的文本输出</strong>
            <span>{{ capabilityMessage }}</span>
          </div>

          <footer class="code-panel__footnote">
            <span>此内容由反编译或字节码分析产生，不代表原始源代码。</span>
            <button
              v-if="hasMoreSource"
              type="button"
              :disabled="sourceLoading"
              :aria-busy="sourceLoading"
              @click="emit('loadMoreSource')"
            >
              <LoaderCircle
                v-if="sourceLoading"
                class="spin"
                :size="13"
                aria-hidden="true"
              />
              <ChevronDown v-else :size="13" aria-hidden="true" />
              继续读取
            </button>
          </footer>
        </template>
      </section>
    </div>
  </div>
</template>

<style scoped>
.decompile-workspace {
  min-width: 0;
}

.capability-strip {
  display: grid;
  min-height: 62px;
  grid-template-columns: minmax(180px, auto) minmax(220px, 1fr) auto;
  align-items: center;
  gap: 16px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--line);
  background: #f2f8f6;
}

.capability-strip__identity {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 9px;
  color: var(--teal-strong);
}

.capability-strip__identity span {
  display: grid;
  gap: 2px;
}

.capability-strip small,
.capability-strip p {
  margin: 0;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.45;
}

.capability-strip strong {
  color: var(--ink-800);
  font-size: 12px;
}

.capability-strip__engine {
  max-width: 260px;
  overflow: hidden;
  padding: 4px 7px;
  border: 1px solid #bdd7d1;
  border-radius: 4px;
  color: #17665f;
  background: #fff;
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.capability-strip__engine--partial,
.capability-strip__engine--bytecode_only,
.capability-strip__engine--unsupported,
.capability-strip__engine--failed,
.capability-strip__engine--cancelled {
  border-color: #dfc67b;
  color: #76560d;
  background: #fffaf0;
}

.capability-warning {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid #e2d39c;
  color: #745615;
  background: #fffaf0;
  font-size: 10px;
  line-height: 1.5;
}

.capability-warning svg {
  flex: 0 0 auto;
}

.capability-warning strong {
  white-space: nowrap;
}

.capability-warning span {
  min-width: 0;
  overflow-wrap: anywhere;
}

.decompile-workspace__body {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(250px, 31%) minmax(0, 1fr);
}

.symbol-panel {
  min-width: 0;
  border-right: 1px solid var(--line);
  background: #fbfcfc;
}

.symbol-panel__heading {
  display: grid;
  gap: 9px;
  padding: 12px;
  border-bottom: 1px solid var(--line);
}

.symbol-panel__heading > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.symbol-panel__heading strong {
  color: var(--ink-800);
  font-size: 11px;
}

.symbol-panel__heading span {
  color: var(--ink-600);
  font-size: 9px;
}

.symbol-search {
  display: grid;
  height: 32px;
  grid-template-columns: 18px minmax(0, 1fr);
  align-items: center;
  gap: 4px;
  padding: 0 8px;
  border: 1px solid #cdd5d6;
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
}

.symbol-search:focus-within {
  border-color: var(--teal);
  box-shadow: 0 0 0 2px rgb(25 130 119 / 12%);
}

.symbol-search input {
  min-width: 0;
  border: 0;
  outline: 0;
  color: var(--ink-800);
  background: transparent;
  font: inherit;
  font-size: 10px;
}

.result-filters {
  display: grid;
  min-width: 0;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid #cdd5d6;
  border-radius: 4px;
  overflow: hidden;
  background: #fff;
}

.result-filters button {
  display: grid;
  min-width: 0;
  min-height: 38px;
  grid-template-columns: 13px minmax(0, 1fr);
  grid-template-rows: auto auto;
  align-items: center;
  column-gap: 3px;
  padding: 4px 3px;
  border: 0;
  border-right: 1px solid #dce2e3;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  font: inherit;
  text-align: left;
}

.result-filters button:last-child {
  border-right: 0;
}

.result-filters button:hover {
  background: #f1f5f4;
}

.result-filters button:focus-visible {
  position: relative;
  z-index: 1;
  outline: 2px solid #4f94b8;
  outline-offset: -2px;
}

.result-filters button > span {
  overflow: hidden;
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.result-filters button > code {
  grid-column: 2;
  color: inherit;
  font-size: 8px;
}

.result-filters .result-filter--active {
  color: var(--teal-strong);
  background: #eaf5f2;
  box-shadow: inset 0 -2px 0 var(--teal);
}

.symbol-tree {
  max-height: 620px;
  overflow: auto;
  padding: 8px 0 12px;
}

.symbol-group h4 {
  margin: 0;
  overflow: hidden;
  padding: 8px 12px 5px;
  color: var(--ink-600);
  font-size: 9px;
  font-weight: 700;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.symbol-row {
  display: grid;
  width: 100%;
  min-height: 47px;
  grid-template-columns: 16px minmax(0, 1fr) auto;
  align-items: center;
  gap: 7px;
  padding: 6px 10px 6px 12px;
  border: 0;
  border-left: 3px solid transparent;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.symbol-row:hover {
  background: #f1f5f4;
}

.symbol-row:focus-visible {
  outline: 2px solid #4f94b8;
  outline-offset: -2px;
}

.symbol-row--active {
  border-left-color: var(--teal);
  color: var(--teal-strong);
  background: #eaf5f2;
}

.symbol-row__main {
  display: grid;
  min-width: 0;
  gap: 3px;
}

.symbol-row__main strong,
.symbol-row__main small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.symbol-row__main strong {
  color: var(--ink-800);
  font-size: 10px;
}

.symbol-row__main small,
.symbol-row__kind {
  color: var(--ink-600);
  font-size: 8px;
}

.symbol-row__kind {
  padding: 2px 4px;
  border: 1px solid #d4dbdc;
  border-radius: 3px;
  white-space: nowrap;
}

.symbol-panel__empty,
.code-panel__state {
  display: flex;
  min-height: 260px;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 8px;
  padding: 24px;
  color: var(--ink-600);
  font-size: 10px;
  text-align: center;
}

.load-more {
  display: flex;
  width: calc(100% - 24px);
  height: 32px;
  align-items: center;
  justify-content: center;
  gap: 6px;
  margin: 8px 12px 0;
  border: 1px solid #cbd5d5;
  border-radius: 4px;
  color: var(--teal-strong);
  background: #fff;
  cursor: pointer;
  font: inherit;
  font-size: 9px;
}

.load-more:disabled {
  cursor: wait;
  opacity: 0.65;
}

.code-panel {
  min-width: 0;
  background: #fff;
}

.code-panel__heading {
  display: flex;
  min-height: 64px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--line);
}

.code-panel__title {
  display: grid;
  min-width: 0;
  gap: 5px;
}

.code-panel__title > span {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
}

.code-panel__title strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 12px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__title small,
.code-panel__badges span {
  padding: 2px 5px;
  border: 1px solid #d1d9da;
  border-radius: 3px;
  color: var(--ink-600);
  font-size: 8px;
  white-space: nowrap;
}

.code-panel__title code {
  overflow: hidden;
  color: var(--ink-600);
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__badges {
  display: flex;
  flex: 0 0 auto;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 5px;
}

.code-panel__meta {
  display: flex;
  min-height: 36px;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 16px;
  padding: 7px 14px;
  border-bottom: 1px solid #33464a;
  color: #a8b8ba;
  background: #233337;
  font-size: 8px;
}

.code-panel__meta code {
  color: #d7e5e6;
}

.code-panel__state {
  min-height: 380px;
  color: #b8c8ca;
  background: #172427;
}

.code-panel__state strong {
  color: #e2eeee;
  font-size: 11px;
}

.code-panel__state--error {
  color: #f0b8a7;
}

.code-panel__footnote {
  display: flex;
  min-height: 38px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 7px 12px;
  border-top: 1px solid var(--line);
  color: var(--ink-600);
  background: #f7f9f9;
  font-size: 8px;
}

.code-panel__footnote button {
  display: inline-flex;
  height: 25px;
  align-items: center;
  gap: 4px;
  padding: 0 7px;
  border: 1px solid #b8cdca;
  border-radius: 3px;
  color: var(--teal-strong);
  background: #fff;
  cursor: pointer;
  font: inherit;
  font-size: 8px;
}

.spin {
  animation: spin 0.9s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@container (max-width: 720px) {
  .capability-strip {
    grid-template-columns: 1fr;
    gap: 7px;
  }

  .capability-strip__engine {
    max-width: 100%;
    width: fit-content;
  }

  .decompile-workspace__body {
    grid-template-columns: 1fr;
  }

  .symbol-panel {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }

  .symbol-tree {
    max-height: 310px;
  }
}

@media (max-width: 520px) {
  .code-panel__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .code-panel__badges {
    justify-content: flex-start;
  }
}
</style>
