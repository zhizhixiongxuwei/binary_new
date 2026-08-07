<script setup lang="ts">
import {
  Box,
  Braces,
  Code2,
  FileCode2,
  Search,
  TriangleAlert,
} from 'lucide-vue-next'
import { computed, shallowRef, type Component } from 'vue'

import ReadOnlyCodeEditor from '@/components/code-editor/ReadOnlyCodeEditor.vue'
import type { ReadOnlyCodeLanguage } from '@/components/code-editor/monacoLoader'
import BytecodeAnalyzerSummary from '@/components/tasks/results/BytecodeAnalyzerSummary.vue'
import BytecodeMethodIndexPanel from '@/components/tasks/results/BytecodeMethodIndexPanel.vue'
import { parseAnalyzerSummary } from '@/components/tasks/results/analyzerSummary'
import type { ParsedBytecodeMethodIndex } from '@/components/tasks/results/jvmMethodIndex'
import {
  type DemoCodeUnit,
  type DemoCodeUnitKind,
  resolveDemoDecompileView,
} from '@/components/tasks/demo/demoResultFixtures'
import DemoPreviewNotice from '@/components/tasks/demo/DemoPreviewNotice.vue'

const props = defineProps<{
  taskId: string
  taskName: string
  inputType: string
}>()

interface DemoCodeGroup {
  name: string
  units: readonly DemoCodeUnit[]
}

const query = shallowRef('')
const selectedUnitId = shallowRef('')
const selectedBytecodeMethodKey = shallowRef('')

const view = computed(() => resolveDemoDecompileView(props.inputType))
const analyzerSummary = computed(() =>
  parseAnalyzerSummary(view.value.analyzerDiagnostics),
)
const normalizedQuery = computed(() => query.value.trim().toLocaleLowerCase('zh-CN'))
const filteredUnits = computed(() => {
  if (!normalizedQuery.value) return view.value.units
  return view.value.units.filter((unit) =>
    [unit.name, unit.group, unit.location, unit.signature, unit.source]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
      .includes(normalizedQuery.value),
  )
})
const groupedUnits = computed<readonly DemoCodeGroup[]>(() => {
  const groups = new Map<string, DemoCodeUnit[]>()
  filteredUnits.value.forEach((unit) => {
    const units = groups.get(unit.group) ?? []
    units.push(unit)
    groups.set(unit.group, units)
  })
  return [...groups].map(([name, units]) => ({ name, units }))
})
const selectedUnit = computed<DemoCodeUnit>(() => {
  const fallbackUnit = view.value.units[0]
  if (!fallbackUnit) {
    throw new Error('Demo decompile view must contain at least one code unit')
  }
  return (
    view.value.units.find((unit) => unit.id === selectedUnitId.value) ??
    filteredUnits.value[0] ??
    fallbackUnit
  )
})
const demoMethodIndex = computed<ParsedBytecodeMethodIndex>(() => {
  const methods = selectedUnit.value.methods ?? []
  return {
    present: Boolean(selectedUnit.value.methods),
    declaredCount: methods.length,
    invalidCount: 0,
    omittedCount: 0,
    methods,
  }
})
const activeBytecodeMethodKey = computed(() => {
  const methods = demoMethodIndex.value.methods
  return methods.some((method) => method.key === selectedBytecodeMethodKey.value)
    ? selectedBytecodeMethodKey.value
    : methods[0]?.key ?? ''
})
const sourceMatchCount = computed(() => {
  if (!normalizedQuery.value) return 0
  const escapedQuery = normalizedQuery.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return (
    selectedUnit.value.source
      .toLocaleLowerCase('zh-CN')
      .match(new RegExp(escapedQuery, 'g'))?.length ?? 0
  )
})
const editorLanguage = computed<ReadOnlyCodeLanguage>(() => {
  const languageByView = {
    native: 'c',
    jvm: 'jvm-bytecode',
    dex: 'smali',
    pyc: 'python-bytecode',
  } as const satisfies Record<
    typeof view.value.kind,
    ReadOnlyCodeLanguage
  >
  return languageByView[view.value.kind]
})

const unitIcons: Readonly<Record<DemoCodeUnitKind, Component>> = {
  function: Braces,
  class: Box,
  method: Code2,
  module: FileCode2,
}

const unitLabels: Readonly<Record<DemoCodeUnitKind, string>> = {
  function: '函数',
  class: '类',
  method: '方法',
  module: '模块',
}

function selectUnit(unitId: string): void {
  selectedUnitId.value = unitId
  selectedBytecodeMethodKey.value = ''
}

function selectBytecodeMethod(methodKey: string): void {
  selectedBytecodeMethodKey.value = methodKey
}
</script>

<template>
  <div class="decompile-preview">
    <DemoPreviewNotice subject="反编译" />

    <section class="capability-strip" aria-labelledby="demo-capability-title">
      <div class="capability-strip__identity">
        <Code2 :size="17" aria-hidden="true" />
        <span>
          <small id="demo-capability-title">当前能力视图</small>
          <strong>{{ view.title }}</strong>
        </span>
      </div>
      <p>{{ view.capability }}</p>
      <span class="capability-strip__engine">未连接真实反编译引擎</span>
    </section>

    <div class="decompile-preview__context" aria-label="反编译示例上下文">
      <span><small>示例模块</small><strong>{{ taskName }}</strong></span>
      <span><small>输入格式</small><strong>{{ inputType }}</strong></span>
      <span><small>结构视图</small><strong>{{ view.treeLabel }}</strong></span>
      <span><small>示例单元</small><strong>{{ view.units.length }}</strong></span>
    </div>

    <div class="capability-warning" role="note">
      <TriangleAlert :size="16" aria-hidden="true" />
      <strong>能力与可信度说明</strong>
      <span>{{ view.limitation }}</span>
    </div>

    <div class="decompile-preview__workspace">
      <aside class="symbol-panel" :aria-label="`示例${view.treeLabel}`">
        <div class="symbol-panel__heading">
          <div>
            <strong>{{ view.treeLabel }}</strong>
            <span>{{ filteredUnits.length }} / {{ view.units.length }}</span>
          </div>
          <label class="symbol-search">
            <span class="sr-only">搜索名称、签名或只读代码内容</span>
            <Search :size="14" aria-hidden="true" />
            <input
              v-model="query"
              type="search"
              autocomplete="off"
              placeholder="搜索名称、签名或代码"
            >
          </label>
        </div>

        <div
          v-if="groupedUnits.length"
          class="symbol-tree"
          role="tree"
          :aria-label="view.treeLabel"
        >
          <section
            v-for="group in groupedUnits"
            :key="group.name"
            class="symbol-group"
            role="group"
            :aria-label="group.name"
          >
            <h4 class="symbol-group__label">{{ group.name }}</h4>
            <button
              v-for="unit in group.units"
              :key="unit.id"
              class="symbol-row"
              :class="{ 'symbol-row--active': selectedUnit.id === unit.id }"
              type="button"
              role="treeitem"
              data-demo-symbol
              :aria-selected="selectedUnit.id === unit.id"
              @click="selectUnit(unit.id)"
            >
              <component :is="unitIcons[unit.kind]" :size="14" aria-hidden="true" />
              <span class="symbol-row__main">
                <strong>{{ unit.name }}</strong>
                <small class="mono">{{ unit.location }}</small>
              </span>
              <span class="symbol-row__kind">{{ unitLabels[unit.kind] }}</span>
            </button>
          </section>
        </div>
        <div v-else class="symbol-panel__empty" role="status">
          没有匹配的类、方法、函数或代码内容
        </div>
      </aside>

      <section
        class="code-panel"
        :class="{
          'code-panel--method-index': view.kind === 'jvm' && demoMethodIndex.present,
          'code-panel--analyzer-summary': analyzerSummary.present,
        }"
        :aria-label="`${view.title}只读代码`"
      >
        <header class="code-panel__heading">
          <div class="code-panel__title">
            <span>
              <strong>{{ selectedUnit.name }}</strong>
              <small>{{ unitLabels[selectedUnit.kind] }}</small>
            </span>
            <code>{{ selectedUnit.signature }}</code>
          </div>
          <div class="code-panel__badges" aria-label="代码属性">
            <span>{{ view.languageBadge }}</span>
            <span>只读</span>
          </div>
        </header>
        <div class="code-panel__meta">
          <span>位置 <code>{{ selectedUnit.location }}</code></span>
          <span>{{ selectedUnit.detail }}</span>
          <span v-if="normalizedQuery" aria-live="polite">
            当前代码命中 <code>{{ sourceMatchCount }}</code> 处
          </span>
          <span class="code-panel__task mono">task: {{ props.taskId }}</span>
        </div>
        <BytecodeAnalyzerSummary
          v-if="analyzerSummary.present"
          :summary="analyzerSummary"
          example
        />
        <BytecodeMethodIndexPanel
          v-if="view.kind === 'jvm' && demoMethodIndex.present"
          :key="selectedUnit.id"
          :index="demoMethodIndex"
          :selected-key="activeBytecodeMethodKey"
          @select="selectBytecodeMethod"
        />
        <ReadOnlyCodeEditor
          :source="selectedUnit.source"
          :language="editorLanguage"
          :label="`只读${view.languageBadge}固定示例代码`"
        />
        <footer class="code-panel__footnote">
          固定示例数据，仅用于验证信息结构、搜索和代码阅读体验，不表示已完成真实分析。
        </footer>
      </section>
    </div>
  </div>
</template>

<style scoped>
.decompile-preview {
  min-width: 0;
}

.capability-strip {
  display: grid;
  min-width: 0;
  min-height: 58px;
  grid-template-columns: minmax(190px, auto) minmax(200px, 1fr) auto;
  align-items: center;
  gap: 16px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--line);
  background: #f4f8f7;
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
  min-width: 0;
  gap: 2px;
}

.capability-strip small {
  color: var(--ink-600);
  font-size: 8px;
}

.capability-strip strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.capability-strip p {
  margin: 0;
  color: var(--ink-600);
  font-size: 9px;
  line-height: 1.5;
}

.capability-strip__engine {
  padding: 4px 7px;
  border: 1px solid #cfb96f;
  border-radius: 3px;
  color: #725817;
  background: #fff9e8;
  font-size: 8px;
  font-weight: 700;
  white-space: nowrap;
}

.decompile-preview__context {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-bottom: 1px solid var(--line);
  background: #f8fafa;
}

.decompile-preview__context > span {
  display: flex;
  min-width: 0;
  min-height: 54px;
  justify-content: center;
  flex-direction: column;
  gap: 4px;
  padding: 9px 13px;
  border-right: 1px solid #e1e6e7;
}

.decompile-preview__context > span:last-child {
  border-right: 0;
}

.decompile-preview__context small {
  color: var(--ink-600);
  font-size: 9px;
}

.decompile-preview__context strong {
  overflow: hidden;
  color: var(--ink-800);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.capability-warning {
  display: grid;
  min-width: 0;
  grid-template-columns: 18px auto minmax(180px, 1fr);
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  border-bottom: 1px solid #e1c787;
  color: #765816;
  background: #fff9e9;
}

.capability-warning strong {
  font-size: 9px;
  white-space: nowrap;
}

.capability-warning span {
  font-size: 9px;
  line-height: 1.5;
}

.decompile-preview__workspace {
  display: grid;
  min-height: 470px;
  grid-template-columns: minmax(260px, 0.34fr) minmax(0, 1fr);
}

.symbol-panel {
  min-width: 0;
  border-right: 1px solid var(--line);
  background: #f8fafa;
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
  gap: 12px;
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
  display: flex;
  height: 34px;
  align-items: center;
  gap: 7px;
  padding: 0 9px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-400);
  background: var(--surface);
}

.symbol-search:focus-within {
  border-color: var(--blue);
  box-shadow: 0 0 0 1px var(--blue);
}

.symbol-search input {
  width: 100%;
  min-width: 0;
  border: 0;
  outline: 0;
  color: var(--ink-800);
  background: transparent;
  font-size: 10px;
}

.symbol-tree {
  display: grid;
}

.symbol-group {
  min-width: 0;
}

.symbol-group__label {
  margin: 0;
  overflow: hidden;
  padding: 7px 11px;
  border-bottom: 1px solid #e4e8e9;
  color: var(--ink-600);
  background: #eef2f2;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 8px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.symbol-row {
  display: grid;
  width: 100%;
  min-width: 0;
  min-height: 56px;
  grid-template-columns: 18px minmax(0, 1fr) auto;
  align-items: center;
  gap: 6px;
  padding: 8px 11px;
  border: 0;
  border-bottom: 1px solid #e4e8e9;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  text-align: left;
}

.symbol-row:hover,
.symbol-row:focus-visible {
  color: var(--teal-strong);
  background: #f0f6f5;
}

.symbol-row:focus-visible {
  outline: 2px solid var(--blue);
  outline-offset: -2px;
}

.symbol-row--active {
  color: var(--teal-strong);
  background: #e8f2f1;
  box-shadow: 3px 0 0 var(--teal) inset;
}

.symbol-row__main {
  display: grid;
  min-width: 0;
  gap: 4px;
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
  border: 1px solid var(--line);
  border-radius: 3px;
  background: #ffffff;
}

.symbol-panel__empty {
  padding: 34px 15px;
  color: var(--ink-600);
  font-size: 10px;
  text-align: center;
}

.code-panel {
  display: grid;
  min-width: 0;
  grid-template-rows: auto auto minmax(320px, 1fr) auto;
  background: #172427;
}

.code-panel--method-index {
  grid-template-rows: auto auto auto minmax(320px, 1fr) auto;
}

.code-panel--analyzer-summary {
  grid-template-rows: auto auto auto minmax(320px, 1fr) auto;
}

.code-panel--method-index.code-panel--analyzer-summary {
  grid-template-rows: auto auto auto auto minmax(320px, 1fr) auto;
}

.code-panel__heading {
  display: flex;
  min-width: 0;
  min-height: 62px;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 14px;
  border-bottom: 1px solid #344549;
  background: #213136;
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
  gap: 7px;
}

.code-panel__title strong {
  overflow: hidden;
  color: #edf4f4;
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__title small {
  padding: 2px 4px;
  border: 1px solid #51666a;
  border-radius: 3px;
  color: #b9ccce;
  font-size: 8px;
}

.code-panel__title code {
  overflow: hidden;
  color: #a8bcbe;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__badges {
  display: flex;
  flex: 0 0 auto;
  gap: 5px;
}

.code-panel__badges span {
  padding: 2px 5px;
  border: 1px solid #60787b;
  border-radius: 3px;
  color: #d5e5e6;
  font-size: 8px;
  font-weight: 700;
}

.code-panel__meta {
  display: flex;
  min-width: 0;
  min-height: 36px;
  align-items: center;
  gap: 16px;
  padding: 5px 14px;
  border-bottom: 1px solid #344549;
  color: #9eb0b3;
  background: #1c2b2f;
  font-size: 8px;
  flex-wrap: wrap;
}

.code-panel__meta code {
  color: #cae2df;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
}

.code-panel__task {
  max-width: 230px;
  margin-left: auto;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.code-panel__source {
  min-width: 0;
  min-height: 320px;
  margin: 0;
  overflow: auto;
  padding: 18px 20px 24px;
  color: #d8e7e7;
  background: #172427;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
  line-height: 1.7;
  tab-size: 4;
}

.code-panel__source:focus-visible {
  outline: 2px solid #58a9cf;
  outline-offset: -3px;
}

.code-panel__footnote {
  padding: 8px 14px;
  border-top: 1px solid #344549;
  color: #9eb0b3;
  background: #1c2b2f;
  font-size: 8px;
  line-height: 1.5;
}

@media (max-width: 820px) {
  .capability-strip {
    grid-template-columns: minmax(0, 1fr) auto;
  }

  .capability-strip p {
    grid-column: 1 / -1;
    grid-row: 2;
  }

  .decompile-preview__context {
    grid-template-columns: 1fr 1fr;
  }

  .decompile-preview__context > span:nth-child(2) {
    border-right: 0;
  }

  .decompile-preview__context > span:nth-child(-n + 2) {
    border-bottom: 1px solid #e1e6e7;
  }

  .decompile-preview__workspace {
    grid-template-columns: 1fr;
  }

  .symbol-panel {
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }

  .symbol-tree {
    grid-template-columns: 1fr 1fr;
  }
}

@media (max-width: 540px) {
  .capability-strip {
    grid-template-columns: 1fr;
  }

  .capability-strip__engine,
  .capability-strip p {
    grid-column: 1;
    grid-row: auto;
    white-space: normal;
  }

  .capability-warning {
    grid-template-columns: 18px minmax(0, 1fr);
  }

  .capability-warning span {
    grid-column: 1 / -1;
  }

  .symbol-tree {
    grid-template-columns: 1fr;
  }

  .code-panel__heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .code-panel__task {
    width: 100%;
    max-width: none;
    margin-left: 0;
  }

  .code-panel__source {
    padding: 14px 12px 20px;
    font-size: 10px;
  }
}
</style>
