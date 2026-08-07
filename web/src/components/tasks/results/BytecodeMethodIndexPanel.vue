<script setup lang="ts">
import { Braces, Code2, Search } from 'lucide-vue-next'
import { computed, nextTick, shallowRef, useId, useTemplateRef } from 'vue'

import type {
  BytecodeMethodIndexEntry,
  ParsedBytecodeMethodIndex,
} from '@/components/tasks/results/jvmMethodIndex'
import { formatBytes } from '@/utils/formatters'

const MAX_VISIBLE_METHODS = 200

const props = defineProps<{
  index: ParsedBytecodeMethodIndex
  selectedKey: string
}>()

const emit = defineEmits<{
  select: [methodKey: string]
}>()

const query = shallowRef('')
const titleId = useId()
const methodList = useTemplateRef<HTMLElement>('methodList')
const normalizedQuery = computed(() => query.value.trim().toLocaleLowerCase('zh-CN'))
const matchingMethods = computed(() => {
  if (!normalizedQuery.value) return props.index.methods
  return props.index.methods.filter((method) =>
    [
      method.name,
      method.qualifiedName,
      method.descriptor,
      method.signature,
      method.bytecode?.offsetBytes.toString() ?? '',
    ]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
      .includes(normalizedQuery.value),
  )
})
const visibleMethods = computed(() =>
  matchingMethods.value.slice(0, MAX_VISIBLE_METHODS),
)
const selectedMethod = computed(() => {
  const selected = props.index.methods.find(
    (method) => method.key === props.selectedKey,
  )
  if (!normalizedQuery.value) return selected ?? props.index.methods[0]
  return (
    visibleMethods.value.find((method) => method.key === props.selectedKey) ??
    visibleMethods.value[0]
  )
})
const keyboardEntryKey = computed(() =>
  visibleMethods.value.some((method) => method.key === selectedMethod.value?.key)
    ? selectedMethod.value?.key ?? ''
    : visibleMethods.value[0]?.key ?? '',
)
const hiddenMatchCount = computed(() =>
  Math.max(0, matchingMethods.value.length - visibleMethods.value.length),
)
const ignoredCount = computed(() =>
  props.index.invalidCount + props.index.omittedCount,
)

function codeLocation(method: BytecodeMethodIndexEntry): string {
  if (!method.bytecode) return '无 Code 属性'
  return `Code +${method.bytecode.offsetBytes} · ${formatBytes(method.bytecode.sizeBytes)}`
}

function codeEnd(method: BytecodeMethodIndexEntry): string {
  if (!method.bytecode) return '不适用'
  const end = method.bytecode.offsetBytes + method.bytecode.sizeBytes
  return Number.isSafeInteger(end) ? `${end}（不含）` : '超出安全显示范围'
}

function selectAndFocus(method: BytecodeMethodIndexEntry, index: number): void {
  emit('select', method.key)
  void nextTick(() => {
    const buttons = methodList.value?.querySelectorAll<HTMLButtonElement>(
      '[data-bytecode-method]',
    )
    buttons?.item(index).focus()
  })
}

function handleSearchKeydown(event: KeyboardEvent): void {
  const first = visibleMethods.value[0]
  if (event.key !== 'ArrowDown' || !first) return
  event.preventDefault()
  selectAndFocus(first, 0)
}

function handleMethodKeydown(event: KeyboardEvent, index: number): void {
  let nextIndex = index
  switch (event.key) {
    case 'ArrowDown':
      nextIndex = Math.min(index + 1, visibleMethods.value.length - 1)
      break
    case 'ArrowUp':
      nextIndex = Math.max(index - 1, 0)
      break
    case 'Home':
      nextIndex = 0
      break
    case 'End':
      nextIndex = visibleMethods.value.length - 1
      break
    default:
      return
  }
  const nextMethod = visibleMethods.value[nextIndex]
  if (!nextMethod) return
  event.preventDefault()
  selectAndFocus(nextMethod, nextIndex)
}
</script>

<template>
  <section class="method-index" :aria-labelledby="titleId">
    <header class="method-index__toolbar">
      <div class="method-index__title">
        <Braces :size="15" aria-hidden="true" />
        <span>
          <strong :id="titleId">JVM 方法索引</strong>
          <small>
            {{ matchingMethods.length }} / {{ index.methods.length }} 个可读方法
          </small>
        </span>
      </div>
      <label class="method-index__search">
        <span class="sr-only">搜索 JVM 方法名称、descriptor 或 Code 偏移</span>
        <Search :size="13" aria-hidden="true" />
        <input
          v-model="query"
          type="search"
          autocomplete="off"
          placeholder="搜索 JVM 方法"
          @keydown="handleSearchKeydown"
        >
      </label>
    </header>

    <p
      v-if="ignoredCount"
      class="method-index__notice"
      role="note"
    >
      已忽略 {{ ignoredCount }} 条无效或超出安全解析上限的方法记录。
    </p>

    <div v-if="index.methods.length" class="method-index__body">
      <div class="method-index__list-pane">
        <div
          ref="methodList"
          class="method-index__list"
          role="listbox"
          aria-label="JVM 方法列表"
        >
          <button
            v-for="(method, methodIndex) in visibleMethods"
            :key="method.key"
            type="button"
            role="option"
            data-bytecode-method
            :aria-selected="selectedMethod?.key === method.key"
            :tabindex="keyboardEntryKey === method.key ? 0 : -1"
            :class="{ 'method-index__row--active': selectedMethod?.key === method.key }"
            @click="emit('select', method.key)"
            @keydown="handleMethodKeydown($event, methodIndex)"
          >
            <Code2 :size="13" aria-hidden="true" />
            <span class="method-index__row-main">
              <strong>{{ method.name }}</strong>
              <code>{{ method.descriptor || 'descriptor 不可用' }}</code>
            </span>
            <small>{{ codeLocation(method) }}</small>
          </button>
        </div>
        <p v-if="!visibleMethods.length" class="method-index__empty" role="status">
          没有匹配的方法
        </p>
        <p v-else-if="hiddenMatchCount" class="method-index__more" role="status">
          继续搜索可定位其余 {{ hiddenMatchCount }} 个方法
        </p>
      </div>

      <div
        v-if="selectedMethod"
        class="method-index__detail"
        role="region"
        aria-label="当前 JVM 方法摘要"
        aria-live="polite"
        tabindex="0"
      >
        <small>当前 JVM 方法</small>
        <strong>{{ selectedMethod.name }}</strong>
        <code>{{ selectedMethod.descriptor || 'descriptor 不可用' }}</code>
        <dl>
          <div>
            <dt>限定名称</dt>
            <dd>{{ selectedMethod.qualifiedName || '未提供' }}</dd>
          </div>
          <div>
            <dt>Code 偏移</dt>
            <dd>{{ selectedMethod.bytecode?.offsetBytes ?? '无 Code 属性' }}</dd>
          </div>
          <div>
            <dt>Code 大小</dt>
            <dd>
              {{ selectedMethod.bytecode ? formatBytes(selectedMethod.bytecode.sizeBytes) : '不适用' }}
            </dd>
          </div>
          <div>
            <dt>Code 结束</dt>
            <dd>{{ codeEnd(selectedMethod) }}</dd>
          </div>
        </dl>
        <p>此处仅展示类文件方法元数据和 Code 范围，不代表 Java 源码。</p>
      </div>
    </div>
    <p v-else class="method-index__empty method-index__empty--standalone" role="status">
      方法索引中没有可安全显示的记录
    </p>
  </section>
</template>

<style scoped>
.method-index {
  min-width: 0;
  border-bottom: 1px solid #34464a;
  background: #f5f8f8;
}

.method-index__toolbar {
  display: grid;
  min-width: 0;
  min-height: 48px;
  grid-template-columns: minmax(170px, 1fr) minmax(180px, 260px);
  align-items: center;
  gap: 12px;
  padding: 7px 12px;
  border-bottom: 1px solid #d8e0e1;
}

.method-index__title {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  color: var(--teal-strong);
}

.method-index__title > span {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.method-index__title strong {
  color: var(--ink-800);
  font-size: 12px;
}

.method-index__title small {
  color: var(--ink-600);
  font-size: 11px;
}

.method-index__search {
  display: grid;
  height: 30px;
  grid-template-columns: 17px minmax(0, 1fr);
  align-items: center;
  gap: 4px;
  padding: 0 7px;
  border: 1px solid #c6d1d2;
  border-radius: 4px;
  color: var(--ink-600);
  background: #fff;
}

.method-index__search:focus-within {
  border-color: var(--teal);
  box-shadow: 0 0 0 2px rgb(25 130 119 / 12%);
}

.method-index__search input {
  min-width: 0;
  border: 0;
  outline: 0;
  color: var(--ink-800);
  background: transparent;
  font: inherit;
  font-size: 12px;
}

.method-index__notice {
  margin: 0;
  padding: 5px 12px;
  border-bottom: 1px solid #eadba9;
  color: #725817;
  background: #fff9e9;
  font-size: 11px;
}

.method-index__body {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(220px, 42%) minmax(0, 1fr);
}

.method-index__list {
  min-width: 0;
  overflow: auto;
  background: #fff;
}

.method-index__list-pane {
  display: grid;
  min-width: 0;
  max-height: 222px;
  grid-template-rows: minmax(0, 1fr) auto;
  border-right: 1px solid #d8e0e1;
  background: #fff;
}

.method-index__row {
  min-width: 0;
}

.method-index__list > button {
  display: grid;
  width: 100%;
  min-width: 0;
  min-height: 56px;
  grid-template-columns: 16px minmax(0, 1fr) auto;
  align-items: center;
  gap: 6px;
  padding: 6px 9px;
  border: 0;
  border-bottom: 1px solid #e3e8e9;
  border-left: 3px solid transparent;
  color: var(--ink-600);
  background: transparent;
  cursor: pointer;
  font: inherit;
  text-align: left;
}

.method-index__list > button:hover {
  background: #f0f6f5;
}

.method-index__list > button:focus-visible {
  outline: 2px solid #4f94b8;
  outline-offset: -2px;
}

.method-index__list > .method-index__row--active {
  border-left-color: var(--teal);
  color: var(--teal-strong);
  background: #eaf5f2;
}

.method-index__row-main {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.method-index__row-main strong,
.method-index__row-main code,
.method-index__list > button > small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.method-index__row-main strong {
  color: var(--ink-800);
  font-size: 12px;
}

.method-index__row-main code,
.method-index__list > button > small {
  color: var(--ink-600);
  font-size: 11px;
}

.method-index__list > button > small {
  max-width: 120px;
}

.method-index__detail {
  min-width: 0;
  min-height: 160px;
  padding: 13px 15px;
  color: var(--ink-600);
  background: #f5f8f8;
}

.method-index__detail:focus-visible {
  outline: 2px solid #4f94b8;
  outline-offset: -3px;
}

.method-index__detail > small {
  display: block;
  margin-bottom: 4px;
  color: var(--ink-600);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}

.method-index__detail > strong,
.method-index__detail > code {
  display: block;
  overflow-wrap: anywhere;
}

.method-index__detail > strong {
  color: var(--ink-800);
  font-size: 14px;
}

.method-index__detail > code {
  margin-top: 4px;
  color: var(--teal-strong);
  font-size: 12px;
}

.method-index__detail dl {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 14px;
  margin: 12px 0 0;
}

.method-index__detail dl > div {
  min-width: 0;
}

.method-index__detail dt {
  color: var(--ink-600);
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
}

.method-index__detail dd {
  margin: 2px 0 0;
  overflow-wrap: anywhere;
  color: var(--ink-800);
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
}

.method-index__detail p {
  margin: 12px 0 0;
  color: var(--ink-600);
  font-size: 11px;
  line-height: 1.5;
}

.method-index__empty,
.method-index__more {
  margin: 0;
  padding: 14px;
  color: var(--ink-600);
  font-size: 11px;
  text-align: center;
}

.method-index__more {
  padding: 7px;
  border-top: 1px solid #e3e8e9;
  font-size: 11px;
}

.method-index__empty--standalone {
  min-height: 70px;
}

@media (max-width: 620px) {
  .method-index__toolbar,
  .method-index__body {
    grid-template-columns: 1fr;
  }

  .method-index__list-pane {
    max-height: 196px;
    border-right: 0;
    border-bottom: 1px solid #d8e0e1;
  }

  .method-index__detail {
    min-height: 0;
  }
}

@media (max-width: 390px) {
  .method-index__list > button {
    grid-template-columns: 16px minmax(0, 1fr);
  }

  .method-index__list > button > small {
    grid-column: 2;
    max-width: none;
  }
}
</style>
