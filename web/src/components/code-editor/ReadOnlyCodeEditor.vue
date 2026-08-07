<script setup lang="ts">
import { Search } from 'lucide-vue-next'
import {
  computed,
  nextTick,
  onMounted,
  onScopeDispose,
  shallowRef,
  useTemplateRef,
  watch,
} from 'vue'

import {
  loadMonacoEditor,
  resolveMonacoLanguage,
  supportsMonacoRuntime,
  type MonacoModule,
  type ReadOnlyCodeLanguage,
} from '@/components/code-editor/monacoLoader'

type EditorState = 'fallback' | 'loading' | 'ready' | 'error'

const props = defineProps<{
  source: string
  language: ReadOnlyCodeLanguage
  label: string
}>()

const editorHost = useTemplateRef<HTMLDivElement>('editorHost')
const fallbackSource = useTemplateRef<HTMLElement>('fallbackSource')
const state = shallowRef<EditorState>('fallback')
const monacoModule = shallowRef<MonacoModule>()
const editor = shallowRef<ReturnType<MonacoModule['editor']['create']>>()

const statusText = computed(() => {
  if (state.value === 'ready') return 'Monaco 只读编辑器已就绪'
  if (state.value === 'loading') return '正在加载 Monaco 只读编辑器'
  if (state.value === 'error') {
    return 'Monaco 加载失败，已切换到安全只读文本'
  }
  return '当前环境使用安全只读文本'
})
const showFallback = computed(() => state.value !== 'ready')

function focusSearch(): void {
  if (editor.value) {
    editor.value.focus()
    void editor.value.getAction('actions.find')?.run()
    return
  }
  fallbackSource.value?.focus()
}

async function mountEditor(): Promise<void> {
  if (!supportsMonacoRuntime()) {
    state.value = 'fallback'
    return
  }

  state.value = 'loading'
  try {
    const monaco = await loadMonacoEditor()
    await nextTick()
    if (!editorHost.value) return

    monacoModule.value = monaco
    editor.value = monaco.editor.create(editorHost.value, {
      value: props.source,
      language: resolveMonacoLanguage(props.language),
      readOnly: true,
      domReadOnly: true,
      automaticLayout: true,
      ariaLabel: props.label,
      minimap: { enabled: false },
      overviewRulerLanes: 0,
      renderLineHighlight: 'line',
      scrollBeyondLastLine: false,
      smoothScrolling: true,
      wordWrap: 'on',
      wrappingIndent: 'same',
      fontFamily:
        '"IBM Plex Mono", "SFMono-Regular", Consolas, monospace',
      fontSize: 12,
      lineHeight: 20,
      lineNumbersMinChars: 3,
      padding: { top: 14, bottom: 18 },
      find: {
        addExtraSpaceOnTop: false,
        seedSearchStringFromSelection: 'always',
      },
    })
    state.value = 'ready'
  } catch {
    state.value = 'error'
  }
}

watch(
  () => props.source,
  (source) => {
    if (editor.value && editor.value.getValue() !== source) {
      editor.value.setValue(source)
    }
  },
)

watch(
  () => props.language,
  (language) => {
    const model = editor.value?.getModel()
    if (model && monacoModule.value) {
      monacoModule.value.editor.setModelLanguage(
        model,
        resolveMonacoLanguage(language),
      )
    }
  },
)

watch(
  () => props.label,
  (label) => {
    editor.value?.updateOptions({ ariaLabel: label })
  },
)

onMounted(() => {
  void mountEditor()
})

onScopeDispose(() => {
  editor.value?.dispose()
  editor.value = undefined
})
</script>

<template>
  <div class="read-only-editor" :data-editor-state="state">
    <div class="read-only-editor__toolbar">
      <span
        class="read-only-editor__status"
        :class="{ 'read-only-editor__status--warning': state === 'error' }"
        role="status"
        aria-live="polite"
      >
        <span class="read-only-editor__status-light" aria-hidden="true" />
        {{ statusText }}
      </span>
      <button
        class="read-only-editor__search"
        type="button"
        :aria-label="state === 'ready' ? '在代码中查找' : '聚焦只读代码'"
        :title="state === 'ready' ? '在代码中查找' : '聚焦只读代码'"
        @click="focusSearch"
      >
        <Search :size="14" aria-hidden="true" />
        <span>{{ state === 'ready' ? '查找' : '只读文本' }}</span>
      </button>
    </div>

    <div class="read-only-editor__stage">
      <div
        ref="editorHost"
        class="read-only-editor__host"
        :aria-hidden="state !== 'ready'"
      />
      <pre
        v-if="showFallback"
        ref="fallbackSource"
        class="code-panel__source"
        tabindex="0"
        :aria-label="label"
      ><code>{{ source }}</code></pre>
    </div>

    <p v-if="state === 'error'" class="read-only-editor__error">
      编辑器增强功能不可用。代码仍可安全阅读，使用浏览器查找可定位内容。
    </p>
  </div>
</template>

<style scoped>
.read-only-editor {
  display: grid;
  width: 100%;
  min-width: 0;
  min-height: 320px;
  grid-template-rows: 34px minmax(286px, 1fr) auto;
  overflow: hidden;
  background: #172427;
}

.read-only-editor__toolbar {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 0 10px 0 14px;
  border-bottom: 1px solid #344549;
  color: #9eb0b3;
  background: #1c2b2f;
}

.read-only-editor__status {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
  overflow: hidden;
  font-size: 8px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.read-only-editor__status-light {
  width: 6px;
  height: 6px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: #6c8b8e;
}

[data-editor-state="ready"] .read-only-editor__status-light {
  background: #4bc4a4;
  box-shadow: 0 0 0 2px rgb(75 196 164 / 16%);
}

[data-editor-state="loading"] .read-only-editor__status-light {
  background: #e0bc55;
}

.read-only-editor__status--warning,
[data-editor-state="error"] .read-only-editor__status-light {
  color: #f2c5b7;
}

[data-editor-state="error"] .read-only-editor__status-light {
  background: #df8063;
}

.read-only-editor__search {
  display: inline-flex;
  height: 26px;
  flex: 0 0 auto;
  align-items: center;
  gap: 5px;
  padding: 0 7px;
  border: 1px solid #51666a;
  border-radius: 3px;
  color: #d5e5e6;
  background: #263a3f;
  cursor: pointer;
  font: inherit;
  font-size: 8px;
}

.read-only-editor__search:hover {
  border-color: #6f9195;
  background: #2c4449;
}

.read-only-editor__search:focus-visible {
  outline: 2px solid #58a9cf;
  outline-offset: 1px;
}

.read-only-editor__stage {
  position: relative;
  width: 100%;
  min-width: 0;
  height: clamp(320px, 52vh, 560px);
  overflow: hidden;
}

.read-only-editor__host {
  position: absolute;
  inset: 0;
  width: 100%;
  min-width: 0;
  height: 100%;
}

.code-panel__source {
  position: absolute;
  inset: 0;
  min-width: 0;
  min-height: 100%;
  margin: 0;
  overflow: auto;
  padding: 18px 20px 24px;
  color: #d8e7e7;
  background: #172427;
  font-family: "IBM Plex Mono", "SFMono-Regular", Consolas, monospace;
  font-size: 11px;
  line-height: 1.7;
  tab-size: 4;
  white-space: pre;
}

.code-panel__source:focus-visible {
  outline: 2px solid #58a9cf;
  outline-offset: -3px;
}

.read-only-editor__error {
  margin: 0;
  padding: 7px 14px;
  border-top: 1px solid #6d443b;
  color: #f2c5b7;
  background: #352a28;
  font-size: 8px;
  line-height: 1.5;
}

@media (max-width: 540px) {
  .read-only-editor__toolbar {
    padding-left: 10px;
  }

  .read-only-editor__stage {
    height: 380px;
  }

  .code-panel__source {
    padding: 14px 12px 20px;
    font-size: 10px;
  }
}
</style>
