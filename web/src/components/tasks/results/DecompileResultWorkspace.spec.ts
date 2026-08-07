import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type {
  DecompileResult,
  DecompileResultStatus,
} from '@/api/types'
import DecompileResultWorkspace from '@/components/tasks/results/DecompileResultWorkspace.vue'

function result(
  id: string,
  overrides: Partial<DecompileResult> = {},
): DecompileResult {
  return {
    id,
    file_node_id: `file-${id}`,
    symbol_key: `symbol-${id}`,
    symbol_kind: 'function',
    display_name: `function_${id}`,
    group_name: 'Native functions',
    location: '0x00401000',
    signature: `int function_${id}(void)`,
    detail: 'ELF x86_64 symbol',
    language: 'c',
    engine_name: 'Ghidra',
    engine_version: '12.1.2',
    status: 'complete',
    size_bytes: 128,
    diagnostics: {},
    created_at: '2026-07-30T01:00:00Z',
    completed_at: '2026-07-30T01:00:02Z',
    ...overrides,
  }
}

const items: readonly DecompileResult[] = [
  result('verify', {
    display_name: 'verify_package',
    group_name: 'PackageVerifier',
    signature: 'bool verify_package(const Header *header)',
    detail: 'validates the package header',
  }),
  result('class', {
    symbol_kind: 'class',
    display_name: 'ManifestReader',
    group_name: 'Java classes',
    location: 'classes.dex:12',
    signature: 'class ManifestReader',
    language: 'java',
  }),
  result('method', {
    symbol_kind: 'method',
    display_name: 'parseManifest',
    group_name: 'Java classes',
    location: 'classes.dex:18',
    signature: 'void parseManifest(byte[] input)',
    language: 'java',
  }),
]

function mountWorkspace(options: {
  items?: readonly DecompileResult[]
  selectedId?: string
  source?: string
  sourceLoading?: boolean
  sourceError?: string
  hasMoreResults?: boolean
  loadingMoreResults?: boolean
  hasMoreSource?: boolean
} = {}) {
  return mount(DecompileResultWorkspace, {
    props: {
      taskId: 'task/decompile-contract',
      items: options.items ?? items,
      selectedId: options.selectedId ?? 'verify',
      source:
        options.source ??
        'bool verify_package(void) {\n  return header_magic == 0x504b;\n}',
      sourceLoading: options.sourceLoading ?? false,
      sourceError: options.sourceError ?? '',
      hasMoreResults: options.hasMoreResults ?? false,
      loadingMoreResults: options.loadingMoreResults ?? false,
      hasMoreSource: options.hasMoreSource ?? false,
    },
    global: {
      stubs: {
        ReadOnlyCodeEditor: {
          props: ['source', 'language', 'label'],
          template:
            '<pre data-testid="code-editor" :data-language="language" :aria-label="label">{{ source }}</pre>',
        },
      },
    },
  })
}

describe('DecompileResultWorkspace', () => {
  it('groups functions, classes and methods and emits the selected result id', async () => {
    const wrapper = mountWorkspace()
    const groups = wrapper.findAll('.symbol-group[role="group"]')

    expect(groups).toHaveLength(2)
    expect(groups.map((group) => group.attributes('aria-label'))).toEqual([
      'PackageVerifier',
      'Java classes',
    ])
    expect(wrapper.findAll('[role="treeitem"]')).toHaveLength(3)
    expect(wrapper.text()).toContain('函数')
    expect(wrapper.text()).toContain('类')
    expect(wrapper.text()).toContain('方法')
    expect(
      wrapper.get('[role="treeitem"][aria-selected="true"]').text(),
    ).toContain('verify_package')

    await wrapper.findAll('[role="treeitem"]')[2]?.trigger('click')

    expect(wrapper.emitted('select')).toEqual([['method']])
  })

  it('searches symbol metadata and the source loaded for the selected result', async () => {
    const wrapper = mountWorkspace({
      source:
        'bool verify_package(void) {\n  audit_marker();\n  audit_marker();\n}',
      hasMoreResults: true,
    })
    const search = wrapper.get('input[type="search"]')

    await search.setValue('classes.dex')
    expect(wrapper.findAll('[role="treeitem"]')).toHaveLength(2)
    expect(wrapper.text()).toContain('ManifestReader')
    expect(wrapper.text()).toContain('parseManifest')
    expect(wrapper.get('[role="tree"]').text()).not.toContain('verify_package')

    await search.setValue('audit_marker')
    expect(wrapper.findAll('[role="treeitem"]')).toHaveLength(1)
    expect(wrapper.get('[role="treeitem"]').text()).toContain('verify_package')
    expect(wrapper.text()).toContain('已加载代码命中 2 处')

    await search.setValue('not-present')
    expect(wrapper.find('[role="tree"]').exists()).toBe(false)
    expect(wrapper.get('[role="status"]').text()).toContain(
      '没有匹配的函数、类、方法或已加载代码',
    )
    expect(
      wrapper
        .findAll('button')
        .some((button) => button.text().includes('加载更多符号')),
    ).toBe(true)
  })

  it('filters large result sets by decompilation capability without losing counts', async () => {
    const filteredItems = [
      result('complete'),
      result('partial', { status: 'partial' }),
      result('bytecode', {
        status: 'bytecode_only',
        language: 'java bytecode',
      }),
      result('failed', { status: 'failed' }),
      result('unsupported', { status: 'unsupported' }),
    ]
    const wrapper = mountWorkspace({
      items: filteredItems,
      selectedId: 'complete',
    })

    const controls = wrapper.get('[aria-label="按反编译能力筛选"]')
    expect(controls.text()).toContain('全部5')
    expect(controls.text()).toContain('源码形态2')
    expect(controls.text()).toContain('仅字节码1')
    expect(controls.text()).toContain('异常2')

    await controls
      .findAll('button')
      .find((button) => button.text().includes('仅字节码'))
      ?.trigger('click')
    expect(wrapper.findAll('[role="treeitem"]')).toHaveLength(1)
    expect(wrapper.get('[role="treeitem"]').text()).toContain('function_bytecode')
    expect(wrapper.emitted('select')).toEqual([['bytecode']])

    await controls
      .findAll('button')
      .find((button) => button.text().includes('异常'))
      ?.trigger('click')
    expect(wrapper.findAll('[role="treeitem"]')).toHaveLength(2)
    expect(wrapper.get('[aria-pressed="true"]').text()).toContain('异常')
    expect(wrapper.emitted('select')).toEqual([['bytecode'], ['failed']])
  })

  it.each<[DecompileResultStatus, string]>([
    ['partial', '分析器仅生成部分输出'],
    ['bytecode_only', '能力已降级为字节码视图'],
    ['unsupported', '当前分析器不支持该符号或输入格式'],
  ])('explains the %s capability downgrade', (status, message) => {
    const selected = result(status, {
      status,
      diagnostics: { limitation: `${status} diagnostic` },
      language: status === 'bytecode_only' ? 'python bytecode' : 'c',
    })
    const wrapper = mountWorkspace({
      items: [selected],
      selectedId: status,
      source: status === 'unsupported' ? '' : 'LOAD_CONST 0',
    })

    expect(wrapper.text()).toContain(message)
    expect(wrapper.text()).toContain(`${status} diagnostic`)
    expect(wrapper.text()).toContain('非原始源码')
    expect(wrapper.text()).toContain(
      '此内容由反编译或字节码分析产生，不代表原始源代码。',
    )
  })

  it('maps the selected language to the read-only editor contract', () => {
    const javaResult = result('java-method', {
      symbol_kind: 'method',
      language: 'java bytecode',
      display_name: 'verify',
    })
    const wrapper = mountWorkspace({
      items: [javaResult],
      selectedId: javaResult.id,
      source: '{"name":"verify","bytecode_hex":"2ab70001b1"}',
    })
    const editor = wrapper.get('[data-testid="code-editor"]')

    expect(editor.attributes('data-language')).toBe('jvm-bytecode')
    expect(editor.attributes('aria-label')).toBe(
      '只读JVM 字节码索引反编译输出',
    )
    expect(editor.text()).toContain('"bytecode_hex":"2ab70001b1"')
  })

  it('shows a parsed JVM method index only for java-bytecode results', async () => {
    const javaResult = result('java-class', {
      symbol_kind: 'class',
      status: 'bytecode_only',
      language: 'java-bytecode',
      display_name: 'ManifestVerifier',
      diagnostics: {
        format: 'CLASS',
        method_count: 2,
        methods: [
          {
            key: 'method:first',
            name: '<init>',
            qualified_name: 'com.example.ManifestVerifier.<init>',
            descriptor: '()V',
            bytecode: { offset_bytes: 384, size_bytes: 5 },
          },
          {
            key: 'method:verify',
            name: 'verifyHeader',
            qualified_name: 'com.example.ManifestVerifier.verifyHeader',
            descriptor: '(Ljava/nio/ByteBuffer;)Z',
            bytecode: { offset_bytes: 418, size_bytes: 18 },
          },
        ],
      },
    })
    const wrapper = mountWorkspace({
      items: [javaResult],
      selectedId: javaResult.id,
      source: '{"class":{"methods":[]}}',
    })

    expect(wrapper.get('[aria-label="JVM 方法列表"]').text()).toContain(
      'verifyHeader',
    )
    expect(wrapper.get('[data-analyzer-summary]').text()).toContain('CLASS')
    expect(wrapper.get('[data-analyzer-summary]').text()).toContain('方法2')
    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain(
      '<init>',
    )
    const verifyMethod = wrapper
      .findAll('[data-bytecode-method]')
      .find((method) => method.text().includes('verifyHeader'))
    if (!verifyMethod) throw new Error('verify method row missing')
    await verifyMethod.trigger('click')
    expect(verifyMethod.attributes('tabindex')).toBe('0')
    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain(
      'verifyHeader',
    )
    expect(wrapper.get('[aria-label="当前 JVM 方法摘要"]').text()).toContain(
      '418',
    )

    await wrapper.setProps({
      items: [result('native', { diagnostics: javaResult.diagnostics })],
      selectedId: 'native',
    })
    expect(wrapper.find('[aria-label="JVM 方法列表"]').exists()).toBe(false)
  })

  it('resets the method search when the selected JVM result changes', async () => {
    const diagnostics = {
      methods: [{ key: 'method:first', name: 'first' }],
    }
    const first = result('first-class', {
      status: 'bytecode_only', language: 'java bytecode', diagnostics,
    })
    const second = result('second-class', {
      status: 'bytecode_only', language: 'java bytecode', diagnostics,
    })
    const wrapper = mountWorkspace({
      items: [first, second], selectedId: first.id, source: '{}',
    })
    await wrapper.get('input[placeholder="搜索 JVM 方法"]').setValue('missing')

    await wrapper.setProps({ selectedId: second.id })

    expect((wrapper.get('input[placeholder="搜索 JVM 方法"]').element as HTMLInputElement).value).toBe('')
  })

  it('replaces structured analyzer fields when the selected result changes', async () => {
    const dex = result('dex-summary', {
      language: 'smali',
      diagnostics: {
        engine: 'JADX 1.5',
        format: 'DEX',
        dex_file_count: 2,
        class_count: 684,
        method_count: 4_218,
        warning_count: 1,
        warnings: ['One external class was not provided'],
      },
    })
    const pyc = result('pyc-summary', {
      language: 'python bytecode',
      diagnostics: {
        format: 'PYC',
        python_version: '3.12',
        magic: 'cb0d0d0a',
        header_size: 16,
        code_object_count: 5,
      },
    })
    const native = result('native-summary', {
      diagnostics: { message: 'No structured analyzer fields' },
    })
    const wrapper = mountWorkspace({
      items: [dex, pyc, native],
      selectedId: dex.id,
      source: 'smali output',
    })

    let summary = wrapper.get('[data-analyzer-summary]')
    expect(summary.text()).toContain('JADX 1.5')
    expect(summary.text()).toContain('4,218')
    expect(summary.text()).not.toContain('Python 版本')

    await wrapper.setProps({ selectedId: pyc.id })
    summary = wrapper.get('[data-analyzer-summary]')
    expect(summary.text()).toContain('Python 版本')
    expect(summary.text()).toContain('3.12')
    expect(summary.text()).toContain('16 B')
    expect(summary.text()).not.toContain('JADX 1.5')
    expect(summary.text()).not.toContain('4,218')

    await wrapper.setProps({ selectedId: native.id })
    expect(wrapper.find('[data-analyzer-summary]').exists()).toBe(false)
  })

  it('does not retain a summary when diagnostics change under the same result id', async () => {
    const first = result('same-result', {
      diagnostics: { format: 'DEX', method_count: 8 },
    })
    const wrapper = mountWorkspace({
      items: [first],
      selectedId: first.id,
    })

    expect(wrapper.get('[data-analyzer-summary]').text()).toContain('DEX')
    await wrapper.setProps({
      items: [result(first.id, { diagnostics: { message: 'No summary fields' } })],
    })

    expect(wrapper.find('[data-analyzer-summary]').exists()).toBe(false)
  })

  it('bounds and neutralizes analyzer diagnostic previews', () => {
    const wrapper = mountWorkspace({
      items: [result('diagnostic', {
        diagnostics: {
          message: `warning\u061c\u2028\u202e\u2060\u2069\ufeff\u0000${'x'.repeat(5_000)}`,
        },
      })],
      selectedId: 'diagnostic',
    })

    const preview = wrapper.get('.capability-warning span').text()
    expect(preview).not.toContain('\u202e')
    expect(preview).not.toContain('\u061c')
    expect(preview).not.toContain('\u2028')
    expect(preview).not.toContain('\u2060')
    expect(preview).not.toContain('\u2069')
    expect(preview).not.toContain('\ufeff')
    expect(preview).not.toContain('\u0000')
    expect(preview.length).toBeLessThanOrEqual(4_099)
  })

  it('emits pagination commands and locks each command while loading', async () => {
    const wrapper = mountWorkspace({
      hasMoreResults: true,
      hasMoreSource: true,
    })
    const loadResults = wrapper
      .findAll('button')
      .find((button) => button.text().includes('加载更多符号'))
    const loadSource = wrapper
      .findAll('button')
      .find((button) => button.text().includes('继续读取'))
    if (!loadResults || !loadSource) throw new Error('pagination controls missing')

    await loadResults.trigger('click')
    await loadSource.trigger('click')
    expect(wrapper.emitted('loadMoreResults')).toHaveLength(1)
    expect(wrapper.emitted('loadMoreSource')).toHaveLength(1)

    await wrapper.setProps({
      loadingMoreResults: true,
      sourceLoading: true,
    })
    expect(loadResults.attributes('disabled')).toBeDefined()
    expect(loadResults.attributes('aria-busy')).toBe('true')
    expect(loadSource.attributes('disabled')).toBeDefined()
    expect(loadSource.attributes('aria-busy')).toBe('true')
  })

  it('keeps explicit loading and error states when no source is available', async () => {
    const wrapper = mountWorkspace({
      source: '',
      sourceLoading: true,
    })

    expect(wrapper.get('.code-panel__state[role="status"]').text()).toContain(
      '正在安全读取反编译输出',
    )

    await wrapper.setProps({
      sourceLoading: false,
      sourceError: '源码分片校验失败',
    })
    expect(wrapper.get('.code-panel__state[role="alert"]').text()).toContain(
      '源码分片校验失败',
    )
  })
})
