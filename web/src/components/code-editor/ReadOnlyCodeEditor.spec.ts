import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import ReadOnlyCodeEditor from '@/components/code-editor/ReadOnlyCodeEditor.vue'

const loaderMocks = vi.hoisted(() => ({
  load: vi.fn(),
  supportsRuntime: vi.fn(),
}))

vi.mock('@/components/code-editor/monacoLoader', () => ({
  loadMonacoEditor: loaderMocks.load,
  resolveMonacoLanguage: (language: string) =>
    ({
      c: 'cpp',
      java: 'java',
      'jvm-bytecode': 'jvm-bytecode',
      smali: 'smali',
      'python-bytecode': 'python-bytecode',
    })[language],
  supportsMonacoRuntime: loaderMocks.supportsRuntime,
}))

function createEditorFixture() {
  const findAction = { run: vi.fn().mockResolvedValue(undefined) }
  const model = {}
  const editor = {
    dispose: vi.fn(),
    focus: vi.fn(),
    getAction: vi.fn(() => findAction),
    getModel: vi.fn(() => model),
    getValue: vi.fn(() => 'int main(void) { return 0; }'),
    setValue: vi.fn(),
    updateOptions: vi.fn(),
  }
  const monaco = {
    editor: {
      create: vi.fn(() => editor),
      setModelLanguage: vi.fn(),
    },
  }
  return { editor, findAction, model, monaco }
}

describe('ReadOnlyCodeEditor', () => {
  beforeEach(() => {
    loaderMocks.load.mockReset()
    loaderMocks.supportsRuntime.mockReset()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('keeps an accessible read-only pre fallback without a Worker runtime', async () => {
    loaderMocks.supportsRuntime.mockReturnValue(false)
    const wrapper = mount(ReadOnlyCodeEditor, {
      props: {
        source: 'LOAD_CONST 0',
        language: 'python-bytecode',
        label: '只读 Python 字节码',
      },
    })
    await flushPromises()

    expect(loaderMocks.load).not.toHaveBeenCalled()
    expect(wrapper.attributes('data-editor-state')).toBe('fallback')
    expect(wrapper.get('.code-panel__source').text()).toContain('LOAD_CONST 0')
    expect(wrapper.get('.code-panel__source').attributes('tabindex')).toBe('0')
    expect(wrapper.get('[role="status"]').text()).toContain('安全只读文本')
  })

  it('falls back safely when the lazy Monaco import fails', async () => {
    loaderMocks.supportsRuntime.mockReturnValue(true)
    loaderMocks.load.mockRejectedValue(new Error('chunk unavailable'))
    const wrapper = mount(ReadOnlyCodeEditor, {
      props: {
        source: '.method public verify()V',
        language: 'smali',
        label: '只读 Smali',
      },
    })
    await flushPromises()

    expect(wrapper.attributes('data-editor-state')).toBe('error')
    expect(wrapper.get('.code-panel__source').text()).toContain('.method')
    expect(wrapper.text()).toContain('已切换到安全只读文本')
    expect(wrapper.text()).not.toContain('chunk unavailable')
  })

  it('creates a read-only editor, updates props, opens find and disposes', async () => {
    loaderMocks.supportsRuntime.mockReturnValue(true)
    const fixture = createEditorFixture()
    loaderMocks.load.mockResolvedValue(fixture.monaco)
    const wrapper = mount(ReadOnlyCodeEditor, {
      props: {
        source: 'int main(void) { return 0; }',
        language: 'c',
        label: '只读伪 C',
      },
    })
    await flushPromises()

    expect(fixture.monaco.editor.create).toHaveBeenCalledWith(
      expect.any(HTMLElement),
      expect.objectContaining({
        value: 'int main(void) { return 0; }',
        language: 'cpp',
        readOnly: true,
        domReadOnly: true,
        automaticLayout: true,
        minimap: { enabled: false },
      }),
    )
    expect(wrapper.attributes('data-editor-state')).toBe('ready')
    expect(wrapper.find('.code-panel__source').exists()).toBe(false)

    await wrapper.setProps({
      source: 'public class Main {}',
      language: 'java',
      label: '只读 Java',
    })
    expect(fixture.editor.setValue).toHaveBeenCalledWith('public class Main {}')
    expect(fixture.monaco.editor.setModelLanguage).toHaveBeenCalledWith(
      fixture.model,
      'java',
    )
    expect(fixture.editor.updateOptions).toHaveBeenCalledWith({
      ariaLabel: '只读 Java',
    })

    await wrapper.get('button[aria-label="在代码中查找"]').trigger('click')
    expect(fixture.editor.focus).toHaveBeenCalled()
    expect(fixture.findAction.run).toHaveBeenCalled()

    wrapper.unmount()
    expect(fixture.editor.dispose).toHaveBeenCalled()
  })
})
