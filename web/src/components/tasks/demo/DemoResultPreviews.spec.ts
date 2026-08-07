import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'

import DemoDecompileResult from '@/components/tasks/demo/DemoDecompileResult.vue'
import DemoReportResult from '@/components/tasks/demo/DemoReportResult.vue'
import DemoVulnerabilityResult from '@/components/tasks/demo/DemoVulnerabilityResult.vue'
import { resolveDemoDecompileView } from '@/components/tasks/demo/demoResultFixtures'

function watchForHttpRequests() {
  return vi.spyOn(globalThis, 'fetch')
}

describe('demo task result previews', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('filters symbols and switches the read-only pseudo C example without HTTP', async () => {
    const fetchSpy = watchForHttpRequests()
    const wrapper = mount(DemoDecompileResult, {
      props: {
        taskId: 'demo-task',
        taskName: 'gateway-agent.exe',
        inputType: 'pe32+',
      },
    })

    expect(wrapper.text()).toContain('固定示例数据')
    expect(wrapper.text()).toContain('伪 C')
    expect(wrapper.text()).toContain('伪 C 非原始源码')
    expect(wrapper.text()).toContain('未连接真实反编译引擎')
    expect(wrapper.text()).toContain('verify_package_header')

    await wrapper.get('input[type="search"]').setValue('unpack')

    expect(wrapper.findAll('[data-demo-symbol]')).toHaveLength(1)
    await wrapper.get('[data-demo-symbol]').trigger('click')
    expect(wrapper.get('.code-panel__source').text()).toContain('ERROR_UNSAFE_PATH')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    ['pe32+', 'Native 反编译视图', '函数树', '伪 C'],
    ['class', 'JVM 类与方法索引', '类 / 方法树', 'bytecode_hex'],
    ['apk', 'DEX / Smali 视图', 'DEX 类 / 方法树', 'Smali'],
    ['pyc', 'PYC 字节码视图', '模块 / 函数树', 'Python 字节码'],
  ])(
    'selects the %s decompile capability from input type',
    (inputType, title, treeLabel, sourceMarker) => {
      const fetchSpy = watchForHttpRequests()
      const wrapper = mount(DemoDecompileResult, {
        props: {
          taskId: `demo-${inputType}`,
          taskName: `sample.${inputType}`,
          inputType,
        },
      })

      expect(wrapper.text()).toContain(title)
      expect(wrapper.text()).toContain(treeLabel)
      expect(wrapper.text()).toContain(sourceMarker)
      expect(wrapper.get('.code-panel__source').attributes('tabindex')).toBe('0')
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )

  it('exposes the searchable JVM method index in the standalone JAR preview', async () => {
    const fetchSpy = watchForHttpRequests()
    const wrapper = mount(DemoDecompileResult, {
      props: {
        taskId: 'demo-jar',
        taskName: 'update-verifier.jar',
        inputType: 'jar',
      },
    })

    expect(wrapper.get('[aria-label="JVM 方法列表"]').text()).toContain(
      'verifyHeader',
    )
    const methodSearch = wrapper.get('input[placeholder="搜索 JVM 方法"]')
    await methodSearch.setValue('Policy')
    expect(wrapper.findAll('[data-bytecode-method]')).toHaveLength(1)
    await wrapper.get('[data-bytecode-method]').trigger('click')
    const detail = wrapper.get('[aria-label="当前 JVM 方法摘要"]')
    expect(detail.text()).toContain('verifyPolicy')
    expect(detail.text()).toContain('(Lcom/binaryscan/update/Policy;)Z')
    expect(detail.text()).toContain('无 Code 属性')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it.each([
    [
      'apk',
      ['JADX 字段契约示例', 'DEX 文件', '2', '方法', '4,218'],
    ],
    [
      'pyc',
      ['PYC 字段契约示例', 'Python 版本', '3.12', 'Magic', 'cb0d0d0a', '16 B'],
    ],
  ])('shows an explicitly marked %s analyzer summary fixture', (inputType, expected) => {
    const wrapper = mount(DemoDecompileResult, {
      props: {
        taskId: `demo-${inputType}`,
        taskName: `sample.${inputType}`,
        inputType,
      },
    })

    const summary = wrapper.get('[data-analyzer-summary]')
    expect(summary.text()).toContain('分析器上报')
    expect(summary.get('[role="note"]').text()).toContain('固定示例')
    expect(summary.get('[role="note"]').text()).toContain('非真实结果')
    for (const value of expected) expect(summary.text()).toContain(value)
  })

  it('keeps JVM method summaries consistent with the fixed JSON fixture', () => {
    const classUnit = resolveDemoDecompileView('jar').units.find(
      (unit) => unit.id === 'java-manifest-class',
    )
    if (!classUnit?.methods) throw new Error('JVM class fixture missing')
    const source = JSON.parse(classUnit.source) as {
      class: { methods: Array<{ name: string; descriptor: string; code?: { offset_bytes: number; size_bytes: number; bytecode_hex: string } }> }
    }

    for (const summary of classUnit.methods) {
      const raw = source.class.methods.find(
        (method) => method.name === summary.name && method.descriptor === summary.descriptor,
      )
      expect(raw).toBeDefined()
      expect(raw?.code?.offset_bytes).toBe(summary.bytecode?.offsetBytes)
      expect(raw?.code?.size_bytes).toBe(summary.bytecode?.sizeBytes)
      if (raw?.code) expect(raw.code.bytecode_hex.length / 2).toBe(raw.code.size_bytes)
    }
  })

  it('filters the example vulnerability table by severity without HTTP', async () => {
    const fetchSpy = watchForHttpRequests()
    const wrapper = mount(DemoVulnerabilityResult, {
      props: {
        taskId: 'demo-task',
        taskName: 'payment-service-oci.tar',
      },
    })

    expect(wrapper.text()).toContain('CVE-DEMO-*')
    expect(wrapper.findAll('[data-demo-finding]')).toHaveLength(6)

    await wrapper.get('[data-severity-filter="CRITICAL"]').trigger('click')

    expect(wrapper.findAll('[data-demo-finding]')).toHaveLength(2)
    expect(wrapper.text()).toContain('CVE-DEMO-0001')
    expect(wrapper.text()).not.toContain('CVE-DEMO-0003')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('selects vulnerability details with the keyboard and exposes offline evidence', async () => {
    const fetchSpy = watchForHttpRequests()
    const wrapper = mount(DemoVulnerabilityResult, {
      props: {
        taskId: 'demo-task',
        taskName: 'payment-service-oci.tar',
      },
    })

    const rows = wrapper.findAll('[data-demo-finding]')
    const firstRow = rows[0]
    if (!firstRow) throw new Error('Expected at least one demo vulnerability row')
    expect(firstRow.attributes('aria-selected')).toBe('true')
    expect(wrapper.get('#demo-finding-detail').text()).toContain('libssl3')
    expect(wrapper.get('#demo-finding-detail').text()).toContain('3.0.15-r1')

    await firstRow.trigger('keydown', { key: 'ArrowDown' })

    const secondRow = wrapper.findAll('[data-demo-finding]')[1]
    if (!secondRow) throw new Error('Expected a second demo vulnerability row')
    expect(secondRow.attributes('aria-selected')).toBe('true')
    expect(wrapper.get('#demo-finding-detail').text()).toContain('busybox')
    expect(wrapper.get('.evidence-panel').text()).toContain('/lib/apk/db/installed')
    expect(wrapper.get('.evidence-panel pre').text()).toContain('P:busybox')
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('keeps JSON and HTML report downloads disabled and shows limit snapshots', () => {
    const fetchSpy = watchForHttpRequests()
    const wrapper = mount(DemoReportResult, {
      props: {
        taskId: 'demo-task',
        taskName: 'gateway-firmware.tar',
        inputType: 'tar',
        taskStatus: 'SUCCEEDED',
      },
    })

    expect(wrapper.text()).toContain('binaryscan-report.json')
    expect(wrapper.text()).toContain('binaryscan-report.html')
    expect(wrapper.text()).toContain('10 GB')
    expect(wrapper.text()).toContain('20,000')
    expect(wrapper.text()).toContain('不会生成、写入或导出')
    expect(wrapper.findAll('[data-report-section]')).toHaveLength(4)
    expect(wrapper.text()).toContain('任务摘要')
    expect(wrapper.text()).toContain('限制与证据')

    const jsonPreview = JSON.parse(wrapper.get('.json-preview').text()) as {
      schema: string
      task: { id: string; input_type: string }
    }
    expect(jsonPreview.schema).toBe('binaryscan.demo.report/v1')
    expect(jsonPreview.task).toEqual(
      expect.objectContaining({ id: 'demo-task', input_type: 'tar' }),
    )

    const downloadButtons = wrapper.findAll('.artifact-row__download')
    expect(downloadButtons).toHaveLength(2)
    expect(downloadButtons.every((button) => button.attributes('disabled') !== undefined)).toBe(true)
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
