import {
  expect,
  expectNoPageOverflow,
  taskUrl,
  test,
} from './fixtures'

const taskIds = {
  firmware: '11111111-1111-4111-8111-111111111111',
  container: '22222222-2222-4222-8222-222222222222',
  executable: '33333333-3333-4333-8333-333333333333',
  jar: '55555555-5555-4555-8555-555555555555',
  apk: '66666666-6666-4666-8666-666666666666',
} as const

async function openFirmwareBinary(page: import('@playwright/test').Page): Promise<void> {
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('button', { name: '展开 gateway-firmware.tar' }).click()
  await page.getByRole('button', { name: '展开 bin' }).click()
  await page.getByRole('button', { name: '查看 gatewayd 的节点详情' }).click()
  await expect(page.getByRole('complementary', { name: '文件节点详情' })).toContainText(
    'gatewayd',
  )
}

test('任务列表、任务详情和递归文件树交互 @mobile', async (
  { page },
  testInfo,
) => {
  await page.goto('/tasks')
  await expect(page.getByRole('heading', { name: '检测任务' })).toBeVisible()
  await expect(
    page.getByRole('region', { name: '任务列表，可横向滚动查看全部字段' }),
  ).toBeVisible()
  await page.getByRole('button', { name: '查看任务：gateway-firmware.tar' }).click()

  await expect(page.getByRole('heading', { name: '任务详情' })).toBeVisible()
  await openFirmwareBinary(page)
  const detail = page.getByRole('complementary', { name: '文件节点详情' })
  await expect(detail.getByText('elf64', { exact: true })).toBeVisible()
  await expect(detail.getByText('x86_64', { exact: true })).toBeVisible()
  await expect(detail.getByText('ET_DYN', { exact: true })).toBeVisible()
  const sourceCommand = detail.getByRole('button', {
    name: /打开来源容器 .*rootfs\.ext4/,
  })
  await expect(sourceCommand).toBeVisible()
  await expect(sourceCommand).toHaveAttribute(
    'title',
    /verified-release-candidate-2026-07\/rootfs\.ext4/,
  )
  await page.screenshot({
    path: testInfo.outputPath('file-provenance.png'),
    fullPage: true,
  })
  await expectNoPageOverflow(page)

  await sourceCommand.focus()
  await page.keyboard.press('Enter')
  await expect(detail).toContainText('rootfs.ext4')
  await expect(detail.getByText('ext4', { exact: true }).first()).toBeVisible()
  await expectNoPageOverflow(page)
})

test('任务详情按工作流显示紧凑阶段页 @mobile', async ({ page }, testInfo) => {
  await page.goto(taskUrl(taskIds.executable))
  await expect(page.getByRole('heading', { name: '任务详情' })).toBeVisible()

  const stages = page.getByRole('region', { name: '阶段进度' })
  await expect(stages.getByText('类 C 反编译', { exact: true })).toBeVisible()
  await expect(stages.getByText(/尚未收到反编译执行日志/)).toBeVisible()
  await expect(page.getByRole('tab', { name: '执行进度', exact: true })).toHaveAttribute(
    'aria-selected',
    'true',
  )
  await expect(page.getByRole('tab', { name: '检测结果', exact: true })).toBeVisible()
  await expect(page.getByRole('tab', { name: '任务信息', exact: true })).toBeVisible()
  await page.screenshot({
    path: testInfo.outputPath('progress-indeterminate.png'),
    fullPage: true,
  })
  await expectNoPageOverflow(page)
})

test('反编译入口门禁与只读类 C 代码预览 @mobile', async ({ page }) => {
  await page.goto(taskUrl(taskIds.firmware))
  await openFirmwareBinary(page)

  const requestButton = page.locator('[data-action="decompile-file"]')
  await expect(requestButton).toBeVisible()
  await expect(requestButton).toBeDisabled()
  await expect(requestButton).toHaveAttribute(
    'title',
    /界面预览不会提交真实反编译任务/,
  )

  await page.goto(taskUrl(taskIds.executable))
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('tab', { name: '反编译' }).click()
  await expect(page.getByText('未连接真实反编译引擎')).toBeVisible()
  await expect(
    page.getByText('以下为固定示例数据，不来自扫描引擎，也不代表当前任务的真实检测结论。'),
  ).toBeVisible()

  const symbolSearch = page.getByPlaceholder('搜索名称、签名或代码')
  await symbolSearch.fill('verify')
  const symbols = page.locator('[data-demo-symbol]')
  await expect(symbols.first()).toBeVisible()
  await symbols.first().click()
  await expect(page.getByText('只读', { exact: true })).toBeVisible()
  await expectNoPageOverflow(page)
})

test('JAR 任务展示 JVM 字节码降级视图 @mobile', async ({ page }, testInfo) => {
  await page.goto(taskUrl(taskIds.jar))
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('tab', { name: '反编译' }).click()

  await expect(page.getByText('JVM 类与方法索引')).toBeVisible()
  await expect(page.getByText('JVM 字节码', { exact: true })).toBeVisible()
  await expect(
    page.getByText('能力已降级为字节码索引；当前未接入 Java 源码反编译器。'),
  ).toBeVisible()
  const methodIndex = page.getByRole('region', { name: 'JVM 方法索引' })
  await expect(methodIndex).toBeVisible()
  const methodSearch = methodIndex.getByPlaceholder('搜索 JVM 方法')
  await methodSearch.fill('Policy')
  await expect(methodIndex.getByRole('option')).toHaveCount(1)
  await methodIndex.getByRole('option').click()
  await expect(
    methodIndex.getByRole('region', { name: '当前 JVM 方法摘要' }),
  ).toContainText('无 Code 属性')

  await methodSearch.fill('')
  await methodSearch.press('ArrowDown')
  await page.keyboard.press('ArrowDown')
  await expect(
    methodIndex.getByRole('region', { name: '当前 JVM 方法摘要' }),
  ).toContainText('verifyHeader')
  await expect(methodIndex).toContainText('(Ljava/nio/ByteBuffer;)Z')
  await expect(methodIndex).toContainText('Code +418')
  await expect(page.locator('.read-only-editor')).toBeVisible()
  await expect(
    page.getByText(/Monaco 只读编辑器已就绪|当前环境使用安全只读文本/),
  ).toBeVisible()
  await page.screenshot({
    path: testInfo.outputPath('jvm-bytecode-fallback.png'),
    fullPage: true,
  })
  await expectNoPageOverflow(page)
})

test('APK 任务展示明确标记的 DEX 结构化摘要 @mobile', async ({ page }, testInfo) => {
  await page.goto(taskUrl(taskIds.apk))
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('tab', { name: '反编译' }).click()

  const summary = page.locator('[data-analyzer-summary]')
  await expect(summary).toBeVisible()
  await expect(summary).toContainText('分析器上报')
  await expect(summary).toContainText('固定示例 · 非真实结果')
  await expect(summary).toContainText('JADX 字段契约示例')
  await expect(summary).toContainText('DEX 文件')
  await expect(summary).toContainText('4,218')
  await expect(summary).toContainText('缺失类')
  await page.screenshot({
    path: testInfo.outputPath('dex-analyzer-summary.png'),
    fullPage: true,
  })
  await expectNoPageOverflow(page)
})

test('新建 PYC 示例任务展示字节码头摘要 @mobile', async ({ page }, testInfo) => {
  await page.goto('/tasks/new')
  await page.getByLabel('选择待检测文件').setInputFiles({
    name: 'playwright-contract.pyc',
    mimeType: 'application/x-python-code',
    buffer: Buffer.from('pyc-demo-contract'),
  })
  await page.getByRole('button', { name: '开始上传' }).click()
  const queue = page.getByRole('list', { name: '上传队列' })
  await expect(queue.getByText('任务已创建')).toBeVisible()
  await queue.getByRole('button', { name: '查看任务', exact: true }).click()
  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('tab', { name: '反编译' }).click()

  const summary = page.locator('[data-analyzer-summary]')
  await expect(summary).toBeVisible()
  await expect(summary).toContainText('固定示例 · 非真实结果')
  await expect(summary).toContainText('Python 版本')
  await expect(summary).toContainText('3.12')
  await expect(summary).toContainText('cb0d0d0a')
  await expect(summary).toContainText('16 B')
  await page.screenshot({
    path: testInfo.outputPath('pyc-analyzer-summary.png'),
    fullPage: true,
  })
  await expectNoPageOverflow(page)
})

test('容器漏洞筛选与 JSON、HTML 报告预览', async ({ page }) => {
  await page.goto(taskUrl(taskIds.container))
  await expect(page.getByRole('heading', { name: '任务详情' })).toBeVisible()
  await expect(page.getByText('镜像漏洞扫描', { exact: true })).toBeVisible()

  await page.getByRole('tab', { name: '检测结果', exact: true }).click()
  await page.getByRole('tab', { name: '容器漏洞' }).click()
  const findings = page.getByRole('grid', { name: '固定示例容器漏洞' })
  await expect(findings).toBeVisible()
  await page.locator('[data-severity-filter="HIGH"]').click()
  await expect(page.locator('[data-demo-finding]')).toHaveCount(2)
  await expect(page.getByText('固定示例数据', { exact: false }).first()).toBeVisible()

  await page.getByRole('tab', { name: '报告' }).click()
  await expect(page.getByRole('heading', { name: '报告产物示例' })).toBeVisible()
  await expect(page.getByLabel('只读 JSON 报告固定结构预览')).toContainText(
    'binaryscan.demo.report/v1',
  )
  await expect(page.getByRole('navigation', { name: 'HTML 报告固定目录预览' })).toBeVisible()
  await expect(
    page.getByRole('button', { name: '下载 JSON 报告（后端未接入）' }),
  ).toBeDisabled()
  await expect(
    page.getByRole('button', { name: '下载 HTML 报告（后端未接入）' }),
  ).toBeDisabled()
  await expectNoPageOverflow(page)
})

test('报告工作区选择原始 JSON 或 gzip 交付 @mobile', async ({ page }) => {
  await page.goto('/e2e/report-workspace.html')
  const jsonReport = page.getByRole('region', { name: 'JSON 报告' })
  await expect(jsonReport).toContainText('样本已到期')

  await jsonReport.getByLabel('JSON 下载格式').selectOption('gzip')
  await jsonReport.getByRole('button', { name: '下载 压缩 JSON 报告' }).click()
  await expect(page.getByLabel('报告下载选择结果')).toHaveText('json:gzip')

  await jsonReport.getByLabel('JSON 下载格式').selectOption('identity')
  await jsonReport.getByRole('button', { name: '下载 JSON 报告' }).click()
  await expect(page.getByLabel('报告下载选择结果')).toHaveText('json:identity')
  await expectNoPageOverflow(page)
})
