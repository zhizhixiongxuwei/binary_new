import type { BytecodeMethodIndexEntry } from '@/components/tasks/results/jvmMethodIndex'

export type DemoSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type DemoDecompileViewKind = 'native' | 'jvm' | 'dex' | 'pyc'
export type DemoCodeUnitKind = 'function' | 'class' | 'method' | 'module'

export interface DemoCodeUnit {
  id: string
  group: string
  name: string
  kind: DemoCodeUnitKind
  location: string
  detail: string
  signature: string
  source: string
  methods?: readonly BytecodeMethodIndexEntry[]
}

export interface DemoDecompileView {
  kind: DemoDecompileViewKind
  title: string
  treeLabel: string
  unitLabel: string
  languageBadge: string
  capability: string
  limitation: string
  analyzerDiagnostics?: unknown
  units: readonly DemoCodeUnit[]
}

export interface DemoVulnerabilityFinding {
  id: string
  severity: DemoSeverity
  cve: string
  title: string
  packageName: string
  installedVersion: string
  fixedVersion: string
  evidence: string
  evidenceExcerpt: string
  scannerSource: string
  description: string
}

export interface DemoReportArtifact {
  format: 'JSON' | 'HTML'
  filename: string
  size: string
  description: string
}

export interface DemoHtmlReportSection {
  id: string
  number: string
  title: string
  summary: string
}

const NATIVE_VIEW = {
  kind: 'native',
  title: 'Native 反编译视图',
  treeLabel: '函数树',
  unitLabel: '函数',
  languageBadge: '伪 C',
  capability: '适用于 EXE、DLL、SYS、ELF 与 Mach-O 的界面能力样例',
  limitation: '伪 C 非原始源码；类型、变量名和控制流均可能因反编译而失真。',
  units: [
    {
      id: 'verify-package-header',
      group: '.text / validation',
      name: 'verify_package_header',
      kind: 'function',
      location: '0x140001420',
      detail: '376 B · 7 calls',
      signature: 'bool verify_package_header(const uint8_t *buffer, size_t length)',
      source: `bool verify_package_header(const uint8_t *buffer, size_t length)
{
    uint32_t expected_magic;
    uint32_t declared_size;

    if (buffer == NULL || length < 0x20) {
        return false;
    }

    expected_magic = read_u32_le(buffer);
    declared_size = read_u32_le(buffer + 8);
    if (expected_magic != PACKAGE_MAGIC) {
        log_validation_error("header magic");
        return false;
    }

    return declared_size <= length && verify_header_crc(buffer, 0x20);
}`,
    },
    {
      id: 'apply-update-policy',
      group: '.text / policy',
      name: 'apply_update_policy',
      kind: 'function',
      location: '0x1400017A0',
      detail: '592 B · 11 calls',
      signature: 'int apply_update_policy(struct update_context *context)',
      source: `int apply_update_policy(struct update_context *context)
{
    int policy_result;

    if (context == NULL || context->manifest == NULL) {
        return ERROR_INVALID_ARGUMENT;
    }

    policy_result = compare_release_counter(
        context->manifest->release_counter,
        context->device_state->release_counter
    );
    if (policy_result < 0 && !context->allow_rollback) {
        return ERROR_POLICY_REJECTED;
    }

    return validate_target_partition(context->manifest);
}`,
    },
    {
      id: 'unpack-manifest-entry',
      group: '.text / archive',
      name: 'unpack_manifest_entry',
      kind: 'function',
      location: '0x140002110',
      detail: '448 B · 5 calls',
      signature: 'int unpack_manifest_entry(struct archive *archive, struct entry *entry)',
      source: `int unpack_manifest_entry(struct archive *archive, struct entry *entry)
{
    char normalized_path[PATH_LIMIT];
    int result;

    result = normalize_relative_path(entry->name, normalized_path);
    if (result != 0 || path_escapes_root(normalized_path)) {
        return ERROR_UNSAFE_PATH;
    }
    if (entry->expanded_size > archive->remaining_budget) {
        return ERROR_SIZE_LIMIT;
    }

    return copy_entry_bounded(archive, entry, normalized_path);
}`,
    },
  ],
} as const satisfies DemoDecompileView

const JAVA_VIEW = {
  kind: 'jvm',
  title: 'JVM 类与方法索引',
  treeLabel: '类 / 方法树',
  unitLabel: '类与方法',
  languageBadge: 'JVM 字节码',
  capability: '适用于 CLASS、JAR 与 multi-release JAR 的字节码索引样例',
  limitation: '能力已降级为字节码索引；当前未接入 Java 源码反编译器。',
  units: [
    {
      id: 'java-manifest-class',
      group: 'com.binaryscan.update',
      name: 'ManifestVerifier',
      kind: 'class',
      location: 'ManifestVerifier.class',
      detail: 'class · Java 17',
      signature: 'com.binaryscan.update.ManifestVerifier',
      methods: [
        {
          key: 'method:02ac721e4c94be5c',
          name: '<init>',
          qualifiedName: 'com.binaryscan.update.ManifestVerifier.<init>',
          descriptor: '()V',
          signature: '',
          bytecode: { offsetBytes: 384, sizeBytes: 5 },
        },
        {
          key: 'method:7ca0ac892c61175f',
          name: 'verifyHeader',
          qualifiedName: 'com.binaryscan.update.ManifestVerifier.verifyHeader',
          descriptor: '(Ljava/nio/ByteBuffer;)Z',
          signature: '',
          bytecode: { offsetBytes: 418, sizeBytes: 19 },
        },
        {
          key: 'method:d9251abf9bca48f1',
          name: 'verifyPolicy',
          qualifiedName: 'com.binaryscan.update.ManifestVerifier.verifyPolicy',
          descriptor: '(Lcom/binaryscan/update/Policy;)Z',
          signature: '',
        },
      ],
      source: `{
  "schema_version": "binaryscan.jvm-bytecode-index.v1",
  "kind": "jvm_class_bytecode_index",
  "target_java_release": 21,
  "class": {
    "entry_path": "com/binaryscan/update/ManifestVerifier.class",
    "selected_release": 0,
    "binary_name": "com.binaryscan.update.ManifestVerifier",
    "major_version": 61,
    "methods": [
      {
        "name": "<init>",
        "descriptor": "()V",
        "code": {
          "offset_bytes": 384,
          "size_bytes": 5,
          "bytecode_hex": "2ab70001b1"
        }
      },
      {
        "name": "verifyHeader",
        "descriptor": "(Ljava/nio/ByteBuffer;)Z",
        "code": {
          "offset_bytes": 418,
            "size_bytes": 19,
          "bytecode_hex": "2ac7000503ac2ab6000c1020a1000503ac04ac"
        }
      },
      {
        "name": "verifyPolicy",
        "descriptor": "(Lcom/binaryscan/update/Policy;)Z"
      }
    ]
  }
}`,
    },
    {
      id: 'java-verify-method',
      group: 'com.binaryscan.update / ManifestVerifier',
      name: 'verifyHeader',
      kind: 'method',
      location: 'Code attribute +418',
      detail: '19 B · 固定 SHA-256 示例',
      signature: 'verifyHeader(Ljava/nio/ByteBuffer;)Z',
      source: `{
  "name": "verifyHeader",
  "descriptor": "(Ljava/nio/ByteBuffer;)Z",
  "access_flags": 9,
  "code": {
    "offset_bytes": 418,
    "size_bytes": 19,
    "sha256": "cd3b41172e4a52f9650b1c32efd88ea3d9c3df2d315b5dbde102f0e03a33996a",
    "bytecode_hex": "2ac7000503ac2ab6000c1020a1000503ac04ac"
  }
}`,
    },
    {
      id: 'java-policy-method',
      group: 'com.binaryscan.update / UpdatePolicy',
      name: 'allowsInstall',
      kind: 'method',
      location: 'META-INF/versions/17/.../UpdatePolicy.class',
      detail: 'multi-release 17 · 24 B',
      signature: 'allowsInstall(LManifest;LState;)Z',
      source: `{
  "entry_path": "META-INF/versions/17/com/binaryscan/update/UpdatePolicy.class",
  "selected_release": 17,
  "binary_name": "com.binaryscan.update.UpdatePolicy",
  "method": {
    "name": "allowsInstall",
    "descriptor": "(LManifest;LState;)Z",
    "code": {
      "offset_bytes": 672,
      "size_bytes": 27,
      "bytecode_hex": "2bc600142cc600102bb9001201002cb900180100a2000503ac04ac"
    }
  }
}`,
    },
  ],
} as const satisfies DemoDecompileView

const DEX_VIEW = {
  kind: 'dex',
  title: 'DEX / Smali 视图',
  treeLabel: 'DEX 类 / 方法树',
  unitLabel: '类与方法',
  languageBadge: 'Smali',
  capability: '适用于 APK 与 DEX 方法结构的界面能力样例',
  limitation: '能力降级：当前仅展示 Smali 级指令形态，不承诺还原为高层 Java/Kotlin 源码。',
  analyzerDiagnostics: {
    engine: 'JADX 字段契约示例',
    format: 'DEX',
    dex_file_count: 2,
    class_count: 684,
    method_count: 4_218,
    missing_class_count: 3,
    error_count: 0,
    warning_count: 2,
    errors: [],
    warnings: [
      'classes2.dex 的 3 个外部类引用未在固定示例输入中提供。',
      '部分 Kotlin 元数据未在固定示例中展开。',
    ],
  },
  units: [
    {
      id: 'dex-verifier-class',
      group: 'classes.dex / com.binaryscan.mobile',
      name: 'Lcom/binaryscan/mobile/Verifier;',
      kind: 'class',
      location: 'class_def[184]',
      detail: 'class · 3 methods',
      signature: '.class public final Lcom/binaryscan/mobile/Verifier;',
      source: `.class public final Lcom/binaryscan/mobile/Verifier;
.super Ljava/lang/Object;

.field private static final HEADER_SIZE:I = 0x20
.field private static final PACKAGE_MAGIC:I = 0x42534e31`,
    },
    {
      id: 'dex-verify-method',
      group: 'classes.dex / Verifier',
      name: 'verifyHeader([B)Z',
      kind: 'method',
      location: 'method_id[912]',
      detail: 'method · 10 registers',
      signature: '.method public static verifyHeader([B)Z',
      source: `.method public static verifyHeader([B)Z
    .registers 4
    if-eqz p0, :invalid
    array-length v0, p0
    const/16 v1, 0x20
    if-lt v0, v1, :invalid
    invoke-static {p0}, Lcom/binaryscan/mobile/Native;->readMagic([B)I
    move-result v0
    const v1, 0x42534e31
    if-ne v0, v1, :invalid
    const/4 v0, 0x1
    return v0
:invalid
    const/4 v0, 0x0
    return v0
.end method`,
    },
    {
      id: 'dex-path-method',
      group: 'classes2.dex / ArchiveGuard',
      name: 'isSafePath(Ljava/lang/String;)Z',
      kind: 'method',
      location: 'method_id[1431]',
      detail: 'method · 4 registers',
      signature: '.method public static isSafePath(Ljava/lang/String;)Z',
      source: `.method public static isSafePath(Ljava/lang/String;)Z
    .registers 3
    const-string v0, ".."
    invoke-virtual {p0, v0}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    xor-int/lit8 v1, v1, 0x1
    return v1
.end method`,
    },
  ],
} as const satisfies DemoDecompileView

const PYC_VIEW = {
  kind: 'pyc',
  title: 'PYC 字节码视图',
  treeLabel: '模块 / 函数树',
  unitLabel: '模块与函数',
  languageBadge: 'Python 字节码',
  capability: '适用于 PYC code object 与指令结构的界面能力样例',
  limitation: '能力降级：仅展示字节码及 Python 形态提示，原始源码、注释与部分名称不可恢复。',
  analyzerDiagnostics: {
    engine: 'PYC 字段契约示例',
    format: 'PYC',
    python_version: '3.12',
    magic: 'cb0d0d0a',
    header_size: 16,
    code_object_count: 5,
    error_count: 0,
    warning_count: 1,
    errors: [],
    warnings: ['1 个嵌套 code object 的原始文件路径未保留。'],
  },
  units: [
    {
      id: 'pyc-module',
      group: 'update_guard.pyc',
      name: '<module>',
      kind: 'module',
      location: 'code object 0',
      detail: 'Python 3.12 · flags 0x00',
      signature: 'code object <module>',
      source: `  0           RESUME                   0
  2           LOAD_CONST               0 (32)
              STORE_NAME               0 (HEADER_SIZE)
  4           LOAD_CONST               1 (<code object verify_header>)
              MAKE_FUNCTION
              STORE_NAME               1 (verify_header)
              RETURN_CONST             2 (None)`,
    },
    {
      id: 'pyc-verify-function',
      group: 'update_guard.pyc / <module>',
      name: 'verify_header',
      kind: 'function',
      location: 'code object 1',
      detail: 'stack 3 · 1 argument',
      signature: 'verify_header(payload)',
      source: `  7           RESUME                   0
  8           LOAD_FAST                0 (payload)
              POP_JUMP_IF_FALSE       22
              LOAD_GLOBAL              1 (len + NULL)
              LOAD_FAST                0 (payload)
              CALL                     1
              LOAD_GLOBAL              2 (HEADER_SIZE)
              COMPARE_OP               2 (>=)
              RETURN_VALUE
             RETURN_CONST              1 (False)`,
    },
    {
      id: 'pyc-normalize-function',
      group: 'archive_guard.pyc / <module>',
      name: 'normalize_entry',
      kind: 'function',
      location: 'code object 4',
      detail: 'stack 4 · 1 argument',
      signature: 'normalize_entry(name)',
      source: ` 18           RESUME                   0
 19           LOAD_GLOBAL              1 (PurePosixPath + NULL)
              LOAD_FAST                0 (name)
              CALL                     1
              STORE_FAST               1 (candidate)
 20           LOAD_CONST               1 ('..')
              LOAD_FAST                1 (candidate)
              LOAD_ATTR                2 (parts)
              CONTAINS_OP              1
              RETURN_VALUE`,
    },
  ],
} as const satisfies DemoDecompileView

export const DEMO_DECOMPILE_VIEWS: Readonly<
  Record<DemoDecompileViewKind, DemoDecompileView>
> = {
  native: NATIVE_VIEW,
  jvm: JAVA_VIEW,
  dex: DEX_VIEW,
  pyc: PYC_VIEW,
}

const JAVA_INPUT_TYPES = new Set(['class', 'jar', 'java-bytecode'])
const DEX_INPUT_TYPES = new Set(['apk', 'dex', 'smali'])
const PYC_INPUT_TYPES = new Set(['pyc', 'python-bytecode'])

export function resolveDemoDecompileView(inputType: string): DemoDecompileView {
  const normalized = inputType.trim().toLocaleLowerCase('en-US')
  if (JAVA_INPUT_TYPES.has(normalized)) return JAVA_VIEW
  if (DEX_INPUT_TYPES.has(normalized)) return DEX_VIEW
  if (PYC_INPUT_TYPES.has(normalized)) return PYC_VIEW
  return NATIVE_VIEW
}

export const DEMO_VULNERABILITY_FINDINGS = [
  {
    id: 'finding-001',
    severity: 'CRITICAL',
    cve: 'CVE-DEMO-0001',
    title: 'TLS 握手边界校验示例',
    packageName: 'libssl3',
    installedVersion: '3.0.14-r0',
    fixedVersion: '3.0.15-r1',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:libssl3\\nV:3.0.14-r0\\nA:x86_64\\nL:Apache-2.0',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '用于展示高风险组件记录、证据位置和修复版本的交互，不对应真实漏洞。',
  },
  {
    id: 'finding-002',
    severity: 'CRITICAL',
    cve: 'CVE-DEMO-0002',
    title: '命令解析状态处理示例',
    packageName: 'busybox',
    installedVersion: '1.36.1-r28',
    fixedVersion: '1.36.1-r30',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:busybox\\nV:1.36.1-r28\\nA:x86_64\\nL:GPL-2.0-only',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '展示单一软件包可能产生的修复建议，编号和结论均为固定示例。',
  },
  {
    id: 'finding-003',
    severity: 'HIGH',
    cve: 'CVE-DEMO-0003',
    title: 'URL 重定向策略示例',
    packageName: 'curl',
    installedVersion: '8.10.0-r0',
    fixedVersion: '8.11.1-r1',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:curl\\nV:8.10.0-r0\\nA:x86_64\\nD:libcurl=8.10.0-r0',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '展示从安装数据库定位当前版本并关联建议修复版本的结果形态。',
  },
  {
    id: 'finding-004',
    severity: 'HIGH',
    cve: 'CVE-DEMO-0004',
    title: '压缩流长度校验示例',
    packageName: 'zlib',
    installedVersion: '1.3.1-r1',
    fixedVersion: '1.3.1-r2',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:zlib\\nV:1.3.1-r1\\nA:x86_64\\nS:102400',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '展示压缩库记录的证据、严重度和目标修复版本，不代表真实风险。',
  },
  {
    id: 'finding-005',
    severity: 'MEDIUM',
    cve: 'CVE-DEMO-0005',
    title: 'XML 实体资源限制示例',
    packageName: 'libxml2',
    installedVersion: '2.12.7-r0',
    fixedVersion: '2.12.9-r0',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:libxml2\\nV:2.12.7-r0\\nA:x86_64\\nL:MIT',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '展示中危结果详情和离线证据摘录，不执行任何在线漏洞查询。',
  },
  {
    id: 'finding-006',
    severity: 'LOW',
    cve: 'CVE-DEMO-0006',
    title: '时区数据一致性示例',
    packageName: 'tzdata',
    installedVersion: '2025a-r0',
    fixedVersion: '2025b-r0',
    evidence: '/lib/apk/db/installed',
    evidenceExcerpt: 'P:tzdata\\nV:2025a-r0\\nA:noarch\\nL:Public-Domain',
    scannerSource: '固定示例规则库 / alpine-demo',
    description: '展示低危记录与可用修复版本，固定编号不对应真实漏洞记录。',
  },
] as const satisfies readonly DemoVulnerabilityFinding[]

export const DEMO_REPORT_ARTIFACTS = [
  {
    format: 'JSON',
    filename: 'binaryscan-report.json',
    size: '284 KB',
    description: '机器可读的任务、文件结构、检测结论和限制记录',
  },
  {
    format: 'HTML',
    filename: 'binaryscan-report.html',
    size: '412 KB',
    description: '适合离线审阅和归档的单文件报告',
  },
] as const satisfies readonly DemoReportArtifact[]

export const DEMO_HTML_REPORT_SECTIONS = [
  {
    id: 'summary',
    number: '01',
    title: '任务摘要',
    summary: '样本标识、输入格式、任务状态与分析范围',
  },
  {
    id: 'inventory',
    number: '02',
    title: '文件结构',
    summary: '归档层级、文件类型与受限解包统计',
  },
  {
    id: 'analysis',
    number: '03',
    title: '分析结果',
    summary: '反编译能力、容器漏洞与能力降级说明',
  },
  {
    id: 'limits',
    number: '04',
    title: '限制与证据',
    summary: '安全限制、证据定位和结果生成信息',
  },
] as const satisfies readonly DemoHtmlReportSection[]
