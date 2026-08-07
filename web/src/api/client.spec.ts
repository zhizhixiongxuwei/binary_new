import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  api,
  ApiError,
  parseRetryAfterSeconds,
  readCookie,
  reportDownloadFilename,
  safeReportDownloadFilename,
} from '@/api/client'
import type {
  CurrentUser,
  FileDecompileRequest,
  ManualImageScanRequest,
  DecompileResultPage,
  DecompileSourceChunk,
  TaskReport,
  TaskDetail,
  VulnerabilityFinding,
  VulnerabilityFindingPage,
} from '@/api/types'

const currentUser: CurrentUser = {
  id: 'user-1',
  username: 'admin',
  display_name: '系统管理员',
  role: 'administrator',
  must_change_password: false,
}

const taskDetail: TaskDetail = {
  id: '20000000-0000-4000-8000-000000000002',
  name: 'sample.exe',
  input_type: 'pe32+',
  status: 'FAILED',
  risk_level: 'HIGH',
  progress: 75,
  progress_indeterminate: false,
  creator_id: '40000000-0000-4000-8000-000000000004',
  creator_name: '系统管理员',
  tags: [],
  created_at: '2026-07-30T00:00:00Z',
  updated_at: '2026-07-30T00:01:00Z',
  original_filename: 'sample.exe',
  size_bytes: 4_096,
  sha256: 'a'.repeat(64),
  sample_expires_at: '2099-08-29T00:00:00Z',
  sample_deleted_at: null,
}

const decompilePage: DecompileResultPage = {
  items: [
    {
      id: '18446744073709551614',
      file_node_id: '18446744073709551613',
      symbol_key: 'FUN_00401000',
      symbol_kind: 'function',
      display_name: 'verify_package',
      group_name: 'package_verifier',
      location: '0x00401000',
      signature: 'bool verify_package(const Header *header)',
      detail: 'ELF x86_64 symbol',
      language: 'c',
      engine_name: 'Ghidra',
      engine_version: '12.1.2',
      status: 'complete',
      size_bytes: null,
      diagnostics: {},
      created_at: '2026-07-30T01:00:00Z',
      completed_at: '2026-07-30T01:00:02Z',
    },
  ],
  next_cursor: '18446744073709551614/cursor',
}

const decompileSource: DecompileSourceChunk = {
  result_id: '18446744073709551614',
  offset: 0,
  content: 'bool verify_package(void) { return true; }',
  next_offset: 43,
  complete: false,
  sha256: 'a'.repeat(64),
  size_bytes: 86,
}

const fileDecompileRequest: FileDecompileRequest = {
  request_id: '423e4567-e89b-42d3-a456-426614174003',
  job_id: '323e4567-e89b-42d3-a456-426614174002',
  task_id: '123e4567-e89b-42d3-a456-426614174000',
  file_node_id: '18446744073709551615',
  target_class: 'native',
  engine_target: 'ghidra',
  status: 'queued',
  created_at: '2026-07-31T01:02:03Z',
}

const manualImageScanRequest: ManualImageScanRequest = {
  job_id: '523e4567-e89b-42d3-a456-426614174004',
  task_id: '123e4567-e89b-42d3-a456-426614174000',
  file_node_id: '18446744073709551615',
  status: 'queued',
  created_at: '2026-07-31T01:02:03Z',
}

const vulnerabilityFinding: VulnerabilityFinding = {
  id: '18446744073709551612',
  vulnerability_id: 'CVE-2026-1001',
  severity: 'CRITICAL',
  package_name: 'openssl',
  installed_version: '3.0.14-r0',
  fixed_version: '3.0.15-r1',
  title: 'OpenSSL certificate validation issue',
  description_summary: 'Upgrade the affected image package.',
  image_logical_path: '/layers/sha256:abc/usr/lib',
  image_platform: 'linux/amd64',
  evidence: {
    package_path: '/lib/apk/db/installed',
    scanner: 'trivy',
  },
  references: ['https://security.example.test/CVE-2026-1001'],
  database_bundle: {
    id: 'db-2026-07-30',
    version: '2026.07.30',
    generated_at: '2026-07-30T00:00:00Z',
    content_sha256: 'a'.repeat(64),
  },
  created_at: '2026-07-30T01:00:00Z',
}

const vulnerabilityPage: VulnerabilityFindingPage = {
  summary: {
    total: 1,
    fixable: 1,
    by_severity: {
      UNKNOWN: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 1,
    },
  },
  items: [vulnerabilityFinding],
  next_cursor: '18446744073709551612/cursor',
}

const jsonReport: TaskReport = {
  id: 'report/id',
  task_id: 'task/id',
  format: 'json',
  schema_version: '1.1.0',
  status: 'complete',
  sha256: 'e'.repeat(64),
  size_bytes: 1_024,
  error_code: null,
  error_message: null,
  created_at: '2026-07-30T01:00:00Z',
  completed_at: '2026-07-30T01:00:01Z',
}

describe('api client', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    document.cookie = 'binaryscan_csrf=; Max-Age=0; Path=/'
  })

  it('reads the standard server error envelope', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'INVALID_FILTER',
              message: '筛选条件无效',
              details: { field: 'status' },
            },
            meta: { request_id: 'request-1' },
          }),
          {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      ),
    )

    const error = await api
      .listTasks({ page_size: 20 })
      .catch((reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 400,
      code: 'INVALID_FILTER',
      message: '筛选条件无效',
    })
  })

  it('retains only a bounded integer Retry-After value on API errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'login_rate_limited',
              message: '请稍后再试',
            },
          }),
          {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'Retry-After': '12',
            },
          },
        ),
      ),
    )

    const error = await api
      .login({ username: 'operator', password: 'not-logged' })
      .catch((reason: unknown) => reason)

    expect(error).toMatchObject({
      status: 429,
      code: 'login_rate_limited',
      retryAfterSeconds: 12,
    })
    expect(parseRetryAfterSeconds(null)).toBeUndefined()
    expect(parseRetryAfterSeconds('0')).toBeUndefined()
    expect(parseRetryAfterSeconds('86401')).toBeUndefined()
    expect(parseRetryAfterSeconds('tomorrow')).toBeUndefined()
    expect(parseRetryAfterSeconds('86400')).toBe(86_400)
  })

  it('serializes every task-list filter with stable API parameter names', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: { items: [], next_cursor: 'opaque_cursor-3' },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.listTasks({
      cursor: 'opaque_cursor-2',
      page_size: 50,
      keyword: 'firmware',
      status: 'SUCCEEDED',
      input_type: 'tar',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
    })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const parsed = new URL(url, 'http://localhost')
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      cursor: 'opaque_cursor-2',
      page_size: '50',
      keyword: 'firmware',
      status: 'SUCCEEDED',
      input_type: 'tar',
      creator: 'Demo Operator',
      tag: 'firmware',
      created_from: '2026-07-01',
      created_to: '2026-07-30',
    })
    expect(init.method).toBe('GET')
  })

  it('decodes a named cookie and returns undefined when it is missing', () => {
    expect(readCookie('binaryscan_csrf', 'theme=light; binaryscan_csrf=token%2Fwith%2Bsymbols')).toBe(
      'token/with+symbols',
    )
    expect(readCookie('binaryscan_csrf', 'theme=light')).toBeUndefined()
  })

  it('logs in without a CSRF header when no token cookie exists', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: currentUser, meta: { requestId: 'request-2' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.login({ username: 'admin', password: 'secret' })).resolves.toEqual(currentUser)

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).has('X-CSRF-Token')).toBe(false)
    expect(init.credentials).toBe('include')
  })

  it('does not attach CSRF to the safe session restore request', async () => {
    document.cookie = 'binaryscan_csrf=safe-request-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: currentUser }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.getMe()).resolves.toEqual(currentUser)

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(init.method).toBe('GET')
    expect(new Headers(init.headers).has('X-CSRF-Token')).toBe(false)
  })

  it('lists one file-tree page with exact string identifiers and cursor', async () => {
    const page = {
      items: [
        {
          id: '18446744073709551614',
          parent_id: '18446744073709551613',
          logical_path: '/root/app',
          display_name: 'app',
          archive_name_id: 'b64:YXBw',
          node_type: 'file' as const,
          depth: 1,
          format: 'elf64',
          mime_type: 'application/x-elf',
          architecture: 'x86_64',
          size_bytes: 8192,
          sha256: 'a'.repeat(64),
          extraction_status: 'indexed',
          error_code: '',
          error_message: '',
          source_container: {
            id: '18446744073709551613',
            logical_path: '/root.tar',
            format: 'tar',
          },
          has_children: false,
        },
      ],
      next_cursor: '18446744073709551614',
    }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: page }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listTaskFiles('task/id', {
        parent_id: '18446744073709551613',
        cursor: '18446744073709551612',
        page_size: 200,
      }),
    ).resolves.toEqual(page)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain(
      '/tasks/task%2Fid/files?parent_id=18446744073709551613' +
        '&cursor=18446744073709551612&page_size=200',
    )
    expect(init.method).toBe('GET')
  })

  it('loads one file-node detail without coercing its unsigned identifier', async () => {
    const detail = {
      id: '18446744073709551615',
      parent_id: '18446744073709551614',
      logical_path: '/root/bin/app',
      display_name: 'app',
      archive_name_id: 'b64:YmluL2FwcA==',
      node_type: 'file' as const,
      depth: 2,
      format: 'elf64',
      mime_type: 'application/x-elf',
      architecture: 'x86_64',
      size_bytes: 8192,
      sha256: 'b'.repeat(64),
      extraction_status: 'indexed',
      error_code: '',
      error_message: '',
      source_container: {
        id: '18446744073709551613',
        logical_path: '/root.tar',
        format: 'tar',
      },
      has_children: false,
      metadata_json: { entry_point: '0x401000' },
      source_parent: {
        id: '18446744073709551614',
        logical_path: '/root/bin',
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: detail }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.getTaskFile('task/id', '18446744073709551615'),
    ).resolves.toEqual(detail)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain(
      '/tasks/task%2Fid/files/18446744073709551615',
    )
    expect(url).not.toContain('storage_key')
    expect(init.method).toBe('GET')
  })

  it('rejects a file-node response that omits or extends source_container', async () => {
    const invalidNode = {
      id: '1',
      parent_id: null,
      logical_path: '/root.tar',
      display_name: 'root.tar',
      archive_name_id: '',
      node_type: 'file',
      depth: 0,
      format: 'tar',
      mime_type: 'application/x-tar',
      architecture: '',
      size_bytes: 1,
      sha256: 'a'.repeat(64),
      extraction_status: 'extracted',
      error_code: '',
      error_message: '',
      source_container: {
        id: '2',
        logical_path: '/outer.tar',
        format: 'tar',
        storage_key: 'must-not-pass',
      },
      has_children: false,
    }
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ data: { items: [invalidNode] } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )

    await expect(api.listTaskFiles('task-id')).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_FILE_NODE_RESPONSE',
      message: '文件节点响应不符合接口契约',
    })
  })

  it('serializes decompile result and source pagination with encoded identifiers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: decompilePage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: decompileSource }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listDecompileResults('task/id', {
        cursor: '18446744073709551614/cursor',
        page_size: 100,
      }),
    ).resolves.toEqual(decompilePage)
    await expect(
      api.getDecompileSource('task/id', 'result/id', {
        offset: 0,
        limit: 262_144,
      }),
    ).resolves.toEqual(decompileSource)
    await expect(
      api.downloadDecompileSources('task/id', true),
    ).resolves.toEqual({
      kind: 'url',
      url: '/api/v1/tasks/task%2Fid/decompile-sources.zip?combined=true',
    })
    await expect(
      api.downloadDecompileSources('task/id'),
    ).resolves.toEqual({
      kind: 'url',
      url: '/api/v1/tasks/task%2Fid/decompile-sources.zip',
    })

    const [listUrl, listInit] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ]
    const [sourceUrl, sourceInit] = fetchMock.mock.calls[1] as [
      string,
      RequestInit,
    ]
    const listParsed = new URL(listUrl, 'http://localhost')
    const sourceParsed = new URL(sourceUrl, 'http://localhost')

    expect(listParsed.pathname).toContain('/tasks/task%2Fid/decompile-results')
    expect(Object.fromEntries(listParsed.searchParams)).toEqual({
      cursor: '18446744073709551614/cursor',
      page_size: '100',
    })
    expect(listInit.method).toBe('GET')
    expect(sourceParsed.pathname).toContain(
      '/tasks/task%2Fid/decompile-results/result%2Fid/source',
    )
    expect(Object.fromEntries(sourceParsed.searchParams)).toEqual({
      offset: '0',
      limit: '262144',
    })
    expect(sourceInit.method).toBe('GET')
  })

  it('submits a file-node decompile request with one idempotency key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: fileDecompileRequest }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.createFileDecompileRequest(
        'task/id',
        'node/id',
        { engine_target: 'auto', options: {} },
        'decompile-intent',
      ),
    ).resolves.toEqual(fileDecompileRequest)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/tasks/task%2Fid/files/node%2Fid/decompile')
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe(
      'decompile-intent',
    )
    expect(JSON.parse(String(init.body))).toEqual({
      engine_target: 'auto',
      options: {},
    })
  })

  it('reads a task-scoped decompile job status', async () => {
    const completed = {
      ...fileDecompileRequest,
      status: 'succeeded' as const,
      completed_at: '2026-08-03T22:16:43Z',
    }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: completed }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.getFileDecompileRequest('task/id', 'job/id'),
    ).resolves.toEqual(completed)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/tasks/task%2Fid/decompile-jobs/job%2Fid')
    expect(init.method).toBe('GET')
  })

  it('submits an empty manual image scan request with one idempotency key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: manualImageScanRequest }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.createManualImageScanRequest(
        'task/id',
        '18446744073709551615',
        'manual-image-intent',
      ),
    ).resolves.toEqual(manualImageScanRequest)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain(
      '/tasks/task%2Fid/files/18446744073709551615/image-scan',
    )
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).get('Idempotency-Key')).toBe(
      'manual-image-intent',
    )
    expect(JSON.parse(String(init.body))).toEqual({})
  })

  it('serializes vulnerability severity pagination and detail identifiers', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: vulnerabilityPage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: vulnerabilityFinding }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.listTaskVulnerabilities('task/id', {
        severity: 'CRITICAL',
        cursor: '18446744073709551612/cursor',
        page_size: 50,
      }),
    ).resolves.toEqual(vulnerabilityPage)
    await expect(
      api.getTaskVulnerability('task/id', 'finding/id'),
    ).resolves.toEqual(vulnerabilityFinding)

    const [listUrl, listInit] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ]
    const [detailUrl, detailInit] = fetchMock.mock.calls[1] as [
      string,
      RequestInit,
    ]
    const listParsed = new URL(listUrl, 'http://localhost')
    const detailParsed = new URL(detailUrl, 'http://localhost')

    expect(listParsed.pathname).toContain('/tasks/task%2Fid/vulnerabilities')
    expect(Object.fromEntries(listParsed.searchParams)).toEqual({
      severity: 'CRITICAL',
      cursor: '18446744073709551612/cursor',
      page_size: '50',
    })
    expect(listInit.method).toBe('GET')
    expect(detailParsed.pathname).toContain(
      '/tasks/task%2Fid/vulnerabilities/finding%2Fid',
    )
    expect(detailParsed.search).toBe('')
    expect(detailInit.method).toBe('GET')
  })

  it('lists, creates, and downloads reports through exact URLs and headers', async () => {
    document.cookie = 'binaryscan_csrf=report-token; Path=/'
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: { items: [jsonReport] } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: jsonReport }), {
          status: 201,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.listTaskReports('task/id')).resolves.toEqual({
      items: [jsonReport],
    })
    await expect(
      api.createTaskReport(
        'task/id',
        { format: 'json' },
        'report-intent',
      ),
    ).resolves.toEqual(jsonReport)
    const downloaded = await api.downloadTaskReport(
      'task/id',
      'report/id',
      'json',
    )

    expect(downloaded).toEqual({
      kind: 'url',
      url: '/api/v1/tasks/task%2Fid/reports/report%2Fid/download',
    })
    await expect(
      api.downloadTaskReport('task/id', 'report/id', 'json', 'gzip'),
    ).resolves.toEqual({
      kind: 'url',
      url: '/api/v1/tasks/task%2Fid/reports/report%2Fid/download?encoding=gzip',
    })

    const [listUrl, listInit] = fetchMock.mock.calls[0] as [
      string,
      RequestInit,
    ]
    const [createUrl, createInit] = fetchMock.mock.calls[1] as [
      string,
      RequestInit,
    ]
    expect(listUrl).toContain('/tasks/task%2Fid/reports')
    expect(listInit.method).toBe('GET')
    expect(createUrl).toContain('/tasks/task%2Fid/reports')
    expect(createInit.method).toBe('POST')
    expect(createInit.body).toBe(JSON.stringify({ format: 'json' }))
    expect(new Headers(createInit.headers).get('Idempotency-Key')).toBe(
      'report-intent',
    )
    expect(new Headers(createInit.headers).get('X-CSRF-Token')).toBe(
      'report-token',
    )
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('rejects injected or path-like report filenames and uses a typed fallback', () => {
    expect(
      reportDownloadFilename(
        'attachment; filename="scan result.html"',
        'html',
      ),
    ).toBe('scan result.html')
    expect(
      reportDownloadFilename(
        "attachment; filename*=UTF-8''%E6%A3%80%E6%B5%8B%E6%8A%A5%E5%91%8A.json",
        'json',
      ),
    ).toBe('检测报告.json')

    const maliciousHeaders = [
      'attachment; filename="../../escape.json"',
      'attachment; filename="..\\\\..\\\\escape.html"',
      "attachment; filename*=UTF-8''..%2F..%2Fescape.json",
      'attachment; filename="C:\\\\temp\\\\escape.json"',
      'attachment; filename="report.json:payload"',
      'attachment; filename="report.exe"',
      'attachment;\r\nfilename="injected.html"',
      'attachment; filename="bad\u0000name.json"',
    ]
    for (const header of maliciousHeaders) {
      expect(reportDownloadFilename(header, 'json')).toBe(
        'binaryscan-report.json',
      )
    }
  })

  it('accepts only the expected gzip report suffix', () => {
    expect(
      safeReportDownloadFilename('task-report.json.gz', 'json', 'gzip'),
    ).toBe('task-report.json.gz')
    expect(
      safeReportDownloadFilename('task-report.json', 'json', 'gzip'),
    ).toBe('binaryscan-report.json.gz')
    expect(
      reportDownloadFilename(
        'attachment; filename="task-report.json.gz"',
        'json',
        'gzip',
      ),
    ).toBe('task-report.json.gz')
  })

  it('attaches the decoded CSRF cookie to logout', async () => {
    document.cookie = 'binaryscan_csrf=logout%2Ftoken%2Bvalue; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.logout()).resolves.toBeUndefined()

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(init.method).toBe('POST')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('logout/token+value')
  })

  it('surfaces a server logout failure as ApiError', async () => {
    document.cookie = 'binaryscan_csrf=logout-token; Path=/'
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: {
              code: 'logout_failed',
              message: '注销服务暂不可用',
            },
            meta: { requestId: 'request-logout' },
          }),
          {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
          },
        ),
      ),
    )

    const error = await api.logout().catch((reason: unknown) => reason)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 503,
      code: 'logout_failed',
      message: '注销服务暂不可用',
    })
  })

  it('changes the current password and returns the updated user', async () => {
    document.cookie = 'binaryscan_csrf=password-token; Path=/'
    const updatedUser = { ...currentUser, must_change_password: false }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: updatedUser }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.changePassword({
        current_password: 'current-password',
        new_password: 'new-password-value',
      }),
    ).resolves.toEqual(updatedUser)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/me/password')
    expect(init.method).toBe('PUT')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe('password-token')
    expect(init.body).toBe(
      JSON.stringify({
        current_password: 'current-password',
        new_password: 'new-password-value',
      }),
    )
  })

  it('restores CurrentUser when password change returns no content', async () => {
    document.cookie = 'binaryscan_csrf=password-token; Path=/'
    const updatedUser = { ...currentUser, must_change_password: false }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ data: updatedUser }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.changePassword({
        current_password: 'current-password',
        new_password: 'new-password-value',
      }),
    ).resolves.toEqual(updatedUser)

    expect(fetchMock).toHaveBeenCalledTimes(2)
    const [, restoreInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(restoreInit.method).toBe('GET')
    expect(new Headers(restoreInit.headers).has('X-CSRF-Token')).toBe(false)
  })

  it('uploads a part with its byte range and lowercase chunk hash', async () => {
    document.cookie = 'binaryscan_csrf=upload-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const chunk = new Blob(['abcd'])

    await api.uploadPart('upload-1', {
      part_number: 2,
      start: 4,
      end: 7,
      total: 10,
      sha256: 'ABCDEF',
      chunk,
    })

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(url).toContain('/uploads/upload-1/parts/2')
    expect(init.method).toBe('PUT')
    expect(init.body).toBe(chunk)
    expect(headers.get('Content-Range')).toBe('bytes 4-7/10')
    expect(headers.get('X-Chunk-SHA256')).toBe('abcdef')
    expect(headers.get('X-CSRF-Token')).toBe('upload-token')
  })

  it('creates an upload with the caller-owned idempotency key', async () => {
    document.cookie = 'binaryscan_csrf=upload-create-token; Path=/'
    const session = {
      id: 'upload-1',
      part_size: 33_554_432,
      size_bytes: 4,
      status: 'created' as const,
      uploaded_parts: [],
      expires_at: '2026-08-30T00:00:00Z',
    }
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: session }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      api.createUpload(
        {
          filename: 'sample.bin',
          size: 4,
          content_type: 'application/octet-stream',
        },
        'stable-upload-create-key',
      ),
    ).resolves.toEqual(session)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    const headers = new Headers(init.headers)
    expect(url).toContain('/uploads')
    expect(init.method).toBe('POST')
    expect(headers.get('Idempotency-Key')).toBe('stable-upload-create-key')
    expect(headers.get('X-CSRF-Token')).toBe('upload-create-token')
    expect(JSON.parse(String(init.body))).toEqual({
      filename: 'sample.bin',
      size: 4,
      content_type: 'application/octet-stream',
    })
  })

  it('submits task lifecycle operations with their exact methods and idempotency headers', async () => {
    document.cookie = 'binaryscan_csrf=lifecycle-token; Path=/'
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: { ...taskDetail, status: 'CANCEL_REQUESTED' },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { ...taskDetail, status: 'QUEUED' } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ data: { ...taskDetail, status: 'DELETING' } }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              ...taskDetail,
              sample_expires_at: '2026-09-28T00:00:00.000Z',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    vi.stubGlobal('fetch', fetchMock)

    await api.cancelTask('task/id', 'cancel-intent')
    await api.retryTask('task/id', 'retry-intent')
    await api.deleteTask('task/id')
    await api.extendTaskRetention('task/id', {
      expected_sample_expires_at: '2026-08-29T00:00:00.000Z',
      sample_expires_at: '2026-09-28T00:00:00.000Z',
    })

    const [cancelUrl, cancelInit] = fetchMock.mock.calls[0] as [string, RequestInit]
    const [retryUrl, retryInit] = fetchMock.mock.calls[1] as [string, RequestInit]
    const [deleteUrl, deleteInit] = fetchMock.mock.calls[2] as [string, RequestInit]
    const [retentionUrl, retentionInit] = fetchMock.mock.calls[3] as [
      string,
      RequestInit,
    ]

    expect(cancelUrl).toContain('/tasks/task%2Fid/cancel')
    expect(cancelInit.method).toBe('POST')
    expect(new Headers(cancelInit.headers).get('Idempotency-Key')).toBe(
      'cancel-intent',
    )
    expect(retryUrl).toContain('/tasks/task%2Fid/retry')
    expect(retryInit.method).toBe('POST')
    expect(new Headers(retryInit.headers).get('Idempotency-Key')).toBe(
      'retry-intent',
    )
    expect(deleteUrl).toContain('/tasks/task%2Fid')
    expect(deleteInit.method).toBe('DELETE')
    expect(new Headers(deleteInit.headers).get('Idempotency-Key')).toBeNull()
    expect(retentionUrl).toContain('/tasks/task%2Fid/retention')
    expect(retentionInit.method).toBe('PATCH')
    expect(new Headers(retentionInit.headers).get('Idempotency-Key')).toBeNull()
    expect(retentionInit.body).toBe(
      JSON.stringify({
        expected_sample_expires_at: '2026-08-29T00:00:00.000Z',
        sample_expires_at: '2026-09-28T00:00:00.000Z',
      }),
    )
    for (const call of fetchMock.mock.calls) {
      const [, init] = call as [string, RequestInit]
      expect(new Headers(init.headers).get('X-CSRF-Token')).toBe(
        'lifecycle-token',
      )
    }
  })

  it('deletes an unfinished upload through the typed transport', async () => {
    document.cookie = 'binaryscan_csrf=upload-delete-token; Path=/'
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(api.deleteUpload('upload/id')).resolves.toBeUndefined()

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toContain('/uploads/upload%2Fid')
    expect(init.method).toBe('DELETE')
    expect(new Headers(init.headers).get('X-CSRF-Token')).toBe(
      'upload-delete-token',
    )
  })
})
