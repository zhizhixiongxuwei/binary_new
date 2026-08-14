import type {
  AdminUser,
  AdminUserListQuery,
  AdminUserPage,
  ApiErrorBody,
  ArchiveImport,
  ArchiveImportListQuery,
  ArchiveImportPage,
  ArchiveImportEntryListQuery,
  ArchiveImportEntryPage,
  ArchiveTaskBatchResult,
  AuditLogListQuery,
  AuditLogPage,
  ChangePasswordInput,
  CAnalysisFindingListQuery,
  CAnalysisFindingPage,
  CAnalysisRun,
  CAnalysisRunListQuery,
  CAnalysisRunPage,
  JavaAnalysisFindingListQuery,
  JavaAnalysisFindingPage,
  JavaAnalysisRun,
  JavaAnalysisRunListQuery,
  JavaAnalysisRunPage,
  PythonAnalysisRun,
  PythonAnalysisRunListQuery,
  PythonAnalysisRunPage,
  PythonAnalysisFinding,
  PythonAnalysisFindingListQuery,
  PythonAnalysisFindingPage,
  CompletedUpload,
  CreatedTask,
  CreateArchiveTaskBatchInput,
  CreateUploadInput,
  CreateTaskInput,
  CreateAdminUserInput,
  CurrentUser,
  CreateFileDecompileRequestInput,
  DecompileProject,
  DecompileProjectDeletionOperation,
  DecompileProjectDeletionPreview,
  ConfirmDecompileProjectDeletionInput,
  DecompileProjectListQuery,
  DecompileProjectPage,
  DecompileResultListQuery,
  DecompileResultPage,
  DecompileSourceChunk,
  DecompileSourceQuery,
  ExtendTaskRetentionInput,
  FileNodeDetail,
  FileDecompileRequest,
  FileNodeListQuery,
  FileNodePage,
  LoginInput,
  ManualImageScanRequest,
  ReportDownload,
  ReportDownloadEncoding,
  ResetAdminUserPasswordInput,
  SystemStatus,
  TaskDetail,
  TaskListQuery,
  TaskReport,
  TaskReportList,
  UploadSession,
  UpdateAdminUserInput,
  UploadPartInput,
  VulnerabilityFinding,
  VulnerabilityFindingPage,
  VulnerabilityListQuery,
  CreateTaskReportInput,
} from '@/api/types'
import type { ApiClient } from '@/api/contract'
import {
  ArchiveImportContractError,
  parseArchiveImport,
  parseArchiveImportPage,
  parseArchiveImportEntryPage,
  parseArchiveTaskBatchResult,
} from '@/api/archiveImportContract'
import {
  CAnalysisContractError,
  parseCAnalysisFindingPage,
  parseCAnalysisRun,
  parseCAnalysisRunPage,
} from '@/api/cAnalysisContract'
import {
  JavaAnalysisContractError,
  parseJavaAnalysisFindingPage,
  parseJavaAnalysisRun,
  parseJavaAnalysisRunPage,
} from '@/api/javaAnalysisContract'
import {
  PythonAnalysisContractError,
  parsePythonAnalysisFindingPage,
  parsePythonAnalysisRun,
  parsePythonAnalysisRunPage,
} from '@/api/pythonAnalysisContract'
import {
  DecompileProjectContractError,
  parseDecompileProject,
  parseDecompileProjectDeletionOperation,
  parseDecompileProjectDeletionPreview,
  parseDecompileProjectPage,
} from '@/api/decompileProjectContract'
import {
  FileNodeContractError,
  parseFileNodeDetail,
  parseFileNodePage,
} from '@/api/fileNodeContract'
import { parseTaskDetail, parseTaskPage } from '@/api/taskContract'
import {
  parseCompletedUpload,
  parseCreatedUploadSession,
  parseUploadSession,
  UploadIntakeContractError,
} from '@/api/uploadIntakeContract'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '/api/v1').replace(/\/$/, '')
const CSRF_COOKIE_NAME = 'binaryscan_csrf'
const CSRF_HEADER_NAME = 'X-CSRF-Token'
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const MAX_RETRY_AFTER_SECONDS = 86_400

interface ApiEnvelope<T> {
  data: T
}

interface ErrorEnvelope {
  error: ApiErrorBody
  meta?: unknown
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string | undefined
  readonly details: unknown
  readonly retryAfterSeconds: number | undefined

  constructor(
    message: string,
    status: number,
    body?: ApiErrorBody,
    options: { retryAfterSeconds?: number | undefined } = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = body?.code
    this.details = body?.details
    this.retryAfterSeconds = boundedRetryAfterSeconds(
      options.retryAfterSeconds,
    )
  }
}

function boundedRetryAfterSeconds(value: number | undefined): number | undefined {
  return Number.isSafeInteger(value) &&
    value !== undefined &&
    value >= 1 &&
    value <= MAX_RETRY_AFTER_SECONDS
    ? value
    : undefined
}

export function parseRetryAfterSeconds(
  value: string | null,
): number | undefined {
  if (value === null) return undefined
  const candidate = value.trim()
  if (!/^\d+$/.test(candidate)) return undefined
  return boundedRetryAfterSeconds(Number(candidate))
}

function isEnvelope<T>(value: unknown): value is ApiEnvelope<T> {
  return typeof value === 'object' && value !== null && 'data' in value
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    'error' in value &&
    typeof value.error === 'object' &&
    value.error !== null
  )
}

export function readCookie(name: string, cookieSource?: string): string | undefined {
  const source =
    cookieSource ?? (typeof document === 'undefined' ? '' : document.cookie)

  for (const part of source.split(';')) {
    const candidate = part.trim()
    if (!candidate) continue
    const separator = candidate.indexOf('=')
    const rawName = separator === -1 ? candidate : candidate.slice(0, separator)
    if (rawName !== name) continue

    const rawValue = separator === -1 ? '' : candidate.slice(separator + 1)
    try {
      return decodeURIComponent(rawValue)
    } catch {
      return rawValue
    }
  }
  return undefined
}

export function apiEndpoint(path: string): string {
  return `${API_BASE_URL}${path}`
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  expectedSuccessStatus?: number,
): Promise<T> {
  const headers = new Headers(init.headers)
  const method = (init.method ?? 'GET').toUpperCase()
  headers.set('Accept', 'application/json')
  if (init.body && !(init.body instanceof Blob) && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }
  if (!SAFE_METHODS.has(method)) {
    const csrfToken = readCookie(CSRF_COOKIE_NAME)
    if (csrfToken) headers.set(CSRF_HEADER_NAME, csrfToken)
  }

  const response = await fetch(apiEndpoint(path), {
    ...init,
    method,
    credentials: 'include',
    headers,
  })

  if (!response.ok) {
    let body: ApiErrorBody | undefined
    try {
      const payload: unknown = await response.json()
      body = isErrorEnvelope(payload) ? payload.error : (payload as ApiErrorBody)
    } catch {
      body = undefined
    }
    throw new ApiError(
      body?.message ?? `请求失败（HTTP ${response.status}）`,
      response.status,
      body,
      {
        retryAfterSeconds: parseRetryAfterSeconds(
          response.headers.get('Retry-After'),
        ),
      },
    )
  }

  if (
    expectedSuccessStatus !== undefined &&
    response.status !== expectedSuccessStatus
  ) {
    throw new ApiError(
      `服务端返回了无效状态（HTTP ${response.status}）`,
      502,
      {
        code: 'INVALID_RESPONSE_STATUS',
        message: '服务端响应状态不符合接口约定',
        details: {
          expected_status: expectedSuccessStatus,
          actual_status: response.status,
        },
      },
    )
  }

  if (response.status === 204) {
    return undefined as T
  }

  const body: unknown = await response.json()
  return isEnvelope<T>(body) ? body.data : (body as T)
}

function fallbackReportFilename(
  format: CreateTaskReportInput['format'],
  encoding: ReportDownloadEncoding = 'identity',
): string {
  return `binaryscan-report.${format}${encoding === 'gzip' ? '.gz' : ''}`
}

function safeFilenameCandidate(value: string): string | undefined {
  const candidate = value.trim()
  const hasControlCharacter = Array.from(candidate).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0
    return codePoint <= 31 || codePoint === 127
  })
  if (
    !candidate ||
    candidate === '.' ||
    candidate === '..' ||
    candidate.length > 255 ||
    hasControlCharacter ||
    /[\\/:]/.test(candidate)
  ) {
    return undefined
  }
  return candidate
}

export function safeReportDownloadFilename(
  value: string,
  format: CreateTaskReportInput['format'],
  encoding: ReportDownloadEncoding = 'identity',
): string {
  const candidate = safeFilenameCandidate(value)
  const suffix = `.${format}${encoding === 'gzip' ? '.gz' : ''}`
  return candidate?.toLowerCase().endsWith(suffix)
    ? candidate
    : fallbackReportFilename(format, encoding)
}

/**
 * Reads only a single safe filename from Content-Disposition.
 *
 * Path separators and control characters are rejected instead of normalized,
 * so a compromised response cannot steer a browser download outside the
 * user's selected download location.
 */
export function reportDownloadFilename(
  contentDisposition: string | null,
  format: CreateTaskReportInput['format'],
  encoding: ReportDownloadEncoding = 'identity',
): string {
  const fallback = fallbackReportFilename(format, encoding)
  if (!contentDisposition || /[\r\n]/.test(contentDisposition)) return fallback
  const validate = (value: string): string | undefined => {
    const candidate = safeReportDownloadFilename(value, format, encoding)
    return candidate === fallback && value.trim() !== fallback
      ? undefined
      : candidate
  }

  const encodedMatch = /(?:^|;)\s*filename\*\s*=\s*UTF-8''([^;]*)/i.exec(
    contentDisposition,
  )
  if (encodedMatch?.[1]) {
    try {
      const decoded = validate(decodeURIComponent(encodedMatch[1].trim()))
      if (decoded) return decoded
    } catch {
      return fallback
    }
  }

  const quotedMatch = /(?:^|;)\s*filename\s*=\s*"([^"]*)"/i.exec(
    contentDisposition,
  )
  const plainMatch = /(?:^|;)\s*filename\s*=\s*([^;]*)/i.exec(
    contentDisposition,
  )
  return (
    validate(quotedMatch?.[1] ?? plainMatch?.[1] ?? '') ??
    fallback
  )
}

function sameOriginReportDownload(path: string): ReportDownload {
  const endpoint = apiEndpoint(path)
  if (typeof window === 'undefined') {
    return { kind: 'url', url: endpoint }
  }

  const target = new URL(endpoint, window.location.href)
  if (
    target.origin !== window.location.origin ||
    target.username ||
    target.password
  ) {
    throw new ApiError('报告下载地址必须与当前页面同源', 0, {
      code: 'UNSAFE_REPORT_DOWNLOAD_URL',
    })
  }
  return {
    kind: 'url',
    url: `${target.pathname}${target.search}${target.hash}`,
  }
}

function buildQuery(query: TaskListQuery): string {
  const params = new URLSearchParams({
    page_size: String(query.page_size),
  })
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.keyword) params.set('keyword', query.keyword)
  if (query.status) params.set('status', query.status)
  if (query.input_type) params.set('input_type', query.input_type)
  if (query.creator) params.set('creator', query.creator)
  if (query.tag) params.set('tag', query.tag)
  if (query.created_from) params.set('created_from', query.created_from)
  if (query.created_to) params.set('created_to', query.created_to)
  return params.toString()
}

function buildFileNodeQuery(query: FileNodeListQuery): string {
  const params = new URLSearchParams()
  if (query.parent_id) params.set('parent_id', query.parent_id)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function invalidFileNodeResponse(error: unknown): never {
  if (!(error instanceof FileNodeContractError)) throw error
  throw new ApiError('文件节点响应不符合接口契约', 502, {
    code: 'INVALID_FILE_NODE_RESPONSE',
  })
}

async function listTaskFiles(
  taskId: string,
  query: FileNodeListQuery = {},
): Promise<FileNodePage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/files${buildFileNodeQuery(query)}`,
    )
    return parseFileNodePage(payload)
  } catch (error) {
    return invalidFileNodeResponse(error)
  }
}

async function getTaskFile(
  taskId: string,
  fileId: string,
): Promise<FileNodeDetail> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/files/${encodeURIComponent(fileId)}`,
    )
    return parseFileNodeDetail(payload)
  } catch (error) {
    return invalidFileNodeResponse(error)
  }
}

function buildDecompileResultQuery(query: DecompileResultListQuery): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildDecompileProjectQuery(query: DecompileProjectListQuery): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function invalidDecompileProjectResponse(error: unknown): never {
  if (!(error instanceof DecompileProjectContractError)) throw error
  throw new ApiError('反编译源码项目响应不符合接口契约', 502, {
    code: 'INVALID_DECOMPILE_PROJECT_RESPONSE',
  })
}

async function listDecompileProjects(
  taskId: string,
  query: DecompileProjectListQuery = {},
): Promise<DecompileProjectPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects${buildDecompileProjectQuery(query)}`,
    )
    return parseDecompileProjectPage(payload)
  } catch (error) {
    return invalidDecompileProjectResponse(error)
  }
}

async function getDecompileProject(
  taskId: string,
  projectId: string,
): Promise<DecompileProject> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}`,
    )
    return parseDecompileProject(payload)
  } catch (error) {
    return invalidDecompileProjectResponse(error)
  }
}

function invalidCAnalysisResponse(error: unknown): never {
  if (!(error instanceof CAnalysisContractError)) throw error
  throw new ApiError('C 源码检测响应不符合接口契约', 502, {
    code: 'INVALID_C_ANALYSIS_RESPONSE',
  })
}

function buildCAnalysisRunQuery(query: CAnalysisRunListQuery): string {
  const params = new URLSearchParams()
  if (query.project_id) params.set('project_id', query.project_id)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildCAnalysisFindingQuery(query: CAnalysisFindingListQuery): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  if (query.cwe) params.set('cwe', query.cwe)
  if (query.severity) params.set('severity', query.severity)
  if (query.function) params.set('function', query.function)
  const value = params.toString()
  return value ? `?${value}` : ''
}

async function createCAnalysisRun(
  taskId: string,
  projectId: string,
  idempotencyKey: string,
): Promise<CAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}/c-analysis-runs`,
      {
        method: 'POST',
        headers: { 'Idempotency-Key': idempotencyKey },
      },
    )
    return parseCAnalysisRun(payload)
  } catch (error) {
    return invalidCAnalysisResponse(error)
  }
}

async function listCAnalysisRuns(
  taskId: string,
  query: CAnalysisRunListQuery = {},
): Promise<CAnalysisRunPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/c-analysis-runs${buildCAnalysisRunQuery(query)}`,
    )
    return parseCAnalysisRunPage(payload)
  } catch (error) {
    return invalidCAnalysisResponse(error)
  }
}

async function getCAnalysisRun(
  taskId: string,
  runId: string,
): Promise<CAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/c-analysis-runs/${encodeURIComponent(runId)}`,
    )
    return parseCAnalysisRun(payload)
  } catch (error) {
    return invalidCAnalysisResponse(error)
  }
}

async function listCAnalysisFindings(
  taskId: string,
  runId: string,
  query: CAnalysisFindingListQuery = {},
): Promise<CAnalysisFindingPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/c-analysis-runs/${encodeURIComponent(runId)}/findings${buildCAnalysisFindingQuery(query)}`,
    )
    return parseCAnalysisFindingPage(payload)
  } catch (error) {
    return invalidCAnalysisResponse(error)
  }
}

function invalidJavaAnalysisResponse(error: unknown): never {
  if (!(error instanceof JavaAnalysisContractError)) throw error
  throw new ApiError('Java 源码检测响应不符合接口契约', 502, {
    code: 'INVALID_JAVA_ANALYSIS_RESPONSE',
  })
}

function invalidPythonAnalysisResponse(error: unknown): never {
  if (!(error instanceof PythonAnalysisContractError)) throw error
  throw new ApiError('Python 检测响应不符合接口契约', 502, {
    code: 'INVALID_PYTHON_ANALYSIS_RESPONSE',
  })
}

function buildPythonAnalysisRunQuery(query: PythonAnalysisRunListQuery): string {
  const params = new URLSearchParams()
  if (query.project_id) params.set('project_id', query.project_id)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildPythonAnalysisFindingQuery(
  query: PythonAnalysisFindingListQuery,
): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  if (query.cwe) params.set('cwe', query.cwe)
  if (query.severity) params.set('severity', query.severity)
  if (query.file) params.set('file', query.file)
  if (query.callable) params.set('callable', query.callable)
  const value = params.toString()
  return value ? `?${value}` : ''
}

async function createPythonAnalysisRun(
  taskId: string,
  projectId: string,
  idempotencyKey: string,
): Promise<PythonAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}/python-analysis-runs`,
      {
        method: 'POST',
        headers: { 'Idempotency-Key': idempotencyKey },
      },
    )
    return parsePythonAnalysisRun(payload)
  } catch (error) {
    return invalidPythonAnalysisResponse(error)
  }
}

async function listPythonAnalysisRuns(
  taskId: string,
  query: PythonAnalysisRunListQuery = {},
): Promise<PythonAnalysisRunPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/python-analysis-runs${buildPythonAnalysisRunQuery(query)}`,
    )
    return parsePythonAnalysisRunPage(payload)
  } catch (error) {
    return invalidPythonAnalysisResponse(error)
  }
}

async function getPythonAnalysisRun(
  taskId: string,
  runId: string,
): Promise<PythonAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/python-analysis-runs/${encodeURIComponent(runId)}`,
    )
    return parsePythonAnalysisRun(payload)
  } catch (error) {
    return invalidPythonAnalysisResponse(error)
  }
}

async function listPythonAnalysisFindings(
  taskId: string,
  runId: string,
  query: PythonAnalysisFindingListQuery = {},
): Promise<PythonAnalysisFindingPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/python-analysis-runs/${encodeURIComponent(runId)}/findings${buildPythonAnalysisFindingQuery(query)}`,
    )
    return parsePythonAnalysisFindingPage(payload)
  } catch (error) {
    return invalidPythonAnalysisResponse(error)
  }
}


function buildJavaAnalysisRunQuery(query: JavaAnalysisRunListQuery): string {
  const params = new URLSearchParams()
  if (query.project_id) params.set('project_id', query.project_id)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildJavaAnalysisFindingQuery(
  query: JavaAnalysisFindingListQuery,
): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  if (query.cwe) params.set('cwe', query.cwe)
  if (query.severity) params.set('severity', query.severity)
  if (query.file) params.set('file', query.file)
  if (query.callable) params.set('callable', query.callable)
  const value = params.toString()
  return value ? `?${value}` : ''
}

async function createJavaAnalysisRun(
  taskId: string,
  projectId: string,
  idempotencyKey: string,
): Promise<JavaAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}/java-analysis-runs`,
      {
        method: 'POST',
        headers: { 'Idempotency-Key': idempotencyKey },
      },
    )
    return parseJavaAnalysisRun(payload)
  } catch (error) {
    return invalidJavaAnalysisResponse(error)
  }
}

async function listJavaAnalysisRuns(
  taskId: string,
  query: JavaAnalysisRunListQuery = {},
): Promise<JavaAnalysisRunPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/java-analysis-runs${buildJavaAnalysisRunQuery(query)}`,
    )
    return parseJavaAnalysisRunPage(payload)
  } catch (error) {
    return invalidJavaAnalysisResponse(error)
  }
}

async function getJavaAnalysisRun(
  taskId: string,
  runId: string,
): Promise<JavaAnalysisRun> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/java-analysis-runs/${encodeURIComponent(runId)}`,
    )
    return parseJavaAnalysisRun(payload)
  } catch (error) {
    return invalidJavaAnalysisResponse(error)
  }
}

async function listJavaAnalysisFindings(
  taskId: string,
  runId: string,
  query: JavaAnalysisFindingListQuery = {},
): Promise<JavaAnalysisFindingPage> {
  try {
    const payload = await request<unknown>(
      `/tasks/${encodeURIComponent(taskId)}/java-analysis-runs/${encodeURIComponent(runId)}/findings${buildJavaAnalysisFindingQuery(query)}`,
    )
    return parseJavaAnalysisFindingPage(payload)
  } catch (error) {
    return invalidJavaAnalysisResponse(error)
  }
}

function buildDecompileSourceQuery(query: DecompileSourceQuery): string {
  const params = new URLSearchParams()
  if (query.offset !== undefined) params.set('offset', String(query.offset))
  if (query.limit !== undefined) params.set('limit', String(query.limit))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildVulnerabilityQuery(query: VulnerabilityListQuery): string {
  const params = new URLSearchParams()
  if (query.severity) params.set('severity', query.severity)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildCursorQuery(
  query: AdminUserListQuery | AuditLogListQuery,
): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  if ('keyword' in query && query.keyword) params.set('keyword', query.keyword)
  if ('role' in query && query.role) params.set('role', query.role)
  if ('status' in query && query.status) params.set('status', query.status)
  if ('action' in query && query.action) params.set('action', query.action)
  if ('outcome' in query && query.outcome) params.set('outcome', query.outcome)
  if ('actor' in query && query.actor) params.set('actor', query.actor)
  if ('created_from' in query && query.created_from) {
    params.set('created_from', query.created_from)
  }
  if ('created_to' in query && query.created_to) {
    params.set('created_to', query.created_to)
  }
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildArchiveEntryQuery(query: ArchiveImportEntryListQuery): string {
  const params = new URLSearchParams()
  if (query.filter && query.filter !== 'all') params.set('filter', query.filter)
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function buildArchiveImportQuery(query: ArchiveImportListQuery): string {
  const params = new URLSearchParams()
  if (query.cursor) params.set('cursor', query.cursor)
  if (query.page_size !== undefined) params.set('page_size', String(query.page_size))
  const value = params.toString()
  return value ? `?${value}` : ''
}

function invalidUploadIntakeResponse(error: unknown): never {
  if (!(error instanceof UploadIntakeContractError)) throw error
  throw new ApiError('上传响应不符合接口契约', 502, {
    code: 'INVALID_UPLOAD_RESPONSE',
  })
}

function invalidArchiveImportResponse(error: unknown): never {
  if (!(error instanceof ArchiveImportContractError)) throw error
  throw new ApiError('归档导入响应不符合接口契约', 502, {
    code: 'INVALID_ARCHIVE_IMPORT_RESPONSE',
  })
}

async function createUpload(
  input: CreateUploadInput,
  idempotencyKey: string,
): Promise<UploadSession> {
  try {
    return parseCreatedUploadSession(
      await request<unknown>('/uploads', {
        method: 'POST',
        body: JSON.stringify(input),
        headers: { 'Idempotency-Key': idempotencyKey },
      }),
      input.input_category,
    )
  } catch (error) {
    return invalidUploadIntakeResponse(error)
  }
}

async function getUpload(uploadId: string): Promise<UploadSession> {
  try {
    return parseUploadSession(
      await request<unknown>(`/uploads/${encodeURIComponent(uploadId)}`),
      uploadId,
    )
  } catch (error) {
    return invalidUploadIntakeResponse(error)
  }
}

async function completeUpload(uploadId: string): Promise<CompletedUpload> {
  try {
    return parseCompletedUpload(
      await request<unknown>(
        `/uploads/${encodeURIComponent(uploadId)}/complete`,
        { method: 'POST' },
      ),
      uploadId,
    )
  } catch (error) {
    return invalidUploadIntakeResponse(error)
  }
}

async function listArchiveImports(
  query: ArchiveImportListQuery = {},
): Promise<ArchiveImportPage> {
  try {
    return parseArchiveImportPage(
      await request<unknown>(`/archive-imports${buildArchiveImportQuery(query)}`),
    )
  } catch (error) {
    return invalidArchiveImportResponse(error)
  }
}

async function getArchiveImport(importId: string): Promise<ArchiveImport> {
  try {
    const parsed = parseArchiveImport(
      await request<unknown>(
        `/archive-imports/${encodeURIComponent(importId)}`,
      ),
    )
    if (parsed.id !== importId) {
      throw new ArchiveImportContractError('data.id')
    }
    return parsed
  } catch (error) {
    return invalidArchiveImportResponse(error)
  }
}

async function listArchiveImportEntries(
  importId: string,
  query: ArchiveImportEntryListQuery = {},
): Promise<ArchiveImportEntryPage> {
  try {
    return parseArchiveImportEntryPage(
      await request<unknown>(
        `/archive-imports/${encodeURIComponent(importId)}/entries${buildArchiveEntryQuery(query)}`,
      ),
    )
  } catch (error) {
    return invalidArchiveImportResponse(error)
  }
}

async function createArchiveTaskBatch(
  importId: string,
  input: CreateArchiveTaskBatchInput,
  idempotencyKey: string,
): Promise<ArchiveTaskBatchResult> {
  try {
    return parseArchiveTaskBatchResult(
      await request<unknown>(
        `/archive-imports/${encodeURIComponent(importId)}/task-batches`,
        {
          method: 'POST',
          body: JSON.stringify(input),
          headers: { 'Idempotency-Key': idempotencyKey },
        },
      ),
      input.entry_ids,
    )
  } catch (error) {
    return invalidArchiveImportResponse(error)
  }
}

async function changePassword(input: ChangePasswordInput): Promise<CurrentUser> {
  const user = await request<CurrentUser | undefined>('/me/password', {
    method: 'PUT',
    body: JSON.stringify(input),
  })
  return user ?? request<CurrentUser>('/me')
}

async function taskRequest(
  path: string,
  init: RequestInit = {},
): Promise<TaskDetail> {
  return parseTaskDetail(await request<unknown>(path, init))
}

export const httpApi: ApiClient = {
  login: (input: LoginInput) =>
    request<CurrentUser>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  getMe: () => request<CurrentUser>('/me'),
  changePassword,
  listTasks: async (query: TaskListQuery) =>
    parseTaskPage(await request<unknown>(`/tasks?${buildQuery(query)}`)),
  getTask: (id: string) => taskRequest(`/tasks/${encodeURIComponent(id)}`),
  cancelTask: (id: string, idempotencyKey: string) =>
    taskRequest(`/tasks/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
      headers: {
        'Idempotency-Key': idempotencyKey,
      },
    }),
  retryTask: (id: string, idempotencyKey: string) =>
    taskRequest(`/tasks/${encodeURIComponent(id)}/retry`, {
      method: 'POST',
      headers: {
        'Idempotency-Key': idempotencyKey,
      },
    }),
  deleteTask: (id: string) =>
    taskRequest(`/tasks/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),
  extendTaskRetention: (id: string, input: ExtendTaskRetentionInput) =>
    taskRequest(`/tasks/${encodeURIComponent(id)}/retention`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    }),
  listTaskFiles,
  getTaskFile,
  createFileDecompileRequest: (
    taskId: string,
    fileId: string,
    input: CreateFileDecompileRequestInput,
    idempotencyKey: string,
  ) =>
    request<FileDecompileRequest>(
      `/tasks/${encodeURIComponent(taskId)}/files/${encodeURIComponent(fileId)}/decompile`,
      {
        method: 'POST',
        body: JSON.stringify(input),
        headers: {
          'Idempotency-Key': idempotencyKey,
        },
      },
    ),
  getFileDecompileRequest: (taskId: string, jobId: string) =>
    request<FileDecompileRequest>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-jobs/${encodeURIComponent(jobId)}`,
    ),
  listDecompileProjects,
  getDecompileProject,
  downloadDecompileProject: (taskId: string, projectId: string) =>
    Promise.resolve(
      sameOriginReportDownload(
        `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}.zip`,
      ),
    ),
  deleteDecompileProject: (taskId: string, projectId: string) =>
    request<void>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}`,
      { method: 'DELETE' },
    ),
  previewDecompileProjectDeletion: async (
    taskId: string,
    projectId: string,
  ): Promise<DecompileProjectDeletionPreview> => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}/deletion-preview`,
        { method: 'POST' },
      )
      return parseDecompileProjectDeletionPreview(payload)
    } catch (error) {
      return invalidDecompileProjectResponse(error)
    }
  },
  confirmDecompileProjectDeletion: async (
    taskId: string,
    projectId: string,
    input: ConfirmDecompileProjectDeletionInput,
  ): Promise<DecompileProjectDeletionOperation> => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/decompile-projects/${encodeURIComponent(projectId)}/deletion`,
        { method: 'POST', body: JSON.stringify(input) },
      )
      return parseDecompileProjectDeletionOperation(payload)
    } catch (error) {
      return invalidDecompileProjectResponse(error)
    }
  },
  getDecompileProjectDeletion: async (
    taskId: string,
    operationId: string,
  ): Promise<DecompileProjectDeletionOperation> => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/decompile-project-deletions/${encodeURIComponent(operationId)}`,
      )
      return parseDecompileProjectDeletionOperation(payload)
    } catch (error) {
      return invalidDecompileProjectResponse(error)
    }
  },
  createCAnalysisRun,
  listCAnalysisRuns,
  getCAnalysisRun,
  listCAnalysisFindings,
  cancelCAnalysisRun: async (taskId: string, runId: string) => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/c-analysis-runs/${encodeURIComponent(runId)}/cancel`,
        { method: 'POST' },
      )
      return parseCAnalysisRun(payload)
    } catch (error) {
      return invalidCAnalysisResponse(error)
    }
  },
  deleteCAnalysisRun: (taskId: string, runId: string) =>
    request<void>(
      `/tasks/${encodeURIComponent(taskId)}/c-analysis-runs/${encodeURIComponent(runId)}`,
      { method: 'DELETE' },
    ),
  createJavaAnalysisRun,
  listJavaAnalysisRuns,
  getJavaAnalysisRun,
  listJavaAnalysisFindings,
  cancelJavaAnalysisRun: async (taskId: string, runId: string) => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/java-analysis-runs/${encodeURIComponent(runId)}/cancel`,
        { method: 'POST' },
      )
      return parseJavaAnalysisRun(payload)
    } catch (error) {
      return invalidJavaAnalysisResponse(error)
    }
  },
  createPythonAnalysisRun,
  listPythonAnalysisRuns,
  getPythonAnalysisRun,
  listPythonAnalysisFindings,
  cancelPythonAnalysisRun: async (taskId: string, runId: string) => {
    try {
      const payload = await request<unknown>(
        `/tasks/${encodeURIComponent(taskId)}/python-analysis-runs/${encodeURIComponent(runId)}/cancel`,
        { method: 'POST' },
      )
      return parsePythonAnalysisRun(payload)
    } catch (error) {
      return invalidPythonAnalysisResponse(error)
    }
  },
  deletePythonAnalysisRun: (taskId: string, runId: string) =>
    request<void>(
      `/tasks/${encodeURIComponent(taskId)}/python-analysis-runs/${encodeURIComponent(runId)}`,
      { method: 'DELETE' },
    ),
  deleteJavaAnalysisRun: (taskId: string, runId: string) =>
    request<void>(
      `/tasks/${encodeURIComponent(taskId)}/java-analysis-runs/${encodeURIComponent(runId)}`,
      { method: 'DELETE' },
    ),
  createManualImageScanRequest: (
    taskId: string,
    fileId: string,
    idempotencyKey: string,
  ) =>
    request<ManualImageScanRequest>(
      `/tasks/${encodeURIComponent(taskId)}/files/${encodeURIComponent(fileId)}/image-scan`,
      {
        method: 'POST',
        body: JSON.stringify({}),
        headers: {
          'Idempotency-Key': idempotencyKey,
        },
      },
    ),
  listDecompileResults: (
    taskId: string,
    query: DecompileResultListQuery = {},
  ) =>
    request<DecompileResultPage>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-results${buildDecompileResultQuery(query)}`,
    ),
  getDecompileSource: (
    taskId: string,
    resultId: string,
    query: DecompileSourceQuery = {},
  ) =>
    request<DecompileSourceChunk>(
      `/tasks/${encodeURIComponent(taskId)}/decompile-results/${encodeURIComponent(resultId)}/source${buildDecompileSourceQuery(query)}`,
    ),
  downloadDecompileSources: (
    taskId: string,
    includeCombined = false,
  ) =>
    Promise.resolve(
      sameOriginReportDownload(
        `/tasks/${encodeURIComponent(taskId)}/decompile-sources.zip${
          includeCombined ? '?combined=true' : ''
        }`,
      ),
    ),
  listTaskVulnerabilities: (
    taskId: string,
    query: VulnerabilityListQuery = {},
  ) =>
    request<VulnerabilityFindingPage>(
      `/tasks/${encodeURIComponent(taskId)}/vulnerabilities${buildVulnerabilityQuery(query)}`,
    ),
  getTaskVulnerability: (taskId: string, findingId: string) =>
    request<VulnerabilityFinding>(
      `/tasks/${encodeURIComponent(taskId)}/vulnerabilities/${encodeURIComponent(findingId)}`,
    ),
  listTaskReports: (taskId: string) =>
    request<TaskReportList>(
      `/tasks/${encodeURIComponent(taskId)}/reports`,
    ),
  createTaskReport: (
    taskId: string,
    input: CreateTaskReportInput,
    idempotencyKey: string,
  ) =>
    request<TaskReport>(`/tasks/${encodeURIComponent(taskId)}/reports`, {
      method: 'POST',
      body: JSON.stringify(input),
      headers: {
        'Idempotency-Key': idempotencyKey,
      },
    }),
  downloadTaskReport: (
    taskId: string,
    reportId: string,
    format: CreateTaskReportInput['format'],
    encoding: ReportDownloadEncoding = 'identity',
  ) => {
    void format
    return Promise.resolve(
      sameOriginReportDownload(
        `/tasks/${encodeURIComponent(taskId)}/reports/${encodeURIComponent(reportId)}/download${
          encoding === 'gzip' ? '?encoding=gzip' : ''
        }`,
      ),
    )
  },
  getSystemStatus: () => request<SystemStatus>('/admin/system'),
  listAdminUsers: (query: AdminUserListQuery = {}) =>
    request<AdminUserPage>(`/admin/users${buildCursorQuery(query)}`),
  createAdminUser: (input: CreateAdminUserInput) =>
    request<AdminUser>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  updateAdminUser: (id: string, input: UpdateAdminUserInput) =>
    request<AdminUser>(`/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    }),
  resetAdminUserPassword: (
    id: string,
    input: ResetAdminUserPasswordInput,
  ) =>
    request<AdminUser>(
      `/admin/users/${encodeURIComponent(id)}/reset-password`,
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
    ),
  listAuditLogs: (query: AuditLogListQuery = {}) =>
    request<AuditLogPage>(`/admin/audit-logs${buildCursorQuery(query)}`),
  createUpload,
  getUpload,
  uploadPart: (uploadId: string, input: UploadPartInput) =>
    request<void>(`/uploads/${encodeURIComponent(uploadId)}/parts/${input.part_number}`, {
      method: 'PUT',
      body: input.chunk,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Range': `bytes ${input.start}-${input.end}/${input.total}`,
        'X-Chunk-SHA256': input.sha256.toLowerCase(),
      },
    }),
  completeUpload,
  deleteUpload: (uploadId: string) =>
    request<void>(`/uploads/${encodeURIComponent(uploadId)}`, {
      method: 'DELETE',
    }, 204),
  listArchiveImports,
  getArchiveImport,
  listArchiveImportEntries,
  createArchiveTaskBatch,
  createTask: (input: CreateTaskInput, idempotencyKey: string) =>
    request<CreatedTask>('/tasks', {
      method: 'POST',
      body: JSON.stringify(input),
      headers: {
        'Idempotency-Key': idempotencyKey,
      },
    }),
}

let activeApi: ApiClient = httpApi

/**
 * Installs one application-wide transport adapter before the router starts.
 * Feature modules keep a stable facade, which also keeps existing unit-test
 * spies predictable.
 */
export function configureApiClient(client: ApiClient): void {
  activeApi = client
}

export function resetApiClient(): void {
  activeApi = httpApi
}

export const api: ApiClient = {
  login: (input) => activeApi.login(input),
  logout: () => activeApi.logout(),
  getMe: () => activeApi.getMe(),
  changePassword: (input) => activeApi.changePassword(input),
  listTasks: (query) => activeApi.listTasks(query),
  getTask: (id) => activeApi.getTask(id),
  cancelTask: (id, idempotencyKey) => activeApi.cancelTask(id, idempotencyKey),
  retryTask: (id, idempotencyKey) => activeApi.retryTask(id, idempotencyKey),
  deleteTask: (id) => activeApi.deleteTask(id),
  extendTaskRetention: (id, input) =>
    activeApi.extendTaskRetention(id, input),
  listTaskFiles: (taskId, query) => activeApi.listTaskFiles(taskId, query),
  getTaskFile: (taskId, fileId) => activeApi.getTaskFile(taskId, fileId),
  createFileDecompileRequest: (taskId, fileId, input, idempotencyKey) =>
    activeApi.createFileDecompileRequest(
      taskId,
      fileId,
      input,
      idempotencyKey,
    ),
  getFileDecompileRequest: (taskId, jobId) =>
    activeApi.getFileDecompileRequest(taskId, jobId),
  listDecompileProjects: (taskId, query) =>
    activeApi.listDecompileProjects(taskId, query),
  getDecompileProject: (taskId, projectId) =>
    activeApi.getDecompileProject(taskId, projectId),
  downloadDecompileProject: (taskId, projectId) =>
    activeApi.downloadDecompileProject(taskId, projectId),
  deleteDecompileProject: (taskId, projectId) =>
    activeApi.deleteDecompileProject(taskId, projectId),
  previewDecompileProjectDeletion: (taskId, projectId) =>
    activeApi.previewDecompileProjectDeletion(taskId, projectId),
  confirmDecompileProjectDeletion: (taskId, projectId, input) =>
    activeApi.confirmDecompileProjectDeletion(taskId, projectId, input),
  getDecompileProjectDeletion: (taskId, operationId) =>
    activeApi.getDecompileProjectDeletion(taskId, operationId),
  createCAnalysisRun: (taskId, projectId, idempotencyKey) =>
    activeApi.createCAnalysisRun(taskId, projectId, idempotencyKey),
  listCAnalysisRuns: (taskId, query) =>
    activeApi.listCAnalysisRuns(taskId, query),
  getCAnalysisRun: (taskId, runId) =>
    activeApi.getCAnalysisRun(taskId, runId),
  listCAnalysisFindings: (taskId, runId, query) =>
    activeApi.listCAnalysisFindings(taskId, runId, query),
  cancelCAnalysisRun: (taskId, runId) =>
    activeApi.cancelCAnalysisRun(taskId, runId),
  deleteCAnalysisRun: (taskId, runId) =>
    activeApi.deleteCAnalysisRun(taskId, runId),
  createJavaAnalysisRun: (taskId, projectId, idempotencyKey) =>
    activeApi.createJavaAnalysisRun(taskId, projectId, idempotencyKey),
  listJavaAnalysisRuns: (taskId, query) =>
    activeApi.listJavaAnalysisRuns(taskId, query),
  getJavaAnalysisRun: (taskId, runId) =>
    activeApi.getJavaAnalysisRun(taskId, runId),
  listJavaAnalysisFindings: (taskId, runId, query) =>
    activeApi.listJavaAnalysisFindings(taskId, runId, query),
  cancelJavaAnalysisRun: (taskId, runId) =>
    activeApi.cancelJavaAnalysisRun(taskId, runId),
  deleteJavaAnalysisRun: (taskId, runId) =>
    activeApi.deleteJavaAnalysisRun(taskId, runId),
  createPythonAnalysisRun: (taskId, projectId, idempotencyKey) =>
    activeApi.createPythonAnalysisRun(taskId, projectId, idempotencyKey),
  listPythonAnalysisRuns: (taskId, query) =>
    activeApi.listPythonAnalysisRuns(taskId, query),
  getPythonAnalysisRun: (taskId, runId) =>
    activeApi.getPythonAnalysisRun(taskId, runId),
  listPythonAnalysisFindings: (taskId, runId, query) =>
    activeApi.listPythonAnalysisFindings(taskId, runId, query),
  cancelPythonAnalysisRun: (taskId, runId) =>
    activeApi.cancelPythonAnalysisRun(taskId, runId),
  deletePythonAnalysisRun: (taskId, runId) =>
    activeApi.deletePythonAnalysisRun(taskId, runId),
  createManualImageScanRequest: (taskId, fileId, idempotencyKey) =>
    activeApi.createManualImageScanRequest(
      taskId,
      fileId,
      idempotencyKey,
    ),
  listDecompileResults: (taskId, query) =>
    activeApi.listDecompileResults(taskId, query),
  getDecompileSource: (taskId, resultId, query) =>
    activeApi.getDecompileSource(taskId, resultId, query),
  downloadDecompileSources: (taskId, includeCombined) =>
    activeApi.downloadDecompileSources(taskId, includeCombined),
  listTaskVulnerabilities: (taskId, query) =>
    activeApi.listTaskVulnerabilities(taskId, query),
  getTaskVulnerability: (taskId, findingId) =>
    activeApi.getTaskVulnerability(taskId, findingId),
  listTaskReports: (taskId) => activeApi.listTaskReports(taskId),
  createTaskReport: (taskId, input, idempotencyKey) =>
    activeApi.createTaskReport(taskId, input, idempotencyKey),
  downloadTaskReport: (taskId, reportId, format, encoding) =>
    activeApi.downloadTaskReport(taskId, reportId, format, encoding),
  getSystemStatus: () => activeApi.getSystemStatus(),
  listAdminUsers: (query) => activeApi.listAdminUsers(query),
  createAdminUser: (input) => activeApi.createAdminUser(input),
  updateAdminUser: (id, input) => activeApi.updateAdminUser(id, input),
  resetAdminUserPassword: (id, input) =>
    activeApi.resetAdminUserPassword(id, input),
  listAuditLogs: (query) => activeApi.listAuditLogs(query),
  createUpload: (input, idempotencyKey) =>
    activeApi.createUpload(input, idempotencyKey),
  getUpload: (uploadId) => activeApi.getUpload(uploadId),
  uploadPart: (uploadId, input) => activeApi.uploadPart(uploadId, input),
  completeUpload: (uploadId) => activeApi.completeUpload(uploadId),
  deleteUpload: (uploadId) => activeApi.deleteUpload(uploadId),
  listArchiveImports: (query) => activeApi.listArchiveImports(query),
  getArchiveImport: (importId) => activeApi.getArchiveImport(importId),
  listArchiveImportEntries: (importId, query) =>
    activeApi.listArchiveImportEntries(importId, query),
  createArchiveTaskBatch: (importId, input, idempotencyKey) =>
    activeApi.createArchiveTaskBatch(importId, input, idempotencyKey),
  createTask: (input, idempotencyKey) => activeApi.createTask(input, idempotencyKey),
}
