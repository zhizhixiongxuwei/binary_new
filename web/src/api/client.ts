import type {
  AdminUser,
  AdminUserListQuery,
  AdminUserPage,
  ApiErrorBody,
  AuditLogListQuery,
  AuditLogPage,
  ChangePasswordInput,
  CompletedUpload,
  CreatedTask,
  CreateUploadInput,
  CreateTaskInput,
  CreateAdminUserInput,
  CurrentUser,
  CreateFileDecompileRequestInput,
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
  FileNodeContractError,
  parseFileNodeDetail,
  parseFileNodePage,
} from '@/api/fileNodeContract'
import { parseTaskDetail, parseTaskPage } from '@/api/taskContract'

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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
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
  createUpload: (input: CreateUploadInput, idempotencyKey: string) =>
    request<UploadSession>('/uploads', {
      method: 'POST',
      body: JSON.stringify(input),
      headers: {
        'Idempotency-Key': idempotencyKey,
      },
    }),
  getUpload: (uploadId: string) =>
    request<UploadSession>(`/uploads/${encodeURIComponent(uploadId)}`),
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
  completeUpload: (uploadId: string) =>
    request<CompletedUpload>(`/uploads/${encodeURIComponent(uploadId)}/complete`, {
      method: 'POST',
    }),
  deleteUpload: (uploadId: string) =>
    request<void>(`/uploads/${encodeURIComponent(uploadId)}`, {
      method: 'DELETE',
    }),
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
  createTask: (input, idempotencyKey) => activeApi.createTask(input, idempotencyKey),
}
