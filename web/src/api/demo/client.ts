import type { ApiClient } from '@/api/contract'
import { ApiError } from '@/api/client'
import {
  DEMO_ADMIN,
  DEMO_FILE_NODES,
  DEMO_OPERATOR,
  DEMO_READER,
  DEMO_TASK_IDS,
  DEMO_TASKS,
} from '@/api/demo/fixtures'
import type {
  AdminUser,
  ArchiveImport,
  ArchiveImportEntry,
  AuditLog,
  AuditLogListQuery,
  CompletedUpload,
  CreateUploadInput,
  CurrentUser,
  FileNodeDetail,
  FileNodeListQuery,
  ReportFormat,
  TaskReport,
  ScanTask,
  TaskDetail,
  TaskListQuery,
  UploadPartInput,
  UploadSession,
} from '@/api/types'

interface DemoApiOptions {
  delayMs?: number
}

interface DemoUpload {
  input: CreateUploadInput
  creationSession: UploadSession
  session: UploadSession
  parts: Set<number>
  completed?: CompletedUpload
}

interface DemoArchiveImport {
  value: ArchiveImport
  entries: ArchiveImportEntry[]
  batchResults: Map<string, string>
}

const DEMO_PART_SIZE = 32 * 1024 * 1024
const DEMO_FILE_PAGE_SIZE = 2
const DEFAULT_DELAY_MS = 120

const DEMO_ADMIN_USERS: readonly AdminUser[] = [
  {
    id: '77777777-7777-4777-8777-777777777777',
    username: 'demo-admin',
    display_name: '界面预览管理员',
    role: 'administrator',
    status: 'active',
    must_change_password: false,
    failed_login_count: 0,
    locked_until: null,
    last_login_at: '2026-07-30T09:42:13+08:00',
    created_at: '2026-06-01T08:00:00+08:00',
    updated_at: '2026-07-30T09:42:13+08:00',
  },
  {
    id: '88888888-8888-4888-8888-888888888888',
    username: 'scanner-op',
    display_name: '检测操作员',
    role: 'operator',
    status: 'active',
    must_change_password: false,
    failed_login_count: 0,
    locked_until: null,
    last_login_at: '2026-07-30T09:18:51+08:00',
    created_at: '2026-06-12T10:20:00+08:00',
    updated_at: '2026-07-30T09:18:51+08:00',
  },
]

const DEMO_AUDIT_LOGS: readonly AuditLog[] = [
  {
    id: '18446744073709551501',
    actor: {
      id: '77777777-7777-4777-8777-777777777777',
      username: 'demo-admin',
      display_name: '界面预览管理员',
    },
    action: 'auth.login',
    outcome: 'success',
    object_type: 'session',
    object_id: null,
    request_id: 'demo-request-1041',
    metadata: { method: 'local-password' },
    created_at: '2026-07-30T09:42:13+08:00',
  },
  {
    id: '18446744073709551500',
    actor: {
      id: '88888888-8888-4888-8888-888888888888',
      username: 'scanner-op',
      display_name: '检测操作员',
    },
    action: 'task.create',
    outcome: 'success',
    object_type: 'task',
    object_id: DEMO_TASK_IDS.executable,
    request_id: 'demo-request-1040',
    metadata: { input_type: 'pe32+' },
    created_at: '2026-07-30T09:18:51+08:00',
  },
]

function cloneTask(task: TaskDetail): TaskDetail {
  return {
    ...task,
    tags: [...task.tags],
  }
}

function cloneFileNode(node: FileNodeDetail): FileNodeDetail {
  return {
    ...node,
    metadata_json: structuredClone(node.metadata_json),
    source_parent: node.source_parent ? { ...node.source_parent } : null,
    source_container: node.source_container ? { ...node.source_container } : null,
  }
}

function cloneSession(session: UploadSession): UploadSession {
  return {
    ...session,
    uploaded_parts: [...session.uploaded_parts],
  }
}

function cloneReport(report: TaskReport): TaskReport {
  return { ...report }
}

function pageOffset(cursor: string | undefined): number {
  if (!cursor) return 0
  const match = /^demo-offset-(\d+)$/.exec(cursor)
  if (!match) throw new ApiError('示例分页游标无效', 400, { code: 'INVALID_CURSOR' })
  return Number(match[1])
}

function normalizePageSize(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || value < 1) {
    throw new ApiError('分页大小无效', 400, { code: 'INVALID_PAGE_SIZE' })
  }
  return Math.min(value, 200)
}

function taskMatches(task: ScanTask, query: TaskListQuery): boolean {
  const keyword = query.keyword?.trim().toLocaleLowerCase('zh-CN')
  if (
    keyword &&
    ![task.name, task.id, task.creator_name, ...task.tags]
      .join(' ')
      .toLocaleLowerCase('zh-CN')
      .includes(keyword)
  ) {
    return false
  }
  if (query.status && task.status !== query.status) return false
  if (query.input_type && task.input_type !== query.input_type) return false
  const creator = query.creator?.trim().toLocaleLowerCase('zh-CN')
  if (
    creator &&
    !task.creator_name.toLocaleLowerCase('zh-CN').includes(creator)
  ) {
    return false
  }
  if (query.tag && !task.tags.includes(query.tag)) return false
  const createdDate = task.created_at.slice(0, 10)
  if (query.created_from && createdDate < query.created_from) return false
  if (query.created_to && createdDate > query.created_to) return false
  return true
}

function createdTaskId(counter: number): string {
  return `90000000-0000-4000-8000-${String(counter).padStart(12, '0')}`
}

function createdNodeId(counter: number): string {
  return `9700000000000${String(counter).padStart(6, '0')}`
}

function inferredInputFormat(filename: string): string {
  const extension = filename.split('.').pop()?.toLowerCase()
  const formats: Record<string, string> = {
    apk: 'apk',
    class: 'class',
    dll: 'pe32+',
    exe: 'pe32+',
    gz: 'gzip',
    img: 'img',
    iso: 'iso9660',
    jar: 'jar',
    pyc: 'pyc',
    sys: 'pe32+',
    tar: 'tar',
    zip: 'zip',
  }
  return extension ? (formats[extension] ?? extension) : 'unknown'
}

/**
 * Creates an isolated, deterministic in-memory API implementation.
 *
 * It intentionally has no HTTP fallback. A missing fixture produces an
 * explicit API error instead of reaching the production endpoint.
 */
export function createDemoApiClient(options: DemoApiOptions = {}): ApiClient {
  const delayMs = options.delayMs ?? DEFAULT_DELAY_MS
  const tasks = DEMO_TASKS.map(cloneTask)
  const fileNodes = new Map(
    Object.entries(DEMO_FILE_NODES).map(([taskId, nodes]) => [
      taskId,
      nodes.map(cloneFileNode),
    ]),
  )
  const uploads = new Map<string, DemoUpload>()
  const archiveImports = new Map<string, DemoArchiveImport>()
  const uploadByIdempotencyKey = new Map<
    string,
    { fingerprint: string; uploadId: string }
  >()
  const taskByIdempotencyKey = new Map<string, string>()
  const lifecycleResultByIdempotencyKey = new Map<string, TaskDetail>()
  const reports = new Map<string, TaskReport[]>()
  const reportByIdempotencyKey = new Map<string, TaskReport>()
  let currentUser: CurrentUser | null = { ...DEMO_ADMIN }
  let uploadCounter = 0
  let taskCounter = 0
  let reportCounter = 0

  async function delay(): Promise<void> {
    if (delayMs <= 0) return
    await new Promise<void>((resolve) => {
      globalThis.setTimeout(resolve, delayMs)
    })
  }

  function requireUser(): CurrentUser {
    if (!currentUser) {
      throw new ApiError('示例会话已退出，请重新登录', 401, {
        code: 'UNAUTHENTICATED',
      })
    }
    return currentUser
  }

  function findTask(taskId: string): TaskDetail {
    const task = tasks.find((candidate) => candidate.id === taskId)
    if (!task) {
      throw new ApiError('示例任务不存在', 404, { code: 'TASK_NOT_FOUND' })
    }
    return task
  }

  function findUpload(uploadId: string): DemoUpload {
    const upload = uploads.get(uploadId)
    if (!upload) {
      throw new ApiError('示例上传会话不存在', 404, { code: 'UPLOAD_NOT_FOUND' })
    }
    return upload
  }

  function ensureDirectUploadTask(
    upload: DemoUpload,
    user: CurrentUser,
  ): string {
    if (!upload.completed) {
      throw new ApiError('示例文件尚未完成上传', 409, {
        code: 'upload_not_completed',
      })
    }
    if (upload.completed.task_id) return upload.completed.task_id
    if (upload.input.input_category === 'archive') {
      throw new ApiError('示例归档上传不能创建外层任务', 409, {
        code: 'task_conflict',
      })
    }

    taskCounter += 1
    const id = createdTaskId(taskCounter)
    const createdAt = `2026-07-30T10:${String(taskCounter).padStart(2, '0')}:00+08:00`
    tasks.unshift({
      id,
      name: upload.input.filename,
      input_type: inferredInputFormat(upload.input.filename),
      status: 'QUEUED',
      risk_level: 'UNKNOWN',
      progress: 0,
      progress_indeterminate: false,
      creator_id: user.id,
      creator_name: user.display_name,
      tags: ['UI-PREVIEW'],
      created_at: createdAt,
      original_filename: upload.input.filename,
      size_bytes: upload.completed.size_bytes,
      sha256: upload.completed.sha256,
      sample_expires_at: '2026-08-29T10:00:00+08:00',
      sample_deleted_at: null,
    })
    fileNodes.set(id, [
      {
        id: createdNodeId(taskCounter),
        parent_id: null,
        logical_path: `/${upload.input.filename}`,
        display_name: upload.input.filename,
        archive_name_id: '',
        node_type: 'file',
        depth: 0,
        format: upload.input.filename.split('.').pop()?.toLowerCase() ?? '',
        mime_type: upload.input.content_type,
        architecture: '',
        size_bytes: upload.input.size,
        sha256: upload.completed.sha256,
        extraction_status: 'queued',
        error_code: '',
        error_message: '',
        source_container: null,
        has_children: false,
        metadata_json: {
          preview_fixture: true,
          note: '纯前端示例任务，不会持久化或执行真实检测',
        },
        source_parent: null,
      },
    ])
    upload.completed = { ...upload.completed, task_id: id }
    upload.session = upload.completed
    return id
  }

  return {
    async login(input) {
      await delay()
      if (!input.username.trim() || !input.password) {
        throw new ApiError('请输入示例用户名和密码', 400, {
          code: 'INVALID_CREDENTIALS',
        })
      }
      const username = input.username.trim().toLocaleLowerCase('en-US')
      if (username === 'demo-rate-limited') {
        throw new ApiError(
          '登录尝试过于频繁，请稍后再试',
          429,
          { code: 'login_rate_limited' },
          { retryAfterSeconds: 3 },
        )
      }
      currentUser =
        username === DEMO_READER.username
          ? { ...DEMO_READER }
          : username === DEMO_OPERATOR.username
            ? { ...DEMO_OPERATOR }
            : { ...DEMO_ADMIN }
      return { ...currentUser }
    },

    async logout() {
      await delay()
      requireUser()
      currentUser = null
    },

    async getMe() {
      await delay()
      return { ...requireUser() }
    },

    async changePassword() {
      await delay()
      currentUser = { ...requireUser(), must_change_password: false }
      return { ...currentUser }
    },

    async listTasks(query) {
      await delay()
      requireUser()
      const pageSize = normalizePageSize(query.page_size, 20)
      const matched = tasks.filter((task) => taskMatches(task, query))
      const offset = pageOffset(query.cursor)
      if (offset > matched.length) {
        throw new ApiError('示例分页游标无效', 400, { code: 'INVALID_CURSOR' })
      }
      const items = matched.slice(offset, offset + pageSize).map(cloneTask)
      const nextOffset = offset + items.length
      return nextOffset < matched.length
        ? { items, next_cursor: `demo-offset-${nextOffset}` }
        : { items }
    },

    async getTask(id) {
      await delay()
      requireUser()
      return cloneTask(findTask(id))
    },

    async cancelTask(id, idempotencyKey) {
      await delay()
      requireUser()
      const intentKey = `cancel:${id}:${idempotencyKey}`
      const knownResult = lifecycleResultByIdempotencyKey.get(intentKey)
      if (knownResult) return cloneTask(knownResult)

      const task = findTask(id)
      Object.assign(task, {
        status: 'CANCEL_REQUESTED' as const,
        current_stage: 'CANCEL_REQUESTED',
        updated_at: '2026-07-30T11:00:00+08:00',
      })
      const result = cloneTask(task)
      lifecycleResultByIdempotencyKey.set(intentKey, result)
      return cloneTask(result)
    },

    async retryTask(id, idempotencyKey) {
      await delay()
      requireUser()
      const intentKey = `retry:${id}:${idempotencyKey}`
      const knownResult = lifecycleResultByIdempotencyKey.get(intentKey)
      if (knownResult) return cloneTask(knownResult)

      const task = findTask(id)
      const sampleExpiresAt = task.sample_expires_at
        ? Date.parse(task.sample_expires_at)
        : Number.NaN
      if (
        task.sample_deleted_at !== null ||
        !Number.isFinite(sampleExpiresAt) ||
        sampleExpiresAt <= Date.now()
      ) {
        throw new ApiError('保留的任务样本已清理或到期，无法重新检测', 409, {
          code: 'task_sample_unavailable',
        })
      }
      Object.assign(task, {
        status: 'QUEUED' as const,
        progress: 0,
        progress_indeterminate: false,
        current_stage: 'QUEUED',
        updated_at: '2026-07-30T11:01:00+08:00',
      })
      delete task.error_code
      delete task.error_message
      const result = cloneTask(task)
      lifecycleResultByIdempotencyKey.set(intentKey, result)
      return cloneTask(result)
    },

    async deleteTask(id) {
      await delay()
      requireUser()
      const task = findTask(id)
      Object.assign(task, {
        status: 'DELETING' as const,
        current_stage: 'DELETING',
        progress_indeterminate: false,
        updated_at: '2026-07-30T11:02:00+08:00',
      })
      return cloneTask(task)
    },

    async extendTaskRetention(id, input) {
      await delay()
      const user = requireUser()
      if (user.role !== 'administrator') {
        throw new ApiError('只有管理员可以延长样本保留期', 403, {
          code: 'FORBIDDEN',
        })
      }

      const task = findTask(id)
      const status = task.status.toUpperCase()
      if (status === 'DELETING' || status === 'DELETED') {
        throw new ApiError('任务已进入删除流程', 409, {
          code: 'TASK_INVALID_STATE',
        })
      }
      if (task.sample_deleted_at !== null) {
        throw new ApiError('任务原始样本已清理，无法延长保留期', 409, {
          code: 'task_sample_unavailable',
        })
      }
      if (
        !task.sample_expires_at ||
        task.sample_expires_at !== input.expected_sample_expires_at
      ) {
        throw new ApiError('样本保留期已发生变化，请刷新后重试', 409, {
          code: 'RETENTION_CONFLICT',
        })
      }

      const expectedTimestamp = Date.parse(input.expected_sample_expires_at)
      const requestedTimestamp = Date.parse(input.sample_expires_at)
      const retentionExtension = 15 * 24 * 60 * 60 * 1000
      if (
        !Number.isFinite(expectedTimestamp) ||
        !Number.isFinite(requestedTimestamp) ||
        expectedTimestamp <= Date.now() ||
        requestedTimestamp !== expectedTimestamp + retentionExtension
      ) {
        throw new ApiError('样本保留期延期参数无效', 409, {
          code: 'INVALID_RETENTION',
        })
      }

      task.sample_expires_at = input.sample_expires_at
      task.updated_at = '2026-07-30T11:03:00+08:00'
      return cloneTask(task)
    },

    async listTaskFiles(taskId, query: FileNodeListQuery = {}) {
      await delay()
      requireUser()
      findTask(taskId)
      const nodes = fileNodes.get(taskId) ?? []
      const parentId = query.parent_id ?? null
      const matching = nodes.filter((node) => node.parent_id === parentId)
      const offset = pageOffset(query.cursor)
      const pageSize = Math.min(
        normalizePageSize(query.page_size, DEMO_FILE_PAGE_SIZE),
        DEMO_FILE_PAGE_SIZE,
      )
      const items = matching.slice(offset, offset + pageSize)
      const nextOffset = offset + items.length
      return {
        items: items.map(cloneFileNode),
        ...(nextOffset < matching.length
          ? { next_cursor: `demo-offset-${nextOffset}` }
          : {}),
      }
    },

    async getTaskFile(taskId, fileId) {
      await delay()
      requireUser()
      findTask(taskId)
      const node = (fileNodes.get(taskId) ?? []).find((candidate) => candidate.id === fileId)
      if (!node) {
        throw new ApiError('示例文件节点不存在', 404, {
          code: 'FILE_NODE_NOT_FOUND',
        })
      }
      return cloneFileNode(node)
    },

    async createFileDecompileRequest() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会提交真实反编译任务', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async getFileDecompileRequest() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会读取真实反编译任务状态', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listDecompileProjects(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      return { items: [] }
    },

    async getDecompileProject(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      throw new ApiError('界面预览不包含反编译源码项目', 404, {
        code: 'DECOMPILE_PROJECT_NOT_FOUND',
      })
    },

    async downloadDecompileProject() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会导出反编译源码项目', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async deleteDecompileProject() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会删除反编译源码项目', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async previewDecompileProjectDeletion() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会删除反编译源码项目', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async confirmDecompileProjectDeletion() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会删除反编译源码项目', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async getDecompileProjectDeletion() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不包含源码删除操作', 404, {
        code: 'SOURCE_PROJECT_DELETION_NOT_FOUND',
      })
    },

    async createCAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会提交真实 C 源码检测', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listCAnalysisRuns(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      return { items: [] }
    },

    async getCAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不包含 C 源码检测运行', 404, {
        code: 'C_ANALYSIS_RUN_NOT_FOUND',
      })
    },

    async listCAnalysisFindings() {
      await delay()
      requireUser()
      return { items: [] }
    },

    async cancelCAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会取消 C 源码检测', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async deleteCAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会删除 C 源码检测运行', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async createJavaAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会提交真实 Java 源码检测', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listJavaAnalysisRuns(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      return { items: [] }
    },

    async getJavaAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不包含 Java 源码检测运行', 404, {
        code: 'JAVA_ANALYSIS_RUN_NOT_FOUND',
      })
    },

    async listJavaAnalysisFindings() {
      await delay()
      requireUser()
      return { items: [] }
    },

    async cancelJavaAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会取消 Java 源码检测', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async deleteJavaAnalysisRun() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会删除 Java 源码检测运行', 501, {
        code: 'DEMO_READ_ONLY',

      })
    },
  async createPythonAnalysisRun(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会创建 Python 源码检测', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可创建 Python 源码检测。',
    })
  },
  async listPythonAnalysisRuns(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会列出 Python 源码检测', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可查看 Python 源码检测结果。',
    })
  },
  async getPythonAnalysisRun(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会读取 Python 源码检测', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可查看 Python 源码检测结果。',
    })
  },
  async listPythonAnalysisFindings(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会列出 Python 源码检测发现', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可查看 Python 源码检测发现。',
    })
  },
  async cancelPythonAnalysisRun(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会取消 Python 源码检测', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可取消 Python 源码检测。',
    })
  },
  async deletePythonAnalysisRun(): Promise<never> {
    await delay()
    requireUser()
    throw new ApiError('界面预览不会删除 Python 源码检测运行', 501, {
      code: 'PYTHON_ANALYSIS_UNAVAILABLE',
      message: '连接后端后可删除 Python 源码检测运行。',
    })
  },

    async createManualImageScanRequest() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会提交真实镜像检测任务', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listDecompileResults(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      return { items: [] }
    },

    async getDecompileSource(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      throw new ApiError('界面预览不读取真实反编译源码', 404, {
        code: 'DECOMPILE_RESULT_NOT_FOUND',
      })
    },

    async downloadDecompileSources() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会导出真实反编译源码', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listTaskVulnerabilities(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      return {
        summary: {
          total: 0,
          fixable: 0,
          by_severity: {
            UNKNOWN: 0,
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
          },
        },
        items: [],
      }
    },

    async getTaskVulnerability(taskId) {
      await delay()
      requireUser()
      findTask(taskId)
      throw new ApiError('界面预览不读取真实漏洞详情', 404, {
        code: 'VULNERABILITY_NOT_FOUND',
      })
    },

    async listTaskReports(taskId) {
      await delay()
      requireUser()
      const task = findTask(taskId)
      const expiresAt = task.sample_expires_at
        ? Date.parse(task.sample_expires_at)
        : Number.NaN
      const sampleRelation =
        task.sample_deleted_at !== null
          ? 'deleted'
          : Number.isFinite(expiresAt) && expiresAt <= Date.now()
            ? 'expired'
            : 'retained'
      return {
        items: (reports.get(taskId) ?? []).map(cloneReport),
        sample_relation: sampleRelation,
      }
    },

    async createTaskReport(taskId, input, idempotencyKey) {
      await delay()
      const user = requireUser()
      findTask(taskId)
      if (user.role === 'reader') {
        throw new ApiError('只读用户不能生成报告', 403, {
          code: 'FORBIDDEN',
        })
      }
      const known = reportByIdempotencyKey.get(idempotencyKey)
      if (known) return cloneReport(known)

      reportCounter += 1
      const format: ReportFormat = input.format
      const created: TaskReport = {
        id: `demo-report-${String(reportCounter).padStart(4, '0')}`,
        task_id: taskId,
        format,
        schema_version: '1.1.0',
        status: 'complete',
        sha256: format === 'json' ? 'c'.repeat(64) : 'd'.repeat(64),
        size_bytes: format === 'json' ? 32_768 : 65_536,
        error_code: null,
        error_message: null,
        created_at: '2026-07-30T12:00:00+08:00',
        completed_at: '2026-07-30T12:00:01+08:00',
      }
      const nextReports = (reports.get(taskId) ?? []).filter(
        (report) => report.format !== format,
      )
      nextReports.push(created)
      reports.set(taskId, nextReports)
      reportByIdempotencyKey.set(idempotencyKey, created)
      return cloneReport(created)
    },

    async downloadTaskReport(taskId, reportId, format, encoding = 'identity') {
      await delay()
      requireUser()
      findTask(taskId)
      const report = (reports.get(taskId) ?? []).find(
        (candidate) =>
          candidate.id === reportId && candidate.format === format,
      )
      if (!report || report.status !== 'complete') {
        throw new ApiError('示例报告不存在或尚未完成', 404, {
          code: 'REPORT_NOT_FOUND',
        })
      }
      if (encoding === 'gzip') {
        throw new ApiError('界面预览不会伪造 gzip 报告内容', 501, {
          code: 'DEMO_READ_ONLY',
        })
      }
      const content =
        format === 'json'
          ? '{"schemaVersion":"1.0.0","preview":true}'
          : '<!doctype html><title>BinaryScan preview report</title>'
      return {
        kind: 'blob',
        blob: new Blob([content], {
          type: format === 'json' ? 'application/json' : 'text/html',
        }),
        filename: `binaryscan-report.${format}`,
      }
    },

    async getSystemStatus() {
      await delay()
      requireUser()
      return {
        version: '0.1.0-ui-preview',
        service: 'binaryscan-api-preview',
        build: {
          version: '0.1.0-ui-preview',
          commit: 'demo-preview',
          build_time: '2026-07-30T08:00:00+08:00',
          go_version: 'go1.25-preview',
        },
        service_status: 'healthy',
        active_tasks: 1,
        queued_tasks: 1,
        queue_depth: 1,
        task_counts: {
          SCANNING: 1,
          QUEUED: 1,
          SUCCEEDED: 2,
          PARTIAL_SUCCEEDED: 1,
          FAILED: 1,
        },
        worker_summary: {
          observed_leases: 3,
          observed_owners: 2,
          leases_by_kind: {
            scanner: 2,
            maintenance: 1,
          },
          oldest_heartbeat_at: '2026-07-30T09:44:42+08:00',
          latest_heartbeat_at: '2026-07-30T09:44:58+08:00',
        },
        operational_metrics: {
          window_hours: 168,
          stage_durations: [
            {
              stage: 'IDENTIFYING',
              sample_count: 18,
              average_duration_ms: 860,
            },
            {
              stage: 'EXTRACTING',
              sample_count: 16,
              average_duration_ms: 18_420,
            },
            {
              stage: 'SCANNING',
              sample_count: 12,
              average_duration_ms: 41_280,
            },
            {
              stage: 'REPORTING',
              sample_count: 9,
              average_duration_ms: 2_460,
            },
          ],
          analyzer_failure_rates: [
            {
              name: 'Ghidra',
              total_runs: 22,
              failed_runs: 2,
              failure_rate_basis_points: 909,
            },
            {
              name: 'Trivy',
              total_runs: 14,
              failed_runs: 1,
              failure_rate_basis_points: 714,
            },
            {
              name: 'archive-extractor',
              total_runs: 36,
              failed_runs: 0,
              failure_rate_basis_points: 0,
            },
          ],
        },
        repository_used_bytes: 38_654_705_664,
        repository_total_bytes: 107_374_182_400,
        trivy_db_version: 'OFFLINE-DEMO-2026-07-28',
        collected_at: '2026-07-30T09:45:00+08:00',
        analyzers: [
          {
            name: '文件类型识别',
            version: 'demo-1.0',
            expected_version: 'demo-1.0',
            status: 'available',
            scope: '本地文件格式识别',
            required_worker_kinds: [],
            ready_worker_kinds: [],
            ready_workers: 0,
            runtime_name: '',
            runtime_version: '',
            last_checked_at: '2026-07-30T09:45:00+08:00',
          },
          {
            name: '归档安全解包',
            version: 'demo-1.0',
            expected_version: 'demo-1.0',
            status: 'available',
            scope: '受限递归解包',
            required_worker_kinds: [],
            ready_worker_kinds: [],
            ready_workers: 0,
            runtime_name: '',
            runtime_version: '',
            last_checked_at: '2026-07-30T09:45:00+08:00',
          },
          {
            name: 'Ghidra 反编译器',
            version: '',
            expected_version: '12.1.2',
            status: 'unavailable',
            scope: 'PE / ELF / Mach-O',
            required_worker_kinds: ['native'],
            ready_worker_kinds: [],
            ready_workers: 0,
            runtime_name: '',
            runtime_version: '',
            last_checked_at: null,
            detail: '演示模式没有真实 Ghidra Worker 心跳。',
          },
          {
            name: 'Trivy 镜像检测',
            version: '',
            expected_version: '0.72.0',
            status: 'unavailable',
            scope: 'Docker / OCI tar',
            required_worker_kinds: ['image', 'trivy'],
            ready_worker_kinds: [],
            ready_workers: 0,
            runtime_name: '',
            runtime_version: '',
            last_checked_at: null,
            detail: '演示模式没有真实 Trivy Worker 心跳。',
          },
          {
            name: 'ISO / EXT4 挂载器',
            version: '',
            expected_version: '',
            status: 'unavailable',
            scope: '映像只读检查',
            required_worker_kinds: [],
            ready_worker_kinds: [],
            ready_workers: 0,
            runtime_name: '',
            runtime_version: '',
            detail: '尚未接入执行器',
            last_checked_at: '2026-07-30T09:45:00+08:00',
          },
        ],
        storage_mounts: [
          {
            id: 'repository',
            label: 'repository',
            purpose: '样本、解包产物与报告仓库',
            host_path: '/opt/binaryscan/shared/data/repository',
            container_path: '/data/repository',
            services: ['api', 'workers'],
            used_bytes: 186 * 1024 ** 3,
            total_bytes: 800 * 1024 ** 3,
            free_bytes: 614 * 1024 ** 3,
            minimum_free_bytes: 20 * 1024 ** 3,
            warning_percent: 80,
            critical_percent: 90,
            writable: true,
            low_water: false,
            status: 'healthy',
          },
          {
            id: 'task-work',
            label: 'task-work',
            purpose: '任务解包与分析工作目录',
            host_path: '/opt/binaryscan/shared/data/task-work',
            container_path: '/data/task-work',
            services: ['workers', 'maintenance'],
            used_bytes: 368 * 1024 ** 3,
            total_bytes: 400 * 1024 ** 3,
            free_bytes: 32 * 1024 ** 3,
            minimum_free_bytes: 40 * 1024 ** 3,
            warning_percent: 80,
            critical_percent: 90,
            writable: true,
            low_water: true,
            status: 'critical',
          },
        ],
		trivy_database_bundle: {
		  id: 'demo-trivy-bundle',
		  version: 'TRIVY-BUNDLE-2026.07.18',
		  trivy_db_version: 'TRIVY-DB-2026.07.18',
		  trivy_java_db_version: 'TRIVY-JAVA-DB-2026.07.18',
		  status: 'stale',
		  generated_at: '2026-07-18T08:30:00+08:00',
		  registered_at: '2026-07-18T08:35:00+08:00',
		  age_days: 12,
		  stale_after_days: 7,
		  content_sha256: '18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc18bc',
		},
        diagnostics: [
          {
            code: 'STORAGE_LOW_WATER',
            severity: 'error',
            component: 'task-work',
            message: '任务工作目录剩余容量低于最小水位。',
            remediation: '清理已完成任务的临时工作目录后重新采集状态。',
          },
        ],
      }
    },

    async listAdminUsers(query = {}) {
      await delay()
      requireUser()
      const keyword = query.keyword?.trim().toLocaleLowerCase('zh-CN')
      const filtered = DEMO_ADMIN_USERS.filter((user) => {
        if (
          keyword &&
          ![user.username, user.display_name]
            .join(' ')
            .toLocaleLowerCase('zh-CN')
            .includes(keyword)
        ) {
          return false
        }
        if (query.role && user.role !== query.role) return false
        if (query.status && user.status !== query.status) return false
        return true
      })
      const offset = pageOffset(query.cursor)
      const pageSize = normalizePageSize(query.page_size, 50)
      const items = filtered.slice(offset, offset + pageSize).map(
        (user) => ({ ...user }),
      )
      const nextOffset = offset + items.length
      return nextOffset < filtered.length
        ? { items, next_cursor: `demo-offset-${nextOffset}` }
        : { items }
    },

    async createAdminUser() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会创建真实账户', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async updateAdminUser() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会修改真实账户', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async resetAdminUserPassword() {
      await delay()
      requireUser()
      throw new ApiError('界面预览不会重置真实密码', 501, {
        code: 'DEMO_READ_ONLY',
      })
    },

    async listAuditLogs(query: AuditLogListQuery = {}) {
      await delay()
      requireUser()
      const filtered = DEMO_AUDIT_LOGS.filter((entry) => {
        if (query.action && entry.action !== query.action) return false
        if (query.outcome && entry.outcome !== query.outcome) return false
        if (
          query.actor &&
          !(entry.actor?.username ?? '')
            .toLocaleLowerCase('zh-CN')
            .includes(query.actor.toLocaleLowerCase('zh-CN'))
        ) {
          return false
        }
        if (query.created_from && entry.created_at < query.created_from) return false
        if (query.created_to && entry.created_at > query.created_to) return false
        return true
      })
      const offset = pageOffset(query.cursor)
      const pageSize = normalizePageSize(query.page_size, 50)
      const items = filtered
        .slice(offset, offset + pageSize)
        .map((entry) => ({ ...entry }))
      const nextOffset = offset + items.length
      return nextOffset < filtered.length
        ? { items, next_cursor: `demo-offset-${nextOffset}` }
        : { items }
    },

    async createUpload(input, idempotencyKey) {
      await delay()
      const user = requireUser()
      const intentKey = `${user.id}:${idempotencyKey}`
      const fingerprint = JSON.stringify([
        input.filename,
        input.size,
        input.content_type,
        input.input_category,
      ])
      const known = uploadByIdempotencyKey.get(intentKey)
      if (known) {
        if (known.fingerprint !== fingerprint) {
          throw new ApiError('示例上传幂等键已用于其他请求', 409, {
            code: 'idempotency_conflict',
          })
        }
        const upload = uploads.get(known.uploadId)
        if (!upload) {
          throw new ApiError('示例上传不存在', 404, {
            code: 'UPLOAD_NOT_FOUND',
          })
        }
        return cloneSession(upload.creationSession)
      }
      uploadCounter += 1
      const id = `demo-upload-${String(uploadCounter).padStart(4, '0')}`
      const session: UploadSession = {
        id,
        part_size: DEMO_PART_SIZE,
        size_bytes: input.size,
        status: 'created',
        uploaded_parts: [],
        expires_at: '2026-08-01T00:00:00+08:00',
        input_category: input.input_category,
        validation_status: 'pending',
      }
      uploads.set(id, {
        input: { ...input },
        creationSession: cloneSession(session),
        session,
        parts: new Set(),
      })
      uploadByIdempotencyKey.set(intentKey, { fingerprint, uploadId: id })
      return cloneSession(session)
    },

    async getUpload(uploadId) {
      await delay()
      requireUser()
      const upload = findUpload(uploadId)
      return cloneSession(upload.completed ?? upload.session)
    },

    async uploadPart(uploadId, input: UploadPartInput) {
      await delay()
      requireUser()
      const upload = findUpload(uploadId)
      if (upload.completed) {
        throw new ApiError('示例上传已完成', 409, {
          code: 'upload_invalid_state',
        })
      }
      if (!Number.isInteger(input.part_number) || input.part_number < 1) {
        throw new ApiError('示例分片编号无效', 400, {
          code: 'INVALID_PART_NUMBER',
        })
      }
      upload.parts.add(input.part_number)
      upload.session = {
        ...upload.session,
        status: 'uploading',
        uploaded_parts: [...upload.parts].sort((left, right) => left - right),
      }
    },

    async completeUpload(uploadId) {
      await delay()
      const user = requireUser()
      const upload = findUpload(uploadId)
      if (upload.completed) {
        return {
          ...upload.completed,
          uploaded_parts: [...upload.completed.uploaded_parts],
        }
      }
      const expectedParts =
        upload.input.size === 0 ? 0 : Math.ceil(upload.input.size / upload.session.part_size)
      if (upload.parts.size !== expectedParts) {
        throw new ApiError('示例上传仍有分片未完成', 409, {
          code: 'upload_incomplete',
        })
      }
      const completed: CompletedUpload = {
        ...upload.session,
        status: 'completed',
        uploaded_parts: [...upload.parts].sort((left, right) => left - right),
        sha256: String(uploadCounter).padStart(64, '0'),
        size_bytes: upload.input.size,
        input_category: upload.input.input_category,
        validation_status: 'valid',
        detected_category: upload.input.input_category,
        detected_format:
          upload.input.input_category === 'archive'
            ? 'zip'
            : upload.input.input_category === 'container'
              ? 'docker-tar'
              : 'elf64',
      }
      if (upload.input.input_category === 'archive') {
        const importId = `demo-archive-${String(uploadCounter).padStart(4, '0')}`
        completed.archive_import_id = importId
        const now = '2026-07-30T10:00:00+08:00'
        archiveImports.set(importId, {
          value: {
            id: importId,
            upload_id: uploadId,
            filename: upload.input.filename,
            status: 'ready',
            scanned_entries: 3,
            total_entries: 3,
            eligible_entries: 2,
            skipped_entries: 1,
            created_tasks: 0,
            created_at: now,
            updated_at: now,
          },
          entries: [
            {
              id: `${importId}-entry-1`,
              path: 'bin/application',
              size_bytes: Math.max(1, Math.min(upload.input.size, 1_048_576)),
              sha256: '1'.repeat(64),
              detected_format: 'elf64',
              detected_category: 'binary',
              status: 'eligible',
            },
            {
              id: `${importId}-entry-2`,
              path: 'images/service-image.tar',
              size_bytes: Math.max(1, Math.min(upload.input.size, 2_097_152)),
              sha256: '2'.repeat(64),
              detected_format: 'docker-tar',
              detected_category: 'container',
              status: 'eligible',
            },
            {
              id: `${importId}-entry-3`,
              path: 'nested/source.zip',
              size_bytes: 512,
              sha256: null,
              detected_format: null,
              detected_category: null,
              status: 'skipped',
              skip_reason: '成员压缩包不递归展开',
            },
          ],
          batchResults: new Map(),
        })
      }
      upload.completed = completed
      upload.session = completed
      if (upload.input.input_category !== 'archive') {
        ensureDirectUploadTask(upload, user)
      }
      return {
        ...upload.completed,
        uploaded_parts: [...upload.completed.uploaded_parts],
      }
    },

    async deleteUpload(uploadId) {
      await delay()
      requireUser()
      findUpload(uploadId)
      for (const [importId, archiveImport] of archiveImports) {
        if (archiveImport.value.upload_id === uploadId) archiveImports.delete(importId)
      }
      uploads.delete(uploadId)
    },

    async listArchiveImports(query = {}) {
      await delay()
      requireUser()
      const offset = pageOffset(query.cursor)
      const pageSize = normalizePageSize(query.page_size, 25)
      const matching = [...archiveImports.values()]
        .map((archiveImport) => archiveImport.value)
        .filter((archiveImport) => archiveImport.status !== 'deleted')
        .sort((left, right) => {
          const byCreatedAt = right.created_at.localeCompare(left.created_at)
          return byCreatedAt || right.id.localeCompare(left.id)
        })
      const items = matching.slice(offset, offset + pageSize)
      const nextOffset = offset + items.length
      return {
        items: items.map((archiveImport) => ({ ...archiveImport })),
        ...(nextOffset < matching.length
          ? { next_cursor: `demo-offset-${nextOffset}` }
          : {}),
      }
    },

    async getArchiveImport(importId) {
      await delay()
      requireUser()
      const archiveImport = archiveImports.get(importId)
      if (!archiveImport) {
        throw new ApiError('示例归档导入不存在', 404, {
          code: 'ARCHIVE_IMPORT_NOT_FOUND',
        })
      }
      return { ...archiveImport.value }
    },

    async listArchiveImportEntries(importId, query = {}) {
      await delay()
      requireUser()
      const archiveImport = archiveImports.get(importId)
      if (!archiveImport) {
        throw new ApiError('示例归档导入不存在', 404, {
          code: 'ARCHIVE_IMPORT_NOT_FOUND',
        })
      }
      const matching = archiveImport.entries.filter((entry) =>
        !query.filter || query.filter === 'all'
          ? true
          : entry.status === query.filter,
      )
      const offset = pageOffset(query.cursor)
      const pageSize = normalizePageSize(query.page_size, 50)
      const items = matching.slice(offset, offset + pageSize)
      const nextOffset = offset + items.length
      return {
        items: items.map((entry) => ({ ...entry })),
        ...(nextOffset < matching.length
          ? { next_cursor: `demo-offset-${nextOffset}` }
          : {}),
      }
    },

    async createArchiveTaskBatch(importId, input, idempotencyKey) {
      await delay()
      const user = requireUser()
      const archiveImport = archiveImports.get(importId)
      if (!archiveImport) {
        throw new ApiError('示例归档导入不存在', 404, {
          code: 'ARCHIVE_IMPORT_NOT_FOUND',
        })
      }
      if (input.entry_ids.length === 0 || input.entry_ids.length > 20) {
        throw new ApiError('示例批量请求必须选择 1 到 20 个条目', 400, {
          code: 'INVALID_ARCHIVE_TASK_BATCH',
        })
      }
      const items = input.entry_ids.map((entryId) => {
        const entry = archiveImport.entries.find((candidate) => candidate.id === entryId)
        if (
          !entry ||
          (entry.status !== 'eligible' &&
            entry.status !== 'failed' &&
            entry.status !== 'created')
        ) {
          return {
            entry_id: entryId,
            outcome: 'failed' as const,
            error_code: 'ENTRY_NOT_ELIGIBLE',
            message: '条目不可创建任务',
          }
        }
        const knownTaskId = archiveImport.batchResults.get(entryId)
        if (knownTaskId) {
          return {
            entry_id: entryId,
            outcome: 'existing' as const,
            task_id: knownTaskId,
          }
        }
        taskCounter += 1
        const taskId = createdTaskId(taskCounter)
        archiveImport.batchResults.set(entryId, taskId)
        entry.status = 'created'
        entry.task_id = taskId
        tasks.unshift({
          id: taskId,
          name: `${archiveImport.value.filename} :: ${entry.path}`,
          input_type: entry.detected_format ?? 'unknown',
          status: 'QUEUED',
          risk_level: 'UNKNOWN',
          progress: 0,
          progress_indeterminate: false,
          creator_id: user.id,
          creator_name: user.display_name,
          tags: ['UI-PREVIEW'],
          created_at: '2026-07-30T10:30:00+08:00',
          original_filename: entry.path,
          size_bytes: entry.size_bytes,
          sha256: entry.sha256 ?? '0'.repeat(64),
          sample_expires_at: '2026-08-29T10:30:00+08:00',
          sample_deleted_at: null,
        })
        return {
          entry_id: entryId,
          outcome: 'created' as const,
          task_id: taskId,
        }
      })
      archiveImport.value.created_tasks = archiveImport.entries.filter(
        (entry) => entry.status === 'created',
      ).length
      archiveImport.value.updated_at = '2026-07-30T10:30:00+08:00'
      void idempotencyKey
      return { items }
    },

    async createTask(input, idempotencyKey) {
      await delay()
      const user = requireUser()
      const knownTaskId = taskByIdempotencyKey.get(idempotencyKey)
      if (knownTaskId) return { id: knownTaskId }
      const upload = findUpload(input.upload_id)
      if (!upload.completed) {
        throw new ApiError('示例文件尚未完成上传', 409, {
          code: 'upload_not_completed',
        })
      }
      const id = ensureDirectUploadTask(upload, user)
      taskByIdempotencyKey.set(idempotencyKey, id)
      return { id }
    },
  }
}
