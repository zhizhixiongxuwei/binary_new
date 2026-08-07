import type {
  AdminUser,
  AdminUserListQuery,
  AdminUserPage,
  AuditLogListQuery,
  AuditLogPage,
  ChangePasswordInput,
  CompletedUpload,
  CreatedTask,
  CreateTaskInput,
  CreateUploadInput,
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
  SystemStatus,
  TaskDetail,
  TaskListQuery,
  TaskPage,
  TaskReport,
  TaskReportList,
  CreateTaskReportInput,
  CreateAdminUserInput,
  ResetAdminUserPasswordInput,
  UpdateAdminUserInput,
  UploadPartInput,
  UploadSession,
  VulnerabilityFinding,
  VulnerabilityFindingPage,
  VulnerabilityListQuery,
} from '@/api/types'

/**
 * The only transport boundary used by UI features.
 *
 * Production and standalone-preview clients both implement this contract. IDs
 * deliberately remain strings so large database identifiers are never rounded
 * by JavaScript.
 */
export interface ApiClient {
  login(input: LoginInput): Promise<CurrentUser>
  logout(): Promise<void>
  getMe(): Promise<CurrentUser>
  changePassword(input: ChangePasswordInput): Promise<CurrentUser>
  listTasks(query: TaskListQuery): Promise<TaskPage>
  getTask(id: string): Promise<TaskDetail>
  cancelTask(id: string, idempotencyKey: string): Promise<TaskDetail>
  retryTask(id: string, idempotencyKey: string): Promise<TaskDetail>
  deleteTask(id: string): Promise<TaskDetail>
  extendTaskRetention(
    id: string,
    input: ExtendTaskRetentionInput,
  ): Promise<TaskDetail>
  listTaskFiles(taskId: string, query?: FileNodeListQuery): Promise<FileNodePage>
  getTaskFile(taskId: string, fileId: string): Promise<FileNodeDetail>
  createFileDecompileRequest(
    taskId: string,
    fileId: string,
    input: CreateFileDecompileRequestInput,
    idempotencyKey: string,
  ): Promise<FileDecompileRequest>
  getFileDecompileRequest(
    taskId: string,
    jobId: string,
  ): Promise<FileDecompileRequest>
  createManualImageScanRequest(
    taskId: string,
    fileId: string,
    idempotencyKey: string,
  ): Promise<ManualImageScanRequest>
  listDecompileResults(
    taskId: string,
    query?: DecompileResultListQuery,
  ): Promise<DecompileResultPage>
  getDecompileSource(
    taskId: string,
    resultId: string,
    query?: DecompileSourceQuery,
  ): Promise<DecompileSourceChunk>
  downloadDecompileSources(
    taskId: string,
    includeCombined?: boolean,
  ): Promise<ReportDownload>
  listTaskVulnerabilities(
    taskId: string,
    query?: VulnerabilityListQuery,
  ): Promise<VulnerabilityFindingPage>
  getTaskVulnerability(
    taskId: string,
    findingId: string,
  ): Promise<VulnerabilityFinding>
  listTaskReports(taskId: string): Promise<TaskReportList>
  createTaskReport(
    taskId: string,
    input: CreateTaskReportInput,
    idempotencyKey: string,
  ): Promise<TaskReport>
  downloadTaskReport(
    taskId: string,
    reportId: string,
    format: CreateTaskReportInput['format'],
    encoding?: ReportDownloadEncoding,
  ): Promise<ReportDownload>
  getSystemStatus(): Promise<SystemStatus>
  listAdminUsers(query?: AdminUserListQuery): Promise<AdminUserPage>
  createAdminUser(input: CreateAdminUserInput): Promise<AdminUser>
  updateAdminUser(id: string, input: UpdateAdminUserInput): Promise<AdminUser>
  resetAdminUserPassword(
    id: string,
    input: ResetAdminUserPasswordInput,
  ): Promise<AdminUser>
  listAuditLogs(query?: AuditLogListQuery): Promise<AuditLogPage>
  createUpload(
    input: CreateUploadInput,
    idempotencyKey: string,
  ): Promise<UploadSession>
  getUpload(uploadId: string): Promise<UploadSession>
  uploadPart(uploadId: string, input: UploadPartInput): Promise<void>
  completeUpload(uploadId: string): Promise<CompletedUpload>
  deleteUpload(uploadId: string): Promise<void>
  createTask(input: CreateTaskInput, idempotencyKey: string): Promise<CreatedTask>
}
