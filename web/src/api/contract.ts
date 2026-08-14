import type {
  AdminUser,
  AdminUserListQuery,
  AdminUserPage,
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
  CreateTaskInput,
  CreateUploadInput,
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
  listDecompileProjects(
    taskId: string,
    query?: DecompileProjectListQuery,
  ): Promise<DecompileProjectPage>
  getDecompileProject(
    taskId: string,
    projectId: string,
  ): Promise<DecompileProject>
  downloadDecompileProject(
    taskId: string,
    projectId: string,
  ): Promise<ReportDownload>
  deleteDecompileProject(taskId: string, projectId: string): Promise<void>
  previewDecompileProjectDeletion(
    taskId: string,
    projectId: string,
  ): Promise<DecompileProjectDeletionPreview>
  confirmDecompileProjectDeletion(
    taskId: string,
    projectId: string,
    input: ConfirmDecompileProjectDeletionInput,
  ): Promise<DecompileProjectDeletionOperation>
  getDecompileProjectDeletion(
    taskId: string,
    operationId: string,
  ): Promise<DecompileProjectDeletionOperation>
  createCAnalysisRun(
    taskId: string,
    projectId: string,
    idempotencyKey: string,
  ): Promise<CAnalysisRun>
  listCAnalysisRuns(
    taskId: string,
    query?: CAnalysisRunListQuery,
  ): Promise<CAnalysisRunPage>
  getCAnalysisRun(taskId: string, runId: string): Promise<CAnalysisRun>
  listCAnalysisFindings(
    taskId: string,
    runId: string,
    query?: CAnalysisFindingListQuery,
  ): Promise<CAnalysisFindingPage>
  cancelCAnalysisRun(taskId: string, runId: string): Promise<CAnalysisRun>
  deleteCAnalysisRun(taskId: string, runId: string): Promise<void>
  createJavaAnalysisRun(
    taskId: string,
    projectId: string,
    idempotencyKey: string,
  ): Promise<JavaAnalysisRun>
  listJavaAnalysisRuns(
    taskId: string,
    query?: JavaAnalysisRunListQuery,
  ): Promise<JavaAnalysisRunPage>
  getJavaAnalysisRun(taskId: string, runId: string): Promise<JavaAnalysisRun>
  listJavaAnalysisFindings(
    taskId: string,
    runId: string,
    query?: JavaAnalysisFindingListQuery,
  ): Promise<JavaAnalysisFindingPage>
  cancelJavaAnalysisRun(taskId: string, runId: string): Promise<JavaAnalysisRun>
  deleteJavaAnalysisRun(taskId: string, runId: string): Promise<void>
  createPythonAnalysisRun(
    taskId: string,
    projectId: string,
    idempotencyKey: string,
  ): Promise<PythonAnalysisRun>
  listPythonAnalysisRuns(
    taskId: string,
    query?: PythonAnalysisRunListQuery,
  ): Promise<PythonAnalysisRunPage>
  getPythonAnalysisRun(taskId: string, runId: string): Promise<PythonAnalysisRun>
  listPythonAnalysisFindings(
    taskId: string,
    runId: string,
    query?: PythonAnalysisFindingListQuery,
  ): Promise<PythonAnalysisFindingPage>
  cancelPythonAnalysisRun(taskId: string, runId: string): Promise<PythonAnalysisRun>
  deletePythonAnalysisRun(taskId: string, runId: string): Promise<void>
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
  listArchiveImports(query?: ArchiveImportListQuery): Promise<ArchiveImportPage>
  getArchiveImport(importId: string): Promise<ArchiveImport>
  listArchiveImportEntries(
    importId: string,
    query?: ArchiveImportEntryListQuery,
  ): Promise<ArchiveImportEntryPage>
  createArchiveTaskBatch(
    importId: string,
    input: CreateArchiveTaskBatchInput,
    idempotencyKey: string,
  ): Promise<ArchiveTaskBatchResult>
  createTask(input: CreateTaskInput, idempotencyKey: string): Promise<CreatedTask>
}
