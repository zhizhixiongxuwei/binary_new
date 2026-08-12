export type UserRole = 'administrator' | 'operator' | 'reader'

export interface CurrentUser {
  id: string
  username: string
  display_name: string
  role: UserRole
  must_change_password: boolean
}

export interface LoginInput {
  username: string
  password: string
}

export interface ChangePasswordInput {
  current_password: string
  new_password: string
}

export type TaskStatus =
  | 'UPLOADING'
  | 'QUEUED'
  | 'VALIDATING'
  | 'IDENTIFYING'
  | 'EXTRACTING'
  | 'INDEXING'
  | 'SCANNING'
  | 'REPORTING'
  | 'SUCCEEDED'
  | 'PARTIAL_SUCCEEDED'
  | 'FAILED'
  | 'CANCEL_REQUESTED'
  | 'CANCELLED'
  | 'DELETING'
  | 'DELETED'
  | 'pending'
  | 'uploading'
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'partial'
  | 'failed'
  | 'cancelled'

export type RiskLevel =
  | 'NONE'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'
  | 'UNKNOWN'
  | 'none'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'
  | 'unknown'

export interface ScanTask {
  id: string
  name: string
  input_type: string
  status: TaskStatus
  risk_level: RiskLevel
  progress: number
  progress_indeterminate: boolean
  creator_id: string
  creator_name: string
  tags: readonly string[]
  created_at: string
  updated_at?: string
  sample_expires_at: string
  sample_deleted_at: string | null
}

export interface TaskListQuery {
  page_size: number
  cursor?: string
  keyword?: string
  status?: TaskStatus
  input_type?: string
  creator?: string
  tag?: string
  created_from?: string
  created_to?: string
}

export interface CursorPage<T> {
  items: T[]
  next_cursor?: string
}

export type TaskPage = CursorPage<ScanTask>

export interface TaskDetail extends ScanTask {
  original_filename?: string
  size_bytes?: number
  sha256?: string
  current_stage?: string
  error_code?: string
  error_message?: string
}

export type TaskEventSeverity =
  | 'debug'
  | 'info'
  | 'warning'
  | 'error'
  | 'critical'
  | string

export interface TaskEvent {
  sequence: number
  type: string
  stage: string | null
  progress: number | null
  progress_indeterminate: boolean
  severity: TaskEventSeverity
  message: string | null
  payload: JsonValue
  created_at: string
}

export interface TaskEventMessage {
  /**
   * The exact SSE `id` field. It remains a string because backend event
   * sequences are unsigned 64-bit values and may exceed JavaScript precision.
   */
  id: string
  event: string
  data: TaskEvent
}

export interface ExtendTaskRetentionInput {
  expected_sample_expires_at: string
  sample_expires_at: string
}

export type FileNodeType = 'file' | 'directory' | 'symlink' | 'hardlink' | 'special'

export interface FileNode {
  id: string
  parent_id: string | null
  logical_path: string
  display_name: string
  archive_name_id: string
  node_type: FileNodeType
  depth: number
  format: string
  mime_type: string
  architecture: string
  size_bytes: number | null
  sha256: string
  extraction_status: string
  error_code: string
  error_message: string
  source_container: FileNodeSourceContainer | null
  has_children: boolean
}

export interface FileNodeListQuery {
  parent_id?: string
  cursor?: string
  page_size?: number
}

export interface FileNodePage {
  items: FileNode[]
  next_cursor?: string
}

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

export interface FileNodeSourceParent {
  id: string
  logical_path: string
}

export interface FileNodeSourceContainer {
  id: string
  logical_path: string
  format: string
}

export interface FileNodeDetail extends FileNode {
  metadata_json: JsonValue
  source_parent: FileNodeSourceParent | null
}

export type DecompileEngineTarget =
  | 'auto'
  | 'ghidra'
  | 'vineflower'
  | 'jadx'
  | 'python-bytecode'

export interface CreateFileDecompileRequestInput {
  engine_target: DecompileEngineTarget
  options: Readonly<Record<string, JsonValue>>
}

export interface FileDecompileRequest {
  request_id: string
  job_id: string
  task_id: string
  file_node_id: string
  target_class: 'native' | 'bytecode'
  engine_target: Exclude<DecompileEngineTarget, 'auto'>
  status:
    | 'queued'
    | 'leased'
    | 'running'
    | 'succeeded'
    | 'failed'
    | 'cancel_requested'
    | 'cancelled'
  created_at: string
  error_code?: string
  error_message?: string
  completed_at?: string
}

export interface ManualImageScanRequest {
  job_id: string
  task_id: string
  file_node_id: string
  status:
    | 'queued'
    | 'leased'
    | 'running'
    | 'succeeded'
    | 'failed'
    | 'cancel_requested'
    | 'cancelled'
  created_at: string
}

export type DecompileSymbolKind =
  | 'function'
  | 'class'
  | 'method'
  | 'module'
  | 'unknown'

export type DecompileResultStatus =
  | 'queued'
  | 'running'
  | 'complete'
  | 'partial'
  | 'bytecode_only'
  | 'unsupported'
  | 'failed'
  | 'cancelled'

export interface DecompileResult {
  id: string
  file_node_id: string
  symbol_key: string
  symbol_kind: DecompileSymbolKind
  display_name: string
  group_name: string
  location: string
  signature: string
  detail: string
  language: string
  engine_name: string
  engine_version: string
  status: DecompileResultStatus
  size_bytes: number | null
  diagnostics: JsonValue
  created_at: string
  completed_at: string | null
}

export interface DecompileResultListQuery {
  cursor?: string
  page_size?: number
}

export interface DecompileResultPage {
  items: DecompileResult[]
  next_cursor?: string
}

export interface DecompileSourceQuery {
  offset?: number
  limit?: number
}

export interface DecompileSourceChunk {
  result_id: string
  offset: number
  content: string
  next_offset?: number
  complete: boolean
  sha256: string
  size_bytes: number
}

export type DecompileProjectLayoutVersion = 'project-v1' | 'legacy-v1'

export type DecompileProjectStatus =
  | 'complete'
  | 'partial'
  | 'bytecode_only'

export type DecompileProjectSourceKind =
  | 'ghidra-pseudoc'
  | 'java'
  | 'kotlin'
  | 'python'
  | 'bytecode'

export interface DecompileProject {
  id: string
  task_id: string
  job_id?: string
  file_node_id: string
  target_path: string
  layout_version: DecompileProjectLayoutVersion
  source_kind: DecompileProjectSourceKind
  language: string
  engine_name: string
  engine_version: string
  status: DecompileProjectStatus
  source_file_count: number
  symbol_count: number
  source_size_bytes: number
  canonical_filename?: string
  manifest_available: boolean
  created_at: string
  completed_at?: string
}

export interface DecompileProjectListQuery {
  cursor?: string
  page_size?: number
}

export type DecompileProjectPage = CursorPage<DecompileProject>

export interface DecompileProjectDeletionCounts {
  c_analysis_runs: number
  c_analysis_findings: number
  java_analysis_runs: number
  java_analysis_findings: number
  reports: number
  report_files: number
  artifacts: number
  decompile_results: number
  source_files: number
}

export interface DecompileProjectDeletionPreview {
  project_id: string
  counts: DecompileProjectDeletionCounts
  typed_suffix: string
  confirmation_token: string
  expires_at: string
}

export interface ConfirmDecompileProjectDeletionInput {
  confirmation_token: string
  cascade: true
  typed_suffix: string
}

export type DecompileProjectDeletionStatus =
  | 'pending'
  | 'cancelling'
  | 'deleting'
  | 'complete'
  | 'failed'

export interface DecompileProjectDeletionOperation {
  id: string
  project_id: string
  status: DecompileProjectDeletionStatus
  counts: DecompileProjectDeletionCounts
  created_at: string
  completed_at: string | null
  error_code: string | null
  error_message: string | null
}

export type CAnalysisRunStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'partial'
  | 'failed'
  | 'cancel_requested'
  | 'cancelled'

export type CAnalysisSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type CAnalysisSeverityCounts = Readonly<
  Record<CAnalysisSeverity, number>
>

export interface CAnalysisProjectSummary {
  id: string
  target_path: string
  status: 'complete' | 'partial'
  engine_name: string
  engine_version: string
}

export interface CAnalysisCoverage {
  total_functions: number
  parsed_functions: number
  failed_functions: number
}

export interface CAnalysisRun {
  id: string
  task_id: string
  source_project_id: string
  source_project: CAnalysisProjectSummary
  job_id: string
  status: CAnalysisRunStatus
  analyzer_name: string
  analyzer_version: string
  ruleset_version?: string
  source_sha256: string
  source_size_bytes: number
  finding_count: number
  diagnostic_count: number
  coverage: CAnalysisCoverage
  severity_counts: CAnalysisSeverityCounts
  findings_truncated: boolean
  diagnostics_truncated: boolean
  error_code: string | null
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface CAnalysisRunListQuery {
  project_id?: string
  cursor?: string
  page_size?: number
}

export type CAnalysisRunPage = CursorPage<CAnalysisRun>

export interface CAnalysisFunctionIdentity {
  result_id: string
  address: string
  name: string
}

export interface CAnalysisLocation {
  start_line: number
  start_column: number
  end_line: number
  end_column: number
}

export interface CAnalysisFinding {
  id: string
  cwe: string
  rule_id: string
  severity: CAnalysisSeverity
  function: CAnalysisFunctionIdentity
  location: CAnalysisLocation
  message: string
  snippet?: string
  created_at?: string
}

export interface CAnalysisFindingListQuery {
  cursor?: string
  page_size?: number
  cwe?: string
  severity?: CAnalysisSeverity
  function?: string
}

export type CAnalysisFindingPage = CursorPage<CAnalysisFinding>

export type JavaAnalysisRunStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'partial'
  | 'failed'
  | 'cancel_requested'
  | 'cancelled'

export type JavaAnalysisSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type JavaAnalysisSeverityCounts = Readonly<
  Record<JavaAnalysisSeverity, number>
>

export interface JavaAnalysisProjectSummary {
  id: string
  target_path: string
  status: 'complete' | 'partial'
  engine_name: string
  engine_version: string
}

export interface JavaAnalysisCoverage {
  total_files: number
  analyzed_files: number
  parsed_files: number
  recovered_files: number
  failed_files: number
}

export interface JavaAnalysisRun {
  id: string
  task_id: string
  source_project_id: string
  source_project: JavaAnalysisProjectSummary
  job_id: string
  status: JavaAnalysisRunStatus
  analyzer_name: string
  analyzer_version: string
  ruleset_version: string
  source_manifest_sha256: string
  input_sha256: string
  bundle_sha256: string
  source_size_bytes: number
  source_file_count: number
  finding_count: number
  diagnostic_count: number
  coverage: JavaAnalysisCoverage
  severity_counts: JavaAnalysisSeverityCounts
  findings_truncated: boolean
  diagnostics_truncated: boolean
  error_code: string | null
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
  updated_at: string
}

export interface JavaAnalysisRunListQuery {
  project_id?: string
  cursor?: string
  page_size?: number
}

export type JavaAnalysisRunPage = CursorPage<JavaAnalysisRun>

export interface JavaAnalysisFileIdentity {
  result_id: string
  logical_path: string
  binary_name: string
}

export interface JavaAnalysisCallableIdentity {
  kind: string
  type_name: string
  name: string
  signature: string
}

export interface JavaAnalysisLocation {
  start_line: number
  start_column: number
  end_line: number
  end_column: number
}

export interface JavaAnalysisFinding {
  id: string
  cwe: string
  rule_id: string
  severity: JavaAnalysisSeverity
  file: JavaAnalysisFileIdentity
  callable: JavaAnalysisCallableIdentity
  location: JavaAnalysisLocation
  message: string
  snippet?: string
  snippet_start_line?: number
  created_at?: string
}

export interface JavaAnalysisFindingListQuery {
  cursor?: string
  page_size?: number
  cwe?: string
  severity?: JavaAnalysisSeverity
  file?: string
  callable?: string
}

export type JavaAnalysisFindingPage = CursorPage<JavaAnalysisFinding>

export type VulnerabilitySeverity =
  | 'UNKNOWN'
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL'

export type VulnerabilitySeverityCounts = Readonly<
  Record<VulnerabilitySeverity, number>
>

export interface VulnerabilitySummary {
  total: number
  fixable: number
  by_severity: VulnerabilitySeverityCounts
}

export interface TrivyDatabaseBundle {
  id: string
  version: string
  generated_at: string
  content_sha256: string
}

export type VulnerabilityDataSource = Readonly<Record<string, JsonValue>> & {
  id?: string
  name?: string
  url?: string
}

export interface VulnerabilityEvidence {
  package_name?: string
  installed_version?: string
  fixed_version?: string
  package_path?: string
  target?: string
  class?: string
  type?: string
  image_logical_path?: string
  image_platform?: string
  image_references?: readonly string[]
  manifest_digest?: string
  data_source?: VulnerabilityDataSource
  readonly [key: string]: JsonValue | undefined
}

export interface VulnerabilityFinding {
  id: string
  vulnerability_id: string
  severity: VulnerabilitySeverity
  package_name: string
  installed_version: string
  fixed_version: string
  title: string
  description_summary: string
  image_logical_path: string
  image_platform: string
  evidence: VulnerabilityEvidence | null
  references: readonly string[] | null
  database_bundle: TrivyDatabaseBundle | null
  created_at: string
}

export interface VulnerabilityListQuery {
  severity?: VulnerabilitySeverity
  cursor?: string
  page_size?: number
}

export interface VulnerabilityFindingPage {
  summary: VulnerabilitySummary
  items: VulnerabilityFinding[]
  next_cursor?: string
}

export type ReportFormat = 'json' | 'html'
export type ReportDownloadEncoding = 'identity' | 'gzip'
export type TaskReportSampleRelation = 'retained' | 'expired' | 'deleted'

export type ReportStatus =
  | 'queued'
  | 'generating'
  | 'complete'
  | 'failed'
  | 'deleted'

export interface TaskReport {
  id: string
  task_id: string
  format: ReportFormat
  schema_version: string
  status: ReportStatus
  sha256: string | null
  size_bytes: number | null
  error_code: string | null
  error_message: string | null
  created_at: string
  completed_at: string | null
}

export interface TaskReportList {
  items: TaskReport[]
  sample_relation?: TaskReportSampleRelation
}

export interface CreateTaskReportInput {
  format: ReportFormat
}

export interface ReportURLDownload {
  kind: 'url'
  url: string
}

export interface ReportBlobDownload {
  kind: 'blob'
  blob: Blob
  filename: string
}

export type ReportDownload = ReportURLDownload | ReportBlobDownload

export interface StageDurationMetric {
  stage:
    | 'VALIDATING'
    | 'IDENTIFYING'
    | 'EXTRACTING'
    | 'INDEXING'
    | 'SCANNING'
    | 'REPORTING'
  sample_count: number
  average_duration_ms: number
}

export interface AnalyzerFailureMetric {
  name: string
  total_runs: number
  failed_runs: number
  failure_rate_basis_points: number
}

export interface OperationalMetrics {
  window_hours: number
  stage_durations: readonly StageDurationMetric[]
  analyzer_failure_rates: readonly AnalyzerFailureMetric[]
}

export interface SystemStatus {
  version: string
  build?: {
    version: string
    commit: string
    build_time: string
    go_version: string
  }
  service_status: 'healthy' | 'degraded' | 'unavailable'
  active_tasks: number
  queued_tasks: number
  queue_depth?: number
  task_counts?: Readonly<Record<string, number>>
  worker_summary?: {
    observed_leases: number
    observed_owners: number
    leases_by_kind: Readonly<Record<string, number>>
    oldest_heartbeat_at: string | null
    latest_heartbeat_at: string | null
  }
  repository_used_bytes: number
  repository_total_bytes: number
  trivy_db_version?: string
  analyzers?: readonly {
    name: string
    version: string
    expected_version: string
    status: 'available' | 'unavailable'
    scope?: string
    required_worker_kinds: readonly ('image' | 'native' | 'trivy')[]
    ready_worker_kinds: readonly ('image' | 'native' | 'trivy')[]
    ready_workers: number
    runtime_name: string
    runtime_version: string
    detail?: string
    last_checked_at?: string | null
    last_run_at?: string | null
  }[]
  storage_mounts?: readonly StorageMountStatus[]
  trivy_database_bundle?: DatabaseBundleStatus | null
  operational_metrics?: OperationalMetrics
  collected_at?: string
  diagnostics?: readonly SystemDiagnostic[]
}

export type StorageMountHealth =
  | 'healthy'
  | 'warning'
  | 'critical'
  | 'unavailable'
  | 'unknown'

export interface StorageMountStatus {
  id: string
  label: string
  purpose: string
  host_path: string | null
  container_path: string
  services: readonly string[]
  used_bytes: number | null
  total_bytes: number | null
  warning_percent: number
  critical_percent: number
  writable: boolean | null
  free_bytes?: number | null
  minimum_free_bytes?: number | null
  low_water?: boolean | null
  status?: StorageMountHealth
}

export interface SystemDiagnostic {
  code: string
  severity: 'warning' | 'error'
  component: string
  message: string
  remediation: string
}

export type DatabaseBundleHealth =
  | 'active'
  | 'stale'

export interface DatabaseBundleStatus {
  id: string
  version: string
  trivy_db_version: string
  trivy_java_db_version: string
  status: DatabaseBundleHealth
  generated_at: string
  registered_at: string
  age_days: number
  stale_after_days: number
	content_sha256: string
}

export type AdminUserStatus = 'active' | 'disabled' | 'locked'

export interface AdminUser {
  id: string
  username: string
  display_name: string
  role: UserRole
  status: AdminUserStatus
  must_change_password: boolean
  failed_login_count: number
  locked_until: string | null
  last_login_at: string | null
  created_at: string
  updated_at: string
}

export interface AdminUserListQuery {
  keyword?: string
  role?: UserRole
  status?: AdminUserStatus
  cursor?: string
  page_size?: number
}

export interface AdminUserPage {
  items: AdminUser[]
  next_cursor?: string
}

export interface CreateAdminUserInput {
  username: string
  display_name: string
  role: UserRole
  temporary_password: string
}

export interface UpdateAdminUserInput {
  role?: UserRole
  status?: Exclude<AdminUserStatus, 'locked'>
  expected_updated_at: string
}

export interface ResetAdminUserPasswordInput {
  temporary_password: string
  expected_updated_at: string
}

export interface AuditActor {
  id: string
  username: string
  display_name: string
}

export interface AuditLog {
  id: string
  actor: AuditActor | null
  action: string
  outcome: 'success' | 'failure' | 'denied'
  object_type: string
  object_id: string | null
  request_id: string
  metadata: JsonValue | null
  created_at: string
}

export interface AuditLogListQuery {
  action?: string
  outcome?: string
  actor?: string
  created_from?: string
  created_to?: string
  cursor?: string
  page_size?: number
}

export interface AuditLogPage {
  items: AuditLog[]
  next_cursor?: string
}

export type InputCategory = 'binary' | 'archive' | 'container'

export type UploadValidationStatus =
  | 'pending'
  | 'valid'
  | 'mismatch'
  | 'unsupported'

export interface UploadValidationError {
  code: string
  message: string
}

export interface UploadSession {
  id: string
  part_size: number
  sha256?: string
  size_bytes?: number
  status: 'created' | 'uploading' | 'assembling' | 'completed' | 'failed' | 'expired' | 'cancelled'
  uploaded_parts: number[]
  expires_at: string
  input_category?: InputCategory
  validation_status?: UploadValidationStatus
  detected_category?: InputCategory
  detected_format?: string
  validation_error?: UploadValidationError
  archive_import_id?: string
  task_id?: string
}

export interface CompletedUpload extends UploadSession {
  sha256: string
  size_bytes: number
}

export interface UploadPartInput {
  part_number: number
  start: number
  end: number
  total: number
  sha256: string
  chunk: Blob
}

export interface CreateTaskInput {
  upload_id: string
  name: string
}

export interface CreateUploadInput {
  filename: string
  size: number
  content_type: string
  input_category: InputCategory
}

export interface CreatedTask {
  id: string
}

export type ArchiveImportStatus =
  | 'queued'
  | 'running'
  | 'ready'
  | 'failed'
  | 'deleting'
  | 'deleted'

export interface ArchiveImport {
  id: string
  upload_id: string
  filename: string
  status: ArchiveImportStatus
  scanned_entries: number
  total_entries: number
  eligible_entries: number
  skipped_entries: number
  created_tasks: number
  error_code?: string
  error_message?: string
  created_at: string
  updated_at: string
}

export interface ArchiveImportListQuery {
  cursor?: string
  page_size?: number
}

export interface ArchiveImportPage {
  items: ArchiveImport[]
  next_cursor?: string
}

export type ArchiveImportEntryStatus =
  | 'eligible'
  | 'skipped'
  | 'created'
  | 'failed'

export interface ArchiveImportEntry {
  id: string
  path: string
  size_bytes: number
  sha256: string | null
  detected_format: string | null
  detected_category: Exclude<InputCategory, 'archive'> | null
  status: ArchiveImportEntryStatus
  skip_reason?: string
  task_id?: string
}

export type ArchiveImportEntryFilter =
  | 'all'
  | ArchiveImportEntryStatus

export interface ArchiveImportEntryListQuery {
  filter?: ArchiveImportEntryFilter
  cursor?: string
  page_size?: number
}

export interface ArchiveImportEntryPage {
  items: ArchiveImportEntry[]
  next_cursor?: string
}

export interface CreateArchiveTaskBatchInput {
  entry_ids: string[]
}

export type ArchiveTaskBatchOutcome = 'created' | 'existing' | 'failed'

export interface ArchiveTaskBatchResultItem {
  entry_id: string
  outcome: ArchiveTaskBatchOutcome
  task_id?: string
  error_code?: string
  message?: string
}

export interface ArchiveTaskBatchResult {
  items: readonly ArchiveTaskBatchResultItem[]
}

export interface ApiErrorBody {
  code?: string
  message?: string
  details?: unknown
}
