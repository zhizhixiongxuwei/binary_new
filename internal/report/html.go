package report

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var reportHTML = template.Must(template.New("report").Funcs(template.FuncMap{
	"nullable": func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	},
	"nullableTime": func(value *time.Time) string {
		if value == nil {
			return ""
		}
		return value.UTC().Format(time.RFC3339Nano)
	},
	"jsonText": readableReportJSON,
}).Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BinaryScan Report</title>
<style>
body{margin:0;background:#f5f7fa;color:#17202a;font:14px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:28px}h1,h2{letter-spacing:0}h1{font-size:28px}h2{font-size:19px;margin-top:30px;border-bottom:2px solid #d7dde5;padding-bottom:7px}
table{width:100%;border-collapse:collapse;margin:10px 0 18px;background:#fff}th,td{padding:8px 10px;border:1px solid #d7dde5;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#eef2f6}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.panel{background:#fff;border:1px solid #d7dde5;padding:14px}.muted{color:#5d6d7e}.severity-CRITICAL,.severity-HIGH{font-weight:700;color:#a93226}.severity-MEDIUM{font-weight:700;color:#b9770e}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8f9fa;border:1px solid #d7dde5;padding:10px}.evidence-list{display:grid;gap:4px;margin:0}.evidence-list div{display:grid;grid-template-columns:72px minmax(0,1fr);gap:6px}.evidence-list dt{font-weight:700;color:#5d6d7e}.evidence-list dd{margin:0}.reference-list{margin:8px 0 0;padding-left:18px}.reference-list a,.source-link{color:#176a80;overflow-wrap:anywhere}@media(max-width:720px){main{padding:14px}.grid{grid-template-columns:1fr}table{display:block;overflow-x:auto}}
</style>
</head>
<body><main data-report-contract="binaryscan-report/v1" data-task-id="{{.Task.ID}}" data-report-id="{{.ReportID}}" data-sample-relation="{{.SampleRelation}}">
<h1>BinaryScan 离线检测报告</h1>
<p class="muted">Schema {{.SchemaVersion}} · Report {{.ReportID}} · Generated {{.GeneratedAt}}</p>
<div class="grid">
<section class="panel"><h2>任务</h2><table>
<tr><th>ID</th><td data-report-field="task-id">{{.Task.ID}}</td></tr><tr><th>名称</th><td data-report-field="task-name">{{.Task.Name}}</td></tr>
<tr><th>状态</th><td>{{.Task.Status}}</td></tr><tr><th>阶段</th><td>{{nullable .Task.Stage}}</td></tr>
<tr><th>风险</th><td>{{.Task.RiskLevel}}</td></tr><tr><th>根格式</th><td>{{nullable .Task.RootFormat}}</td></tr>
<tr><th>错误</th><td>{{nullable .Task.ErrorCode}} {{nullable .Task.ErrorMessage}}</td></tr>
<tr><th>原始样本</th><td data-report-field="sample-relation" data-sample-relation="{{.SampleRelation}}">{{.SampleRelationMessage}}</td></tr>
</table></section>
<section class="panel"><h2>输入</h2><table>
<tr><th>文件名</th><td data-report-field="input-filename">{{.Task.Input.Filename}}</td></tr><tr><th>大小</th><td>{{.Task.Input.SizeBytes}}</td></tr>
<tr><th>SHA-256</th><td>{{.Task.Input.SHA256}}</td></tr>
</table></section>
</div>
<h2>限制与执行</h2>
<table><tr><th>任务状态</th><th>尝试状态</th><th>进度基点</th><th>开始</th><th>完成</th></tr>
<tr><td>{{nullable .Execution.Status}}</td><td>{{nullable .Execution.AttemptStatus}}</td><td>{{.Execution.ProgressBasisPoints}}</td><td>{{nullableTime .Execution.StartedAt}}</td><td>{{nullableTime .Execution.CompletedAt}}</td></tr></table>
<div class="grid"><section><h3>限制快照</h3><pre>{{.Limits}}</pre></section><section><h3>执行统计</h3><pre>{{.Statistics}}</pre></section></div>
<h2>文件类型分布</h2><p class="muted">按持久化文件节点统计，共 {{.FileCount}} 个文件；目录和链接不计入。</p><table><thead><tr><th>格式</th><th>文件数</th><th>总大小</th></tr></thead><tbody>
{{range .FileTypes}}<tr data-report-file-format="{{.Format}}" data-count="{{.Count}}" data-size-bytes="{{.SizeBytes}}"><td>{{.Format}}</td><td>{{.Count}}</td><td>{{.SizeBytes}}</td></tr>{{else}}<tr><td colspan="3">无文件节点</td></tr>{{end}}
</tbody></table>
<h2>映像结构摘要</h2>
{{if .ImageStructures}}<table><thead><tr><th>映像路径</th><th>识别格式</th><th>持久化结构元数据</th></tr></thead><tbody>
{{range .ImageStructures}}<tr data-report-image-path="{{.LogicalPath}}" data-format="{{.Format}}"><td>{{.LogicalPath}}</td><td>{{.Format}}</td><td><pre data-report-field="image-structure">{{.Metadata}}</pre></td></tr>{{end}}
</tbody></table>{{else}}<p class="muted">未提供持久化映像结构元数据；本报告不会推断分区或文件系统结构。</p>{{end}}
<h2>漏洞汇总</h2><table><thead><tr><th>严重级别</th><th>数量</th><th>可修复</th></tr></thead><tbody>
{{range .VulnerabilitySummary}}<tr data-report-severity="{{.Severity}}" data-count="{{.Count}}" data-fixable="{{.Fixable}}"><td class="severity-{{.Severity}}">{{.Severity}}</td><td>{{.Count}}</td><td>{{.Fixable}}</td></tr>{{else}}<tr><td colspan="3">无漏洞发现</td></tr>{{end}}
</tbody></table>
		<h2>漏洞详情</h2><table><thead><tr><th>ID</th><th>级别</th><th>包</th><th>版本 / 修复</th><th>镜像路径</th><th>标题与说明</th><th>证据 / 引用</th></tr></thead><tbody>
		{{range .Vulnerabilities}}<tr data-report-vulnerability-id="{{.VulnerabilityID}}" data-severity="{{.Severity}}" data-package-name="{{.PackageName}}"><td>{{.VulnerabilityID}}</td><td class="severity-{{.Severity}}">{{.Severity}}</td><td>{{.PackageName}}</td><td>{{nullable .InstalledVersion}}<br>{{nullable .FixedVersion}}</td><td>{{.ImageLogicalPath}}</td><td>{{nullable .Title}}<br>{{nullable .DescriptionSummary}}</td><td>{{if .Evidence.HasValues}}<dl class="evidence-list">{{if .Evidence.Target}}<div><dt>扫描目标</dt><dd><code>{{.Evidence.Target}}</code></dd></div>{{end}}{{if .Evidence.PackagePath}}<div><dt>包路径</dt><dd><code>{{.Evidence.PackagePath}}</code></dd></div>{{end}}{{if .Evidence.Class}}<div><dt>组件类别</dt><dd><code>{{.Evidence.Class}}</code></dd></div>{{end}}{{if .Evidence.Type}}<div><dt>包类型</dt><dd><code>{{.Evidence.Type}}</code></dd></div>{{end}}{{if .Evidence.ImagePlatform}}<div><dt>镜像平台</dt><dd><code>{{.Evidence.ImagePlatform}}</code></dd></div>{{end}}{{if .Evidence.ManifestDigest}}<div><dt>清单摘要</dt><dd><code>{{.Evidence.ManifestDigest}}</code></dd></div>{{end}}{{if .Evidence.ImageReferences}}<div><dt>镜像引用</dt><dd>{{range .Evidence.ImageReferences}}<code>{{.}}</code><br>{{end}}</dd></div>{{end}}{{if .Evidence.HasDataSource}}<div><dt>漏洞数据源</dt><dd>{{.Evidence.DataSourceName}}{{if and .Evidence.DataSourceName .Evidence.DataSourceID}} / {{end}}{{.Evidence.DataSourceID}}{{if .Evidence.DataSourceURL}}<br><a class="source-link" href="{{.Evidence.DataSourceURL}}" target="_blank" rel="noreferrer noopener">{{.Evidence.DataSourceURL}}</a>{{end}}</dd></div>{{end}}</dl>{{else}}<span class="muted">无结构化证据</span>{{end}}{{if .References}}<strong>漏洞引用</strong><ul class="reference-list">{{range .References}}<li><a href="{{.URL}}" target="_blank" rel="noreferrer noopener">{{.URL}}</a></li>{{end}}</ul>{{end}}</td></tr>{{else}}<tr><td colspan="7">无漏洞发现</td></tr>{{end}}
	</tbody></table>
	{{if .VulnerabilitiesTruncated}}<p class="muted">漏洞详情仅展示前 {{.VulnerabilityLimit}} 项；完整数据请使用 JSON 报告。</p>{{end}}
	<h2>分析器运行</h2><table><thead><tr><th>分析器</th><th>版本</th><th>状态</th><th>文件节点</th><th>错误</th></tr></thead><tbody>
	{{range .Analyzers}}<tr><td>{{.AnalyzerName}}</td><td>{{.AnalyzerVersion}}</td><td>{{.Status}}</td><td>{{nullable .FileNodeID}}</td><td>{{nullable .ErrorCode}} {{nullable .ErrorMessage}}</td></tr>{{else}}<tr><td colspan="5">无分析器记录</td></tr>{{end}}
	</tbody></table>
	{{if .AnalyzersTruncated}}<p class="muted">分析器运行仅展示前 {{.AnalyzerLimit}} 项；完整数据请使用 JSON 报告。</p>{{end}}
	<h2>反编译函数索引</h2>
	<p class="muted">Ghidra 等反编译器按函数生成独立结果；此处仅包含可持久化元数据，不嵌入反编译源码。</p>
	<table><thead><tr><th>函数 / 符号</th><th>类型</th><th>位置</th><th>签名</th><th>引擎</th><th>状态</th><th>大小</th></tr></thead><tbody>
	{{range .Decompilations}}<tr data-report-decompile-result-id="{{.ID}}" data-file-node-id="{{.FileNodeID}}" data-symbol-kind="{{.SymbolKind}}" data-status="{{.Status}}"><td><strong>{{.DisplayName}}</strong><br><code>{{.SymbolKey}}</code></td><td>{{.SymbolKind}}</td><td><code>{{.Location}}</code></td><td><code>{{.Signature}}</code></td><td>{{.EngineName}} {{.EngineVersion}}<br>{{.Language}}</td><td>{{.Status}}</td><td>{{if .SizeBytes}}{{.SizeBytes}}{{end}}</td></tr>{{else}}<tr><td colspan="7">无反编译结果</td></tr>{{end}}
	</tbody></table>
	{{if .DecompilationsTruncated}}<p class="muted">反编译函数索引仅展示前 {{.DecompilationLimit}} 项；完整元数据请使用 JSON 报告，源码请从任务报告区按需读取或导出。</p>{{end}}
	<h2>Trivy 数据库 Bundle</h2><table><thead><tr><th>Bundle</th><th>主库版本</th><th>Java 库版本</th><th>生成时间</th><th>内容 SHA-256</th></tr></thead><tbody>
	{{range .Databases}}<tr><td>{{.Version}}</td><td>{{.TrivyDBVersion}}</td><td>{{.TrivyJavaDBVersion}}</td><td>{{.GeneratedAt}}</td><td>{{.ContentSHA256}}</td></tr>{{else}}<tr><td colspan="5">无 Trivy 数据库 Bundle</td></tr>{{end}}
	</tbody></table>
		{{if .DatabasesTruncated}}<p class="muted">数据库 Bundle 仅展示前 {{.DatabaseLimit}} 项；完整数据请使用 JSON 报告。</p>{{end}}
		<h2>警告、限制、未支持与失败</h2><table><thead><tr><th>类别</th><th>代码</th><th>来源</th><th>路径</th><th>消息</th></tr></thead><tbody>
		{{range .Issues}}<tr data-report-issue-category="{{.Category}}" data-report-issue-code="{{.Code}}"><td>{{.Category}}</td><td>{{.Code}}</td><td>{{nullable .Source}}</td><td>{{nullable .LogicalPath}}</td><td>{{.Message}}</td></tr>{{else}}<tr><td colspan="5">无诊断项</td></tr>{{end}}
	</tbody></table>
	{{if .IssuesTruncated}}<p class="muted">诊断项仅展示前 {{.IssueLimit}} 项；完整数据请使用 JSON 报告。</p>{{end}}
	<p class="muted">此 HTML 报告完全离线生成，不包含脚本、外部资源、完整反编译源码或全部文件节点清单。</p>
	</main></body></html>`))

const (
	htmlVulnerabilityDetailLimit = 1000
	htmlAnalyzerRunLimit         = 1000
	htmlDecompileResultLimit     = 3000
	htmlDatabaseVersionLimit     = 100
	htmlDiagnosticLimit          = 1000
)

type htmlReportData struct {
	SchemaVersion            string
	ReportID                 string
	GeneratedAt              string
	Task                     taskSnapshot
	Execution                executionSnapshot
	SampleRelation           string
	SampleRelationMessage    string
	Limits                   string
	Statistics               string
	FileCount                uint64
	FileTypes                []htmlFileType
	ImageStructures          []htmlImageStructure
	VulnerabilitySummary     []htmlVulnerabilitySummary
	Vulnerabilities          []htmlVulnerabilityFinding
	Analyzers                []analyzerRunSnapshot
	Decompilations           []htmlDecompileResult
	Databases                []databaseBundleSnapshot
	Issues                   []htmlIssue
	VulnerabilitiesTruncated bool
	AnalyzersTruncated       bool
	DecompilationsTruncated  bool
	DatabasesTruncated       bool
	IssuesTruncated          bool
	VulnerabilityLimit       int
	AnalyzerLimit            int
	DecompilationLimit       int
	DatabaseLimit            int
	IssueLimit               int
}

type htmlFileType struct {
	Format    string
	Count     uint64
	SizeBytes uint64
}

type htmlImageStructure struct {
	LogicalPath string
	Format      string
	Metadata    string
}

type htmlVulnerabilitySummary struct {
	Severity string
	Count    uint64
	Fixable  uint64
}

type htmlVulnerabilityFinding struct {
	vulnerabilitySnapshot
	Evidence   htmlVulnerabilityEvidence
	References []htmlVulnerabilityReference
}

type htmlVulnerabilityEvidence struct {
	HasValues       bool
	Target          string
	PackagePath     string
	Class           string
	Type            string
	ImagePlatform   string
	ManifestDigest  string
	ImageReferences []string
	HasDataSource   bool
	DataSourceID    string
	DataSourceName  string
	DataSourceURL   string
}

type htmlVulnerabilityReference struct {
	URL string
}

type persistedVulnerabilityEvidence struct {
	PackagePath     string                               `json:"package_path"`
	Target          string                               `json:"target"`
	Class           string                               `json:"class"`
	Type            string                               `json:"type"`
	ImagePlatform   string                               `json:"image_platform"`
	ManifestDigest  string                               `json:"manifest_digest"`
	ImageReferences []string                             `json:"image_references"`
	DataSource      persistedVulnerabilityEvidenceSource `json:"data_source"`
}

type persistedVulnerabilityEvidenceSource struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type htmlDecompileResult struct {
	ID            string
	FileNodeID    string
	SymbolKey     string
	SymbolKind    string
	DisplayName   string
	Location      string
	Signature     string
	Language      string
	EngineName    string
	EngineVersion string
	Status        string
	SizeBytes     *uint64
}

type htmlIssue struct {
	Category string
	issueSnapshot
}

// readableReportJSON keeps persisted JSON as escaped text while avoiding the
// byte-slice representation produced when json.RawMessage is rendered directly.
func readableReportJSON(value json.RawMessage) string {
	if len(value) == 0 || !json.Valid(value) {
		return "null"
	}
	var output bytes.Buffer
	if err := json.Indent(&output, value, "", "  "); err != nil {
		return "null"
	}
	return output.String()
}

func (r *MySQLRepository) WriteHTMLSnapshot(
	ctx context.Context,
	request SnapshotRequest,
	writer io.Writer,
) error {
	return r.withReadSnapshot(ctx, func(transaction *sql.Tx) error {
		task, err := loadTaskSnapshot(ctx, transaction, request.TaskID)
		if err != nil {
			return err
		}
		execution, err := loadExecutionSnapshot(ctx, transaction, task)
		if err != nil {
			return err
		}
		data := htmlReportData{
			SchemaVersion:      SchemaVersion,
			ReportID:           request.ReportID,
			GeneratedAt:        request.GeneratedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			Task:               task,
			Execution:          execution,
			SampleRelation:     sampleRelationAt(task, request.GeneratedAt),
			Statistics:         string(execution.Statistics),
			VulnerabilityLimit: htmlVulnerabilityDetailLimit,
			AnalyzerLimit:      htmlAnalyzerRunLimit,
			DecompilationLimit: htmlDecompileResultLimit,
			DatabaseLimit:      htmlDatabaseVersionLimit,
			IssueLimit:         htmlDiagnosticLimit,
		}
		data.SampleRelationMessage = sampleRelationMessage(
			task,
			data.SampleRelation,
		)
		encodedLimits, err := json.Marshal(task.LimitsSnapshot)
		if err != nil {
			return fmt.Errorf("encode HTML limits snapshot: %w", err)
		}
		data.Limits = string(encodedLimits)
		if data.FileTypes, err = loadHTMLFileTypes(ctx, transaction, request.TaskID); err != nil {
			return err
		}
		for _, fileType := range data.FileTypes {
			data.FileCount += fileType.Count
		}
		if data.ImageStructures, err = loadHTMLImageStructures(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if data.VulnerabilitySummary, err = loadHTMLVulnerabilitySummary(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if data.Vulnerabilities, data.VulnerabilitiesTruncated, err = loadHTMLVulnerabilities(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if data.Analyzers, data.AnalyzersTruncated, err = loadHTMLAnalyzers(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if data.Decompilations, data.DecompilationsTruncated, err =
			loadHTMLDecompilations(ctx, transaction, request.TaskID); err != nil {
			return err
		}
		if data.Databases, data.DatabasesTruncated, err = loadHTMLDatabases(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if data.Issues, data.IssuesTruncated, err = loadHTMLIssues(
			ctx, transaction, request.TaskID,
		); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := reportHTML.Execute(writer, data); err != nil {
			return fmt.Errorf("render static HTML report: %w", err)
		}
		return nil
	})
}

func sampleRelationAt(task taskSnapshot, generatedAt time.Time) string {
	if task.SampleDeletedAt != nil {
		return "deleted"
	}
	if !task.SampleExpiresAt.After(generatedAt) {
		return "expired"
	}
	return "retained"
}

func sampleRelationMessage(task taskSnapshot, relation string) string {
	switch relation {
	case "deleted":
		return "该任务已不再保留可复用样本（" +
			task.SampleDeletedAt.UTC().Format(time.RFC3339Nano) + "）"
	case "expired":
		return "样本保留期已于 " +
			task.SampleExpiresAt.UTC().Format(time.RFC3339Nano) + " 到期"
	default:
		return "仍保留，计划保留至 " +
			task.SampleExpiresAt.UTC().Format(time.RFC3339Nano)
	}
}

func loadHTMLFileTypes(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlFileType, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT COALESCE(NULLIF(format, ''), 'unknown'), COUNT(*),
       COALESCE(SUM(size_bytes), 0)
FROM file_nodes
WHERE task_id = ? AND node_type = 'file'
GROUP BY COALESCE(NULLIF(format, ''), 'unknown')
ORDER BY COUNT(*) DESC, COALESCE(NULLIF(format, ''), 'unknown') ASC`, taskID)
	if err != nil {
		return nil, fmt.Errorf("summarize report file types: %w", err)
	}
	defer rows.Close()
	values := []htmlFileType{}
	for rows.Next() {
		var value htmlFileType
		if err := rows.Scan(&value.Format, &value.Count, &value.SizeBytes); err != nil {
			return nil, fmt.Errorf("scan report file type summary: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate report file type summary: %w", err)
	}
	return values, nil
}

func loadHTMLImageStructures(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlImageStructure, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT logical_path, format, metadata_json
FROM file_nodes
WHERE task_id = ?
  AND node_type = 'file'
  AND format IN (
      'mbr-img', 'gpt-img', 'ext2', 'ext3', 'ext4',
      'squashfs', 'iso9660', 'udf'
  )
  AND metadata_json IS NOT NULL
  AND JSON_TYPE(metadata_json) = 'OBJECT'
ORDER BY depth ASC, logical_path ASC
LIMIT 128`, taskID)
	if err != nil {
		return nil, fmt.Errorf("query HTML image structure metadata: %w", err)
	}
	defer rows.Close()

	values := make([]htmlImageStructure, 0)
	for rows.Next() {
		var logicalPath string
		var format string
		var raw []byte
		if err := rows.Scan(&logicalPath, &format, &raw); err != nil {
			return nil, fmt.Errorf("scan HTML image structure metadata: %w", err)
		}
		metadata, ok := imageStructureMetadata(format, raw)
		if !ok {
			continue
		}
		values = append(values, htmlImageStructure{
			LogicalPath: logicalPath,
			Format:      format,
			Metadata:    metadata,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate HTML image structure metadata: %w", err)
	}
	return values, nil
}

func imageStructureMetadata(format string, raw []byte) (string, bool) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(raw, &source); err != nil {
		return "", false
	}
	keysByFormat := map[string][]string{
		"mbr-img":  {"partition_table", "partitions", "sector_size"},
		"gpt-img":  {"partition_table", "partition_slots", "partition_stride", "sector_size"},
		"ext2":     {"block_size", "inodes", "blocks"},
		"ext3":     {"block_size", "inodes", "blocks"},
		"ext4":     {"block_size", "inodes", "blocks"},
		"squashfs": {"endianness", "version", "block_size", "compression"},
		"udf":      {"revision"},
		"iso9660":  {},
	}
	keys, supported := keysByFormat[format]
	if !supported {
		return "", false
	}
	summary := make(map[string]json.RawMessage, len(keys))
	for _, key := range keys {
		value, exists := source[key]
		if !exists || !validImageMetadataScalar(value) {
			continue
		}
		summary[key] = value
	}
	if len(summary) == 0 {
		return "", false
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func validImageMetadataScalar(value json.RawMessage) bool {
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return false
	}
	switch decoded.(type) {
	case string, float64, bool:
		return true
	default:
		return false
	}
}

func loadHTMLVulnerabilitySummary(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlVulnerabilitySummary, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT severity, COUNT(*),
       COALESCE(SUM(CASE WHEN NULLIF(TRIM(fixed_version), '') IS NULL
                         THEN 0 ELSE 1 END), 0)
FROM vulnerability_findings
WHERE task_id = ?
GROUP BY severity
ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')`,
		taskID,
	)
	if err != nil {
		return nil, fmt.Errorf("summarize HTML vulnerabilities: %w", err)
	}
	defer rows.Close()
	values := []htmlVulnerabilitySummary{}
	for rows.Next() {
		var value htmlVulnerabilitySummary
		if err := rows.Scan(&value.Severity, &value.Count, &value.Fixable); err != nil {
			return nil, fmt.Errorf("scan HTML vulnerability summary: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate HTML vulnerability summary: %w", err)
	}
	return values, nil
}

func loadHTMLVulnerabilities(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlVulnerabilityFinding, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, analyzer_run_id, trivy_database_bundle_id, image_logical_path,
       image_platform, vulnerability_id, severity, package_name,
       installed_version, fixed_version, title, description_summary,
       evidence_json, references_json, created_at
FROM vulnerability_findings
WHERE task_id = ?
ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'),
         id ASC
LIMIT ?`, taskID, htmlVulnerabilityDetailLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML vulnerabilities: %w", err)
	}
	defer rows.Close()
	values := make([]htmlVulnerabilityFinding, 0, htmlVulnerabilityDetailLimit)
	truncated := false
	for rows.Next() {
		var snapshot vulnerabilitySnapshot
		var id uint64
		var analyzerRunID sql.NullString
		var databaseID sql.NullString
		var imagePlatform sql.NullString
		var installedVersion sql.NullString
		var fixedVersion sql.NullString
		var title sql.NullString
		var description sql.NullString
		var evidence []byte
		var references []byte
		if err := rows.Scan(
			&id, &analyzerRunID, &databaseID, &snapshot.ImageLogicalPath,
			&imagePlatform, &snapshot.VulnerabilityID, &snapshot.Severity,
			&snapshot.PackageName, &installedVersion, &fixedVersion, &title,
			&description, &evidence, &references, &snapshot.CreatedAt,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML vulnerability: %w", err)
		}
		if len(values) == htmlVulnerabilityDetailLimit {
			truncated = true
			break
		}
		snapshot.ID = fmt.Sprint(id)
		snapshot.AnalyzerRunID = nullableString(analyzerRunID)
		snapshot.DatabaseBundleID = nullableString(databaseID)
		snapshot.ImagePlatform = nullableString(imagePlatform)
		snapshot.InstalledVersion = nullableString(installedVersion)
		snapshot.FixedVersion = nullableString(fixedVersion)
		snapshot.Title = nullableString(title)
		snapshot.DescriptionSummary = nullableString(description)
		snapshot.Evidence = safeRawJSON(evidence, `null`)
		snapshot.References = safeRawJSON(references, `null`)
		values = append(values, newHTMLVulnerabilityFinding(snapshot))
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML vulnerabilities: %w", err)
	}
	return values, truncated, nil
}

func newHTMLVulnerabilityFinding(snapshot vulnerabilitySnapshot) htmlVulnerabilityFinding {
	value := htmlVulnerabilityFinding{vulnerabilitySnapshot: snapshot}
	var evidence persistedVulnerabilityEvidence
	if json.Unmarshal(snapshot.Evidence, &evidence) == nil {
		value.Evidence.Target = readableHTMLVulnerabilityTarget(evidence.Target)
		value.Evidence.PackagePath = strings.TrimSpace(evidence.PackagePath)
		value.Evidence.Class = strings.TrimSpace(evidence.Class)
		value.Evidence.Type = strings.TrimSpace(evidence.Type)
		value.Evidence.ImagePlatform = strings.TrimSpace(evidence.ImagePlatform)
		if value.Evidence.ImagePlatform == "" && snapshot.ImagePlatform != nil {
			value.Evidence.ImagePlatform = *snapshot.ImagePlatform
		}
		value.Evidence.ManifestDigest = strings.TrimSpace(evidence.ManifestDigest)
		value.Evidence.ImageReferences = boundedHTMLStrings(
			evidence.ImageReferences,
			32,
			512,
		)
		value.Evidence.DataSourceID = strings.TrimSpace(evidence.DataSource.ID)
		value.Evidence.DataSourceName = strings.TrimSpace(evidence.DataSource.Name)
		value.Evidence.DataSourceURL = safeHTMLVulnerabilityURL(evidence.DataSource.URL)
		value.Evidence.HasDataSource = value.Evidence.DataSourceID != "" ||
			value.Evidence.DataSourceName != "" ||
			value.Evidence.DataSourceURL != ""
	}
	value.Evidence.HasValues = value.Evidence.Target != "" ||
		value.Evidence.PackagePath != "" || value.Evidence.Class != "" ||
		value.Evidence.Type != "" || value.Evidence.ImagePlatform != "" ||
		value.Evidence.ManifestDigest != "" ||
		len(value.Evidence.ImageReferences) != 0 || value.Evidence.HasDataSource
	value.References = htmlVulnerabilityReferences(snapshot.References)
	return value
}

func readableHTMLVulnerabilityTarget(value string) string {
	value = strings.TrimSpace(value)
	if opening := strings.LastIndex(value, " ("); opening >= 0 &&
		strings.HasSuffix(value, ")") {
		if display := strings.TrimSpace(value[opening+2 : len(value)-1]); display != "" {
			return display
		}
	}
	if strings.Contains(value, "/oci-layout@sha256:") {
		return "container image"
	}
	return value
}

func boundedHTMLStrings(values []string, maximumItems int, maximumBytes int) []string {
	result := make([]string, 0, min(len(values), maximumItems))
	seen := make(map[string]struct{}, cap(result))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maximumBytes || containsControl(value) {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) == maximumItems {
			break
		}
	}
	return result
}

func htmlVulnerabilityReferences(raw json.RawMessage) []htmlVulnerabilityReference {
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		return nil
	}
	urls := boundedHTMLStrings(values, 20, 2048)
	result := make([]htmlVulnerabilityReference, 0, len(urls))
	for _, candidate := range urls {
		if safe := safeHTMLVulnerabilityURL(candidate); safe != "" {
			result = append(result, htmlVulnerabilityReference{URL: safe})
		}
	}
	return result
}

func safeHTMLVulnerabilityURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 2048 || containsControl(value) {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return parsed.String()
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func loadHTMLAnalyzers(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]analyzerRunSnapshot, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, file_node_id, analyzer_name, analyzer_version, status,
       error_code, error_message, created_at
FROM analyzer_runs
WHERE task_id = ?
ORDER BY created_at ASC, id ASC
LIMIT ?`, taskID, htmlAnalyzerRunLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML analyzers: %w", err)
	}
	defer rows.Close()
	values := make([]analyzerRunSnapshot, 0, htmlAnalyzerRunLimit)
	truncated := false
	for rows.Next() {
		var value analyzerRunSnapshot
		var fileNodeID sql.Null[uint64]
		var errorCode sql.NullString
		var errorMessage sql.NullString
		if err := rows.Scan(
			&value.ID, &fileNodeID, &value.AnalyzerName,
			&value.AnalyzerVersion, &value.Status, &errorCode, &errorMessage,
			&value.CreatedAt,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML analyzer: %w", err)
		}
		if len(values) == htmlAnalyzerRunLimit {
			truncated = true
			break
		}
		value.FileNodeID = nullableUint64String(fileNodeID)
		value.ErrorCode = nullableString(errorCode)
		value.ErrorMessage = nullableString(errorMessage)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML analyzers: %w", err)
	}
	return values, truncated, nil
}

func loadHTMLDecompilations(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlDecompileResult, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id, file_node_id, symbol_key, language, engine_name, engine_version,
       status, size_bytes, diagnostics_json
FROM decompile_results
WHERE task_id = ? AND deleted_at IS NULL
ORDER BY created_at ASC, id ASC
LIMIT ?`, taskID, htmlDecompileResultLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML decompile results: %w", err)
	}
	defer rows.Close()

	values := make([]htmlDecompileResult, 0, htmlDecompileResultLimit)
	truncated := false
	for rows.Next() {
		var value htmlDecompileResult
		var fileNodeID uint64
		var sizeBytes sql.Null[uint64]
		var diagnostics []byte
		if err := rows.Scan(
			&value.ID, &fileNodeID, &value.SymbolKey, &value.Language,
			&value.EngineName, &value.EngineVersion, &value.Status,
			&sizeBytes, &diagnostics,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML decompile result: %w", err)
		}
		if len(values) == htmlDecompileResultLimit {
			truncated = true
			break
		}
		value.FileNodeID = strconv.FormatUint(fileNodeID, 10)
		value.SymbolKind = "unknown"
		value.DisplayName = value.SymbolKey
		if value.DisplayName == "" {
			value.DisplayName = "unnamed symbol"
		}
		if sizeBytes.Valid {
			size := sizeBytes.V
			value.SizeBytes = &size
		}
		applyHTMLDecompileDiagnostics(&value, diagnostics)
		value.SymbolKey = safeHTMLDisplayText(value.SymbolKey)
		value.DisplayName = safeHTMLDisplayText(value.DisplayName)
		value.Location = safeHTMLDisplayText(value.Location)
		value.Signature = safeHTMLDisplayText(value.Signature)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML decompile results: %w", err)
	}
	return values, truncated, nil
}

func applyHTMLDecompileDiagnostics(
	value *htmlDecompileResult,
	raw []byte,
) {
	if len(raw) == 0 || !json.Valid(raw) {
		return
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return
	}
	var nested map[string]json.RawMessage
	if symbol, found := object["symbol"]; found {
		_ = json.Unmarshal(symbol, &nested)
	}
	value.SymbolKind = normalizeHTMLSymbolKind(reportDiagnosticString(
		object, nested, value.SymbolKind, "symbol_kind", "kind",
	))
	value.DisplayName = reportDiagnosticString(
		object, nested, value.DisplayName, "display_name", "name",
	)
	value.Location = reportDiagnosticString(
		object, nested, "", "location",
	)
	value.Signature = reportDiagnosticString(
		object, nested, "", "signature",
	)
}

func reportDiagnosticString(
	object map[string]json.RawMessage,
	nested map[string]json.RawMessage,
	fallback string,
	keys ...string,
) string {
	for _, source := range []map[string]json.RawMessage{object, nested} {
		for _, key := range keys {
			var value string
			raw, found := source[key]
			if found && json.Unmarshal(raw, &value) == nil &&
				value != "" && len(value) <= 8192 {
				return value
			}
		}
	}
	return fallback
}

func normalizeHTMLSymbolKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "function", "class", "method", "module":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

func safeHTMLDisplayText(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) ||
			unicode.In(character, unicode.Cf) ||
			character == '\u2028' || character == '\u2029' {
			return '\ufffd'
		}
		return character
	}, value)
}

func loadHTMLDatabases(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]databaseBundleSnapshot, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
	SELECT database_bundle.id, database_bundle.version,
	       database_bundle.generated_at, database_bundle.content_sha256,
	       database_bundle.trivy_db_version,
	       database_bundle.trivy_java_db_version,
	       database_bundle.manifest_json, database_bundle.registered_at
	FROM trivy_database_bundles database_bundle
	WHERE EXISTS (
	    SELECT 1 FROM vulnerability_findings finding
	    WHERE finding.task_id = ?
	      AND finding.trivy_database_bundle_id = database_bundle.id
)
OR EXISTS (
    SELECT 1
    FROM analyzer_runs analyzer
    WHERE analyzer.task_id = ?
      AND analyzer.analyzer_name = 'trivy'
	      AND JSON_UNQUOTE(JSON_EXTRACT(
	          analyzer.parameters_json, '$.database_bundle.id'
	      )) = database_bundle.id
	)
	ORDER BY database_bundle.generated_at DESC, database_bundle.id ASC
	LIMIT ?`, taskID, taskID, htmlDatabaseVersionLimit+1)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML Trivy database bundles: %w", err)
	}
	defer rows.Close()
	values := make([]databaseBundleSnapshot, 0, htmlDatabaseVersionLimit)
	truncated := false
	for rows.Next() {
		var value databaseBundleSnapshot
		var manifest []byte
		if err := rows.Scan(
			&value.ID, &value.Version, &value.GeneratedAt,
			&value.ContentSHA256, &value.TrivyDBVersion,
			&value.TrivyJavaDBVersion, &manifest, &value.RegisteredAt,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML Trivy database bundle: %w", err)
		}
		if len(values) == htmlDatabaseVersionLimit {
			truncated = true
			break
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML Trivy database bundles: %w", err)
	}
	return values, truncated, nil
}

func loadHTMLIssues(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) ([]htmlIssue, bool, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT category, source, logical_path, code, message
FROM (
    SELECT 'warning' AS category, 'task_event' AS source, NULL AS logical_path,
           'task_warning' AS code,
           COALESCE(NULLIF(message, ''), 'Task warning.') AS message,
           created_at, CAST(id AS CHAR) AS stable_id
    FROM task_events
    WHERE task_id = ? AND severity = 'warning'
    UNION ALL
    SELECT 'unsupported', 'file_node', logical_path,
           COALESCE(NULLIF(error_code, ''), 'file_unsupported'),
           COALESCE(NULLIF(error_message, ''), 'File format is unsupported.'),
           created_at, CAST(id AS CHAR)
    FROM file_nodes
    WHERE task_id = ? AND extraction_status = 'unsupported'
    UNION ALL
    SELECT 'unsupported', 'decompile_result', NULL,
           'decompile_unsupported',
           'Decompilation is unsupported for this result.',
           created_at, id
    FROM decompile_results
    WHERE task_id = ? AND status = 'unsupported' AND deleted_at IS NULL
    UNION ALL
    SELECT 'failed', 'file_node', logical_path,
           COALESCE(NULLIF(error_code, ''),
                    CASE WHEN extraction_status = 'limit_reached'
                         THEN 'extraction_limit_reached' ELSE 'file_failed' END),
           COALESCE(NULLIF(error_message, ''),
                    CASE WHEN extraction_status = 'limit_reached'
                         THEN 'Extraction stopped at a configured limit.'
                         ELSE 'File processing failed.' END),
           created_at, CAST(id AS CHAR)
    FROM file_nodes
    WHERE task_id = ? AND extraction_status IN ('failed', 'limit_reached')
    UNION ALL
    SELECT 'failed', 'analyzer_run', NULL,
           COALESCE(NULLIF(error_code, ''), 'analyzer_failed'),
           COALESCE(NULLIF(error_message, ''), 'Analyzer execution failed.'),
           created_at, id
    FROM analyzer_runs
    WHERE task_id = ? AND status IN ('failed', 'timed_out')
    UNION ALL
    SELECT 'failed', 'decompile_result', NULL,
           CASE WHEN status = 'cancelled'
                THEN 'decompile_cancelled' ELSE 'decompile_failed' END,
           CASE WHEN status = 'cancelled'
                THEN 'Decompilation was cancelled.'
                ELSE 'Decompilation failed.' END,
           created_at, id
    FROM decompile_results
    WHERE task_id = ? AND status IN ('failed', 'cancelled')
      AND deleted_at IS NULL
    UNION ALL
    SELECT 'failed', 'task', NULL,
           COALESCE(NULLIF(error_code, ''), 'task_failed'),
           COALESCE(NULLIF(error_message, ''), 'Task execution failed.'),
           created_at, id
    FROM tasks
    WHERE id = ? AND status = 'FAILED'
) diagnostics
ORDER BY created_at ASC, stable_id ASC
LIMIT ?`,
		taskID, taskID, taskID, taskID, taskID, taskID, taskID,
		htmlDiagnosticLimit+1,
	)
	if err != nil {
		return nil, false, fmt.Errorf("query HTML diagnostics: %w", err)
	}
	defer rows.Close()
	values := make([]htmlIssue, 0, htmlDiagnosticLimit)
	truncated := false
	for rows.Next() {
		var value htmlIssue
		var source sql.NullString
		var logicalPath sql.NullString
		if err := rows.Scan(
			&value.Category, &source, &logicalPath,
			&value.Code, &value.Message,
		); err != nil {
			return nil, false, fmt.Errorf("scan HTML diagnostic: %w", err)
		}
		if len(values) == htmlDiagnosticLimit {
			truncated = true
			break
		}
		value.Source = nullableString(source)
		value.LogicalPath = nullableString(logicalPath)
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate HTML diagnostics: %w", err)
	}
	return values, truncated, nil
}
