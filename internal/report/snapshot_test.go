package report

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestWriteJSONSnapshotStreamsCompleteSanitizedSnapshot(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	completedAt := reportTestTime.Add(time.Minute)
	sampleExpiresAt := reportTestTime.Add(30 * 24 * time.Hour)
	limits := `{"max_upload_bytes":2147483648,"max_expanded_bytes":10737418240,` +
		`"max_archive_ratio":50,"max_depth":6,"max_file_nodes":20000,` +
		`"max_nested_images":3}`

	mock.ExpectBegin()
	mock.ExpectQuery(
		"(?s)SELECT task.id, task.name, task.status.*" +
			"JOIN blobs input_blob ON input_blob.id = task.blob_id",
	).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "status", "stage", "progress_basis_points",
			"risk_level", "root_format", "error_code", "error_message",
			"created_at", "completed_at", "sample_expires_at",
			"sample_deleted_at", "limits_snapshot", "display_name",
			"size_bytes", "sha256",
		}).AddRow(
			testTaskID, "task <unsafe>", "PARTIAL_SUCCEEDED", "REPORTING",
			10000, "HIGH", "zip", nil, nil, reportTestTime, completedAt,
			sampleExpiresAt, reportTestTime, []byte(limits), "sample.zip",
			1234, strings.Repeat("1", 64),
		))
	mock.ExpectQuery("SELECT attempt_number, status, statistics").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"attempt_number", "status", "statistics", "error_code",
			"error_message", "started_at", "completed_at",
		}).AddRow(
			2, "partial",
			[]byte(`{"counts":{"storage_key":"hidden","files":1}}`),
			nil, nil, reportTestTime, completedAt,
		))
	mock.ExpectQuery("SELECT id, parent_id, logical_path").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "parent_id", "logical_path", "display_name", "node_type",
			"depth", "format", "mime_type", "architecture", "size_bytes",
			"sha256", "extraction_status", "metadata_json", "error_code",
			"error_message", "created_at",
		}).AddRow(
			42, nil, "/sample.zip", "sample.zip", "file", 0, "zip",
			"application/zip", nil, 1234, strings.Repeat("2", 64),
			"extracted",
			[]byte(`{"nested":{"password":"hidden","safe":"value"}}`),
			nil, nil, reportTestTime,
		).AddRow(
			43, 42, "/sample.zip/skipped.bin", "skipped.bin", "file", 1,
			"unknown", "application/octet-stream", nil, 64,
			strings.Repeat("5", 64), "skipped", []byte(`{"reason":"policy"}`),
			"file_skipped_by_policy", "File was skipped by policy.",
			reportTestTime,
		))
	mock.ExpectQuery("SELECT id, task_attempt_id, job_id").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_attempt_id", "job_id", "file_node_id",
			"analyzer_name", "analyzer_version", "parameters_json", "status",
			"exit_code", "error_code", "error_message", "started_at",
			"completed_at", "created_at",
		}).AddRow(
			"323e4567-e89b-42d3-a456-426614174002", 7,
			"423e4567-e89b-42d3-a456-426614174003", 42, "trivy", "0.60",
			[]byte(`{"apiKey":"hidden","offline":true}`), "succeeded", 0,
			nil, nil, reportTestTime, completedAt, reportTestTime,
		))
	mock.ExpectQuery("SELECT id, file_node_id, analyzer_run_id, symbol_key").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "file_node_id", "analyzer_run_id", "symbol_key",
			"language", "engine_name", "engine_version", "status",
			"content_sha256", "size_bytes", "diagnostics_json", "created_at",
			"completed_at",
		}).AddRow(
			"523e4567-e89b-42d3-a456-426614174004", 42, nil,
			"FUN_00401000", "c", "ghidra", "11.4", "complete",
			strings.Repeat("3", 64), 256,
			[]byte(`{"sourceContent":"hidden","symbol":{"name":"safe"}}`),
			reportTestTime, completedAt,
		))
	mock.ExpectQuery("SELECT id, analyzer_run_id, trivy_database_bundle_id").
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "analyzer_run_id", "trivy_database_bundle_id",
			"image_logical_path", "image_platform", "vulnerability_id",
			"severity", "package_name", "installed_version", "fixed_version",
			"title", "description_summary", "evidence_json",
			"references_json", "created_at",
		}).AddRow(
			99, "323e4567-e89b-42d3-a456-426614174002",
			"623e4567-e89b-42d3-a456-426614174005", "/image",
			"linux/amd64", "CVE-2026-0001", "HIGH", "openssl", "1.0",
			"1.1", "<script>title</script>", "description",
			[]byte(`{"privateKey":"hidden","location":"/usr/lib"}`),
			[]byte(`["https://offline.invalid/CVE-2026-0001"]`),
			reportTestTime,
		))
	mock.ExpectQuery(
		`(?s)SELECT database_bundle\.id, database_bundle\.version.*`+
			`FROM trivy_database_bundles`,
	).
		WithArgs(testTaskID, testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "version", "generated_at", "content_sha256",
			"trivy_db_version", "trivy_java_db_version", "manifest_json",
			"registered_at",
		}).AddRow(
			"623e4567-e89b-42d3-a456-426614174005", "2026-07-29",
			reportTestTime, strings.Repeat("4", 64), "2026-07-29",
			"2026-07-29", []byte(`{"schema_version":1}`), reportTestTime,
		))
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT 'task_event', NULL, 'task_warning',`)).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source", "logical_path", "code", "message",
		}).AddRow("task_event", nil, "task_warning", "warning"))
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT 'file_node', logical_path,`)).
		WithArgs(testTaskID, testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source", "logical_path", "code", "message",
		}).AddRow(
			"file_node", "/unsupported", "file_unsupported", "unsupported",
		))
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT 'file_node', logical_path,`)).
		WithArgs(testTaskID, testTaskID, testTaskID, testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"source", "logical_path", "code", "message",
		}).AddRow("analyzer_run", nil, "analyzer_failed", "failed"))
	mock.ExpectCommit()

	var output bytes.Buffer
	err := repository.WriteJSONSnapshot(
		context.Background(),
		SnapshotRequest{
			TaskID: testTaskID, ReportID: testReportID,
			GeneratedAt: reportTestTime,
		},
		&output,
	)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(output.Bytes(), &value); err != nil {
		t.Fatalf("decode generated JSON: %v\n%s", err, output.Bytes())
	}
	if value["schemaVersion"] != SchemaVersion ||
		value["reportId"] != testReportID {
		t.Fatalf("report identity = %#v", value)
	}
	task, ok := value["task"].(map[string]any)
	if !ok || task["sampleDeletedAt"] == nil ||
		task["sampleExpiresAt"] == nil {
		t.Fatalf("task retention metadata = %#v", value["task"])
	}
	limitsValue, ok := value["limitsSnapshot"].(map[string]any)
	if !ok || limitsValue["maxUploadBytes"] != float64(2147483648) {
		t.Fatalf("limits snapshot = %#v", value["limitsSnapshot"])
	}
	if _, exists := limitsValue["max_upload_bytes"]; exists {
		t.Fatalf("limits retain snake_case: %#v", limitsValue)
	}
	execution, ok := value["execution"].(map[string]any)
	if !ok || len(execution) != 4 || execution["status"] != "partial" {
		t.Fatalf("execution snapshot = %#v", value["execution"])
	}
	files := value["fileNodes"].([]any)
	file := files[0].(map[string]any)
	if file["id"] != "42" || file["path"] != "/sample.zip" ||
		file["name"] != "sample.zip" || file["type"] != "file" {
		t.Fatalf("file node = %#v", file)
	}
	skipped := files[1].(map[string]any)
	if skipped["extractionStatus"] != "skipped" ||
		skipped["errorCode"] != "file_skipped_by_policy" ||
		skipped["errorMessage"] != "File was skipped by policy." {
		t.Fatalf("skipped file reason = %#v", skipped)
	}
	databases := value["trivyDatabaseBundles"].([]any)
	database := databases[0].(map[string]any)
	if database["version"] != "2026-07-29" ||
		database["trivyJavaDbVersion"] != "2026-07-29" {
		t.Fatalf("Trivy database bundle = %#v", database)
	}
	for _, name := range []string{
		"fileNodes", "analyzerRuns", "decompileResults",
		"vulnerabilityFindings", "trivyDatabaseBundles",
		"warnings", "unsupported", "failed",
	} {
		if _, ok := value[name].([]any); !ok {
			t.Errorf("%s is not an array: %#v", name, value[name])
		}
	}
	encoded := output.String()
	for _, forbidden := range []string{
		"storage_key", "storagePath", "password", "apiKey",
		"sourceContent", "privateKey", "hidden", "cacheKey",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Errorf("generated JSON contains forbidden %q: %s", forbidden, encoded)
		}
	}
}

func TestHTMLVulnerabilityDetailsAreBounded(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	rows := sqlmock.NewRows([]string{
		"id", "analyzer_run_id", "trivy_database_bundle_id",
		"image_logical_path", "image_platform", "vulnerability_id",
		"severity", "package_name", "installed_version", "fixed_version",
		"title", "description_summary", "evidence_json",
		"references_json", "created_at",
	})
	for index := 0; index <= htmlVulnerabilityDetailLimit; index++ {
		rows.AddRow(
			index+1, nil, nil, "/image", "linux/amd64",
			fmt.Sprintf("CVE-2026-%04d", index), "LOW", "package",
			"1.0", nil, nil, nil, []byte(`null`), []byte(`[]`),
			reportTestTime,
		)
	}
	mock.ExpectBegin()
	mock.ExpectQuery(
		"(?s)SELECT id, analyzer_run_id.*FROM vulnerability_findings.*LIMIT \\?",
	).WithArgs(
		testTaskID, htmlVulnerabilityDetailLimit+1,
	).WillReturnRows(rows)
	mock.ExpectRollback()

	transaction, err := repository.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	values, truncated, err := loadHTMLVulnerabilities(
		context.Background(), transaction, testTaskID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !truncated || len(values) != htmlVulnerabilityDetailLimit {
		t.Fatalf(
			"HTML vulnerability details = %d, truncated=%v",
			len(values), truncated,
		)
	}
}

func TestHTMLDecompileIndexUsesFunctionMetadataWithoutSourceBodies(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	rows := sqlmock.NewRows([]string{
		"id", "file_node_id", "symbol_key", "language", "engine_name",
		"engine_version", "status", "size_bytes", "diagnostics_json",
	}).AddRow(
		testReportID, uint64(42), "FUN_140001000", "c", "ghidra", "12.1.2",
		"complete", uint64(128), []byte(`{
			"symbol_kind":"function",
			"display_name":"verify_header",
			"location":"0x140001000",
			"signature":"int verify_header(void)",
			"decompiled_source":"must-not-render"
		}`),
	)
	mock.ExpectBegin()
	mock.ExpectQuery(
		"(?s)SELECT id, file_node_id, symbol_key.*FROM decompile_results.*LIMIT \\?",
	).WithArgs(
		testTaskID, htmlDecompileResultLimit+1,
	).WillReturnRows(rows)
	mock.ExpectRollback()

	transaction, err := repository.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	values, truncated, err := loadHTMLDecompilations(
		context.Background(), transaction, testTaskID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	if truncated || len(values) != 1 {
		t.Fatalf("HTML decompile index = %d, truncated=%v", len(values), truncated)
	}
	value := values[0]
	if value.FileNodeID != "42" || value.SymbolKind != "function" ||
		value.DisplayName != "verify_header" || value.Location != "0x140001000" ||
		value.Signature != "int verify_header(void)" || value.SizeBytes == nil ||
		*value.SizeBytes != 128 {
		t.Fatalf("HTML decompile metadata = %#v", value)
	}
	var rendered bytes.Buffer
	if err := reportHTML.Execute(&rendered, htmlReportData{
		SchemaVersion:  SchemaVersion,
		Task:           taskSnapshot{ID: testTaskID},
		Decompilations: values,
	}); err != nil {
		t.Fatal(err)
	}
	output := rendered.String()
	for _, expected := range []string{
		"反编译函数索引", "verify_header", "0x140001000",
		`data-report-decompile-result-id="` + testReportID + `"`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("HTML decompile index omits %q", expected)
		}
	}
	if strings.Contains(output, "must-not-render") ||
		strings.Contains(output, "decompiled_source") {
		t.Fatalf("HTML decompile index leaked source body: %s", output)
	}
}

func TestSafeHTMLDisplayTextNeutralizesControlAndDirectionOverrides(t *testing.T) {
	value := safeHTMLDisplayText("main\x00\n\u202efile\u2028")
	if value != "main\ufffd\ufffd\ufffdfile\ufffd" {
		t.Fatalf("safeHTMLDisplayText() = %q", value)
	}
}

func TestHTMLSummaryUsesPersistedFileAndImageAggregates(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()

	mock.ExpectBegin()
	mock.ExpectQuery(
		"(?s)SELECT COALESCE.*FROM file_nodes.*node_type = 'file'.*GROUP BY",
	).WithArgs(testTaskID).WillReturnRows(
		sqlmock.NewRows([]string{"format", "count", "size_bytes"}).
			AddRow("elf64", 2, 4096).
			AddRow("gpt-img", 1, 8192),
	)
	mock.ExpectQuery(
		"(?s)SELECT logical_path, format, metadata_json.*JSON_TYPE.*LIMIT 128",
	).WithArgs(testTaskID).WillReturnRows(
		sqlmock.NewRows([]string{
			"logical_path", "format", "metadata_json",
		}).AddRow(
			"/fixture/disk.img",
			"gpt-img",
			[]byte(`{"partition_table":"gpt","partition_slots":128,`+
				`"partition_stride":128,"sector_size":512,`+
				`"storage_key":"must-not-render"}`),
		),
	)
	mock.ExpectRollback()

	transaction, err := repository.db.BeginTx(
		context.Background(), &sql.TxOptions{ReadOnly: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	fileTypes, err := loadHTMLFileTypes(
		context.Background(), transaction, testTaskID,
	)
	if err != nil {
		t.Fatal(err)
	}
	imageStructures, err := loadHTMLImageStructures(
		context.Background(), transaction, testTaskID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}

	data := htmlReportData{
		SchemaVersion:         SchemaVersion,
		ReportID:              testReportID,
		GeneratedAt:           reportTestTime.Format(time.RFC3339),
		Task:                  taskSnapshot{ID: testTaskID, Name: "fixture <script>probe</script>"},
		SampleRelation:        "expired",
		SampleRelationMessage: "sample expired",
		FileCount:             3,
		FileTypes:             fileTypes,
		ImageStructures:       imageStructures,
	}
	var rendered bytes.Buffer
	if err := reportHTML.Execute(&rendered, data); err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	for _, expected := range []string{
		"按持久化文件节点统计，共 3 个文件",
		"<td>elf64</td><td>2</td><td>4096</td>",
		"<td>gpt-img</td><td>1</td><td>8192</td>",
		"/fixture/disk.img",
		"&#34;partition_slots&#34;:128",
		`data-report-contract="binaryscan-report/v1"`,
		`data-task-id="` + testTaskID + `"`,
		`data-sample-relation="expired"`,
		`data-report-file-format="gpt-img" data-count="1" data-size-bytes="8192"`,
		`data-report-image-path="/fixture/disk.img" data-format="gpt-img"`,
		"fixture &lt;script&gt;probe&lt;/script&gt;",
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("HTML does not contain %q", expected)
		}
	}
	if strings.Contains(html, "must-not-render") ||
		strings.Contains(html, "storage_key") ||
		strings.Contains(html, "<script>") {
		t.Fatalf("HTML leaked non-structural metadata: %s", html)
	}
}

func TestImageStructureMetadataRequiresPersistedAllowlistedFields(t *testing.T) {
	summary, ok := imageStructureMetadata(
		"ext4",
		[]byte(`{"block_size":4096,"blocks":1024,"inodes":128,`+
			`"password":"hidden","nested":{"untrusted":true}}`),
	)
	if !ok ||
		!strings.Contains(summary, `"block_size":4096`) ||
		strings.Contains(summary, "password") ||
		strings.Contains(summary, "nested") {
		t.Fatalf("image structure summary = %q, ok=%v", summary, ok)
	}
	if summary, ok := imageStructureMetadata(
		"iso9660", []byte(`{"volume":"unverified"}`),
	); ok || summary != "" {
		t.Fatalf("unrecognized ISO metadata = %q, ok=%v", summary, ok)
	}
}

func TestHTMLSampleRelationDistinguishesExpiredFromRetained(t *testing.T) {
	generatedAt := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	expiredAt := generatedAt.Add(-time.Second)
	retainedUntil := generatedAt.Add(time.Second)
	deletedAt := generatedAt.Add(-time.Minute)

	tests := []struct {
		name     string
		task     taskSnapshot
		relation string
		message  string
	}{
		{
			name: "expired",
			task: taskSnapshot{
				SampleExpiresAt: expiredAt,
			},
			relation: "expired",
			message:  "样本保留期已于 " + expiredAt.Format(time.RFC3339Nano) + " 到期",
		},
		{
			name: "retained",
			task: taskSnapshot{
				SampleExpiresAt: retainedUntil,
			},
			relation: "retained",
			message:  "仍保留，计划保留至 " + retainedUntil.Format(time.RFC3339Nano),
		},
		{
			name: "deleted takes precedence",
			task: taskSnapshot{
				SampleExpiresAt: retainedUntil,
				SampleDeletedAt: &deletedAt,
			},
			relation: "deleted",
			message:  "该任务已不再保留可复用样本（" + deletedAt.Format(time.RFC3339Nano) + "）",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relation := sampleRelationAt(test.task, generatedAt)
			if relation != test.relation {
				t.Fatalf("sample relation = %q, want %q", relation, test.relation)
			}
			if message := sampleRelationMessage(test.task, relation); message != test.message {
				t.Fatalf("sample relation message = %q, want %q", message, test.message)
			}
		})
	}
}
