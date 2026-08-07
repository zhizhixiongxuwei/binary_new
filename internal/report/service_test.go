package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testTaskID   = "123e4567-e89b-42d3-a456-426614174000"
	testReportID = "223e4567-e89b-42d3-a456-426614174001"
)

type repositoryStub struct {
	list              List
	listErr           error
	claim             Report
	claimGenerate     bool
	claimErr          error
	claimCalls        int
	jsonWriter        func(context.Context, SnapshotRequest, io.Writer) error
	htmlWriter        func(context.Context, SnapshotRequest, io.Writer) error
	authorizeErr      error
	authorizeCalls    int
	complete          Report
	completeErr       error
	completedArtifact ArtifactMetadata
	failCalls         int
	failedCode        string
	failedMessage     string
	download          DownloadDescriptor
	downloadErr       error
}

func (s *repositoryStub) List(context.Context, string) (List, error) {
	return s.list, s.listErr
}

func (s *repositoryStub) Claim(
	_ context.Context,
	claim Claim,
) (Report, bool, error) {
	s.claimCalls++
	if s.claim.ID == "" {
		s.claim = Report{
			ID: claim.ReportID, TaskID: claim.TaskID, Format: claim.Format,
			SchemaVersion: claim.SchemaVersion, Status: "generating",
			CreatedAt:       claim.CreatedAt,
			GenerationOwner: claim.LeaseOwner,
			GenerationFence: 1,
		}
	}
	return s.claim, s.claimGenerate, s.claimErr
}

func (s *repositoryStub) WriteJSONSnapshot(
	ctx context.Context,
	request SnapshotRequest,
	writer io.Writer,
) error {
	if s.jsonWriter == nil {
		return nil
	}
	return s.jsonWriter(ctx, request, writer)
}

func (s *repositoryStub) WriteHTMLSnapshot(
	ctx context.Context,
	request SnapshotRequest,
	writer io.Writer,
) error {
	if s.htmlWriter == nil {
		return nil
	}
	return s.htmlWriter(ctx, request, writer)
}

func (s *repositoryStub) AuthorizePublish(
	context.Context,
	string,
	string,
	string,
	uint64,
) error {
	s.authorizeCalls++
	return s.authorizeErr
}

func (s *repositoryStub) Renew(
	context.Context,
	string,
	string,
	string,
	uint64,
	time.Duration,
) (bool, error) {
	return true, nil
}

func (s *repositoryStub) Complete(
	_ context.Context,
	_ string,
	_ string,
	_ string,
	_ uint64,
	artifact ArtifactMetadata,
) (Report, error) {
	s.completedArtifact = artifact
	if s.complete.ID == "" {
		digest := artifact.SHA256
		size := artifact.SizeBytes
		completedAt := artifact.CompletedAt
		s.complete = s.claim
		s.complete.Status = "complete"
		s.complete.SHA256 = &digest
		s.complete.SizeBytes = &size
		s.complete.CompletedAt = &completedAt
	}
	return s.complete, s.completeErr
}

func (s *repositoryStub) Fail(
	_ context.Context,
	_ string,
	_ string,
	_ string,
	_ uint64,
	code string,
	message string,
	_ time.Time,
) error {
	s.failCalls++
	s.failedCode = code
	s.failedMessage = message
	return nil
}

func (s *repositoryStub) Download(
	context.Context,
	string,
	string,
) (DownloadDescriptor, error) {
	return s.download, s.downloadErr
}

func newTestService(t *testing.T, repository *repositoryStub) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	service.newID = func() (string, error) { return testReportID, nil }
	service.now = func() time.Time {
		return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	}
	return service, root
}

func TestGenerateStreamsHashesAndAtomicallyPublishesReport(t *testing.T) {
	payload := `{"schemaVersion":"1.1.0","fileNodes":[]}` + "\n"
	repository := &repositoryStub{
		claimGenerate: true,
		jsonWriter: func(
			_ context.Context,
			request SnapshotRequest,
			writer io.Writer,
		) error {
			if request.TaskID != testTaskID ||
				request.ReportID != testReportID {
				t.Fatalf("snapshot request = %#v", request)
			}
			_, err := io.WriteString(writer, payload)
			return err
		},
	}
	service, root := newTestService(t, repository)

	value, created, err := service.Generate(
		context.Background(), testTaskID, FormatJSON, "report-request-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created || value.Status != "complete" {
		t.Fatalf("generated report = %#v, created=%v", value, created)
	}
	expectedDigest := sha256.Sum256([]byte(payload))
	if repository.completedArtifact.SHA256 !=
		hex.EncodeToString(expectedDigest[:]) ||
		repository.completedArtifact.SizeBytes != uint64(len(payload)) ||
		repository.completedArtifact.StorageKey !=
			"reports/"+testTaskID+"/"+testReportID+".json" {
		t.Fatalf("completed artifact = %#v", repository.completedArtifact)
	}
	storedPath := filepath.Join(root, filepath.FromSlash(
		repository.completedArtifact.StorageKey,
	))
	stored, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != payload {
		t.Fatalf("stored report = %q", stored)
	}
	info, err := os.Stat(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("stored report mode = %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(storedPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != testReportID+".json" {
		t.Fatalf("report directory entries = %#v", entries)
	}
	if repository.authorizeCalls != 1 {
		t.Fatalf(
			"report publish authorization calls = %d, want 1",
			repository.authorizeCalls,
		)
	}
}

func TestGenerateReplaysCompleteReportWithoutWriting(t *testing.T) {
	repository := &repositoryStub{
		claim: Report{
			ID: testReportID, TaskID: testTaskID, Format: FormatJSON,
			SchemaVersion: SchemaVersion, Status: "complete",
		},
		claimGenerate: false,
		jsonWriter: func(context.Context, SnapshotRequest, io.Writer) error {
			t.Fatal("replayed report reached snapshot writer")
			return nil
		},
	}
	service, _ := newTestService(t, repository)
	value, created, err := service.Generate(
		context.Background(), testTaskID, FormatJSON, "same-request",
	)
	if err != nil {
		t.Fatal(err)
	}
	if created || value.Status != "complete" {
		t.Fatalf("replay = %#v, created=%v", value, created)
	}
}

func TestGenerateFailureCleansStagingAndPersistsBoundedFailure(t *testing.T) {
	repository := &repositoryStub{
		claimGenerate: true,
		jsonWriter: func(
			_ context.Context,
			_ SnapshotRequest,
			writer io.Writer,
		) error {
			_, _ = io.WriteString(writer, "partial")
			return errors.New(
				"/srv/binaryscan/repository/reports/" + testTaskID +
					"/private.staging: permission denied",
			)
		},
	}
	service, root := newTestService(t, repository)
	_, _, err := service.Generate(
		context.Background(), testTaskID, FormatJSON, "failed-request",
	)
	if err == nil {
		t.Fatal("generation error = nil")
	}
	if repository.failCalls != 1 ||
		repository.failedCode != "report_generation_failed" ||
		repository.failedMessage != "Report generation failed." {
		t.Fatalf(
			"failed record = calls %d code %q message %q",
			repository.failCalls, repository.failedCode,
			repository.failedMessage,
		)
	}
	if strings.Contains(repository.failedMessage, "/srv/") ||
		strings.Contains(repository.failedMessage, "staging") {
		t.Fatalf("failed record exposes storage path: %q", repository.failedMessage)
	}
	taskDirectory := filepath.Join(root, "reports", testTaskID)
	entries, readErr := os.ReadDir(taskDirectory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("staging files were not cleaned: %#v", entries)
	}
}

func TestGenerateDoesNotPublishAfterTaskStartsDeleting(t *testing.T) {
	payload := `{"task":"deleting"}` + "\n"
	repository := &repositoryStub{
		claimGenerate: true,
		authorizeErr:  ErrTaskNotTerminal,
		jsonWriter: func(
			_ context.Context,
			_ SnapshotRequest,
			writer io.Writer,
		) error {
			_, err := io.WriteString(writer, payload)
			return err
		},
	}
	service, root := newTestService(t, repository)

	_, created, err := service.Generate(
		context.Background(),
		testTaskID,
		FormatJSON,
		"deleting-report",
	)
	if created || !errors.Is(err, ErrTaskNotTerminal) {
		t.Fatalf("Generate() = (created=%v, err=%v)", created, err)
	}
	if repository.authorizeCalls != 1 ||
		repository.failCalls != 1 ||
		repository.completedArtifact.StorageKey != "" {
		t.Fatalf(
			"publish guard calls=%d failures=%d completed=%+v",
			repository.authorizeCalls,
			repository.failCalls,
			repository.completedArtifact,
		)
	}
	taskDirectory := filepath.Join(root, "reports", testTaskID)
	entries, readErr := os.ReadDir(taskDirectory)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("publish guard left report files: %#v", entries)
	}
}

func TestGenerateRemovesArtifactWhenDeletionWinsCompletionCAS(t *testing.T) {
	repository := &repositoryStub{
		claimGenerate: true,
		completeErr:   ErrTaskNotTerminal,
		jsonWriter: func(
			_ context.Context,
			_ SnapshotRequest,
			writer io.Writer,
		) error {
			_, err := io.WriteString(writer, `{"published":true}`+"\n")
			return err
		},
	}
	service, root := newTestService(t, repository)

	_, created, err := service.Generate(
		context.Background(),
		testTaskID,
		FormatJSON,
		"delete-wins-completion",
	)
	if created || !errors.Is(err, ErrTaskNotTerminal) {
		t.Fatalf("Generate() = (created=%v, err=%v)", created, err)
	}
	if repository.authorizeCalls != 1 ||
		repository.completedArtifact.StorageKey == "" ||
		repository.failCalls != 1 {
		t.Fatalf(
			"completion CAS calls=%d artifact=%+v failures=%d",
			repository.authorizeCalls,
			repository.completedArtifact,
			repository.failCalls,
		)
	}
	taskDirectory := filepath.Join(root, "reports", testTaskID)
	if _, statErr := os.Lstat(taskDirectory); !errors.Is(
		statErr,
		os.ErrNotExist,
	) {
		t.Fatalf("completion CAS left report scope: %v", statErr)
	}
}

func TestGenerateCancellationPersistsFailureWithCleanupContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	repository := &repositoryStub{
		claimGenerate: true,
		jsonWriter: func(
			ctx context.Context,
			_ SnapshotRequest,
			_ io.Writer,
		) error {
			cancel()
			return ctx.Err()
		},
	}
	service, _ := newTestService(t, repository)
	_, _, err := service.Generate(
		ctx, testTaskID, FormatJSON, "cancelled-request",
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("generation error = %v", err)
	}
	if repository.failCalls != 1 ||
		repository.failedCode != "report_generation_cancelled" {
		t.Fatalf(
			"failure = calls %d code %q",
			repository.failCalls, repository.failedCode,
		)
	}
}

func TestGenerateValidatesFormatTaskAndIdempotencyKey(t *testing.T) {
	repository := &repositoryStub{}
	service, _ := newTestService(t, repository)
	tests := []struct {
		taskID string
		format Format
		key    string
	}{
		{taskID: "bad", format: FormatJSON, key: "key"},
		{taskID: testTaskID, format: "xml", key: "key"},
		{taskID: testTaskID, format: FormatJSON, key: ""},
		{taskID: testTaskID, format: FormatJSON, key: strings.Repeat("x", 129)},
		{taskID: testTaskID, format: FormatJSON, key: "line\nbreak"},
		{taskID: testTaskID, format: FormatJSON, key: "non-ascii-\u4e2d"},
	}
	for _, test := range tests {
		_, _, err := service.Generate(
			context.Background(), test.taskID, test.format, test.key,
		)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Generate(%q,%q,%q) error = %v",
				test.taskID, test.format, test.key, err)
		}
	}
	if repository.claimCalls != 0 {
		t.Fatalf("invalid requests reached claim %d times", repository.claimCalls)
	}
}

func TestDownloadVerifiesArtifactBeforeReturning(t *testing.T) {
	content := []byte(`{"schemaVersion":"1.1.0"}`)
	digest := sha256.Sum256(content)
	repository := &repositoryStub{download: DownloadDescriptor{
		ReportID: testReportID, TaskID: testTaskID, Format: FormatJSON,
		Status:     "complete",
		StorageKey: "reports/" + testTaskID + "/" + testReportID + ".json",
		SHA256:     hex.EncodeToString(digest[:]), SizeBytes: uint64(len(content)),
	}}
	service, root := newTestService(t, repository)
	directory := filepath.Join(root, "reports", testTaskID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, testReportID+".json"), content, 0o600,
	); err != nil {
		t.Fatal(err)
	}

	download, err := service.Download(
		context.Background(), testTaskID, testReportID,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer download.Content.Close()
	got, err := io.ReadAll(download.Content)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) ||
		download.ContentType != "application/json" ||
		download.Filename !=
			"binaryscan-"+testTaskID+"-report.json" {
		t.Fatalf("download = %#v, content=%q", download, got)
	}
}

func TestDownloadRejectsTamperAndSymlink(t *testing.T) {
	expected := []byte("expected")
	digest := sha256.Sum256(expected)
	newRepository := func() *repositoryStub {
		return &repositoryStub{download: DownloadDescriptor{
			ReportID: testReportID, TaskID: testTaskID, Format: FormatHTML,
			Status:     "complete",
			StorageKey: "reports/" + testTaskID + "/" + testReportID + ".html",
			SHA256:     hex.EncodeToString(digest[:]),
			SizeBytes:  uint64(len(expected)),
		}}
	}
	t.Run("tamper", func(t *testing.T) {
		repository := newRepository()
		service, root := newTestService(t, repository)
		directory := filepath.Join(root, "reports", testTaskID)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, testReportID+".html"),
			[]byte("tampered"), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		_, err := service.Download(
			context.Background(), testTaskID, testReportID,
		)
		if !errors.Is(err, ErrArtifactUnavailable) {
			t.Fatalf("tamper error = %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		repository := newRepository()
		service, root := newTestService(t, repository)
		directory := filepath.Join(root, "reports", testTaskID)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, expected, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			target, filepath.Join(directory, testReportID+".html"),
		); err != nil {
			t.Fatal(err)
		}
		_, err := service.Download(
			context.Background(), testTaskID, testReportID,
		)
		if !errors.Is(err, ErrArtifactUnavailable) {
			t.Fatalf("symlink error = %v", err)
		}
	})
}

func TestDownloadRejectsNonCanonicalStorageKeyAndCancelledContext(t *testing.T) {
	repository := &repositoryStub{download: DownloadDescriptor{
		ReportID: testReportID, TaskID: testTaskID, Format: FormatJSON,
		Status: "complete", StorageKey: "../outside.json",
		SHA256: strings.Repeat("a", 64), SizeBytes: 1,
	}}
	service, _ := newTestService(t, repository)
	_, err := service.Download(
		context.Background(), testTaskID, testReportID,
	)
	if !errors.Is(err, ErrArtifactUnavailable) {
		t.Fatalf("non-canonical storage key error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.Download(ctx, testTaskID, testReportID)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled download error = %v", err)
	}
}

func TestSafeRawJSONRecursivelyRemovesSecretsAndRejectsBounds(t *testing.T) {
	raw := safeRawJSON([]byte(`{
		"ok":1,
		"nested":{"storage_key":"repo/private","password":"secret","keep":true},
		"array":[{"cacheKey":"x","sourceContent":"code","name":"safe"}]
	}`), `null`)
	value := string(raw)
	for _, forbidden := range []string{
		"storage_key", "password", "cacheKey", "sourceContent",
		"repo/private", "secret", `"code"`,
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("sanitized JSON contains %q: %s", forbidden, value)
		}
	}
	if !strings.Contains(value, `"keep":true`) ||
		!strings.Contains(value, `"name":"safe"`) {
		t.Fatalf("sanitized JSON lost safe fields: %s", value)
	}
	tooLong := `{"value":"` + strings.Repeat("x", 65537) + `"}`
	if got := string(safeRawJSON([]byte(tooLong), `null`)); got != "null" {
		t.Fatalf("oversized JSON = %s", got[:min(len(got), 100)])
	}
	tooLarge := `["` + strings.Repeat("x", maxReportJSONBytes) + `"]`
	if got := string(safeRawJSON([]byte(tooLarge), `null`)); got != "null" {
		t.Fatalf("oversized JSON document was retained")
	}
}

func TestStaticHTMLTemplateEscapesUntrustedContentAndHasNoScripts(t *testing.T) {
	malicious := `<script>alert("stored-xss")</script>`
	var output bytes.Buffer
	err := reportHTML.Execute(&output, htmlReportData{
		SchemaVersion: SchemaVersion,
		ReportID:      testReportID,
		Task: taskSnapshot{
			ID: testTaskID, Name: malicious, Status: "SUCCEEDED",
			Input: inputSnapshot{Filename: malicious},
		},
		Execution:  executionSnapshot{},
		Limits:     `{}`,
		Statistics: `null`,
		Vulnerabilities: []htmlVulnerabilityFinding{{
			vulnerabilitySnapshot: vulnerabilitySnapshot{
				VulnerabilityID: malicious,
				Title:           &malicious,
			},
			Evidence: htmlVulnerabilityEvidence{
				HasValues: true,
				Target:    malicious,
			},
			References: []htmlVulnerabilityReference{{
				URL: "https://security.example.test/CVE-2026-0001",
			}},
		}},
		Decompilations: []htmlDecompileResult{{
			ID: testReportID, FileNodeID: "42",
			SymbolKey: "FUN_140001000", SymbolKind: "function",
			DisplayName: malicious, Location: "0x140001000",
			Signature: malicious, Language: "c",
			EngineName: "ghidra", EngineVersion: "12.1.2",
			Status: "complete",
		}},
		Issues: []htmlIssue{
			{
				Category: "warning",
				issueSnapshot: issueSnapshot{
					Code: "task_warning", Message: "bounded warning",
				},
			},
			{
				Category: "unsupported",
				issueSnapshot: issueSnapshot{
					Code: "format_unsupported", Message: malicious,
				},
			},
			{
				Category: "failed",
				issueSnapshot: issueSnapshot{
					Code: "analyzer_failed", Message: "bounded failure",
				},
			},
		},
		VulnerabilitiesTruncated: true,
		AnalyzersTruncated:       true,
		DecompilationsTruncated:  true,
		DatabasesTruncated:       true,
		IssuesTruncated:          true,
		VulnerabilityLimit:       htmlVulnerabilityDetailLimit,
		AnalyzerLimit:            htmlAnalyzerRunLimit,
		DecompilationLimit:       htmlDecompileResultLimit,
		DatabaseLimit:            htmlDatabaseVersionLimit,
		IssueLimit:               htmlDiagnosticLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	html := output.String()
	if strings.Contains(strings.ToLower(html), "<script") ||
		strings.Contains(html, malicious) {
		t.Fatalf("static HTML contains executable markup: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("static HTML did not render escaped evidence: %s", html)
	}
	for _, diagnostic := range []string{
		"task_warning", "format_unsupported", "analyzer_failed",
		"限制快照", "反编译函数索引", "FUN_140001000",
	} {
		if !strings.Contains(html, diagnostic) {
			t.Errorf("static HTML omits diagnostic/limit %q", diagnostic)
		}
	}
	for _, notice := range []string{
		"漏洞详情仅展示前 1000 项",
		"分析器运行仅展示前 1000 项",
		"反编译函数索引仅展示前 3000 项",
		"数据库 Bundle 仅展示前 100 项",
		"诊断项仅展示前 1000 项",
	} {
		if !strings.Contains(html, notice) {
			t.Errorf("static HTML omits truncation notice %q", notice)
		}
	}
	if !strings.Contains(
		html,
		`href="https://security.example.test/CVE-2026-0001"`,
	) || !strings.Contains(html, `rel="noreferrer noopener"`) {
		t.Errorf("static HTML omits safe vulnerability reference: %s", html)
	}
	for _, external := range []string{
		`<link`, `<iframe`, `<img`, `javascript:`,
	} {
		if strings.Contains(strings.ToLower(html), external) {
			t.Errorf("static HTML contains external resource marker %q", external)
		}
	}
}

func TestHTMLVulnerabilityEvidenceIsReadableAndHidesInternalPaths(t *testing.T) {
	installed := "1:2.41.3-3ubuntu2"
	fixed := "1:2.41.4"
	platform := "linux/amd64"
	snapshot := vulnerabilitySnapshot{
		VulnerabilityID:  "CVE-2026-27456",
		Severity:         "MEDIUM",
		PackageName:      "bsdutils",
		InstalledVersion: &installed,
		FixedVersion:     &fixed,
		ImageLogicalPath: "/",
		ImagePlatform:    &platform,
		Evidence: json.RawMessage(`{
			"package_name":"bsdutils",
			"installed_version":"1:2.41.3-3ubuntu2",
			"fixed_version":"1:2.41.4",
			"package_path":"var/lib/dpkg/status",
			"target":"/data/task-work/scan-opaque/input/oci-layout@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (ubuntu 26.04)",
			"class":"os-pkgs",
			"type":"ubuntu",
			"image_platform":"linux/amd64",
			"image_references":["latest"],
			"manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"data_source":{
				"id":"ubuntu",
				"name":"Ubuntu CVE Tracker",
				"url":"https://git.launchpad.net/ubuntu-cve-tracker"
			}
		}`),
		References: json.RawMessage(`[
			"https://avd.aquasec.com/nvd/cve-2026-27456",
			"https://nvd.nist.gov/vuln/detail/CVE-2026-27456",
			"javascript:alert(1)",
			"latest"
		]`),
	}
	finding := newHTMLVulnerabilityFinding(snapshot)
	if finding.Evidence.Target != "ubuntu 26.04" ||
		finding.Evidence.PackagePath != "var/lib/dpkg/status" ||
		finding.Evidence.DataSourceName != "Ubuntu CVE Tracker" ||
		len(finding.References) != 2 {
		t.Fatalf("HTML finding = %+v", finding)
	}

	var output bytes.Buffer
	err := reportHTML.Execute(&output, htmlReportData{
		SchemaVersion: SchemaVersion,
		ReportID:      testReportID,
		Task: taskSnapshot{
			ID: testTaskID, Name: "Trivy fixture", Status: "SUCCEEDED",
			Input: inputSnapshot{Filename: "image.tar"},
		},
		Execution:       executionSnapshot{},
		Limits:          `{}`,
		Statistics:      `null`,
		Vulnerabilities: []htmlVulnerabilityFinding{finding},
	})
	if err != nil {
		t.Fatal(err)
	}
	html := output.String()
	for _, expected := range []string{
		"扫描目标", "ubuntu 26.04", "包路径", "var/lib/dpkg/status",
		"组件类别", "os-pkgs", "包类型", "Ubuntu CVE Tracker",
		"镜像引用", "latest", "漏洞引用",
		`href="https://avd.aquasec.com/nvd/cve-2026-27456"`,
		`href="https://nvd.nist.gov/vuln/detail/CVE-2026-27456"`,
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("HTML vulnerability evidence omits %q: %s", expected, html)
		}
	}
	for _, forbidden := range []string{
		"/data/task-work/", "javascript:alert", "[123 34", `href="latest"`,
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("HTML vulnerability evidence contains %q: %s", forbidden, html)
		}
	}
}

func TestReadableReportJSONRendersStructuredTextInsteadOfBytes(t *testing.T) {
	value := readableReportJSON(json.RawMessage(`{"package":"openssl","count":2}`))
	if !strings.Contains(value, `"package": "openssl"`) ||
		!strings.Contains(value, `"count": 2`) ||
		strings.HasPrefix(value, "[") {
		t.Fatalf("readableReportJSON() = %q", value)
	}
	if value := readableReportJSON(json.RawMessage(`not-json`)); value != "null" {
		t.Fatalf("invalid readableReportJSON() = %q", value)
	}
}
