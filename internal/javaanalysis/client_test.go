package javaanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"
)

type javaRoundTripFunc func(*http.Request) (*http.Response, error)

func (f javaRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHTTPClientUsesJavaMultipartContractAndValidatesResponse(t *testing.T) {
	content := "class A {}"
	file := javaTestFile(testResultA, "src/main/java/a/A.java", "a.A", content)
	file.OffsetBytes = 0
	file.LengthBytes = file.SizeBytes
	inputSHA, err := canonicalInputSHA256([]SourceFile{file})
	if err != nil {
		t.Fatal(err)
	}
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: testRunID,
		InputSHA256: inputSHA, BundleSHA256: javaDigest(content),
		SourceManifestSHA256: strings.Repeat("a", 64),
		ProjectID:            testProjectID,
		Language:             "java",
		ProjectStatus:        "complete",
		Files:                []SourceFile{file},
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "complete", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: javaDigest(content),
		Coverage: ResultCoverage{
			FilesTotal: 1, FilesAnalyzed: 1, FilesParsed: 1,
		},
		Summary: ResultSummary{FindingCount: 1},
		Findings: []Finding{{
			CWE: "CWE-328", RuleID: "java-weak-message-digest", Severity: "MEDIUM",
			File: file.FileIdentity, Callable: CallableIdentity{
				Kind: "method", TypeName: "a.A", Name: "run", Signature: "void run()",
			},
			Location: Location{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 5},
			Message:  "Weak message digest.", Snippet: "MD5", SnippetStartLine: 1,
		}},
		Diagnostics: []Diagnostic{},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	transport := javaRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/internal/v1/analyses/"+testRunID {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			t.Fatalf("content type = %q: %v", mediaType, err)
		}
		reader := multipart.NewReader(request.Body, params["boundary"])
		metadataPart, err := reader.NextPart()
		if err != nil || metadataPart.FormName() != "metadata" {
			t.Fatalf("metadata part: %v", err)
		}
		var gotMetadata RequestMetadata
		if err := json.NewDecoder(metadataPart).Decode(&gotMetadata); err != nil {
			t.Fatal(err)
		}
		if gotMetadata.InputSHA256 != inputSHA ||
			gotMetadata.ProjectID != testProjectID ||
			gotMetadata.Language != "java" ||
			gotMetadata.ProjectStatus != "complete" ||
			len(gotMetadata.Files) != 1 ||
			gotMetadata.Files[0].LengthBytes != uint64(len(content)) {
			t.Fatalf("metadata = %#v", gotMetadata)
		}
		sourcePart, err := reader.NextPart()
		if err != nil || sourcePart.FormName() != "source" {
			t.Fatalf("source part: %v", err)
		}
		gotSource, err := io.ReadAll(sourcePart)
		if err != nil || string(gotSource) != content {
			t.Fatalf("source = %q: %v", gotSource, err)
		}
		return &http.Response{
			StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)),
			Header: make(http.Header),
		}, nil
	})
	client, err := NewHTTPClient(ClientConfig{
		BaseURL: "http://java-checker:8080", MaxDuration: time.Minute,
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Analyze(context.Background(), AnalysisRequest{
		Metadata: metadata, Source: strings.NewReader(content),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "complete" || len(got.Findings) != 1 {
		t.Fatalf("result = %#v", got)
	}
}

func TestResultCoverageTreatsRecoveredAsParsedSubset(t *testing.T) {
	files := []SourceFile{
		javaTestFile(testResultA, "src/main/java/a/A.java", "a.A", "a"),
		javaTestFile(testResultB, "src/main/java/b/B.java", "b.B", "b"),
		javaTestFile(testResultC, "src/main/java/c/C.java", "c.C", "c"),
	}
	inputSHA, err := canonicalInputSHA256(files)
	if err != nil {
		t.Fatal(err)
	}
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: testRunID,
		InputSHA256: inputSHA, BundleSHA256: strings.Repeat("b", 64),
		SourceManifestSHA256: strings.Repeat("a", 64),
		ProjectID:            testProjectID,
		Language:             "mixed",
		ProjectStatus:        "partial",
		Files:                files,
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "partial", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: metadata.BundleSHA256,
		Coverage: ResultCoverage{
			FilesTotal: 3, FilesAnalyzed: 1, FilesParsed: 2,
			FilesRecovered: 1, FilesFailed: 1,
		},
		Findings: []Finding{}, Diagnostics: []Diagnostic{},
	}
	if err := validateResult(result, metadata, MaxFindings, MaxDiagnostics); err != nil {
		t.Fatalf("valid recovered coverage rejected: %v", err)
	}
	for _, mutate := range []func(*Result){
		func(value *Result) { value.Coverage.FilesAnalyzed = 3 },
		func(value *Result) { value.Coverage.FilesRecovered = 3 },
		func(value *Result) { value.Coverage.FilesFailed = 0 },
	} {
		invalid := result
		mutate(&invalid)
		if err := validateResult(invalid, metadata, MaxFindings, MaxDiagnostics); err == nil {
			t.Fatalf("invalid coverage accepted: %#v", invalid)
		}
	}
}

func TestResultCoverageKeepsOversizedFileAsFailedPartialInput(t *testing.T) {
	small := javaTestFile(
		testResultA, "src/main/java/a/A.java", "a.A", "class A {}\n",
	)
	large := javaTestFile(
		testResultB, "src/main/java/b/B.java", "b.B",
		strings.Repeat(" ", int(MaxFileBytes)+1),
	)
	files := []SourceFile{small, large}
	var offset uint64
	for index := range files {
		files[index].OffsetBytes = offset
		files[index].LengthBytes = files[index].SizeBytes
		offset += files[index].SizeBytes
	}
	inputSHA, err := canonicalInputSHA256(files)
	if err != nil {
		t.Fatal(err)
	}
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: testRunID,
		InputSHA256: inputSHA, BundleSHA256: strings.Repeat("b", 64),
		SourceManifestSHA256: strings.Repeat("a", 64),
		ProjectID:            testProjectID, Language: "java", ProjectStatus: "complete",
		Files: files,
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "partial", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: metadata.BundleSHA256,
		Coverage: ResultCoverage{
			FilesTotal: 2, FilesAnalyzed: 1, FilesParsed: 1, FilesFailed: 1,
		},
		Summary: ResultSummary{DiagnosticCount: 1}, Findings: []Finding{},
		Diagnostics: []Diagnostic{{
			Code: "file_too_large", Message: "File exceeds the parse limit.",
			Severity: "WARNING", File: &DiagnosticFile{
				ResultID: large.ResultID, LogicalPath: large.LogicalPath,
				BinaryName: large.BinaryName,
			},
		}},
	}
	if err := validateResult(result, metadata, MaxFindings, MaxDiagnostics); err != nil {
		t.Fatalf("oversized file partial coverage rejected: %v", err)
	}
}

func TestDecodeCheckerResultAcceptsEngineNestedCoverageFixture(t *testing.T) {
	content := "class Rules {\n  void run() {}\n}\n"
	file := javaTestFile(
		testResultA, "src/main/java/Rules.java", "Rules", content,
	)
	file.LengthBytes = file.SizeBytes
	inputSHA, err := canonicalInputSHA256([]SourceFile{file})
	if err != nil {
		t.Fatal(err)
	}
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: testRunID,
		InputSHA256: inputSHA, BundleSHA256: javaDigest(content),
		SourceManifestSHA256: strings.Repeat("a", 64),
		ProjectID:            testProjectID, Language: "mixed", ProjectStatus: "partial",
		Files: []SourceFile{file},
	}
	fixture := `{
  "schema_version":"java-analysis-response-v1",
  "analysis_id":"` + testRunID + `",
  "status":"partial",
  "identity":{"product":"binaryscan-java-checker","version":"0.1.0","ruleset":"java-rules-v1"},
  "input_sha256":"` + inputSHA + `",
  "bundle_sha256":"` + javaDigest(content) + `",
  "coverage":{"files_total":1,"files_analyzed":1,"files_parsed":1,"files_recovered":0,"files_failed":0},
  "summary":{"finding_count":1,"diagnostic_count":0,"findings_truncated":false,"diagnostics_truncated":false},
  "findings":[{
    "rule_id":"java-command-injection","cwe":"CWE-78","severity":"HIGH",
    "message":"Command execution uses untrusted input.",
    "file":{"result_id":"` + testResultA + `","logical_path":"src/main/java/Rules.java","binary_name":"Rules"},
    "callable":{"kind":"method","type_name":"Rules","name":"run","signature":"void run()"},
    "location":{"start_line":2,"start_column":3,"end_line":2,"end_column":16},
    "snippet":"void run() {}","snippet_start_line":2
  }],
  "diagnostics":[]
}`
	result, err := decodeCheckerResult(
		strings.NewReader(fixture), MaxResponseBytes, metadata,
		MaxFindings, MaxDiagnostics,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage.FilesTotal != 1 || result.Coverage.FilesAnalyzed != 1 ||
		result.Status != "partial" || len(result.Findings) != 1 {
		t.Fatalf("decoded engine response = %#v", result)
	}
}

func TestValidateResultRejectsFindingPastVerifiedFileEnd(t *testing.T) {
	content := "class A {}\n"
	file := javaTestFile(testResultA, "src/main/java/A.java", "A", content)
	file.LengthBytes = file.SizeBytes
	inputSHA, err := canonicalInputSHA256([]SourceFile{file})
	if err != nil {
		t.Fatal(err)
	}
	metadata := RequestMetadata{
		SchemaVersion: RequestSchemaVersion, AnalysisID: testRunID,
		InputSHA256: inputSHA, BundleSHA256: javaDigest(content),
		SourceManifestSHA256: strings.Repeat("a", 64),
		ProjectID:            testProjectID, Language: "java", ProjectStatus: "complete",
		Files: []SourceFile{file},
	}
	result := Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "complete", Identity: CheckerIdentity{
			Product: AnalyzerName, Version: AnalyzerVersion,
			Ruleset: DefaultRulesetVersion,
		},
		InputSHA256: inputSHA, BundleSHA256: metadata.BundleSHA256,
		Coverage: ResultCoverage{
			FilesTotal: 1, FilesAnalyzed: 1, FilesParsed: 1,
		},
		Summary: ResultSummary{FindingCount: 1},
		Findings: []Finding{{
			RuleID: "java-weak-cipher", CWE: "CWE-327", Severity: "MEDIUM",
			Message: "Weak cipher.", File: file.FileIdentity,
			Callable: CallableIdentity{
				Kind: "type", TypeName: "A", Name: "A", Signature: "A",
			},
			Location: Location{
				StartLine: file.LineCount + 1, StartColumn: 1,
				EndLine: file.LineCount + 1, EndColumn: 2,
			},
		}},
		Diagnostics: []Diagnostic{},
	}
	if err := validateResult(result, metadata, MaxFindings, MaxDiagnostics); err == nil {
		t.Fatal("finding past verified source line count was accepted")
	}
}

func TestValidateDiagnosticRejectsLinePastVerifiedFileEnd(t *testing.T) {
	file := javaTestFile(
		testResultA, "src/main/java/A.java", "A", "class A {}\n",
	)
	line := file.LineCount + 1
	diagnosticFile := DiagnosticFile{
		ResultID: file.ResultID, LogicalPath: file.LogicalPath,
		BinaryName: file.BinaryName,
	}
	diagnostic := Diagnostic{
		Code: "parse_warning", Message: "Parser recovered.",
		Severity: "WARNING", File: &diagnosticFile, Line: &line,
	}
	if validDiagnostic(diagnostic, map[string]SourceFile{file.ResultID: file}) {
		t.Fatal("diagnostic past verified source line count was accepted")
	}
	line = file.LineCount
	if !validDiagnostic(diagnostic, map[string]SourceFile{file.ResultID: file}) {
		t.Fatal("diagnostic on the verified final source line was rejected")
	}
}
