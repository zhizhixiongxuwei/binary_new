package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func sampleTaskSnapshot() taskSnapshot {
	return taskSnapshot{
		ID:        "task-123",
		Name:      "sample.ext4",
		Status:    "SUCCEEDED",
		RiskLevel: "HIGH",
		Input: inputSnapshot{
			Filename: "sample.ext4", SizeBytes: 4096,
			SHA256: strings.Repeat("a", 64),
		},
	}
}

func TestRenderWordDocumentProducesValidDocx(t *testing.T) {
	stage := "REPORTING"
	rootFormat := "ext4"
	data := htmlReportData{
		SchemaVersion: "1",
		ReportID:      "report-456",
		GeneratedAt:   "2026-08-13T00:00:00Z",
		Task: taskSnapshot{
			ID: "task-123", Name: "sample.ext4", Status: "SUCCEEDED",
			Stage: &stage, RiskLevel: "HIGH", RootFormat: &rootFormat,
			Input: inputSnapshot{
				Filename: "sample.ext4", SizeBytes: 4096,
				SHA256: strings.Repeat("a", 64),
			},
		},
		CAnalysisRuns: []cAnalysisRunSnapshot{{
			ID: "run-1", AnalyzerName: "c-checker", AnalyzerVersion: "0.1.0",
			Status: "complete", FindingCount: 1, DiagnosticCount: 0,
		}},
		CAnalysisFindings: []cAnalysisFindingSnapshot{{
			ID: "f1", CWE: "CWE-242", RuleID: "cwe-242-gets",
			Severity: "HIGH", FunctionName: "main",
			StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4,
			Message: "use of gets is unsafe",
		}},
	}

	var output bytes.Buffer
	if err := renderWordDocument(&output, data); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatalf("docx output is not a valid zip: %v", err)
	}
	parts := make(map[string]string)
	for _, file := range reader.File {
		content, err := readZipEntry(file)
		if err != nil {
			t.Fatal(err)
		}
		parts[file.Name] = content
	}
	for _, required := range []string{
		"[Content_Types].xml", "_rels/.rels", "word/document.xml",
	} {
		if _, found := parts[required]; !found {
			t.Fatalf("docx missing part %q: %v", required, parts)
		}
	}
	document := parts["word/document.xml"]
	for _, wanted := range []string{
		"BinaryScan 离线检测报告",
		"task-123",
		"sample.ext4",
		"CWE-242",
		"使用 gets 读取输入，存在缓冲区溢出风险 — use of gets is unsafe",
	} {
		if !strings.Contains(document, wanted) {
			t.Fatalf("document.xml missing %q", wanted)
		}
	}
	if strings.Contains(document, "<&") {
		t.Fatal("document.xml contains unescaped markup")
	}
}

func TestRenderWordDocumentEscapesXML(t *testing.T) {
	data := htmlReportData{
		SchemaVersion: "1",
		ReportID:      "r",
		GeneratedAt:   "2026-08-13T00:00:00Z",
		Task: taskSnapshot{
			ID: "task-<&\"'", Name: "a<b>c", Status: "S",
			Input: inputSnapshot{Filename: "x&y", SizeBytes: 1, SHA256: "z"},
		},
	}
	var output bytes.Buffer
	if err := renderWordDocument(&output, data); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		content, err := readZipEntry(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(content, "<w:t>task-<") {
			t.Fatalf("unescaped XML in %s", file.Name)
		}
	}
	document := extractDocxText(t, output.Bytes())
	for _, escaped := range []string{
		"task-&lt;&amp;&#34;", "a&lt;b&gt;c", "x&amp;y",
	} {
		if !strings.Contains(document, escaped) {
			t.Fatalf("document.xml missing escaped text %q", escaped)
		}
	}
}

func extractDocxText(t *testing.T, docx []byte) string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		if file.Name != "word/document.xml" {
			continue
		}
		content, err := readZipEntry(file)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	t.Fatal("document.xml not found")
	return ""
}

func readZipEntry(file *zip.File) (string, error) {
	reader, err := file.Open()
	if err != nil {
		return "", err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
