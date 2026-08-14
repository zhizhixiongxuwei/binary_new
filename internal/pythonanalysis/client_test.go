package pythonanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, server *httptest.Server) *HTTPClient {
	t.Helper()
	client, err := NewHTTPClient(ClientConfig{
		BaseURL:          server.URL,
		MaxDuration:      10 * time.Second,
		MaxResponseBytes: MaxResponseBytes,
		MaxFindings:      MaxFindings,
		MaxDiagnostics:   MaxDiagnostics,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testRequest() AnalysisRequest {
	return AnalysisRequest{
		Source: []SourceFile{{
			FileIdentity: FileIdentity{
				ResultID:    "src/main/python/main.py",
				LogicalPath: "src/main/python/main.py",
				BinaryName:  "src/main/python/main.py",
			},
			Content: "import os\nos.system(cmd)\n",
		}},
	}
}

func TestAnalyzeParsesValidCheckerResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/analyze" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["schema"] != RequestSchema {
			t.Fatalf("schema = %v", payload["schema"])
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"schema": "binaryscan-python-analysis-response/v1",
			"name": "binaryscan-python-checker",
			"version": "0.1.0",
			"analyzedFiles": 1,
			"findings": [{
				"ruleId": "python-command-injection",
				"cwe": "CWE-78",
				"severity": "HIGH",
				"message": "通过系统调用执行命令",
				"file": {"logicalPath": "src/main/python/main.py"},
				"line": 2
			}],
			"diagnostics": [],
			"findingsTruncated": false,
			"diagnosticsTruncated": false
		}`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	result, err := client.Analyze(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if result.AnalyzedFiles != 1 || len(result.Findings) != 1 {
		t.Fatalf("result = %+v", result)
	}
	finding := result.Findings[0]
	if finding.RuleID != "python-command-injection" ||
		finding.CWE != "CWE-78" || finding.Severity != "HIGH" ||
		finding.Location.StartLine != 2 ||
		finding.File.LogicalPath != "src/main/python/main.py" {
		t.Fatalf("finding = %+v", finding)
	}
	low, medium, high, critical := result.SeverityCounts()
	if low != 0 || medium != 0 || high != 1 || critical != 0 {
		t.Fatalf("severity counts = %d/%d/%d/%d", low, medium, high, critical)
	}
}

func TestAnalyzeRejectsInvalidResponse(t *testing.T) {
	for _, body := range []string{
		`{"schema":"wrong","analyzedFiles":1,"findings":[],"diagnostics":[]}`,
		`{"schema":"binaryscan-python-analysis-response/v1","analyzedFiles":1,` +
			`"findings":[{"ruleId":"Bad rule!","cwe":"CWE-78","severity":"HIGH",` +
			`"message":"m","file":{"logicalPath":"p"},"line":1}],"diagnostics":[]}`,
		`not json`,
		``,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			_, _ = writer.Write([]byte(body))
		}))
		client := newTestClient(t, server)
		if _, err := client.Analyze(context.Background(), testRequest()); !errors.Is(
			err, ErrInvalidResponse,
		) {
			t.Fatalf("body %q error = %v, want invalid response", body, err)
		}
		server.Close()
	}
}

func TestAnalyzePropagatesCheckerRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = writer.Write([]byte(
			`{"error":{"code":"invalid_request","message":"schema is invalid"}}`,
		))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	_, err := client.Analyze(context.Background(), testRequest())
	var rejection *CheckerRejection
	if !errors.As(err, &rejection) ||
		rejection.StatusCode != http.StatusUnprocessableEntity ||
		rejection.Code != "invalid_request" {
		t.Fatalf("error = %v", err)
	}
}

func TestReadyChecksHealthEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/healthz" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	if err := client.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAnalyzeRejectsOversizedInput(t *testing.T) {
	client, err := NewHTTPClient(ClientConfig{
		BaseURL: "http://127.0.0.1:1", MaxDuration: time.Second,
		MaxResponseBytes: MaxResponseBytes,
		MaxFindings:      MaxFindings, MaxDiagnostics: MaxDiagnostics,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := AnalysisRequest{Source: []SourceFile{{
		FileIdentity: FileIdentity{
			ResultID: "main.py", LogicalPath: "main.py", BinaryName: "main.py",
		},
		Content: strings.Repeat("x", MaxSourceBytes+1),
	}}}
	if _, err := client.Analyze(context.Background(), request); !errors.Is(
		err, ErrInvalidInput,
	) {
		t.Fatalf("error = %v, want invalid input", err)
	}
}
