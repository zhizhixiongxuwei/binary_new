package canalysis

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testTaskID    = "11111111-1111-4111-8111-111111111111"
	testRunID     = "22222222-2222-4222-8222-222222222222"
	testProjectID = "33333333-3333-4333-8333-333333333333"
	testJobID     = "44444444-4444-4444-8444-444444444444"
	testResultID  = "55555555-5555-4555-8555-555555555555"
	testSHA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestHTTPClientAnalyzeUsesBoundedV1MultipartContract(t *testing.T) {
	source := []byte("int main(void) { return 0; }\n")
	httpClient := handlerHTTPClient(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPost ||
			request.URL.Path != "/internal/v1/analyses/"+testRunID {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "multipart/form-data" {
			t.Fatalf("content type = %q / %v", mediaType, err)
		}
		reader := multipart.NewReader(request.Body, parameters["boundary"])
		metadataPart, err := reader.NextPart()
		if err != nil || metadataPart.FormName() != "metadata" ||
			metadataPart.FileName() != "metadata.json" ||
			metadataPart.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("metadata part = %#v / %v", metadataPart, err)
		}
		var metadata RequestMetadata
		if err := json.NewDecoder(metadataPart).Decode(&metadata); err != nil ||
			metadata.AnalysisID != testRunID || len(metadata.Functions) != 1 {
			t.Fatalf("metadata = %#v / %v", metadata, err)
		}
		sourcePart, err := reader.NextPart()
		if err != nil || sourcePart.FormName() != "source" ||
			sourcePart.FileName() != "decompiled.c" {
			t.Fatalf("source part = %#v / %v", sourcePart, err)
		}
		actual, err := io.ReadAll(sourcePart)
		if err != nil || !bytes.Equal(actual, source) {
			t.Fatalf("source = %q / %v", actual, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(validCheckerResult())
	}))
	client, err := NewHTTPClient(ClientConfig{
		BaseURL: "http://checker", MaxDuration: time.Second,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata := validRequestMetadataFixture(uint64(len(source)))
	result, err := client.Analyze(t.Context(), AnalysisRequest{
		Metadata: metadata, Source: bytes.NewReader(source),
	})
	if err != nil || result.Status != "succeeded" || len(result.Findings) != 1 {
		t.Fatalf("Analyze() = %#v / %v", result, err)
	}
}

func TestHTTPClientPreservesBoundedCheckerRejection(t *testing.T) {
	httpClient := handlerHTTPClient(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(
			writer,
			`{"code":"invalid_request","message":"Required part 'metadata' is not present."}`,
		)
	}))
	client, err := NewHTTPClient(ClientConfig{
		BaseURL: "http://checker", MaxDuration: time.Second,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Analyze(t.Context(), AnalysisRequest{
		Metadata: validRequestMetadataFixture(1),
		Source:   bytes.NewReader([]byte("x")),
	})
	var rejection *CheckerRejection
	if !errors.As(err, &rejection) ||
		!errors.Is(err, ErrCheckerRejected) ||
		rejection.StatusCode != http.StatusBadRequest ||
		rejection.Code != "invalid_request" ||
		rejection.Message != "Required part 'metadata' is not present." {
		t.Fatalf("Analyze() error = %#v / %v", rejection, err)
	}
}

func TestHTTPClientRejectsUnknownOrOversizedCheckerOutput(t *testing.T) {
	tests := []struct {
		name string
		body string
		max  int64
	}{
		{
			name: "unknown field",
			body: strings.TrimSuffix(checkerResultJSON(t), "}\n") +
				`,"confidence":0.9}`,
			max: MaxResponseBytes,
		},
		{name: "response limit", body: checkerResultJSON(t), max: 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpClient := handlerHTTPClient(http.HandlerFunc(func(
				writer http.ResponseWriter,
				request *http.Request,
			) {
				_, _ = io.Copy(io.Discard, request.Body)
				writer.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(writer, test.body)
			}))
			client, err := NewHTTPClient(ClientConfig{
				BaseURL: "http://checker", MaxDuration: time.Second,
				MaxResponseBytes: test.max,
				HTTPClient:       httpClient,
			})
			if test.max < 1 || test.max > MaxResponseBytes {
				if err == nil {
					t.Fatal("NewHTTPClient() accepted invalid response limit")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Analyze(t.Context(), AnalysisRequest{
				Metadata: validRequestMetadataFixture(1),
				Source:   bytes.NewReader([]byte("x")),
			})
			if !errors.Is(err, ErrCheckerInvalidResponse) {
				t.Fatalf("Analyze() error = %v", err)
			}
		})
	}
}

func TestHTTPClientClassifiesServerFailureAsTransient(t *testing.T) {
	httpClient := handlerHTTPClient(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	client, err := NewHTTPClient(ClientConfig{
		BaseURL: "http://checker", MaxDuration: time.Second,
		HTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Analyze(t.Context(), AnalysisRequest{
		Metadata: validRequestMetadataFixture(1),
		Source:   bytes.NewReader([]byte("x")),
	})
	if !errors.Is(err, ErrCheckerTransient) {
		t.Fatalf("Analyze() error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func handlerHTTPClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(
		request *http.Request,
	) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}
}

func validRequestMetadataFixture(size uint64) RequestMetadata {
	return RequestMetadata{
		SchemaVersion: RequestSchemaVersion,
		AnalysisID:    testRunID, ProjectID: testProjectID,
		CanonicalSHA256: testSHA, CanonicalSizeBytes: size,
		ProjectStatus: "complete", EngineName: "ghidra",
		EngineVersion: "12.1.2",
		Functions: []Function{{
			ResultID: testResultID, Address: "00401000", Name: "main",
			SHA256: testSHA, OffsetBytes: 0, LengthBytes: size,
			StartLine: 1, EndLine: 1,
		}},
	}
}

func validCheckerResult() Result {
	return Result{
		SchemaVersion: ResponseSchemaVersion, AnalysisID: testRunID,
		Status: "succeeded",
		Checker: CheckerIdentity{
			Name: AnalyzerName, Version: AnalyzerVersion,
			RulesetVersion: DefaultRulesetVersion,
		},
		Coverage: Coverage{TotalFunctions: 1, ParsedFunctions: 1},
		Summary:  ResultSummary{FindingCount: 1},
		Findings: []Finding{{
			CWE: "CWE-242", RuleID: "cwe-242-gets", Severity: "HIGH",
			Function: FunctionIdentity{
				ResultID: testResultID, Address: "00401000", Name: "main",
			},
			Location: Location{
				StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 4,
			},
			Message: "Call to gets is unsafe.", Snippet: "gets(buf)",
		}},
		Diagnostics: []Diagnostic{},
	}
}

func checkerResultJSON(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal(validCheckerResult())
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}
