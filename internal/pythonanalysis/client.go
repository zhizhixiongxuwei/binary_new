package pythonanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CheckerRejection preserves the checker's bounded, validated error response.
// It unwraps to ErrCheckerRejected for callers that only need the class.
type CheckerRejection struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *CheckerRejection) Error() string {
	if e.Code != "" {
		return fmt.Sprintf(
			"%s: HTTP %d (%s): %s",
			ErrCheckerRejected, e.StatusCode, e.Code, e.Message,
		)
	}
	return fmt.Sprintf("%s: HTTP %d", ErrCheckerRejected, e.StatusCode)
}

func (e *CheckerRejection) Unwrap() error { return ErrCheckerRejected }

// ClientConfig fixes every network and response limit of the checker client.
type ClientConfig struct {
	BaseURL          string
	MaxDuration      time.Duration
	MaxResponseBytes int64
	MaxFindings      int
	MaxDiagnostics   int
	HTTPClient       *http.Client
}

// HTTPClient submits Python sources to the offline python-checker service.
type HTTPClient struct {
	baseURL          string
	maxDuration      time.Duration
	maxResponseBytes int64
	maxFindings      int
	maxDiagnostics   int
	client           *http.Client
}

func NewHTTPClient(config ClientConfig) (*HTTPClient, error) {
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" ||
		parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, errors.New("python checker URL is invalid")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	parsed.RawPath = ""
	if config.MaxDuration == 0 {
		config.MaxDuration = 10 * time.Minute
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = MaxResponseBytes
	}
	if config.MaxFindings == 0 {
		config.MaxFindings = MaxFindings
	}
	if config.MaxDiagnostics == 0 {
		config.MaxDiagnostics = MaxDiagnostics
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPClient{
		baseURL: parsed.String(), maxDuration: config.MaxDuration,
		maxResponseBytes: config.MaxResponseBytes,
		maxFindings: config.MaxFindings,
		maxDiagnostics: config.MaxDiagnostics,
		client: client,
	}, nil
}

// Analyze submits all sources and validates the checker response.
func (c *HTTPClient) Analyze(
	ctx context.Context,
	request AnalysisRequest,
) (Result, error) {
	if ctx == nil || len(request.Source) == 0 ||
		len(request.Source) > MaxSourceFiles {
		return Result{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	var totalBytes int64
	for _, file := range request.Source {
		if file.LogicalPath == "" || len(file.LogicalPath) > MaxFileNameBytes ||
			len(file.Content) > MaxSourceBytes {
			return Result{}, ErrInvalidInput
		}
		totalBytes += int64(len(file.Content))
		if totalBytes > MaxSourceBytes {
			return Result{}, ErrInvalidInput
		}
	}
	payload := map[string]any{
		"schema": RequestSchema,
		"files":  requestFiles(request.Source),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Result{}, fmt.Errorf("encode python checker request: %w", err)
	}
	analysisCtx, cancel := context.WithTimeout(ctx, c.maxDuration)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(
		analysisCtx,
		http.MethodPost,
		strings.TrimSuffix(c.baseURL, "/")+"/analyze",
		bytes.NewReader(raw),
	)
	if err != nil {
		return Result{}, fmt.Errorf("create python checker request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, requestErr := c.client.Do(httpRequest)
	if requestErr != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if errors.Is(analysisCtx.Err(), context.DeadlineExceeded) ||
			errors.Is(requestErr, context.DeadlineExceeded) {
			return Result{}, ErrCheckerTimedOut
		}
		return Result{}, fmt.Errorf("%w: %v", ErrCheckerTransient, requestErr)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(
		response.Body, c.maxResponseBytes+1,
	))
	if readErr != nil {
		return Result{}, fmt.Errorf("%w: read python checker response: %v",
			ErrCheckerTransient, readErr)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return Result{}, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK {
		rejection := parseRejection(response.StatusCode, body)
		return Result{}, rejection
	}
	return parseResult(body, c.maxFindings, c.maxDiagnostics)
}

// Ready verifies the checker health endpoint.
func (c *HTTPClient) Ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet,
		strings.TrimSuffix(c.baseURL, "/")+"/healthz", nil,
	)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCheckerTransient, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ErrNotReady
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(
		response.Body, 1<<20,
	)).Decode(&payload); err != nil || payload.Status != "ok" {
		return ErrNotReady
	}
	return nil
}

func requestFiles(sources []SourceFile) []map[string]string {
	files := make([]map[string]string, 0, len(sources))
	for _, source := range sources {
		files = append(files, map[string]string{
			"logicalPath": source.LogicalPath,
			"content":     source.Content,
		})
	}
	return files
}

func parseRejection(status int, body []byte) error {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil ||
		payload.Error.Code == "" {
		return &CheckerRejection{StatusCode: status}
	}
	return &CheckerRejection{
		StatusCode: status,
		Code:       payload.Error.Code,
		Message:    payload.Error.Message,
	}
}

func parseResult(body []byte, maxFindings int, maxDiagnostics int) (Result, error) {
	if len(body) == 0 {
		return Result{}, ErrInvalidResponse
	}
	var payload struct {
		Schema             string `json:"schema"`
		Name               string `json:"name"`
		Version            string `json:"version"`
		AnalyzedFiles      int    `json:"analyzedFiles"`
		Findings           []struct {
			RuleID   string `json:"ruleId"`
			CWE      string `json:"cwe"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			File     struct {
				LogicalPath string `json:"logicalPath"`
			} `json:"file"`
			Line int `json:"line"`
		} `json:"findings"`
		Diagnostics []struct {
			Code     string `json:"code"`
			Message  string `json:"message"`
			Severity string `json:"severity"`
			File     struct {
				LogicalPath string `json:"logicalPath"`
			} `json:"file"`
			Line int `json:"line"`
		} `json:"diagnostics"`
		FindingsTruncated    bool `json:"findingsTruncated"`
		DiagnosticsTruncated bool `json:"diagnosticsTruncated"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Result{}, ErrInvalidResponse
	}
	if payload.Schema != ResponseSchema || payload.AnalyzedFiles < 0 ||
		len(payload.Findings) > maxFindings ||
		len(payload.Diagnostics) > maxDiagnostics {
		return Result{}, ErrInvalidResponse
	}
	result := Result{
		AnalyzedFiles:        payload.AnalyzedFiles,
		FindingsTruncated:    payload.FindingsTruncated,
		DiagnosticsTruncated: payload.DiagnosticsTruncated,
	}
	for _, raw := range payload.Findings {
		if !validRuleID(raw.RuleID) || raw.CWE == "" || raw.Message == "" ||
			len(raw.Message) > MaxMessageBytes ||
			raw.File.LogicalPath == "" ||
			!validSeverity(raw.Severity) {
			return Result{}, ErrInvalidResponse
		}
		line := uint32(raw.Line)
		result.Findings = append(result.Findings, Finding{
			RuleID: raw.RuleID, CWE: raw.CWE, Severity: raw.Severity,
			File: FileIdentity{
				ResultID:    raw.File.LogicalPath,
				LogicalPath: raw.File.LogicalPath,
				BinaryName:  raw.File.LogicalPath,
			},
			Callable: CallableIdentity{
				Kind: "module", Name: raw.File.LogicalPath,
			},
			Location: Location{
				StartLine: line, StartColumn: 1,
				EndLine: line, EndColumn: 1,
			},
			Message: raw.Message,
		})
	}
	for _, raw := range payload.Diagnostics {
		if raw.Code == "" || len(raw.Code) > MaxDiagnosticCode ||
			raw.Message == "" || len(raw.Message) > MaxMessageBytes {
			return Result{}, ErrInvalidResponse
		}
		line := uint32(raw.Line)
		result.Diagnostics = append(result.Diagnostics, Diagnostic{
			Code: raw.Code, Message: raw.Message, Severity: raw.Severity,
			File: &DiagnosticFile{
				ResultID:    raw.File.LogicalPath,
				LogicalPath: raw.File.LogicalPath,
				BinaryName:  raw.File.LogicalPath,
			},
			Line: &line,
		})
	}
	return result, nil
}

func validSeverity(value string) bool {
	switch value {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

var ruleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func validRuleID(value string) bool {
	return ruleIDPattern.MatchString(value)
}
