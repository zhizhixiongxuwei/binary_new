package canalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrCheckerTransient       = errors.New("C checker request failed transiently")
	ErrCheckerRejected        = errors.New("C checker rejected the analysis")
	ErrCheckerInvalidResponse = errors.New("C checker returned an invalid response")
	ErrCheckerTimedOut        = errors.New("C checker analysis timed out")
)

const maxCheckerErrorResponseBytes int64 = 64 << 10

// CheckerRejection preserves the checker's bounded, validated error response.
// It still unwraps to ErrCheckerRejected for callers that only need the class.
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

type ClientConfig struct {
	BaseURL          string
	MaxDuration      time.Duration
	MaxResponseBytes int64
	MaxFindings      int
	MaxDiagnostics   int
	HTTPClient       *http.Client
}

type HTTPClient struct {
	baseURL          *url.URL
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
		return nil, errors.New("C checker URL is invalid")
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
	if config.MaxDuration <= 0 || config.MaxDuration > 10*time.Minute ||
		config.MaxResponseBytes <= 0 ||
		config.MaxResponseBytes > MaxResponseBytes ||
		config.MaxFindings < 1 || config.MaxFindings > MaxFindings ||
		config.MaxDiagnostics < 1 || config.MaxDiagnostics > MaxDiagnostics {
		return nil, errors.New("C checker client limits are invalid")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          8,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: config.MaxDuration,
				ExpectContinueTimeout: time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &HTTPClient{
		baseURL: parsed, maxDuration: config.MaxDuration,
		maxResponseBytes: config.MaxResponseBytes,
		maxFindings:      config.MaxFindings,
		maxDiagnostics:   config.MaxDiagnostics,
		client:           config.HTTPClient,
	}, nil
}

func (c *HTTPClient) Analyze(
	ctx context.Context,
	request AnalysisRequest,
) (Result, error) {
	if ctx == nil || request.Source == nil ||
		!validRequestMetadata(request.Metadata) {
		return Result{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	metadata, err := json.Marshal(request.Metadata)
	if err != nil {
		return Result{}, fmt.Errorf("encode C checker metadata: %w", err)
	}
	analysisCtx, cancel := context.WithTimeout(ctx, c.maxDuration)
	defer cancel()
	bodyReader, bodyWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(bodyWriter)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeMultipartAnalysis(
			bodyWriter, multipartWriter, metadata, request.Source,
		)
	}()
	httpRequest, err := http.NewRequestWithContext(
		analysisCtx,
		http.MethodPost,
		c.endpoint("/internal/v1/analyses/"+request.Metadata.AnalysisID),
		bodyReader,
	)
	if err != nil {
		bodyReader.CloseWithError(err)
		<-writeDone
		return Result{}, fmt.Errorf("create C checker request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("X-Content-Type-Options", "nosniff")
	response, requestErr := c.client.Do(httpRequest)
	if requestErr != nil {
		bodyReader.CloseWithError(requestErr)
	}
	writeErr := <-writeDone
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
	if writeErr != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, fmt.Errorf("%w: stream request: %v", ErrCheckerTransient, writeErr)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(
			response.Body, maxCheckerErrorResponseBytes+1,
		))
		if response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= 500 {
			return Result{}, fmt.Errorf(
				"%w: HTTP %d", ErrCheckerTransient, response.StatusCode,
			)
		}
		return Result{}, decodeCheckerRejection(response.StatusCode, body)
	}
	result, err := decodeCheckerResult(
		response.Body, c.maxResponseBytes, request.Metadata,
		c.maxFindings, c.maxDiagnostics,
	)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (c *HTTPClient) Cancel(ctx context.Context, analysisID string) error {
	if ctx == nil || !uuidPattern.MatchString(analysisID) {
		return ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodDelete,
		c.endpoint("/internal/v1/analyses/"+analysisID), nil,
	)
	if err != nil {
		return fmt.Errorf("create C checker cancellation: %w", err)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: cancel: %v", ErrCheckerTransient, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNoContent {
		if response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= 500 {
			return fmt.Errorf("%w: cancel HTTP %d", ErrCheckerTransient, response.StatusCode)
		}
		return fmt.Errorf("%w: cancel HTTP %d", ErrCheckerRejected, response.StatusCode)
	}
	return nil
}

func (c *HTTPClient) Ready(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, c.endpoint("/actuator/health/readiness"), nil,
	)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: readiness: %v", ErrCheckerTransient, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: readiness HTTP %d", ErrCheckerTransient, response.StatusCode)
	}
	return nil
}

func (c *HTTPClient) endpoint(suffix string) string {
	return strings.TrimSuffix(c.baseURL.String(), "/") + suffix
}

func writeMultipartAnalysis(
	pipe *io.PipeWriter,
	writer *multipart.Writer,
	metadata []byte,
	source io.Reader,
) (returnErr error) {
	defer func() {
		returnErr = errors.Join(returnErr, writer.Close(), pipe.CloseWithError(returnErr))
	}()
	metadataHeader := make(textproto.MIMEHeader)
	metadataHeader.Set(
		"Content-Disposition",
		`form-data; name="metadata"; filename="metadata.json"`,
	)
	metadataHeader.Set("Content-Type", "application/json")
	metadataPart, err := writer.CreatePart(metadataHeader)
	if err != nil {
		return err
	}
	if _, err := metadataPart.Write(metadata); err != nil {
		return err
	}
	sourceHeader := make(textproto.MIMEHeader)
	sourceHeader.Set(
		"Content-Disposition",
		`form-data; name="source"; filename="decompiled.c"`,
	)
	sourceHeader.Set("Content-Type", "application/octet-stream")
	sourcePart, err := writer.CreatePart(sourceHeader)
	if err != nil {
		return err
	}
	_, err = io.Copy(sourcePart, source)
	return err
}

func decodeCheckerRejection(statusCode int, raw []byte) error {
	rejection := &CheckerRejection{StatusCode: statusCode}
	if int64(len(raw)) > maxCheckerErrorResponseBytes {
		return rejection
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if decoder.Decode(&payload) != nil || requireJSONEnd(decoder) != nil ||
		!validSafeASCII(payload.Code, 128) ||
		!validText(payload.Message, 2048, false) {
		return rejection
	}
	rejection.Code = payload.Code
	rejection.Message = payload.Message
	return rejection
}

func decodeCheckerResult(
	reader io.Reader,
	maximum int64,
	request RequestMetadata,
	maxFindings int,
	maxDiagnostics int,
) (Result, error) {
	limited := &io.LimitedReader{R: reader, N: maximum + 1}
	raw, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, fmt.Errorf("%w: read response: %v", ErrCheckerTransient, err)
	}
	if int64(len(raw)) > maximum {
		return Result{}, fmt.Errorf("%w: response exceeds limit", ErrCheckerInvalidResponse)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result Result
	if err := decoder.Decode(&result); err != nil {
		return Result{}, fmt.Errorf("%w: decode: %v", ErrCheckerInvalidResponse, err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return Result{}, fmt.Errorf("%w: trailing content", ErrCheckerInvalidResponse)
	}
	if err := validateResult(result, request, maxFindings, maxDiagnostics); err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrCheckerInvalidResponse, err)
	}
	return result, nil
}

func validateResult(
	result Result,
	request RequestMetadata,
	maxFindings int,
	maxDiagnostics int,
) error {
	if result.SchemaVersion != ResponseSchemaVersion ||
		result.AnalysisID != request.AnalysisID ||
		result.Checker.Name != AnalyzerName ||
		result.Checker.Version != AnalyzerVersion ||
		result.Checker.RulesetVersion != DefaultRulesetVersion ||
		result.Findings == nil || result.Diagnostics == nil ||
		len(result.Findings) > maxFindings ||
		len(result.Diagnostics) > maxDiagnostics ||
		result.Summary.FindingCount != uint32(len(result.Findings)) ||
		result.Summary.DiagnosticCount != uint32(len(result.Diagnostics)) ||
		result.Coverage.TotalFunctions != uint32(len(request.Functions)) ||
		result.Coverage.ParsedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.FailedFunctions > result.Coverage.TotalFunctions ||
		result.Coverage.ParsedFunctions+result.Coverage.FailedFunctions >
			result.Coverage.TotalFunctions {
		return errors.New("response identity, summary, or coverage is invalid")
	}
	switch result.Status {
	case "succeeded", "partial":
	case "failed", "cancelled":
		if len(result.Findings) != 0 {
			return errors.New("failed or cancelled response contains findings")
		}
	default:
		return errors.New("response status is invalid")
	}
	functions := make(map[string]Function, len(request.Functions))
	for _, function := range request.Functions {
		functions[function.ResultID] = function
	}
	for _, finding := range result.Findings {
		function, ok := functions[finding.Function.ResultID]
		if !ok || function.Address != finding.Function.Address ||
			function.Name != finding.Function.Name ||
			!validFinding(finding, function) {
			return errors.New("finding is invalid")
		}
	}
	for _, diagnostic := range result.Diagnostics {
		if !validDiagnostic(diagnostic, functions) {
			return errors.New("diagnostic is invalid")
		}
	}
	return nil
}

func validRequestMetadata(value RequestMetadata) bool {
	if value.SchemaVersion != RequestSchemaVersion ||
		!uuidPattern.MatchString(value.AnalysisID) ||
		!uuidPattern.MatchString(value.ProjectID) ||
		!sha256Pattern.MatchString(value.CanonicalSHA256) ||
		value.CanonicalSizeBytes == 0 || value.CanonicalSizeBytes > uint64(MaxSourceBytes) ||
		(value.ProjectStatus != "complete" && value.ProjectStatus != "partial") ||
		!validSafeASCII(value.EngineName, 128) ||
		!validSafeASCII(value.EngineVersion, 128) || len(value.Functions) == 0 ||
		len(value.Functions) > MaxFunctions {
		return false
	}
	seen := make(map[string]struct{}, len(value.Functions))
	for _, function := range value.Functions {
		if !uuidPattern.MatchString(function.ResultID) ||
			!validText(function.Address, 128, false) ||
			!validText(function.Name, 512, false) ||
			!sha256Pattern.MatchString(function.SHA256) ||
			function.LengthBytes == 0 ||
			function.OffsetBytes > value.CanonicalSizeBytes ||
			function.LengthBytes > value.CanonicalSizeBytes-function.OffsetBytes ||
			function.StartLine == 0 || function.EndLine < function.StartLine {
			return false
		}
		if _, duplicate := seen[function.ResultID]; duplicate {
			return false
		}
		seen[function.ResultID] = struct{}{}
	}
	return true
}

var ruleCWEs = map[string]map[string]struct{}{
	"cwe-242-gets":             {"CWE-242": {}},
	"cwe-120-bounds":           {"CWE-120": {}},
	"cwe-134-format":           {"CWE-134": {}},
	"cwe-78-command":           {"CWE-78": {}},
	"cwe-787-oob-write":        {"CWE-787": {}},
	"cwe-125-oob-read":         {"CWE-125": {}},
	"cwe-562-stack-address":    {"CWE-562": {}},
	"cwe-590-invalid-free":     {"CWE-590": {}},
	"cwe-761-offset-free":      {"CWE-761": {}},
	"cwe-369-zero-divisor":     {"CWE-369": {}},
	"cwe-377-temp-file":        {"CWE-377": {}},
	"cwe-252-unchecked-return": {"CWE-252": {}},
	"cwe-131-size-calculation": {"CWE-131": {}},
	"cwe-327-328-weak-crypto":  {"CWE-327": {}, "CWE-328": {}},
	"cwe-732-permissions":      {"CWE-732": {}},
}

func validFinding(value Finding, function Function) bool {
	allowed, ok := ruleCWEs[value.RuleID]
	if !ok {
		return false
	}
	if _, ok := allowed[value.CWE]; !ok || !validSeverity(value.Severity) ||
		!validText(value.Message, 2048, false) ||
		len(value.Snippet) > 1024 || !validText(value.Snippet, 1024, true) ||
		value.Location.StartLine < function.StartLine ||
		value.Location.EndLine > function.EndLine ||
		value.Location.StartColumn == 0 || value.Location.EndColumn == 0 ||
		value.Location.EndLine < value.Location.StartLine ||
		(value.Location.EndLine == value.Location.StartLine &&
			value.Location.EndColumn < value.Location.StartColumn) {
		return false
	}
	return true
}

func validDiagnostic(value Diagnostic, functions map[string]Function) bool {
	if !validSafeASCII(value.Code, 128) || !validText(value.Message, 2048, false) {
		return false
	}
	if value.FunctionResultID == "" {
		return value.Line == nil || *value.Line > 0
	}
	function, ok := functions[value.FunctionResultID]
	if !ok {
		return false
	}
	return value.Line == nil ||
		(*value.Line >= function.StartLine && *value.Line <= function.EndLine)
}

func validText(value string, maximum int, allowEmpty bool) bool {
	if len(value) > maximum || !utf8.ValidString(value) || (!allowEmpty && value == "") {
		return false
	}
	for _, character := range value {
		if character == 0 || (unicode.IsControl(character) &&
			character != '\n' && character != '\r' && character != '\t') {
			return false
		}
	}
	return true
}

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
