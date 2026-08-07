package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Status string

const (
	StatusSucceeded   Status = "succeeded"
	StatusPartial     Status = "partial"
	StatusFailed      Status = "failed"
	StatusCancelled   Status = "cancelled"
	StatusUnsupported Status = "unsupported"
)

const SchemaVersion = "1.0"

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Limits struct {
	MaxDuration            time.Duration
	MaxOutputBytes         int64
	MaxArtifacts           int
	MaxStandardOutputBytes int64
}

type Input struct {
	TaskID           string
	JobID            string
	Attempt          uint32
	FencingToken     uint64
	SourceStorageKey string
	SourceSHA256     string
	WorkDirectory    string
	Format           string
	Architecture     string
	Options          json.RawMessage
	Limits           Limits
}

type Artifact struct {
	Kind       string          `json:"kind"`
	MediaType  string          `json:"mediaType"`
	StorageKey string          `json:"storageKey"`
	SHA256     string          `json:"sha256"`
	SizeBytes  int64           `json:"size"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type Result struct {
	Status    Status
	Artifacts []Artifact
	Warnings  []string
	Errors    []Diagnostic
	Metrics   map[string]int64
}

type Descriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InputReference struct {
	StorageKey string `json:"storageKey"`
	SHA256     string `json:"sha256"`
}

type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
}

type Document struct {
	SchemaVersion string           `json:"schemaVersion"`
	Analyzer      Descriptor       `json:"analyzer"`
	Input         InputReference   `json:"input"`
	Status        Status           `json:"status"`
	Artifacts     []Artifact       `json:"artifacts"`
	Warnings      []string         `json:"warnings"`
	Errors        []Diagnostic     `json:"errors"`
	Metrics       map[string]int64 `json:"metrics,omitempty"`
}

type Adapter interface {
	Name() string
	Version() string
	Analyze(context.Context, Input) (Result, error)
}

func Execute(ctx context.Context, adapter Adapter, input Input) (Document, error) {
	if err := validateAdapter(adapter); err != nil {
		return Document{}, err
	}
	if err := input.Validate(); err != nil {
		return Document{}, err
	}
	if err := ctx.Err(); err != nil {
		return resultDocument(adapter, input, Result{Status: StatusCancelled}), err
	}

	runCtx, cancel := context.WithTimeout(ctx, input.Limits.MaxDuration)
	defer cancel()
	result, err := adapter.Analyze(runCtx, input)
	if contextErr := runCtx.Err(); contextErr != nil {
		return resultDocument(adapter, input, Result{Status: StatusCancelled}), contextErr
	}
	if err != nil {
		return resultDocument(adapter, input, result), fmt.Errorf("analyzer %s failed: %w", adapter.Name(), err)
	}
	if err := result.Validate(input.Limits); err != nil {
		return Document{}, fmt.Errorf("analyzer %s returned invalid result: %w", adapter.Name(), err)
	}
	document := resultDocument(adapter, input, result)
	if err := document.Validate(input.Limits); err != nil {
		return Document{}, fmt.Errorf("analyzer %s returned invalid document: %w", adapter.Name(), err)
	}
	return document, nil
}

func (i Input) Validate() error {
	var errs []error
	if strings.TrimSpace(i.TaskID) == "" || strings.TrimSpace(i.JobID) == "" {
		errs = append(errs, errors.New("task ID and job ID are required"))
	}
	if i.Attempt == 0 || i.FencingToken == 0 {
		errs = append(errs, errors.New("attempt and fencing token must be positive"))
	}
	if i.SourceStorageKey == "" || filepath.IsAbs(i.SourceStorageKey) || escapesRoot(i.SourceStorageKey) {
		errs = append(errs, errors.New("source storage key must be a safe relative path"))
	}
	if !sha256Pattern.MatchString(i.SourceSHA256) {
		errs = append(errs, errors.New("source SHA-256 must contain 64 lowercase hexadecimal characters"))
	}
	if !filepath.IsAbs(i.WorkDirectory) || filepath.Clean(i.WorkDirectory) == "/" {
		errs = append(errs, errors.New("work directory must be an absolute path below the filesystem root"))
	}
	if i.Limits.MaxDuration <= 0 || i.Limits.MaxOutputBytes <= 0 ||
		i.Limits.MaxArtifacts <= 0 || i.Limits.MaxStandardOutputBytes <= 0 {
		errs = append(errs, errors.New("all analyzer limits must be positive"))
	}
	if len(i.Options) != 0 && !json.Valid(i.Options) {
		errs = append(errs, errors.New("analyzer options must be valid JSON"))
	}
	return errors.Join(errs...)
}

func (r Result) Validate(limits Limits) error {
	switch r.Status {
	case StatusSucceeded, StatusPartial, StatusFailed, StatusCancelled, StatusUnsupported:
	default:
		return fmt.Errorf("unknown result status %q", r.Status)
	}
	if len(r.Artifacts) > limits.MaxArtifacts {
		return fmt.Errorf("artifact count %d exceeds limit %d", len(r.Artifacts), limits.MaxArtifacts)
	}
	var total int64
	for index, artifact := range r.Artifacts {
		if artifact.Kind == "" || artifact.MediaType == "" {
			return fmt.Errorf("artifact %d requires kind and media type", index)
		}
		if artifact.StorageKey == "" || filepath.IsAbs(artifact.StorageKey) || escapesRoot(artifact.StorageKey) {
			return fmt.Errorf("artifact %d has unsafe storage key", index)
		}
		if artifact.SizeBytes < 0 {
			return fmt.Errorf("artifact %d has negative size", index)
		}
		if !sha256Pattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("artifact %d has invalid SHA-256", index)
		}
		if artifact.SizeBytes > limits.MaxOutputBytes-total {
			return errors.New("artifact bytes exceed output limit")
		}
		total += artifact.SizeBytes
		if len(artifact.Metadata) != 0 && !json.Valid(artifact.Metadata) {
			return fmt.Errorf("artifact %d metadata is not valid JSON", index)
		}
	}
	for index, diagnostic := range r.Errors {
		if diagnostic.Code == "" || diagnostic.Message == "" {
			return fmt.Errorf("diagnostic %d requires code and message", index)
		}
	}
	return nil
}

func (d Document) Validate(limits Limits) error {
	if d.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported analyzer document schema %q", d.SchemaVersion)
	}
	if d.Analyzer.Name == "" || d.Analyzer.Version == "" {
		return errors.New("analyzer descriptor requires name and version")
	}
	if d.Input.StorageKey == "" || filepath.IsAbs(d.Input.StorageKey) || escapesRoot(d.Input.StorageKey) {
		return errors.New("document input storage key is unsafe")
	}
	if !sha256Pattern.MatchString(d.Input.SHA256) {
		return errors.New("document input SHA-256 is invalid")
	}
	return (Result{
		Status: d.Status, Artifacts: d.Artifacts, Warnings: d.Warnings,
		Errors: d.Errors, Metrics: d.Metrics,
	}).Validate(limits)
}

func resultDocument(adapter Adapter, input Input, result Result) Document {
	artifacts := result.Artifacts
	if artifacts == nil {
		artifacts = []Artifact{}
	}
	warnings := result.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	diagnostics := result.Errors
	if diagnostics == nil {
		diagnostics = []Diagnostic{}
	}
	return Document{
		SchemaVersion: SchemaVersion,
		Analyzer:      Descriptor{Name: adapter.Name(), Version: adapter.Version()},
		Input:         InputReference{StorageKey: input.SourceStorageKey, SHA256: input.SourceSHA256},
		Status:        result.Status, Artifacts: artifacts, Warnings: warnings,
		Errors: diagnostics, Metrics: result.Metrics,
	}
}

func validateAdapter(adapter Adapter) error {
	if adapter == nil {
		return errors.New("analyzer adapter is required")
	}
	if strings.TrimSpace(adapter.Name()) == "" || strings.TrimSpace(adapter.Version()) == "" {
		return errors.New("analyzer name and version are required")
	}
	return nil
}

func escapesRoot(path string) bool {
	cleaned := filepath.Clean(path)
	return cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator))
}
