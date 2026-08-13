// Package trivy provides the offline, vulnerability-only Trivy command
// boundary. It deliberately does not publish findings or interact with queues.
package trivy

import (
	"errors"
	"fmt"
	"time"
)

const rawReportFilename = "trivy-result.json"

var (
	ErrInvalidConfiguration = errors.New("trivy adapter configuration is invalid")
	ErrInvalidInput         = errors.New("trivy adapter input is invalid")
	ErrExecutionFailed      = errors.New("trivy execution failed")
	ErrOutputLimit          = errors.New("trivy output limit exceeded")
	ErrInvalidReport        = errors.New("trivy report is invalid")
	ErrMultiPlatform        = errors.New("multi-platform OCI layout requires explicit platform selection")
)

// SourceKind is the already-verified container archive representation.
type SourceKind string

const (
	SourceDockerSaveTAR SourceKind = "docker-save-tar"
	SourceOCILayout     SourceKind = "oci-layout"
	SourceVMImage       SourceKind = "vm-image"
)

// VerifiedSource can only be created by the verification constructors in this
// package. The adapter repeats the structural check immediately before use.
type VerifiedSource struct {
	path           string
	kind           SourceKind
	manifestDigest string
}

// Path returns the canonical filesystem path accepted by the verifier.
func (s VerifiedSource) Path() string {
	return s.path
}

// Kind returns the verified source representation.
func (s VerifiedSource) Kind() SourceKind {
	return s.kind
}

// ManifestDigest returns the explicitly selected OCI index descriptor. It is
// empty for Docker Save TAR inputs.
func (s VerifiedSource) ManifestDigest() string {
	return s.manifestDigest
}

// Config fixes every path and resource limit controlled by the adapter.
type Config struct {
	Executable             string
	InputRoots             []string
	CacheDirectory         string
	WorkRoot               string
	MaxDuration            time.Duration
	TerminationGracePeriod time.Duration
	MaxStandardOutputBytes int64
	MaxStandardErrorBytes  int64
	MaxReportBytes         int64
	// MaxWorkBytes bounds conservative filesystem usage below WorkRoot. Regular
	// files are charged the larger of logical and allocated bytes plus metadata;
	// zero disables monitoring for callers without a task-level budget.
	MaxWorkBytes int64
	MaxResults   int
	MaxFindings  int
}

// Request contains no arbitrary cache or output path. WorkDirectory must be an
// existing task-local directory below Config.WorkRoot.
type Request struct {
	Source        VerifiedSource
	WorkDirectory string
}

// Finding is the normalized vulnerability evidence retained from Trivy.
type Finding struct {
	VulnerabilityID    string     `json:"vulnerability_id"`
	Severity           string     `json:"severity"`
	PackageName        string     `json:"package_name"`
	PackagePath        string     `json:"package_path,omitempty"`
	InstalledVersion   string     `json:"installed_version"`
	FixedVersion       string     `json:"fixed_version,omitempty"`
	Title              string     `json:"title,omitempty"`
	DescriptionSummary string     `json:"description_summary,omitempty"`
	Target             string     `json:"target"`
	Class              string     `json:"class"`
	Type               string     `json:"type"`
	DataSource         DataSource `json:"data_source,omitempty"`
	References         []string   `json:"references"`
}

// DataSource identifies the frozen advisory feed used by Trivy. URL is
// retained as offline report metadata only; the worker never resolves it.
type DataSource struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// RawReportMetadata describes the bounded raw Trivy JSON kept in the task work
// directory. The raw JSON itself is not copied into memory-backed domain data.
type RawReportMetadata struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	SizeBytes     int64  `json:"size_bytes"`
	SchemaVersion int    `json:"schema_version"`
	ArtifactName  string `json:"artifact_name"`
	ArtifactType  string `json:"artifact_type"`
	ResultCount   int    `json:"result_count"`
	FindingCount  int    `json:"finding_count"`
}

// Report is a successful Trivy invocation, whether or not vulnerabilities were
// found. A non-zero Trivy exit status is returned as an error instead.
type Report struct {
	Findings []Finding         `json:"findings"`
	Raw      RawReportMetadata `json:"raw_report"`
}

// ExecutionError is a bounded diagnostic for a non-zero Trivy exit status.
type ExecutionError struct {
	ExitCode int
	Stderr   string
}

func (e *ExecutionError) Error() string {
	return fmt.Sprintf("trivy exited with status %d", e.ExitCode)
}

func (e *ExecutionError) Unwrap() error {
	return ErrExecutionFailed
}
