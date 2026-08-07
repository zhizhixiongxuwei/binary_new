package bytecode

import (
	"context"
	"io"
	"time"
)

const SchemaVersion = "1.0"

type Format string

const (
	FormatClass Format = "class"
	FormatJAR   Format = "jar"
	FormatWAR   Format = "war"
	FormatEAR   Format = "ear"
	FormatDEX   Format = "dex"
	FormatAPK   Format = "apk"
	FormatPYC   Format = "pyc"
)

func (format Format) Valid() bool {
	switch format {
	case FormatClass, FormatJAR, FormatWAR, FormatEAR, FormatDEX, FormatAPK, FormatPYC:
		return true
	default:
		return false
	}
}

type Status string

const (
	StatusComplete     Status = "complete"
	StatusPartial      Status = "partial"
	StatusBytecodeOnly Status = "bytecode_only"
	StatusUnsupported  Status = "unsupported"
)

type ClassStatus string

const (
	ClassSource       ClassStatus = "source"
	ClassBytecodeOnly ClassStatus = "bytecode_only"
	ClassFailed       ClassStatus = "failed"
	ClassUnsupported  ClassStatus = "unsupported"
)

type ClassKind string

const (
	KindClass  ClassKind = "class"
	KindModule ClassKind = "module"
)

type ArtifactKind string

const (
	ArtifactSource      ArtifactKind = "source"
	ArtifactBytecode    ArtifactKind = "bytecode"
	ArtifactIndex       ArtifactKind = "index"
	ArtifactDiagnostics ArtifactKind = "diagnostics"
)

// ArtifactValidation describes evidence collected from the actual output
// file. A successful process exit is deliberately not a validation level.
type ArtifactValidation string

const (
	ValidationHashVerified    ArtifactValidation = "hash_verified"
	ValidationContentVerified ArtifactValidation = "content_verified"
)

type Descriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Input struct {
	Path      string `json:"-"`
	SHA256    string `json:"sha256"`
	Format    Format `json:"format"`
	SizeBytes int64  `json:"size_bytes"`
	verified  *verifiedInput
}

// VerifiedReader returns an independent logical view over the immutable input
// snapshot created by Execute. Engines must consume it before Decompile
// returns. The original caller-supplied path is intentionally unavailable to
// engines, so a path replacement cannot change the analyzed bytes.
func (input Input) VerifiedReader() (*io.SectionReader, error) {
	if input.verified == nil {
		return nil, ErrInvalidRequest
	}
	return input.verified.reader(input.SizeBytes)
}

type Limits struct {
	MaxDuration      time.Duration
	MaxInputBytes    int64
	MaxClasses       int
	MaxMethods       int
	MaxArtifacts     int
	MaxArtifactBytes int64
	MaxClassErrors   int
}

type Request struct {
	Input             Input
	Workspace         string
	Arguments         []string
	Limits            Limits
	ArtifactValidator ArtifactValidator
}

type SourceRange struct {
	StartLine uint32 `json:"start_line"`
	EndLine   uint32 `json:"end_line"`
}

type BytecodeRange struct {
	OffsetBytes uint64 `json:"offset_bytes"`
	SizeBytes   uint64 `json:"size_bytes"`
}

type MethodIndex struct {
	Key           string         `json:"key"`
	Name          string         `json:"name"`
	QualifiedName string         `json:"qualified_name,omitempty"`
	Descriptor    string         `json:"descriptor,omitempty"`
	Signature     string         `json:"signature,omitempty"`
	Source        *SourceRange   `json:"source,omitempty"`
	Bytecode      *BytecodeRange `json:"bytecode,omitempty"`
}

type ClassIndex struct {
	Key         string        `json:"key"`
	Kind        ClassKind     `json:"kind"`
	BinaryName  string        `json:"binary_name"`
	DisplayName string        `json:"display_name"`
	SourceFile  string        `json:"source_file,omitempty"`
	Language    string        `json:"language"`
	Status      ClassStatus   `json:"status"`
	ArtifactIDs []string      `json:"artifact_ids"`
	Methods     []MethodIndex `json:"methods"`
}

// ArtifactChunk identifies one member of a complete, zero-based shard set.
// Singleton artifacts use Index=0 and Count=1.
type ArtifactChunk struct {
	SetID string `json:"set_id"`
	Index uint32 `json:"index"`
	Count uint32 `json:"count"`
}

type Artifact struct {
	ID           string             `json:"id"`
	Kind         ArtifactKind       `json:"kind"`
	MediaType    string             `json:"media_type"`
	RelativePath string             `json:"relative_path"`
	SHA256       string             `json:"sha256"`
	SizeBytes    int64              `json:"size_bytes"`
	Validation   ArtifactValidation `json:"validation"`
	Chunk        ArtifactChunk      `json:"chunk"`
	ClassKeys    []string           `json:"class_keys"`
}

type ClassError struct {
	ClassKey string `json:"class_key"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type Execution struct {
	ExitCode    int   `json:"exit_code"`
	DurationMS  int64 `json:"duration_ms"`
	OutputBytes int64 `json:"output_bytes"`
	OutputFiles int   `json:"output_files"`
}

// Output is returned by an Engine. Execute validates and normalizes it before
// exposing a Result.
type Output struct {
	Status      Status       `json:"status"`
	Classes     []ClassIndex `json:"classes"`
	Artifacts   []Artifact   `json:"artifacts"`
	ClassErrors []ClassError `json:"class_errors"`
	Warnings    []string     `json:"warnings"`
	Execution   *Execution   `json:"execution,omitempty"`
}

type Result struct {
	SchemaVersion string       `json:"schema_version"`
	Engine        Descriptor   `json:"engine"`
	Input         Input        `json:"input"`
	CacheKey      string       `json:"cache_key"`
	Status        Status       `json:"status"`
	Classes       []ClassIndex `json:"classes"`
	Artifacts     []Artifact   `json:"artifacts"`
	ClassErrors   []ClassError `json:"class_errors"`
	Warnings      []string     `json:"warnings"`
	Execution     *Execution   `json:"execution,omitempty"`
}

// ArtifactValidator must inspect the actual artifact bytes. It must not infer
// validity from an engine exit code or from stdout text.
type ArtifactValidator interface {
	ValidateArtifact(
		ctx context.Context,
		workspace string,
		artifact Artifact,
	) (ArtifactValidation, error)
}
