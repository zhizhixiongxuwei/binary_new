// Package trivyhandoff defines the versioned scan-to-Trivy job contract.
package trivyhandoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	LegacySchemaVersion = 1
	SchemaVersion       = 2
	MaxSources          = 10
	maxPayloadBytes     = 64 << 10
	maxExpandedBytes    = int64(50 * 1024 * 1024 * 1024)
	maxArchiveRatio     = 100

	// FormatVMImage marks a raw disk-image or filesystem-image source that is
	// scanned with the Trivy vm subcommand instead of container archives.
	FormatVMImage = "vm-image"
)

var (
	ErrInvalidPayload = errors.New("Trivy handoff payload is invalid")
	sha256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// Source binds one logical image archive to an immutable repository blob.
type Source struct {
	Format           string `json:"format"`
	SourceStorageKey string `json:"source_storage_key"`
	SourceSHA256     string `json:"source_sha256"`
	SourceSizeBytes  int64  `json:"source_size_bytes"`
	ImageLogicalPath string `json:"image_logical_path"`
}

// Payload batches all automatically selected image archives under one task
// attempt. A single job is required because claiming another job advances the
// shared attempt fence.
type Payload struct {
	SchemaVersion    int      `json:"schema_version"`
	Sources          []Source `json:"sources"`
	MaxExpandedBytes int64    `json:"max_expanded_bytes"`
	MaxArchiveRatio  int      `json:"max_archive_ratio"`
	UpstreamPartial  bool     `json:"upstream_partial"`
}

type wireV1 struct {
	SchemaVersion    *int    `json:"schema_version"`
	Format           *string `json:"format"`
	SourceStorageKey *string `json:"source_storage_key"`
	SourceSHA256     *string `json:"source_sha256"`
	SourceSizeBytes  *int64  `json:"source_size_bytes"`
	ImageLogicalPath *string `json:"image_logical_path"`
	UpstreamPartial  *bool   `json:"upstream_partial"`
}

type wireSource struct {
	Format           *string `json:"format"`
	SourceStorageKey *string `json:"source_storage_key"`
	SourceSHA256     *string `json:"source_sha256"`
	SourceSizeBytes  *int64  `json:"source_size_bytes"`
	ImageLogicalPath *string `json:"image_logical_path"`
}

type wireV2 struct {
	SchemaVersion    *int          `json:"schema_version"`
	Sources          *[]wireSource `json:"sources"`
	MaxExpandedBytes *int64        `json:"max_expanded_bytes"`
	MaxArchiveRatio  *int          `json:"max_archive_ratio"`
	UpstreamPartial  *bool         `json:"upstream_partial"`
}

// Encode emits only the current schema and validates every source first.
func Encode(value Payload, maxSourceBytes int64, maxSources int) ([]byte, error) {
	value.SchemaVersion = SchemaVersion
	if err := Validate(value, maxSourceBytes, maxSources); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrInvalidPayload, err)
	}
	if len(raw) > maxPayloadBytes {
		return nil, fmt.Errorf("%w: payload is too large", ErrInvalidPayload)
	}
	return raw, nil
}

// Decode accepts legacy version one jobs and normalizes them to the batched
// in-memory representation. New writers always emit version two.
func Decode(raw []byte, maxSourceBytes int64, maxSources int) (Payload, error) {
	if len(raw) == 0 || len(raw) > maxPayloadBytes || !utf8.Valid(raw) {
		return Payload{}, fmt.Errorf(
			"%w: payload must be bounded UTF-8 JSON",
			ErrInvalidPayload,
		)
	}
	var header struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil ||
		header.SchemaVersion == nil {
		return Payload{}, fmt.Errorf(
			"%w: schema_version is required",
			ErrInvalidPayload,
		)
	}

	var value Payload
	switch *header.SchemaVersion {
	case LegacySchemaVersion:
		var wire wireV1
		if err := decodeExact(raw, &wire); err != nil {
			return Payload{}, err
		}
		if wire.SchemaVersion == nil || wire.Format == nil ||
			wire.SourceStorageKey == nil || wire.SourceSHA256 == nil ||
			wire.SourceSizeBytes == nil || wire.ImageLogicalPath == nil ||
			wire.UpstreamPartial == nil {
			return Payload{}, fmt.Errorf(
				"%w: every version one field is required",
				ErrInvalidPayload,
			)
		}
		value = Payload{
			SchemaVersion: LegacySchemaVersion,
			Sources: []Source{{
				Format:           *wire.Format,
				SourceStorageKey: *wire.SourceStorageKey,
				SourceSHA256:     *wire.SourceSHA256,
				SourceSizeBytes:  *wire.SourceSizeBytes,
				ImageLogicalPath: *wire.ImageLogicalPath,
			}},
			UpstreamPartial: *wire.UpstreamPartial,
		}
	case SchemaVersion:
		var wire wireV2
		if err := decodeExact(raw, &wire); err != nil {
			return Payload{}, err
		}
		if wire.SchemaVersion == nil || wire.Sources == nil ||
			wire.MaxExpandedBytes == nil || wire.MaxArchiveRatio == nil ||
			wire.UpstreamPartial == nil {
			return Payload{}, fmt.Errorf(
				"%w: every version two field is required",
				ErrInvalidPayload,
			)
		}
		value = Payload{
			SchemaVersion:    SchemaVersion,
			Sources:          make([]Source, 0, len(*wire.Sources)),
			MaxExpandedBytes: *wire.MaxExpandedBytes,
			MaxArchiveRatio:  *wire.MaxArchiveRatio,
			UpstreamPartial:  *wire.UpstreamPartial,
		}
		for _, source := range *wire.Sources {
			if source.Format == nil || source.SourceStorageKey == nil ||
				source.SourceSHA256 == nil || source.SourceSizeBytes == nil ||
				source.ImageLogicalPath == nil {
				return Payload{}, fmt.Errorf(
					"%w: every source field is required",
					ErrInvalidPayload,
				)
			}
			value.Sources = append(value.Sources, Source{
				Format:           *source.Format,
				SourceStorageKey: *source.SourceStorageKey,
				SourceSHA256:     *source.SourceSHA256,
				SourceSizeBytes:  *source.SourceSizeBytes,
				ImageLogicalPath: *source.ImageLogicalPath,
			})
		}
	default:
		return Payload{}, fmt.Errorf(
			"%w: unsupported schema version",
			ErrInvalidPayload,
		)
	}
	if err := Validate(value, maxSourceBytes, maxSources); err != nil {
		return Payload{}, err
	}
	return value, nil
}

// Validate checks the normalized current-schema representation.
func Validate(value Payload, maxSourceBytes int64, maxSources int) error {
	if (value.SchemaVersion != SchemaVersion &&
		value.SchemaVersion != LegacySchemaVersion) ||
		maxSourceBytes <= 0 ||
		maxSources <= 0 || maxSources > MaxSources ||
		len(value.Sources) == 0 || len(value.Sources) > maxSources {
		return fmt.Errorf(
			"%w: source count or schema is outside the contract",
			ErrInvalidPayload,
		)
	}
	switch value.SchemaVersion {
	case SchemaVersion:
		if value.MaxExpandedBytes <= 0 ||
			value.MaxExpandedBytes > maxExpandedBytes ||
			value.MaxArchiveRatio <= 0 ||
			value.MaxArchiveRatio > maxArchiveRatio {
			return fmt.Errorf(
				"%w: extraction limits are outside the contract",
				ErrInvalidPayload,
			)
		}
	case LegacySchemaVersion:
		if len(value.Sources) != 1 ||
			value.Sources[0].ImageLogicalPath != "/" ||
			value.MaxExpandedBytes != 0 ||
			value.MaxArchiveRatio != 0 {
			return fmt.Errorf(
				"%w: invalid legacy source contract",
				ErrInvalidPayload,
			)
		}
	}
	paths := make(map[string]struct{}, len(value.Sources))
	var totalSourceBytes int64
	for index, source := range value.Sources {
		if !validSourceFormat(source.Format) ||
			source.SourceSizeBytes <= 0 ||
			source.SourceSizeBytes > maxSourceBytes ||
			!sha256Pattern.MatchString(source.SourceSHA256) ||
			!validLogicalPath(source.ImageLogicalPath) {
			return fmt.Errorf(
				"%w: source %d is outside the supported contract",
				ErrInvalidPayload,
				index,
			)
		}
		expectedKey := path.Join(
			"blobs",
			"sha256",
			source.SourceSHA256[:2],
			source.SourceSHA256,
		)
		if source.SourceStorageKey != expectedKey ||
			path.IsAbs(source.SourceStorageKey) ||
			path.Clean(source.SourceStorageKey) != source.SourceStorageKey ||
			strings.Contains(source.SourceStorageKey, `\`) {
			return fmt.Errorf(
				"%w: source %d storage key is not canonical",
				ErrInvalidPayload,
				index,
			)
		}
		if _, duplicate := paths[source.ImageLogicalPath]; duplicate {
			return fmt.Errorf(
				"%w: duplicate image logical path",
				ErrInvalidPayload,
			)
		}
		paths[source.ImageLogicalPath] = struct{}{}
		if totalSourceBytes > int64(^uint64(0)>>1)-source.SourceSizeBytes {
			return fmt.Errorf(
				"%w: aggregate source size overflows",
				ErrInvalidPayload,
			)
		}
		totalSourceBytes += source.SourceSizeBytes
	}
	if value.SchemaVersion == SchemaVersion &&
		totalSourceBytes > value.MaxExpandedBytes {
		return fmt.Errorf(
			"%w: aggregate source size exceeds the extraction snapshot",
			ErrInvalidPayload,
		)
	}
	return nil
}

func decodeExact(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf(
			"%w: payload must contain one JSON value",
			ErrInvalidPayload,
		)
	}
	return nil
}

func validSourceFormat(format string) bool {
	return format == "docker-tar" || format == "oci-tar" ||
		format == FormatVMImage
}

func validLogicalPath(value string) bool {
	if !utf8.ValidString(value) || value == "" || !path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, `\`) ||
		utf8.RuneCountInString(value) > 2048 {
		return false
	}
	for _, character := range value {
		if character == 0 || character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
