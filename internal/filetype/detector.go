// Package filetype identifies supported binary, archive, and image formats from
// their contents. File names and extensions are deliberately not considered.
package filetype

import (
	"context"
	"errors"
	"io"
	"strings"
)

const (
	maxInspectionBytes = int64(16 << 20)
	maxSingleRead      = int64(8 << 20)
	maxCandidates      = 8
)

var supportedFormats = []string{
	"7z", "apk", "ar", "bzip2", "cab", "cpio", "deb", "dex",
	"docker-tar", "ear", "elf32", "elf64", "ext2", "ext3", "ext4",
	"gpt-img", "gzip", "iso9660", "jar", "java-class", "macho-fat",
	"macho-thin", "mbr-img", "oci-tar", "pe32", "pe32+", "pyc",
	"rar", "rpm", "squashfs", "tar", "udf", "war", "xz", "zip", "zstd",
}

// Result is the stable, content-derived description returned by Detector.
type Result struct {
	Format       string         `json:"format"`
	MIMEType     string         `json:"mime_type"`
	Architecture string         `json:"architecture"`
	Metadata     map[string]any `json:"metadata"`
}

type detectorFunc func(*boundedReader) (Result, bool, error)

type detectorDefinition struct {
	detect          detectorFunc
	candidateDetect detectorFunc
}

var contentDetectors = []detectorDefinition{
	{detect: detectPE},
	{detect: detectELF},
	{detect: detectJavaClass},
	{detect: detectMachO},
	{detect: detectDEX},
	{detect: detectPYC},
	{detect: detectZIP, candidateDetect: detectStrictZIPCandidate},
	{detect: detectTAR},
	{detect: detectAR},
	{detect: detectRPM},
	{detect: detectCPIO},
	{detect: detectCAB},
	{detect: detectGZIP},
	{detect: detectBZIP2},
	{detect: detectXZ},
	{detect: detectZSTD},
	{detect: detect7Z},
	{detect: detectRAR},
	{detect: detectSquashFS},
	{detect: detectExt},
	{detect: detectOpticalImage},
	{detect: detectDiskImage},
}

// MagicResult is the bounded result returned by an optional libmagic service.
// Format selection remains owned by the structural detectors; libmagic adds an
// independently maintained MIME classification and never weakens validation.
type MagicResult struct {
	MIMEType string
	Version  string
}

// MagicClassifier is implemented by the isolated archive sandbox client.
type MagicClassifier interface {
	Classify(context.Context, io.ReaderAt, int64) (MagicResult, error)
}

// Detector identifies files by magic bytes and minimum structural validation.
// A zero value uses only the built-in bounded structural parsers.
type Detector struct {
	magic MagicClassifier
}

// NewDetector enables libmagic enrichment through an isolated classifier.
func NewDetector(magic MagicClassifier) Detector {
	return Detector{magic: magic}
}

// Detect identifies the input without consulting its file name or extension.
func (detector Detector) Detect(source io.ReaderAt, size int64) (Result, error) {
	return detector.DetectContext(context.Background(), source, size)
}

// DetectContext identifies the input and enriches the result with libmagic
// evidence when a classifier was explicitly configured.
func (detector Detector) DetectContext(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("filetype: nil context")
	}
	if source == nil {
		return Result{}, errors.New("filetype: nil reader")
	}
	if size < 0 {
		return Result{}, errors.New("filetype: negative size")
	}
	reader := &boundedReader{source: source, size: size}
	for index, definition := range contentDetectors {
		result, found, err := definition.detect(reader)
		if err != nil {
			return Result{}, err
		}
		if found {
			if result.Metadata == nil {
				result.Metadata = map[string]any{}
			}
			addIdentificationCandidates(
				&result,
				reader,
				index,
			)
			return detector.enrichWithMagic(ctx, source, size, result)
		}
	}
	return detector.enrichWithMagic(ctx, source, size, unknownResult())
}

func (detector Detector) enrichWithMagic(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
	result Result,
) (Result, error) {
	if detector.magic == nil {
		return result, nil
	}
	classified, err := detector.magic.Classify(ctx, source, size)
	if err != nil {
		return Result{}, err
	}
	mime := strings.TrimSpace(classified.MIMEType)
	if !validMagicMIME(mime) {
		return Result{}, errors.New("filetype: libmagic returned an invalid MIME type")
	}
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	result.Metadata["libmagic"] = map[string]any{
		"mime_type": mime,
		"version":   classified.Version,
	}
	if result.Format == "unknown" && mime != "application/octet-stream" {
		result.MIMEType = mime
	}
	return result, nil
}

func validMagicMIME(value string) bool {
	if value == "" || len(value) > 255 || strings.Count(value, "/") != 1 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$&^_.+-/", character)) {
			return false
		}
	}
	return true
}

func unknownResult() Result {
	return Result{
		Format:   "unknown",
		MIMEType: "application/octet-stream",
		Metadata: map[string]any{
			"identification_candidates": []identificationCandidate{},
		},
	}
}

type boundedReader struct {
	source   io.ReaderAt
	size     int64
	consumed int64
}

func (r *boundedReader) readAt(offset, length int64) ([]byte, bool, error) {
	if !r.canRead(offset, length) {
		return nil, false, nil
	}
	buffer := make([]byte, int(length))
	count, err := r.source.ReadAt(buffer, offset)
	r.consumed += int64(count)
	if count == len(buffer) {
		return buffer, true, nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return nil, false, nil
	}
	return nil, false, err
}

// ReadAt lets bounded structural parsers share the detector's aggregate and
// per-read inspection budget instead of reaching through to the source.
func (r *boundedReader) ReadAt(buffer []byte, offset int64) (int, error) {
	length := int64(len(buffer))
	if length == 0 {
		return 0, nil
	}
	if !r.canRead(offset, length) {
		return 0, io.EOF
	}
	count, err := r.source.ReadAt(buffer, offset)
	r.consumed += int64(count)
	if count == len(buffer) {
		return count, err
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return count, err
}

func (r *boundedReader) canRead(offset, length int64) bool {
	return offset >= 0 &&
		length >= 0 &&
		length <= maxSingleRead &&
		offset <= r.size &&
		length <= r.size-offset &&
		r.consumed <= maxInspectionBytes &&
		length <= maxInspectionBytes-r.consumed
}

func result(format, mime, architecture string, metadata map[string]any) Result {
	if metadata == nil {
		metadata = map[string]any{}
	}
	return Result{
		Format:       format,
		MIMEType:     mime,
		Architecture: architecture,
		Metadata:     metadata,
	}
}
