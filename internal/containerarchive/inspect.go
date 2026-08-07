// Package containerarchive validates Docker Save and OCI image archives before
// they are handed to an external image scanner. Validation is content based,
// fail closed, and never extracts archive entries onto the host filesystem.
package containerarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

const (
	FormatDocker = "docker-tar"
	FormatOCI    = "oci-tar"

	defaultMaxEntries       = 100_000
	defaultMaxMetadataBytes = int64(16 << 20)
	defaultMaxDescriptors   = 100_000
	defaultMaxIndexDepth    = 8
	defaultMaxArchiveRatio  = 100
	maxTrailingZeroBytes    = int64(1 << 20)
	tarBlockBytes           = int64(512)
)

const (
	mediaOCIManifest       = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex          = "application/vnd.oci.image.index.v1+json"
	mediaDockerManifest    = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerManifestSet = "application/vnd.docker.distribution.manifest.list.v2+json"
)

var (
	sha256DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	platformPartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Limits bounds archive metadata work independently from the uploaded file
// size. Zero values are replaced by conservative defaults.
type Limits struct {
	MaxEntries       int
	MaxMetadataBytes int64
	MaxDescriptors   int
	MaxIndexDepth    int
	MaxArchiveRatio  int
}

// Platform is the scanner-visible operating system and CPU tuple.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p Platform) String() string {
	value := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		value += "/" + p.Variant
	}
	return value
}

func validImageReference(value string) bool {
	if len(value) == 0 || len(value) > 512 ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e ||
			character == '\\' {
			return false
		}
	}
	return true
}

// Target is one image manifest that must be scanned. OCI indexes always
// produce every leaf manifest instead of silently selecting the first one.
type Target struct {
	ManifestDigest string   `json:"manifest_digest,omitempty"`
	References     []string `json:"references"`
	Platform       Platform `json:"platform"`
}

// Inspection is the immutable scan plan derived from a validated archive.
type Inspection struct {
	Format     string   `json:"format"`
	EntryCount int      `json:"entry_count"`
	Targets    []Target `json:"targets"`
}

// Error is a stable, non-secret validation failure suitable for job metadata.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return e.Code + ": " + e.Message
}

type archiveEntry struct {
	offset int64
	size   int64
}

type archiveIndex struct {
	source  io.ReaderAt
	size    int64
	entries map[string]archiveEntry
	count   int
	limits  Limits
}

// Inspect validates the complete TAR envelope and then validates either the
// Docker Save or OCI descriptor graph. expectedFormat may be empty, but when
// provided it must be docker-tar or oci-tar and must match the archive.
func Inspect(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
	expectedFormat string,
	limits Limits,
) (Inspection, error) {
	if ctx == nil {
		return Inspection{}, errors.New("containerarchive: nil context")
	}
	if source == nil || size < 0 {
		return Inspection{}, errors.New("containerarchive: invalid source")
	}
	if expectedFormat != "" &&
		expectedFormat != FormatDocker &&
		expectedFormat != FormatOCI {
		return Inspection{}, errors.New("containerarchive: invalid expected format")
	}
	limits = normalizeLimits(limits)
	index, err := indexArchive(ctx, source, size, limits)
	if err != nil {
		return Inspection{}, err
	}

	_, hasDocker := index.entries["manifest.json"]
	_, hasLayout := index.entries["oci-layout"]
	_, hasOCIIndex := index.entries["index.json"]
	hasOCI := hasLayout || hasOCIIndex
	if hasDocker && hasOCI {
		if !hasLayout || !hasOCIIndex {
			return Inspection{}, validationError(
				"oci_layout_incomplete",
				"OCI archive requires both oci-layout and index.json",
			)
		}
		if expectedFormat == "" {
			return Inspection{}, validationError(
				"container_archive_ambiguous",
				"archive contains both Docker Save and OCI root metadata",
			)
		}
	}

	var inspection Inspection
	switch {
	case hasDocker && hasLayout && hasOCIIndex &&
		expectedFormat == FormatDocker:
		inspection, err = inspectDocker(ctx, index)
	case hasDocker && hasLayout && hasOCIIndex &&
		expectedFormat == FormatOCI:
		inspection, err = inspectOCI(ctx, index)
	case hasDocker:
		inspection, err = inspectDocker(ctx, index)
	case hasLayout && hasOCIIndex:
		inspection, err = inspectOCI(ctx, index)
	case hasLayout || hasOCIIndex:
		err = validationError(
			"oci_layout_incomplete",
			"OCI archive requires both oci-layout and index.json",
		)
	default:
		err = validationError(
			"container_archive_unrecognized",
			"TAR does not contain a validated Docker Save or OCI layout",
		)
	}
	if err != nil {
		return Inspection{}, err
	}
	if expectedFormat != "" && inspection.Format != expectedFormat {
		return Inspection{}, validationError(
			"container_archive_format_mismatch",
			"archive structure does not match the identified format",
		)
	}
	inspection.EntryCount = index.count
	return inspection, nil
}

func normalizeLimits(limits Limits) Limits {
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaultMaxEntries
	}
	if limits.MaxMetadataBytes == 0 {
		limits.MaxMetadataBytes = defaultMaxMetadataBytes
	}
	if limits.MaxDescriptors == 0 {
		limits.MaxDescriptors = defaultMaxDescriptors
	}
	if limits.MaxIndexDepth == 0 {
		limits.MaxIndexDepth = defaultMaxIndexDepth
	}
	if limits.MaxArchiveRatio == 0 {
		limits.MaxArchiveRatio = defaultMaxArchiveRatio
	}
	return limits
}

func indexArchive(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
	limits Limits,
) (*archiveIndex, error) {
	if limits.MaxEntries < 1 || limits.MaxEntries > defaultMaxEntries ||
		limits.MaxMetadataBytes < 1 ||
		limits.MaxMetadataBytes > 64<<20 ||
		limits.MaxDescriptors < 1 ||
		limits.MaxDescriptors > defaultMaxDescriptors ||
		limits.MaxIndexDepth < 1 || limits.MaxIndexDepth > 32 ||
		limits.MaxArchiveRatio < 1 ||
		limits.MaxArchiveRatio > defaultMaxArchiveRatio {
		return nil, errors.New("containerarchive: invalid limits")
	}
	if size < 2*tarBlockBytes || size%tarBlockBytes != 0 {
		return nil, validationError(
			"container_archive_invalid_tar",
			"archive must contain complete 512-byte TAR records",
		)
	}

	index := &archiveIndex{
		source: source, size: size, entries: make(map[string]archiveEntry),
		limits: limits,
	}
	offset := int64(0)
	zeroBlocks := 0
	for offset <= size-tarBlockBytes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var header [tarBlockBytes]byte
		if err := readAtFull(source, header[:], offset); err != nil {
			return nil, validationError(
				"container_archive_invalid_tar",
				"archive header could not be read",
			)
		}
		if allZero(header[:]) {
			zeroBlocks++
			offset += tarBlockBytes
			if zeroBlocks == 2 {
				break
			}
			continue
		}
		if zeroBlocks != 0 {
			return nil, validationError(
				"container_archive_invalid_tar",
				"non-zero TAR header follows an end marker",
			)
		}
		name, entrySize, typeFlag, err := parseHeader(header[:])
		if err != nil {
			return nil, err
		}
		index.count++
		if index.count > limits.MaxEntries {
			return nil, validationError(
				"container_archive_entry_limit",
				"archive entry count exceeds the configured limit",
			)
		}
		if _, exists := index.entries[name]; exists {
			return nil, validationError(
				"container_archive_duplicate_path",
				"archive contains a duplicate normalized path",
			)
		}
		switch typeFlag {
		case 0, '0':
			index.entries[name] = archiveEntry{
				offset: offset + tarBlockBytes,
				size:   entrySize,
			}
		case '5':
			if entrySize != 0 {
				return nil, validationError(
					"container_archive_invalid_tar",
					"directory entry declares a non-zero body",
				)
			}
			index.entries[name] = archiveEntry{offset: -1}
		default:
			return nil, validationError(
				"container_archive_unsafe_entry",
				"links, devices, extended headers, and special entries are not accepted",
			)
		}
		padded, ok := paddedSize(entrySize)
		if !ok || offset > size-tarBlockBytes-padded {
			return nil, validationError(
				"container_archive_invalid_tar",
				"archive entry extends beyond the input",
			)
		}
		offset += tarBlockBytes + padded
	}
	if zeroBlocks < 2 {
		return nil, validationError(
			"container_archive_invalid_tar",
			"archive is missing the two-block TAR end marker",
		)
	}
	trailing := size - offset
	if trailing > maxTrailingZeroBytes {
		return nil, validationError(
			"container_archive_trailing_limit",
			"archive trailing padding exceeds the configured safety limit",
		)
	}
	buffer := make([]byte, 32<<10)
	for offset < size {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		length := int64(len(buffer))
		if length > size-offset {
			length = size - offset
		}
		if err := readAtFull(source, buffer[:length], offset); err != nil ||
			!allZero(buffer[:length]) {
			return nil, validationError(
				"container_archive_trailing_data",
				"archive contains non-zero data after the TAR end marker",
			)
		}
		offset += length
	}
	return index, nil
}

func parseHeader(header []byte) (string, int64, byte, error) {
	if len(header) != int(tarBlockBytes) ||
		(!bytes.Equal(header[257:263], []byte("ustar\x00")) &&
			!bytes.Equal(header[257:263], []byte("ustar "))) {
		return "", 0, 0, validationError(
			"container_archive_invalid_tar",
			"archive requires a valid USTAR header",
		)
	}
	expected, ok := parseOctal(header[148:156])
	if !ok {
		return "", 0, 0, validationError(
			"container_archive_invalid_tar",
			"archive header checksum is invalid",
		)
	}
	var actual int64
	for index, value := range header {
		if index >= 148 && index < 156 {
			actual += int64(' ')
		} else {
			actual += int64(value)
		}
	}
	if expected != actual {
		return "", 0, 0, validationError(
			"container_archive_invalid_tar",
			"archive header checksum does not match",
		)
	}
	entrySize, ok := parseOctal(header[124:136])
	if !ok || entrySize < 0 {
		return "", 0, 0, validationError(
			"container_archive_invalid_tar",
			"archive entry size is invalid",
		)
	}
	name := cString(header[:100])
	prefix := cString(header[345:500])
	if prefix != "" {
		name = prefix + "/" + name
	}
	if header[156] == '5' {
		name = strings.TrimSuffix(name, "/")
	}
	if !safePath(name) {
		return "", 0, 0, validationError(
			"container_archive_unsafe_path",
			"archive contains an unsafe or non-canonical path",
		)
	}
	return name, entrySize, header[156], nil
}

func parseOctal(field []byte) (int64, bool) {
	value := strings.Trim(string(field), " \x00")
	if value == "" {
		return 0, true
	}
	if len(value) > 21 {
		return 0, false
	}
	for _, current := range value {
		if current < '0' || current > '7' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseInt(value, 8, 64)
	return parsed, err == nil
}

func cString(field []byte) string {
	if index := bytes.IndexByte(field, 0); index >= 0 {
		return string(field[:index])
	}
	return string(field)
}

func safePath(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, `\`) ||
		strings.ContainsRune(value, 0) {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func paddedSize(size int64) (int64, bool) {
	if size < 0 || size > (1<<63-1)-511 {
		return 0, false
	}
	return (size + 511) &^ 511, true
}

func (index *archiveIndex) regular(name string) (archiveEntry, error) {
	entry, found := index.entries[name]
	if !found || entry.offset < 0 {
		return archiveEntry{}, validationError(
			"container_archive_missing_blob",
			"container manifest references a missing regular archive entry",
		)
	}
	return entry, nil
}

func (index *archiveIndex) readMetadata(
	ctx context.Context,
	name string,
) ([]byte, error) {
	entry, err := index.regular(name)
	if err != nil {
		return nil, err
	}
	if entry.size > index.limits.MaxMetadataBytes {
		return nil, validationError(
			"container_archive_metadata_limit",
			"container metadata entry exceeds the configured limit",
		)
	}
	content := make([]byte, int(entry.size))
	if err := readAtFullContext(ctx, index.source, content, entry.offset); err != nil {
		return nil, err
	}
	return content, nil
}

func (index *archiveIndex) verifyDescriptor(
	ctx context.Context,
	descriptor descriptor,
) (string, error) {
	if !sha256DigestPattern.MatchString(descriptor.Digest) ||
		descriptor.Size < 0 {
		return "", validationError(
			"oci_descriptor_invalid",
			"OCI descriptor requires a lowercase SHA-256 digest and non-negative size",
		)
	}
	hexDigest := strings.TrimPrefix(descriptor.Digest, "sha256:")
	entry, err := index.regular("blobs/sha256/" + hexDigest)
	if err != nil {
		return "", err
	}
	if entry.size != descriptor.Size {
		return "", validationError(
			"oci_descriptor_size_mismatch",
			"OCI descriptor size does not match its blob",
		)
	}
	digest := sha256.New()
	reader := &contextReader{
		ctx: ctx,
		reader: io.NewSectionReader(
			index.source, entry.offset, entry.size,
		),
	}
	if _, err := io.CopyBuffer(digest, reader, make([]byte, 1<<20)); err != nil {
		return "", fmt.Errorf("verify OCI descriptor blob: %w", err)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != hexDigest {
		return "", validationError(
			"oci_descriptor_digest_mismatch",
			"OCI descriptor digest does not match its blob",
		)
	}
	return "blobs/sha256/" + hexDigest, nil
}

func decodeJSON(content []byte, destination any, code string) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(destination); err != nil {
		return validationError(code, "container metadata is not valid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return validationError(code, "container metadata contains trailing JSON values")
	}
	return nil
}

func validPlatform(platform Platform) bool {
	return platformPartPattern.MatchString(platform.OS) &&
		platformPartPattern.MatchString(platform.Architecture) &&
		(platform.Variant == "" || platformPartPattern.MatchString(platform.Variant))
}

func samePlatform(left, right Platform) bool {
	return left.OS == right.OS &&
		left.Architecture == right.Architecture &&
		left.Variant == right.Variant
}

func validationError(code string, message string) error {
	return &Error{Code: code, Message: message}
}

func readAtFull(source io.ReaderAt, destination []byte, offset int64) error {
	count, err := source.ReadAt(destination, offset)
	if count != len(destination) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func readAtFullContext(
	ctx context.Context,
	source io.ReaderAt,
	destination []byte,
	offset int64,
) error {
	const chunkBytes = 1 << 20
	for len(destination) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := len(destination)
		if length > chunkBytes {
			length = chunkBytes
		}
		if err := readAtFull(source, destination[:length], offset); err != nil {
			return fmt.Errorf("read container metadata: %w", err)
		}
		destination = destination[length:]
		offset += int64(length)
	}
	return nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(value []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(value)
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
