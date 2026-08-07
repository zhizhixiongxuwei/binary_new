package decompile

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxSourceArchiveResults = 3000
	maxSourceArchiveBytes   = 64 << 20
)

type sourceArchiveManifest struct {
	SchemaVersion     string                       `json:"schema_version"`
	TaskID            string                       `json:"task_id"`
	ExportGeneratedAt time.Time                    `json:"export_generated_at"`
	SourcePolicy      string                       `json:"source_policy"`
	ResultCount       int                          `json:"result_count"`
	SourceCount       int                          `json:"source_count"`
	CombinedPath      string                       `json:"combined_path,omitempty"`
	Items             []sourceArchiveManifestEntry `json:"items"`
}

type sourceArchiveManifestEntry struct {
	ResultID      string  `json:"result_id"`
	FileNodeID    string  `json:"file_node_id"`
	SymbolKey     string  `json:"symbol_key"`
	SymbolKind    string  `json:"symbol_kind"`
	DisplayName   string  `json:"display_name"`
	Location      string  `json:"location"`
	Signature     string  `json:"signature"`
	Language      string  `json:"language"`
	EngineName    string  `json:"engine_name"`
	EngineVersion string  `json:"engine_version"`
	Status        string  `json:"status"`
	SHA256        string  `json:"sha256,omitempty"`
	SizeBytes     *uint64 `json:"size_bytes"`
	ArchivePath   string  `json:"archive_path,omitempty"`
}

type preparedSourceArchiveEntry struct {
	result     Result
	descriptor SourceDescriptor
	name       string
}

func (s *Service) ExportSources(
	ctx context.Context,
	query SourceArchiveQuery,
) (archive SourceArchive, returnErr error) {
	if err := ctx.Err(); err != nil {
		return SourceArchive{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) {
		return SourceArchive{}, ErrInvalidInput
	}

	manifest, entries, err := s.prepareSourceArchive(ctx, query)
	if err != nil {
		return SourceArchive{}, err
	}
	if query.IncludeCombined && hasCSource(entries) {
		manifest.CombinedPath = "all-functions.c"
	}

	temporary, err := os.CreateTemp(
		s.repositoryRoot,
		".decompile-sources-*.zip",
	)
	if err != nil {
		return SourceArchive{}, fmt.Errorf("create source archive: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			returnErr = errors.Join(
				returnErr,
				temporary.Close(),
				os.Remove(temporaryPath),
			)
		}
	}()

	hasher := sha256.New()
	counter := &archiveByteCounter{}
	zipWriter := zip.NewWriter(io.MultiWriter(temporary, hasher, counter))
	if err := writeSourceArchiveManifest(zipWriter, manifest); err != nil {
		return SourceArchive{}, err
	}
	for _, entry := range entries {
		if err := s.writeSourceArchiveEntry(ctx, zipWriter, entry); err != nil {
			return SourceArchive{}, err
		}
	}
	if manifest.CombinedPath != "" {
		if err := s.writeCombinedCSource(ctx, zipWriter, entries); err != nil {
			return SourceArchive{}, err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return SourceArchive{}, fmt.Errorf("finalize source archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return SourceArchive{}, fmt.Errorf("sync source archive: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return SourceArchive{}, fmt.Errorf("rewind source archive: %w", err)
	}

	cleanup = false
	return SourceArchive{
		Content: &removingArchiveFile{
			File: temporary,
			path: temporaryPath,
		},
		Filename:    "binaryscan-" + query.TaskID + "-decompile-sources.zip",
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:   counter.bytes,
		ResultCount: manifest.ResultCount,
	}, nil
}

func (s *Service) prepareSourceArchive(
	ctx context.Context,
	query SourceArchiveQuery,
) (sourceArchiveManifest, []preparedSourceArchiveEntry, error) {
	manifest := sourceArchiveManifest{
		SchemaVersion:     "binaryscan-decompile-sources/v1",
		TaskID:            query.TaskID,
		ExportGeneratedAt: s.now().UTC(),
		SourcePolicy:      "current_task_repeatable_read_metadata_snapshot",
		Items:             []sourceArchiveManifestEntry{},
	}
	entries := make([]preparedSourceArchiveEntry, 0)
	var totalBytes uint64

	page, err := s.repository.List(ctx, ListQuery{
		TaskID: query.TaskID, PageSize: maxSourceArchiveResults,
	})
	if err != nil {
		return sourceArchiveManifest{}, nil, err
	}
	if page.HasMore {
		return sourceArchiveManifest{}, nil, ErrExportTooLarge
	}
	for _, result := range page.Items {
		item := sourceArchiveManifestEntry{
			ResultID: result.ID, FileNodeID: result.FileNodeID,
			SymbolKey: result.SymbolKey, SymbolKind: result.SymbolKind,
			DisplayName: result.DisplayName, Location: result.Location,
			Signature: result.Signature, Language: result.Language,
			EngineName:    result.EngineName,
			EngineVersion: result.EngineVersion, Status: result.Status,
			SizeBytes: result.SizeBytes,
		}
		if resultSupportsSource(result.Status) {
			descriptor := SourceDescriptor{
				ResultID: result.ID, Status: result.Status,
				StorageKey: result.StorageKey,
				SHA256:     result.ContentSHA256,
			}
			if result.SizeBytes != nil {
				descriptor.SizeBytes = *result.SizeBytes
				descriptor.SizeKnown = true
			}
			if err := validateSourceDescriptor(descriptor, SourceQuery{
				TaskID: query.TaskID, ResultID: result.ID,
			}); err != nil {
				return sourceArchiveManifest{}, nil, err
			}
			expandedBytes := descriptor.SizeBytes
			if expandedBytes > maxSourceArchiveBytes-totalBytes {
				return sourceArchiveManifest{}, nil, ErrExportTooLarge
			}
			if query.IncludeCombined && isCLanguage(result.Language) {
				combinedBytes := descriptor.SizeBytes +
					uint64(len(combinedSourceBanner(result))+2)
				if combinedBytes >
					maxSourceArchiveBytes-totalBytes-expandedBytes {
					return sourceArchiveManifest{}, nil, ErrExportTooLarge
				}
				expandedBytes += combinedBytes
			}
			totalBytes += expandedBytes
			item.SHA256 = descriptor.SHA256
			size := descriptor.SizeBytes
			item.SizeBytes = &size
			item.ArchivePath = sourceArchivePath(len(manifest.Items), result)
			entries = append(entries, preparedSourceArchiveEntry{
				result: result, descriptor: descriptor, name: item.ArchivePath,
			})
		}
		manifest.Items = append(manifest.Items, item)
	}

	manifest.ResultCount = len(manifest.Items)
	manifest.SourceCount = len(entries)
	if query.IncludeCombined && hasCSource(entries) {
		manifest.CombinedPath = "all-functions.c"
	}
	encodedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return sourceArchiveManifest{}, nil, err
	}
	if uint64(len(encodedManifest)+1) > maxSourceArchiveBytes-totalBytes {
		return sourceArchiveManifest{}, nil, ErrExportTooLarge
	}
	return manifest, entries, nil
}

func writeSourceArchiveManifest(
	writer *zip.Writer,
	manifest sourceArchiveManifest,
) error {
	header := &zip.FileHeader{Name: "manifest.json", Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = manifest.ExportGeneratedAt
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create source archive manifest: %w", err)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode source archive manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if _, err := entry.Write(encoded); err != nil {
		return fmt.Errorf("write source archive manifest: %w", err)
	}
	return nil
}

func (s *Service) writeSourceArchiveEntry(
	ctx context.Context,
	writer *zip.Writer,
	entry preparedSourceArchiveEntry,
) error {
	header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = entry.result.CreatedAt.UTC()
	target, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create source archive entry: %w", err)
	}
	return s.copyVerifiedSource(ctx, target, entry.descriptor)
}

func (s *Service) writeCombinedCSource(
	ctx context.Context,
	writer *zip.Writer,
	entries []preparedSourceArchiveEntry,
) error {
	header := &zip.FileHeader{Name: "all-functions.c", Method: zip.Deflate}
	header.SetMode(0o600)
	target, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create combined C source: %w", err)
	}
	for _, entry := range entries {
		if !isCLanguage(entry.result.Language) {
			continue
		}
		banner := combinedSourceBanner(entry.result)
		if _, err := io.WriteString(target, banner); err != nil {
			return fmt.Errorf("write combined C source banner: %w", err)
		}
		if err := s.copyVerifiedSource(ctx, target, entry.descriptor); err != nil {
			return err
		}
		if _, err := io.WriteString(target, "\n\n"); err != nil {
			return fmt.Errorf("separate combined C source: %w", err)
		}
	}
	return nil
}

func combinedSourceBanner(result Result) string {
	return fmt.Sprintf(
		"/* result %s | %s | %s */\n",
		result.ID,
		safeSourceComment(result.DisplayName),
		safeSourceComment(result.Location),
	)
}

func (s *Service) copyVerifiedSource(
	ctx context.Context,
	target io.Writer,
	descriptor SourceDescriptor,
) error {
	file, info, err := openRepositoryFile(
		ctx, s.repositoryRoot, descriptor.StorageKey,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	defer file.Close()
	if uint64(info.Size()) != descriptor.SizeBytes {
		return fmt.Errorf("%w: stored size does not match metadata", ErrSourceUnavailable)
	}
	if err := verifySourceSHA256(ctx, file, descriptor.SHA256); err != nil {
		return err
	}
	buffer := make([]byte, 256<<10)
	remaining := descriptor.SizeBytes
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		readSize := uint64(len(buffer))
		if readSize > remaining {
			readSize = remaining
		}
		read, readErr := file.Read(buffer[:readSize])
		if read > 0 {
			written, writeErr := target.Write(buffer[:read])
			if writeErr != nil {
				return fmt.Errorf("write source archive content: %w", writeErr)
			}
			if written != read {
				return io.ErrShortWrite
			}
			remaining -= uint64(read)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read source archive content: %w", readErr)
		}
		if read == 0 {
			return fmt.Errorf("%w: stored source ended early", ErrSourceUnavailable)
		}
	}
	return nil
}

func resultSupportsSource(status string) bool {
	switch status {
	case "complete", "partial", "bytecode_only":
		return true
	default:
		return false
	}
}

func sourceArchivePath(index int, result Result) string {
	stem := safeSourceFilename(result.DisplayName)
	if stem == "" {
		stem = safeSourceFilename(result.SymbolKey)
	}
	if stem == "" {
		stem = "symbol"
	}
	return fmt.Sprintf(
		"functions/%06d-%s-%s%s",
		index+1,
		stem,
		safeResultIDPrefix(result.ID),
		sourceExtension(result.Language),
	)
}

func safeResultIDPrefix(value string) string {
	value = strings.ReplaceAll(value, "-", "")
	if len(value) > 8 {
		value = value[:8]
	}
	value = safeSourceFilename(value)
	if value == "" {
		return "result"
	}
	return value
}

func safeSourceFilename(value string) string {
	var builder strings.Builder
	previousSeparator := false
	for _, character := range value {
		if builder.Len() >= 64 {
			break
		}
		allowed := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '-'
		if allowed {
			builder.WriteRune(character)
			previousSeparator = false
			continue
		}
		if !previousSeparator {
			builder.WriteByte('_')
			previousSeparator = true
		}
	}
	return strings.Trim(builder.String(), "._-")
}

func sourceExtension(language string) string {
	normalized := strings.ToLower(strings.TrimSpace(language))
	switch {
	case strings.Contains(normalized, "smali"):
		return ".smali"
	case strings.Contains(normalized, "java") &&
		!strings.Contains(normalized, "bytecode"):
		return ".java"
	case isCLanguage(normalized):
		return ".c"
	default:
		return ".txt"
	}
}

func isCLanguage(language string) bool {
	normalized := strings.ToLower(strings.TrimSpace(language))
	return normalized == "c" || strings.Contains(normalized, "pseudo-c") ||
		strings.Contains(normalized, "pseudo c")
}

func hasCSource(entries []preparedSourceArchiveEntry) bool {
	for _, entry := range entries {
		if isCLanguage(entry.result.Language) {
			return true
		}
	}
	return false
}

func safeSourceComment(value string) string {
	value = strings.ReplaceAll(value, "*/", "* /")
	var builder strings.Builder
	for _, character := range value {
		if unicode.IsControl(character) ||
			unicode.In(character, unicode.Cf) ||
			character == '\u2028' || character == '\u2029' {
			character = ' '
		}
		width := utf8.RuneLen(character)
		if width < 1 || builder.Len()+width > 512 {
			break
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

type archiveByteCounter struct {
	bytes uint64
}

func (counter *archiveByteCounter) Write(value []byte) (int, error) {
	counter.bytes += uint64(len(value))
	return len(value), nil
}

type removingArchiveFile struct {
	*os.File
	path string
}

func (file *removingArchiveFile) Close() error {
	return errors.Join(file.File.Close(), os.Remove(file.path))
}

var _ ReadSeekCloser = (*removingArchiveFile)(nil)
