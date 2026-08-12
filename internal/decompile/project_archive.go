package decompile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	maxSourceProjectArchiveFiles   = 10_000
	maxSourceProjectArchiveBytes   = 256 << 20
	maxSourceProjectArchiveDepth   = 32
	maxSourceProjectArchiveEntries = 100_000
)

type sourceProjectArchiveFile struct {
	StorageKey string
	ArchiveKey string
	SizeBytes  uint64
	SHA256     string
}

type sourceProjectArchiveManifestDocument struct {
	SchemaVersion   string                              `json:"schema_version"`
	ProjectID       string                              `json:"project_id"`
	LayoutVersion   string                              `json:"layout_version"`
	SourceKind      string                              `json:"source_kind"`
	Language        string                              `json:"language"`
	EngineName      string                              `json:"engine_name"`
	EngineVersion   string                              `json:"engine_version"`
	Status          string                              `json:"status"`
	CanonicalSource *projectManifestFile                `json:"canonical_source,omitempty"`
	SourceFileCount uint64                              `json:"source_file_count"`
	SymbolCount     uint64                              `json:"symbol_count"`
	MetadataFiles   []projectManifestFile               `json:"metadata_files,omitempty"`
	Files           []sourceProjectArchiveManifestEntry `json:"files,omitempty"`
}

type sourceProjectArchiveManifestEntry struct {
	ResultID    string `json:"result_id"`
	SymbolKey   string `json:"symbol_key"`
	BinaryName  string `json:"binary_name"`
	DisplayName string `json:"display_name"`
	Language    string `json:"language"`
	Status      string `json:"status"`
	LogicalPath string `json:"logical_path,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	SizeBytes   uint64 `json:"size_bytes,omitempty"`
}

type legacyProjectArchiveManifest struct {
	SchemaVersion     string                             `json:"schema_version"`
	ProjectID         string                             `json:"project_id"`
	TaskID            string                             `json:"task_id"`
	LayoutVersion     string                             `json:"layout_version"`
	ExportGeneratedAt time.Time                          `json:"export_generated_at"`
	Items             []legacyProjectArchiveManifestItem `json:"items"`
}

type legacyProjectArchiveManifestItem struct {
	ResultID    string `json:"result_id"`
	SymbolKey   string `json:"symbol_key"`
	Language    string `json:"language"`
	Status      string `json:"status"`
	ArchivePath string `json:"archive_path"`
	SHA256      string `json:"sha256"`
	SizeBytes   uint64 `json:"size_bytes"`
}

func (s *Service) ExportProject(
	ctx context.Context,
	query SourceProjectArchiveQuery,
) (archive SourceArchive, returnErr error) {
	projectQuery := SourceProjectQuery{
		TaskID: query.TaskID, ProjectID: query.ProjectID,
	}
	if err := ctx.Err(); err != nil {
		return SourceArchive{}, err
	}
	if !validSourceProjectQuery(projectQuery) {
		return SourceArchive{}, ErrInvalidInput
	}
	repository, err := s.projectRepository()
	if err != nil {
		return SourceArchive{}, err
	}
	record, err := repository.GetSourceProject(ctx, projectQuery)
	if err != nil {
		return SourceArchive{}, err
	}

	temporary, err := createUnlinkedArchiveTemp(".source-project-*.zip")
	if err != nil {
		return SourceArchive{}, fmt.Errorf("create source project archive: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
	}()

	hasher := sha256.New()
	counter := &archiveByteCounter{}
	writer := zip.NewWriter(io.MultiWriter(temporary, hasher, counter))
	switch record.LayoutVersion {
	case SourceProjectLayoutV1:
		files, err := s.collectSourceProjectArchiveFiles(ctx, record)
		if err != nil {
			_ = writer.Close()
			return SourceArchive{}, err
		}
		for _, file := range files {
			if err := s.writeSourceProjectArchiveFile(
				ctx, writer, record.CreatedAt, file,
			); err != nil {
				_ = writer.Close()
				return SourceArchive{}, err
			}
		}
	case SourceProjectLayoutLegacyV1:
		if err := s.writeLegacySourceProjectArchive(
			ctx, writer, repository, record,
		); err != nil {
			_ = writer.Close()
			return SourceArchive{}, err
		}
	default:
		_ = writer.Close()
		return SourceArchive{}, ErrSourceUnavailable
	}
	if err := writer.Close(); err != nil {
		return SourceArchive{}, fmt.Errorf("finalize source project archive: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return SourceArchive{}, fmt.Errorf("sync source project archive: %w", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return SourceArchive{}, fmt.Errorf("rewind source project archive: %w", err)
	}
	if record.SymbolCount > math.MaxInt {
		return SourceArchive{}, ErrExportTooLarge
	}
	cleanup = false
	return SourceArchive{
		Content:  &removingArchiveFile{File: temporary},
		Filename: "binaryscan-" + query.ProjectID + "-source-project.zip",
		SHA256:   hex.EncodeToString(hasher.Sum(nil)), SizeBytes: counter.bytes,
		ResultCount: int(record.SymbolCount),
	}, nil
}

func (s *Service) collectSourceProjectArchiveFiles(
	ctx context.Context,
	record sourceProjectRecord,
) ([]sourceProjectArchiveFile, error) {
	expectedRoot := sourceProjectRoot(record.ID)
	if record.RootStorageKey != expectedRoot ||
		record.ManifestStorageKey != path.Join(expectedRoot, sourceProjectManifestName) ||
		!record.ManifestSizeKnown || record.ManifestSizeBytes == 0 ||
		!sha256Pattern.MatchString(record.ManifestSHA256) {
		return nil, ErrSourceUnavailable
	}
	if record.CanonicalStorageKey != "" &&
		(!safeProjectStorageKey(record.CanonicalStorageKey, expectedRoot) ||
			!record.CanonicalSizeKnown || record.CanonicalSizeBytes == 0 ||
			!sha256Pattern.MatchString(record.CanonicalSHA256)) {
		return nil, ErrSourceUnavailable
	}
	expectedFiles, err := s.sourceProjectArchiveManifestFiles(ctx, record)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: open repository root: %v", ErrSourceUnavailable, err)
	}
	defer root.Close()
	if err := ensureProjectDirectory(root, expectedRoot); err != nil {
		return nil, fmt.Errorf("%w: inspect source project root: %v", ErrSourceUnavailable, err)
	}

	files := make([]sourceProjectArchiveFile, 0, len(expectedFiles))
	expectedDirectories := map[string]struct{}{"": {}}
	for relative := range expectedFiles {
		for directory := path.Dir(relative); directory != "."; directory = path.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	var totalBytes uint64
	entryCount := 0
	var visit func(string, int) error
	visit = func(relativeDirectory string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxSourceProjectArchiveDepth {
			return fmt.Errorf("%w: source project directory depth exceeded", ErrSourceUnavailable)
		}
		directoryKey := expectedRoot
		if relativeDirectory != "" {
			directoryKey = path.Join(expectedRoot, relativeDirectory)
		}
		directory, err := root.Open(directoryKey)
		if err != nil {
			return fmt.Errorf("%w: open source project directory: %v", ErrSourceUnavailable, err)
		}
		for {
			entries, readErr := directory.ReadDir(256)
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].Name() < entries[j].Name()
			})
			for _, entry := range entries {
				entryCount++
				if entryCount > maxSourceProjectArchiveEntries {
					_ = directory.Close()
					return ErrExportTooLarge
				}
				relative := path.Join(relativeDirectory, entry.Name())
				storageKey := path.Join(expectedRoot, relative)
				info, err := root.Lstat(storageKey)
				if err != nil {
					_ = directory.Close()
					return fmt.Errorf("%w: inspect source project entry: %v", ErrSourceUnavailable, err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					_ = directory.Close()
					return fmt.Errorf("%w: source project contains a symbolic link", ErrSourceUnavailable)
				}
				if info.IsDir() {
					if _, declared := expectedDirectories[relative]; !declared {
						_ = directory.Close()
						return fmt.Errorf("%w: source project contains an undeclared directory", ErrSourceUnavailable)
					}
					if err := visit(relative, depth+1); err != nil {
						_ = directory.Close()
						return err
					}
					continue
				}
				if !info.Mode().IsRegular() || info.Size() < 0 {
					_ = directory.Close()
					return fmt.Errorf("%w: source project contains a non-regular file", ErrSourceUnavailable)
				}
				expected, found := expectedFiles[relative]
				if !found || expected.StorageKey != storageKey ||
					expected.SizeBytes != uint64(info.Size()) {
					_ = directory.Close()
					return fmt.Errorf(
						"%w: source project contains an undeclared or changed file",
						ErrSourceUnavailable,
					)
				}
				if len(files) >= maxSourceProjectArchiveFiles ||
					uint64(info.Size()) > maxSourceProjectArchiveBytes-totalBytes {
					_ = directory.Close()
					return ErrExportTooLarge
				}
				totalBytes += uint64(info.Size())
				files = append(files, expected)
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = directory.Close()
				return fmt.Errorf(
					"%w: read source project directory: %v",
					ErrSourceUnavailable, readErr,
				)
			}
		}
		if err := directory.Close(); err != nil {
			return fmt.Errorf("%w: close source project directory: %v", ErrSourceUnavailable, err)
		}
		return nil
	}
	if err := visit("", 0); err != nil {
		return nil, err
	}
	if len(files) == 0 || len(files) != len(expectedFiles) {
		return nil, ErrSourceUnavailable
	}
	sort.Slice(files, func(left, right int) bool {
		return files[left].ArchiveKey < files[right].ArchiveKey
	})
	return files, nil
}

func (s *Service) sourceProjectArchiveManifestFiles(
	ctx context.Context,
	record sourceProjectRecord,
) (map[string]sourceProjectArchiveFile, error) {
	if record.ManifestSizeBytes > maxSourceProjectArchiveBytes ||
		record.SourceFileCount > maxSourceProjectArchiveFiles ||
		record.SymbolCount > math.MaxInt {
		return nil, ErrExportTooLarge
	}
	if !validSourceProjectKind(record.SourceKind) {
		return nil, ErrSourceUnavailable
	}
	file, info, err := openRepositoryFile(
		ctx, s.repositoryRoot, record.ManifestStorageKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: open source project manifest: %v", ErrSourceUnavailable, err)
	}
	defer file.Close()
	if info.Size() < 0 || uint64(info.Size()) != record.ManifestSizeBytes {
		return nil, fmt.Errorf("%w: source project manifest size changed", ErrSourceUnavailable)
	}
	var manifestBuffer bytes.Buffer
	manifestBuffer.Grow(int(record.ManifestSizeBytes))
	if err := copyVerifiedSourceSection(
		ctx, &manifestBuffer, file, info, 0,
		record.ManifestSizeBytes, record.ManifestSHA256,
	); err != nil {
		return nil, err
	}
	manifestBytes := manifestBuffer.Bytes()
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest sourceProjectArchiveManifestDocument
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("%w: decode source project manifest: %v", ErrSourceUnavailable, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: source project manifest has trailing data", ErrSourceUnavailable)
	}
	if manifest.SchemaVersion != "binaryscan-source-project/v1" ||
		manifest.ProjectID != record.ID || manifest.LayoutVersion != record.LayoutVersion ||
		manifest.SourceKind != record.SourceKind || manifest.Language != record.Language ||
		manifest.EngineName != record.EngineName ||
		manifest.EngineVersion != record.EngineVersion || manifest.Status != record.Status ||
		manifest.SourceFileCount != record.SourceFileCount ||
		manifest.SymbolCount != record.SymbolCount {
		return nil, fmt.Errorf("%w: source project manifest identity mismatch", ErrSourceUnavailable)
	}

	projectRoot := sourceProjectRoot(record.ID)
	expected := make(map[string]sourceProjectArchiveFile, record.SourceFileCount+4)
	addFile := func(relative string, digest string, size uint64) error {
		if !safeSourceProjectArchivePath(relative) || relative == sourceProjectManifestName ||
			!sha256Pattern.MatchString(digest) || size == 0 {
			return fmt.Errorf("%w: source project manifest file is invalid", ErrSourceUnavailable)
		}
		if _, exists := expected[relative]; exists {
			return fmt.Errorf("%w: source project manifest file is duplicated", ErrSourceUnavailable)
		}
		storageKey := path.Join(projectRoot, relative)
		if !safeProjectStorageKey(storageKey, projectRoot) {
			return fmt.Errorf("%w: source project manifest path is unsafe", ErrSourceUnavailable)
		}
		expected[relative] = sourceProjectArchiveFile{
			StorageKey: storageKey, ArchiveKey: relative,
			SizeBytes: size, SHA256: digest,
		}
		return nil
	}
	expected[sourceProjectManifestName] = sourceProjectArchiveFile{
		StorageKey: record.ManifestStorageKey, ArchiveKey: sourceProjectManifestName,
		SizeBytes: record.ManifestSizeBytes, SHA256: record.ManifestSHA256,
	}

	var sourceBytes uint64
	switch record.SourceKind {
	case SourceProjectKindGhidraPseudoC:
		if manifest.CanonicalSource == nil || len(manifest.Files) != 0 ||
			record.CanonicalStorageKey != path.Join(projectRoot, "src", "decompiled.c") ||
			manifest.CanonicalSource.Path != "src/decompiled.c" ||
			manifest.CanonicalSource.SHA256 != record.CanonicalSHA256 ||
			manifest.CanonicalSource.SizeBytes != record.CanonicalSizeBytes ||
			!record.CanonicalSizeKnown || manifest.SourceFileCount != 1 {
			return nil, fmt.Errorf("%w: canonical Ghidra source metadata mismatch", ErrSourceUnavailable)
		}
		if err := addFile(
			manifest.CanonicalSource.Path,
			manifest.CanonicalSource.SHA256,
			manifest.CanonicalSource.SizeBytes,
		); err != nil {
			return nil, err
		}
		sourceBytes = manifest.CanonicalSource.SizeBytes
		for _, metadata := range manifest.MetadataFiles {
			if !strings.HasPrefix(metadata.Path, "metadata/") {
				return nil, fmt.Errorf("%w: Ghidra metadata path is invalid", ErrSourceUnavailable)
			}
			if err := addFile(metadata.Path, metadata.SHA256, metadata.SizeBytes); err != nil {
				return nil, err
			}
		}
	case SourceProjectKindJava, SourceProjectKindKotlin,
		SourceProjectKindPython, SourceProjectKindBytecode:
		if manifest.CanonicalSource != nil || len(manifest.MetadataFiles) != 0 ||
			record.CanonicalStorageKey != "" || record.CanonicalSizeKnown ||
			len(manifest.Files) != int(manifest.SymbolCount) {
			return nil, fmt.Errorf("%w: bytecode source manifest shape is invalid", ErrSourceUnavailable)
		}
		var sourceFileCount uint64
		for _, entry := range manifest.Files {
			if entry.LogicalPath == "" {
				if entry.SHA256 != "" || entry.SizeBytes != 0 {
					return nil, fmt.Errorf("%w: empty project entry owns storage", ErrSourceUnavailable)
				}
				continue
			}
			if !strings.HasPrefix(entry.LogicalPath, "src/") &&
				!strings.HasPrefix(entry.LogicalPath, "artifacts/bytecode/") {
				return nil, fmt.Errorf("%w: bytecode project path is invalid", ErrSourceUnavailable)
			}
			if err := addFile(entry.LogicalPath, entry.SHA256, entry.SizeBytes); err != nil {
				return nil, err
			}
			if entry.SizeBytes > ^uint64(0)-sourceBytes {
				return nil, ErrExportTooLarge
			}
			sourceBytes += entry.SizeBytes
			sourceFileCount++
		}
		if sourceFileCount != manifest.SourceFileCount {
			return nil, fmt.Errorf("%w: source project file count mismatch", ErrSourceUnavailable)
		}
	default:
		return nil, fmt.Errorf("%w: source project kind is unsupported", ErrSourceUnavailable)
	}
	if sourceBytes != record.SourceSizeBytes ||
		len(expected) > maxSourceProjectArchiveFiles {
		return nil, fmt.Errorf("%w: source project size or file count mismatch", ErrSourceUnavailable)
	}
	return expected, nil
}

func safeSourceProjectArchivePath(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, `\`) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func (s *Service) writeSourceProjectArchiveFile(
	ctx context.Context,
	writer *zip.Writer,
	modified time.Time,
	entry sourceProjectArchiveFile,
) error {
	header := &zip.FileHeader{Name: entry.ArchiveKey, Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = modified.UTC()
	target, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create source project archive entry: %w", err)
	}
	file, info, err := openRepositoryFile(ctx, s.repositoryRoot, entry.StorageKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	defer file.Close()
	if info.Size() < 0 || uint64(info.Size()) != entry.SizeBytes {
		return fmt.Errorf("%w: source project file size changed", ErrSourceUnavailable)
	}
	return copyVerifiedSourceSection(
		ctx, target, file, info, 0, entry.SizeBytes, entry.SHA256,
	)
}

func ensureProjectDirectory(root *os.Root, key string) error {
	if validateStorageKey(key) != nil {
		return fmt.Errorf("%w: invalid source project storage key", ErrSourceUnavailable)
	}
	current := ""
	for _, component := range strings.Split(key, "/") {
		current = path.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: source project path is not a real directory", ErrSourceUnavailable)
		}
	}
	return nil
}

func (s *Service) writeLegacySourceProjectArchive(
	ctx context.Context,
	writer *zip.Writer,
	repository sourceProjectRepository,
	record sourceProjectRecord,
) error {
	entries, err := repository.ListLegacySourceProjectEntries(ctx, SourceProjectQuery{
		TaskID: record.TaskID, ProjectID: record.ID,
	})
	if err != nil {
		return err
	}
	if len(entries) == 0 || len(entries) > maxSourceProjectArchiveFiles {
		return ErrSourceUnavailable
	}
	manifest := legacyProjectArchiveManifest{
		SchemaVersion: "binaryscan-source-project-legacy-export/v1",
		ProjectID:     record.ID, TaskID: record.TaskID,
		LayoutVersion: record.LayoutVersion, ExportGeneratedAt: s.now().UTC(),
		Items: make([]legacyProjectArchiveManifestItem, 0, len(entries)),
	}
	prepared := make([]preparedSourceArchiveEntry, 0, len(entries))
	var totalBytes uint64
	for index, value := range entries {
		if err := validateSourceDescriptor(value.Descriptor, SourceQuery{
			TaskID: record.TaskID, ResultID: value.Result.ID,
		}); err != nil {
			return err
		}
		directory, err := legacySourceDirectory(value.Descriptor.StorageKey)
		if err != nil || directory != path.Join("decompile", value.Result.ID) {
			return fmt.Errorf(
				"%w: legacy source path does not match its result",
				ErrSourceUnavailable,
			)
		}
		if value.Descriptor.SizeBytes > maxSourceProjectArchiveBytes-totalBytes {
			return ErrExportTooLarge
		}
		totalBytes += value.Descriptor.SizeBytes
		archivePath := sourceArchivePath(index, value.Result)
		manifest.Items = append(manifest.Items, legacyProjectArchiveManifestItem{
			ResultID: value.Result.ID, SymbolKey: value.Result.SymbolKey,
			Language: value.Result.Language, Status: value.Result.Status,
			ArchivePath: archivePath, SHA256: value.Descriptor.SHA256,
			SizeBytes: value.Descriptor.SizeBytes,
		})
		prepared = append(prepared, preparedSourceArchiveEntry{
			result: value.Result, descriptor: value.Descriptor, name: archivePath,
		})
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode legacy source project manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if uint64(len(encoded)) > maxSourceProjectArchiveBytes-totalBytes {
		return ErrExportTooLarge
	}
	header := &zip.FileHeader{Name: "manifest.json", Method: zip.Deflate}
	header.SetMode(0o600)
	header.Modified = manifest.ExportGeneratedAt
	target, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("create legacy source project manifest: %w", err)
	}
	if _, err := target.Write(encoded); err != nil {
		return fmt.Errorf("write legacy source project manifest: %w", err)
	}
	for _, entry := range prepared {
		if err := s.writeSourceArchiveEntry(ctx, writer, entry); err != nil {
			return err
		}
	}
	return nil
}
