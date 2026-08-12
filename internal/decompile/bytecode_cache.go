package decompile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"binaryscan/internal/bytecode"

	"golang.org/x/sys/unix"
)

const (
	bytecodeReuseContract            = "binaryscan-bytecode-reuse-v1"
	maxBytecodeCacheResults          = 3_000
	maxBytecodeCacheDiagnosticsBytes = 64 << 20
)

func bytecodeReuseIdentity(
	payload JobPayload,
	identity BytecodeAnalyzerIdentity,
	parameterKey string,
) (string, error) {
	if !sha256Pattern.MatchString(payload.Target.SHA256) ||
		payload.Target.SizeBytes == 0 || payload.Target.Format == "" ||
		!safeEngineVersion(identity.Engine.Name) ||
		!safeEngineVersion(identity.Engine.Version) ||
		!sha256Pattern.MatchString(identity.ParametersSHA256) ||
		!sha256Pattern.MatchString(parameterKey) {
		return "", ErrRequestConflict
	}
	digest := sha256.Sum256([]byte(
		bytecodeReuseContract + "\x00" + payload.Target.SHA256 + "\x00" +
			strconv.FormatUint(payload.Target.SizeBytes, 10) + "\x00" +
			payload.Target.Format + "\x00" + payload.Target.Architecture + "\x00" +
			payload.Engine.Target + "\x00" + identity.Engine.Name + "\x00" +
			identity.Engine.Version + "\x00" + identity.ParametersSHA256 + "\x00" +
			parameterKey,
	))
	return hex.EncodeToString(digest[:]), nil
}

func (p *BytecodeProcessor) materializeBytecodeCache(
	ctx context.Context,
	runID string,
	candidate BytecodeCacheCandidate,
	limits JobLimits,
) (PublishedSourceProject, []BytecodePublishedResult, func(), error) {
	if !validJobLimits(limits) || !uuidPattern.MatchString(runID) ||
		!validBytecodeCacheCandidate(candidate, limits) {
		return PublishedSourceProject{}, nil, func() {}, errBytecodeCacheInvalid
	}
	root, err := os.OpenRoot(p.config.RepositoryRoot)
	if err != nil {
		return PublishedSourceProject{}, nil, func() {}, err
	}
	defer root.Close()
	projectRoot := sourceProjectRoot(runID)
	publication, err := newSourceProjectPublication(
		p.config.RepositoryRoot, runID,
	)
	if err != nil {
		return PublishedSourceProject{}, nil, func() {}, err
	}
	defer publication.Close()
	cleanup := func() {
		cleanupSourceProject(p.config.RepositoryRoot, runID)
	}
	fail := func(err error) (PublishedSourceProject, []BytecodePublishedResult, func(), error) {
		err = errors.Join(err, publication.Close())
		cleanup()
		return PublishedSourceProject{}, nil, func() {}, err
	}
	values := make([]BytecodePublishedResult, 0, len(candidate.Results))
	manifestEntries := make([]bytecodeProjectEntry, 0, len(candidate.Results))
	usedPaths := make(map[string]struct{}, len(candidate.Results))
	var sourceBytes uint64
	for _, cached := range candidate.Results {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		id := bytecodeResultID(runID, cached.SymbolKey)
		logicalPath, pathErr := bytecodeCachedProjectPath(cached, id, usedPaths)
		if pathErr != nil {
			return fail(pathErr)
		}
		destinationKey := path.Join(projectRoot, logicalPath)
		if err := publication.MkdirAll(path.Dir(logicalPath)); err != nil {
			return fail(err)
		}
		digest, size, copyErr := copyVerifiedBytecodeCacheFile(
			ctx, root, publication, cached, logicalPath,
		)
		if copyErr != nil {
			return fail(copyErr)
		}
		values = append(values, BytecodePublishedResult{
			ID: id, SymbolKey: cached.SymbolKey, Language: cached.Language,
			Status: cached.Status, LogicalPath: logicalPath,
			StorageKey: destinationKey,
			SHA256:     digest, SizeBytes: size,
			Diagnostics: append([]byte(nil), cached.Diagnostics...),
		})
		manifestEntries = append(manifestEntries, bytecodeProjectEntry{
			ResultID: id, SymbolKey: cached.SymbolKey,
			BinaryName:  bytecodeCachedDiagnosticString(cached.Diagnostics, "binary_name"),
			DisplayName: bytecodeCachedDiagnosticString(cached.Diagnostics, "display_name"),
			Language:    cached.Language, Status: cached.Status,
			LogicalPath: logicalPath, SHA256: digest, SizeBytes: size,
		})
		if size > ^uint64(0)-sourceBytes {
			return fail(errBytecodeCacheInvalid)
		}
		sourceBytes += size
	}
	sourceKind, language := bytecodeProjectKind(values)
	manifest := bytecodeProjectManifest{
		SchemaVersion: "binaryscan-source-project/v1", ProjectID: runID,
		LayoutVersion: sourceProjectLayoutV1, SourceKind: sourceKind,
		Language: language, EngineName: p.identity.Engine.Name,
		EngineVersion: p.identity.Engine.Version,
		Status:        string(candidate.ResultStatus), SourceFileCount: len(values),
		SymbolCount: len(values), Files: manifestEntries,
	}
	manifestKey := path.Join(projectRoot, sourceProjectManifestName)
	manifestFile, err := writeProjectJSON(
		publication, sourceProjectManifestName, manifest,
	)
	if err != nil {
		return fail(err)
	}
	project := PublishedSourceProject{
		ID: runID, LayoutVersion: sourceProjectLayoutV1,
		SourceKind: sourceKind, Language: language,
		RootStorageKey: projectRoot, ManifestStorageKey: manifestKey,
		ManifestSHA256:    manifestFile.SHA256,
		ManifestSizeBytes: manifestFile.SizeBytes,
		SourceFileCount:   len(values), SymbolCount: len(values),
		SourceSizeBytes: sourceBytes,
	}
	if err := publication.Finalize(ctx); err != nil {
		return fail(err)
	}
	if err := publication.Close(); err != nil {
		return fail(err)
	}
	return project, values, cleanup, nil
}

func validBytecodeCacheCandidate(
	candidate BytecodeCacheCandidate,
	limits JobLimits,
) bool {
	if !uuidPattern.MatchString(candidate.RunID) ||
		!uuidPattern.MatchString(candidate.TaskID) || len(candidate.Results) == 0 ||
		len(candidate.Results) > bytecodeCacheResultLimit(limits) {
		return false
	}
	expectedStatus := ""
	switch candidate.ResultStatus {
	case bytecode.StatusComplete:
		expectedStatus = "complete"
	case bytecode.StatusBytecodeOnly:
		expectedStatus = "bytecode_only"
	default:
		return false
	}
	seen := make(map[string]struct{}, len(candidate.Results))
	var total uint64
	var diagnosticBytes uint64
	for _, result := range candidate.Results {
		if result.Status != expectedStatus ||
			!validBytecodeCachedResult(result) ||
			result.SizeBytes > uint64(limits.MaxOutputBytes)-total {
			return false
		}
		if _, exists := seen[result.SymbolKey]; exists {
			return false
		}
		seen[result.SymbolKey] = struct{}{}
		total += result.SizeBytes
		if uint64(len(result.Diagnostics)) >
			maxBytecodeCacheDiagnosticsBytes-diagnosticBytes {
			return false
		}
		diagnosticBytes += uint64(len(result.Diagnostics))
	}
	return sort.SliceIsSorted(candidate.Results, func(left, right int) bool {
		if candidate.Results[left].SymbolKey != candidate.Results[right].SymbolKey {
			return candidate.Results[left].SymbolKey < candidate.Results[right].SymbolKey
		}
		return candidate.Results[left].ID < candidate.Results[right].ID
	})
}

func bytecodeCacheResultLimit(limits JobLimits) int {
	if limits.MaxArtifacts < maxBytecodeCacheResults {
		return limits.MaxArtifacts
	}
	return maxBytecodeCacheResults
}

func validBytecodeCachedResult(value BytecodeCachedResult) bool {
	if !uuidPattern.MatchString(value.ID) || value.SymbolKey == "" ||
		len(value.SymbolKey) > 512 || !utf8.ValidString(value.SymbolKey) ||
		strings.ContainsRune(value.SymbolKey, 0) ||
		value.Language == "" ||
		len(value.Language) > 32 || !validASCIIBytecodeLanguage(value.Language) ||
		(value.Status != "complete" && value.Status != "bytecode_only") ||
		!sha256Pattern.MatchString(value.SHA256) || value.SizeBytes == 0 ||
		len(value.Diagnostics) == 0 ||
		len(value.Diagnostics) > maxBytecodeDiagnosticsBytes ||
		!utf8.Valid(value.Diagnostics) || !json.Valid(value.Diagnostics) {
		return false
	}
	return validBytecodeCacheStorageKey(value.StorageKey, value.ID, value.Status)
}

func validASCIIBytecodeLanguage(value string) bool {
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func bytecodeCachedDestinationName(value BytecodeCachedResult) (string, bool) {
	name := path.Base(value.StorageKey)
	switch value.Status {
	case "complete":
		extension := path.Ext(bytecodeSourceName(value.Language))
		return name, extension != "" && strings.EqualFold(path.Ext(name), extension)
	case "bytecode_only":
		if name == "bytecode.json" || name == "bytecode.txt" {
			return name, true
		}
	}
	return "", false
}

func validBytecodeCacheStorageKey(key string, resultID string, status string) bool {
	if key == "" || path.IsAbs(key) || path.Clean(key) != key ||
		strings.Contains(key, `\`) {
		return false
	}
	components := strings.Split(key, "/")
	legacy := len(components) == 3 && components[0] == "decompile" &&
		components[1] == resultID
	project := len(components) >= 4 && components[0] == sourceProjectRootName &&
		uuidPattern.MatchString(components[1])
	if !legacy && !project {
		return false
	}
	name := path.Base(key)
	if status == "bytecode_only" {
		return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".txt")
	}
	return path.Ext(name) != ""
}

func bytecodeCachedProjectPath(
	cached BytecodeCachedResult,
	resultID string,
	used map[string]struct{},
) (string, error) {
	binaryName := bytecodeCachedDiagnosticString(cached.Diagnostics, "binary_name")
	sourceFile := bytecodeCachedDiagnosticString(cached.Diagnostics, "source_file")
	classStatus := bytecode.ClassSource
	if cached.Status == "bytecode_only" {
		classStatus = bytecode.ClassBytecodeOnly
	}
	mediaType := "text/plain"
	switch strings.ToLower(cached.Language) {
	case "java":
		mediaType = "text/x-java-source"
	case "kotlin":
		mediaType = "text/x-kotlin-source"
	case "python":
		mediaType = "text/x-python"
	}
	if cached.Status == "bytecode_only" && strings.HasSuffix(cached.StorageKey, ".json") {
		mediaType = "application/json"
	}
	return bytecodeProjectPath(bytecode.ClassIndex{
		BinaryName: binaryName, SourceFile: sourceFile,
		Language: cached.Language, Status: classStatus,
	}, []bytecode.Artifact{{MediaType: mediaType}}, resultID, used)
}

func bytecodeCachedDiagnosticString(raw json.RawMessage, key string) string {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return ""
	}
	var value string
	_ = json.Unmarshal(values[key], &value)
	return value
}

func copyVerifiedBytecodeCacheFile(
	ctx context.Context,
	root *os.Root,
	publication *sourceProjectPublication,
	cached BytecodeCachedResult,
	destinationPath string,
) (string, uint64, error) {
	if !bytecodeCachePathHasNoSymlinks(root, cached.StorageKey) {
		return "", 0, errBytecodeCacheInvalid
	}
	expected, err := root.Lstat(cached.StorageKey)
	if err != nil || !expected.Mode().IsRegular() ||
		expected.Mode()&os.ModeSymlink != 0 ||
		expected.Mode().Perm()&0o077 != 0 ||
		expected.Size() < 1 || uint64(expected.Size()) != cached.SizeBytes {
		return "", 0, errBytecodeCacheInvalid
	}
	source, err := root.Open(cached.StorageKey)
	if err != nil {
		return "", 0, fmt.Errorf("%w: open cached artifact", errBytecodeCacheInvalid)
	}
	opened, statErr := source.Stat()
	if statErr != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(expected, opened) ||
		opened.Mode() != expected.Mode() ||
		uint64(opened.Size()) != cached.SizeBytes {
		source.Close()
		return "", 0, fmt.Errorf("%w: cached artifact changed", errBytecodeCacheInvalid)
	}
	var openedStat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &openedStat); err != nil ||
		openedStat.Mode&unix.S_IFMT != unix.S_IFREG ||
		openedStat.Nlink != 1 || openedStat.Size != opened.Size() {
		source.Close()
		return "", 0, fmt.Errorf(
			"%w: cached artifact link identity is invalid",
			errBytecodeCacheInvalid,
		)
	}
	destination, err := publication.CreateFile(destinationPath)
	if err != nil {
		source.Close()
		return "", 0, err
	}
	fail := func(value error) (string, uint64, error) {
		return "", 0, errors.Join(value, source.Close(), destination.Close())
	}
	hasher := sha256.New()
	validator := &utf8StreamValidator{}
	written, copyErr := io.Copy(
		io.MultiWriter(destination, hasher, validator),
		io.LimitReader(
			&contextReader{ctx: ctx, reader: source}, int64(cached.SizeBytes)+1,
		),
	)
	after, afterErr := source.Stat()
	var afterStat unix.Stat_t
	fstatErr := unix.Fstat(int(source.Fd()), &afterStat)
	if copyErr != nil || afterErr != nil || fstatErr != nil ||
		!sameBytecodeCacheFileIdentity(opened, openedStat, after, afterStat) ||
		uint64(after.Size()) != cached.SizeBytes ||
		uint64(written) != cached.SizeBytes ||
		hex.EncodeToString(hasher.Sum(nil)) != cached.SHA256 ||
		!validator.Valid() {
		return fail(fmt.Errorf(
			"%w: cached artifact content changed", errBytecodeCacheInvalid,
		))
	}
	if err := source.Close(); err != nil {
		return "", 0, errors.Join(errBytecodeCacheInvalid, err, destination.Close())
	}
	if err := destination.Commit(); err != nil {
		return "", 0, err
	}
	return cached.SHA256, cached.SizeBytes, nil
}

func sameBytecodeCacheFileIdentity(
	before os.FileInfo,
	beforeStat unix.Stat_t,
	after os.FileInfo,
	afterStat unix.Stat_t,
) bool {
	return before != nil && after != nil &&
		os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime()) &&
		beforeStat.Mode&unix.S_IFMT == unix.S_IFREG &&
		afterStat.Mode&unix.S_IFMT == unix.S_IFREG &&
		beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino &&
		beforeStat.Size == afterStat.Size &&
		beforeStat.Nlink == 1 && afterStat.Nlink == 1
}

func bytecodeCachePathHasNoSymlinks(root *os.Root, storageKey string) bool {
	components := strings.Split(storageKey, "/")
	if len(components) < 3 ||
		(components[0] != "decompile" && components[0] != sourceProjectRootName) {
		return false
	}
	for index := range components {
		current := path.Join(components[:index+1]...)
		info, err := root.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if index < len(components)-1 && !info.IsDir() {
			return false
		}
		if info.Mode().Perm()&0o077 != 0 {
			return false
		}
	}
	return true
}
