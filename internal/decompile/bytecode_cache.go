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
) ([]BytecodePublishedResult, func(), error) {
	if !validJobLimits(limits) || !uuidPattern.MatchString(runID) ||
		!validBytecodeCacheCandidate(candidate, limits) {
		return nil, func() {}, errBytecodeCacheInvalid
	}
	root, err := os.OpenRoot(p.config.RepositoryRoot)
	if err != nil {
		return nil, func() {}, err
	}
	defer root.Close()
	if err := ensureNativeDirectory(root, "decompile"); err != nil {
		return nil, func() {}, err
	}

	directories := make([]string, 0, len(candidate.Results))
	cleanup := func() {
		cleanupRoot, openErr := os.OpenRoot(p.config.RepositoryRoot)
		if openErr != nil {
			return
		}
		defer cleanupRoot.Close()
		for _, directory := range directories {
			_ = cleanupRoot.RemoveAll(directory)
		}
	}
	values := make([]BytecodePublishedResult, 0, len(candidate.Results))
	for _, cached := range candidate.Results {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		id := bytecodeResultID(runID, cached.SymbolKey)
		directory := path.Join("decompile", id)
		if err := root.Mkdir(directory, 0o700); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		directories = append(directories, directory)
		name, ok := bytecodeCachedDestinationName(cached)
		if !ok {
			cleanup()
			return nil, func() {}, errBytecodeCacheInvalid
		}
		destinationKey := path.Join(directory, name)
		digest, size, copyErr := copyVerifiedBytecodeCacheFile(
			ctx, root, cached, destinationKey,
		)
		if copyErr != nil {
			cleanup()
			return nil, func() {}, copyErr
		}
		values = append(values, BytecodePublishedResult{
			ID: id, SymbolKey: cached.SymbolKey, Language: cached.Language,
			Status: cached.Status, StorageKey: destinationKey,
			SHA256: digest, SizeBytes: size,
			Diagnostics: append([]byte(nil), cached.Diagnostics...),
		})
	}
	return values, cleanup, nil
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
	expectedPrefix := path.Join("decompile", value.ID) + "/"
	return strings.HasPrefix(value.StorageKey, expectedPrefix) &&
		path.Clean(value.StorageKey) == value.StorageKey &&
		!strings.Contains(value.StorageKey, `\`)
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
		expected := bytecodeSourceName(value.Language)
		return expected, name == expected
	case "bytecode_only":
		if name == "bytecode.json" || name == "bytecode.txt" {
			return name, true
		}
	}
	return "", false
}

func copyVerifiedBytecodeCacheFile(
	ctx context.Context,
	root *os.Root,
	cached BytecodeCachedResult,
	destinationKey string,
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
	destination, err := root.OpenFile(
		destinationKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
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
	if err := destination.Sync(); err != nil {
		return "", 0, errors.Join(err, destination.Close())
	}
	destinationInfo, err := destination.Stat()
	if err != nil || !destinationInfo.Mode().IsRegular() ||
		destinationInfo.Mode().Perm()&0o077 != 0 ||
		uint64(destinationInfo.Size()) != cached.SizeBytes {
		return "", 0, errors.Join(errBytecodeCacheInvalid, err, destination.Close())
	}
	if err := destination.Close(); err != nil {
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
	if len(components) != 3 || components[0] != "decompile" {
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
