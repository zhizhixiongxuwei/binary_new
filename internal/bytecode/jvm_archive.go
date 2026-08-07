package bytecode

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	jvmZIPDirectoryHeaderSignature    = 0x02014b50
	jvmZIPDirectoryEndSignature       = 0x06054b50
	jvmZIP64DirectoryEndSignature     = 0x06064b50
	jvmZIP64DirectoryLocatorSignature = 0x07064b50

	jvmZIPDirectoryHeaderLength = 46
	jvmZIPEndLength             = 22
	jvmZIP64EndMinimumLength    = 56
	jvmZIP64LocatorLength       = 20
	jvmZIPMaximumCommentLength  = 1<<16 - 1
	jvmZIPMaximumDirectoryBytes = 64 << 20
	jvmMaximumManifestBytes     = 1 << 20
	jvmMaximumArchivePathBytes  = 8192
)

var (
	ErrUnsafeJVMArchive = errors.New("bytecode: unsafe JVM archive")
	ErrJVMArchiveLimit  = errors.New("bytecode: JVM archive limit exceeded")
	errJVMZIPEntryRead  = errors.New("bytecode: JVM ZIP entry read failed")
)

type jvmArchiveCandidate struct {
	entryPath         string
	logicalPath       string
	identityPath      string
	release           int
	file              *zip.File
	spool             *os.File
	spoolOffset       int64
	spoolSize         int64
	readFailureCode   string
	readFailureReason string
}

type jvmArchiveFailure struct {
	entryPath    string
	identityPath string
	code         string
	message      string
}

type jvmArchiveCandidateSet struct {
	candidates []jvmArchiveCandidate
	failures   []jvmArchiveFailure
	cleanup    func()
}

type jvmArchiveInspection struct {
	selected []jvmArchiveCandidate
	nested   []*zip.File
}

type jvmArchiveBudget struct {
	config        JVMEngineConfig
	rootSize      uint64
	entries       uint64
	expandedBytes uint64
}

type jvmArchiveScratch struct {
	directory string
	spool     *os.File
	spoolSize int64
}

type jvmZIPEndRecord struct {
	directoryEnd     int64
	directorySize    uint64
	directoryOffset  uint64
	directoryRecords uint64
}

func enumerateJVMArchive(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	config JVMEngineConfig,
) ([]jvmArchiveCandidate, error) {
	budget, err := newJVMArchiveBudget(config, size)
	if err != nil {
		return nil, err
	}
	inspection, err := inspectJVMArchive(ctx, reader, size, budget)
	if err != nil {
		return nil, err
	}
	for index := range inspection.selected {
		candidate := &inspection.selected[index]
		candidate.identityPath = encodeJVMArchiveIdentity(candidate.logicalPath)
	}
	return inspection.selected, nil
}

func enumerateNestedJVMArchives(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	config JVMEngineConfig,
	workspace string,
) (jvmArchiveCandidateSet, error) {
	budget, err := newJVMArchiveBudget(config, size)
	if err != nil {
		return jvmArchiveCandidateSet{}, err
	}
	scratch, err := newJVMArchiveScratch(workspace)
	if err != nil {
		return jvmArchiveCandidateSet{}, err
	}
	set := jvmArchiveCandidateSet{cleanup: scratch.cleanup}
	if err := walkJVMArchive(
		ctx, reader, size, 1, nil, budget, scratch, &set,
	); err != nil {
		scratch.cleanup()
		return jvmArchiveCandidateSet{}, err
	}
	sort.Slice(set.candidates, func(left, right int) bool {
		if set.candidates[left].identityPath != set.candidates[right].identityPath {
			return set.candidates[left].identityPath < set.candidates[right].identityPath
		}
		return set.candidates[left].entryPath < set.candidates[right].entryPath
	})
	sort.Slice(set.failures, func(left, right int) bool {
		return set.failures[left].identityPath < set.failures[right].identityPath
	})
	return set, nil
}

func walkJVMArchive(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	depth int,
	ancestry []string,
	budget *jvmArchiveBudget,
	scratch *jvmArchiveScratch,
	set *jvmArchiveCandidateSet,
) error {
	inspection, err := inspectJVMArchive(ctx, reader, size, budget)
	if err != nil {
		return err
	}
	for _, selected := range inspection.selected {
		rawEntryPath := selected.entryPath
		rawLogicalPath := selected.logicalPath
		sourceFile := selected.file
		entryPath, err := joinJVMArchivePath(ancestry, rawEntryPath)
		if err != nil {
			return err
		}
		logicalPath, err := joinJVMArchivePath(ancestry, rawLogicalPath)
		if err != nil {
			return err
		}
		selected.entryPath = entryPath
		selected.logicalPath = logicalPath
		selected.identityPath = encodeJVMArchiveIdentity(
			appendArchiveIdentity(ancestry, rawLogicalPath)...,
		)
		if depth > 1 {
			selected.file = nil
			offset, length, copyErr := scratch.spoolEntry(ctx, sourceFile)
			if copyErr != nil {
				if contextErr := ctx.Err(); contextErr != nil {
					return contextErr
				}
				if errors.Is(copyErr, errJVMZIPEntryRead) {
					selected.readFailureCode = "class_read_failed"
					selected.readFailureReason = "class bytes could not be read"
				} else {
					return copyErr
				}
			} else {
				selected.spool = scratch.spool
				selected.spoolOffset = offset
				selected.spoolSize = length
			}
		}
		set.candidates = append(set.candidates, selected)
	}
	for _, nested := range inspection.nested {
		childAncestry := appendArchiveIdentity(ancestry, nested.Name)
		entryPath, pathErr := joinJVMArchivePath(childAncestry, "")
		if pathErr != nil {
			return pathErr
		}
		identityPath := encodeJVMArchiveIdentity(childAncestry...)
		if depth >= budget.config.MaxArchiveDepth {
			set.failures = append(set.failures, jvmArchiveFailure{
				entryPath: entryPath, identityPath: identityPath,
				code:    "nested_archive_depth_exceeded",
				message: "nested JVM archive depth limit reached",
			})
			continue
		}
		temporary, materializeErr := scratch.materializeArchive(ctx, nested)
		if materializeErr != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			if errors.Is(materializeErr, errJVMZIPEntryRead) {
				set.failures = append(set.failures, jvmArchiveFailure{
					entryPath: entryPath, identityPath: identityPath,
					code:    "nested_archive_read_failed",
					message: "nested JVM archive bytes could not be read",
				})
				continue
			}
			return materializeErr
		}
		walkErr := walkJVMArchive(
			ctx, temporary, int64(nested.UncompressedSize64), depth+1,
			childAncestry, budget, scratch, set,
		)
		closeErr := temporary.Close()
		if closeErr != nil {
			return fmt.Errorf("clean nested JVM archive workspace")
		}
		if walkErr != nil {
			if errors.Is(walkErr, ErrUnsafeJVMArchive) {
				set.failures = append(set.failures, jvmArchiveFailure{
					entryPath: entryPath, identityPath: identityPath,
					code:    "nested_archive_invalid",
					message: "nested JVM archive is invalid",
				})
				continue
			}
			return walkErr
		}
	}
	return nil
}

func newJVMArchiveBudget(config JVMEngineConfig, rootSize int64) (*jvmArchiveBudget, error) {
	if rootSize < 0 {
		return nil, unsafeJVMArchive("ZIP size is invalid")
	}
	return &jvmArchiveBudget{config: config, rootSize: uint64(rootSize)}, nil
}

func inspectJVMArchive(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	budget *jvmArchiveBudget,
) (jvmArchiveInspection, error) {
	if budget == nil {
		return jvmArchiveInspection{}, unsafeJVMArchive("ZIP budget is missing")
	}
	maximumEntries := uint64(budget.config.MaxArchiveEntries)
	if budget.entries > maximumEntries {
		return jvmArchiveInspection{}, fmt.Errorf(
			"%w: entry count limit", ErrJVMArchiveLimit,
		)
	}
	remainingEntries := maximumEntries - budget.entries
	records, err := preflightJVMZIP(ctx, reader, size, remainingEntries)
	if err != nil {
		return jvmArchiveInspection{}, err
	}
	if records > remainingEntries {
		return jvmArchiveInspection{}, fmt.Errorf(
			"%w: entry count limit", ErrJVMArchiveLimit,
		)
	}
	budget.entries += records
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return jvmArchiveInspection{}, unsafeJVMArchive("ZIP directory cannot be parsed")
	}
	if uint64(len(archive.File)) != records {
		return jvmArchiveInspection{}, unsafeJVMArchive(
			"ZIP directory changed after preflight",
		)
	}
	byName := make(map[string]*zip.File, len(archive.File))
	for _, file := range archive.File {
		if err := ctx.Err(); err != nil {
			return jvmArchiveInspection{}, err
		}
		canonical, directory, validateErr := validateJVMZIPEntry(file)
		if validateErr != nil {
			return jvmArchiveInspection{}, validateErr
		}
		if _, exists := byName[canonical]; exists {
			return jvmArchiveInspection{}, unsafeJVMArchive(
				"ZIP entry path is duplicated",
			)
		}
		byName[canonical] = file
		maximumExpandedBytes := uint64(budget.config.MaxExpandedBytes)
		if budget.expandedBytes > maximumExpandedBytes ||
			file.UncompressedSize64 > maximumExpandedBytes-budget.expandedBytes {
			return jvmArchiveInspection{}, fmt.Errorf(
				"%w: expanded byte limit", ErrJVMArchiveLimit,
			)
		}
		budget.expandedBytes += file.UncompressedSize64
		if !directory && exceedsJVMCompressionRatio(
			file.UncompressedSize64,
			file.CompressedSize64,
			uint64(budget.config.MaxCompressionRatio),
		) {
			return jvmArchiveInspection{}, fmt.Errorf(
				"%w: compression ratio limit", ErrJVMArchiveLimit,
			)
		}
	}
	if exceedsJVMCompressionRatio(
		budget.expandedBytes,
		budget.rootSize,
		uint64(budget.config.MaxCompressionRatio),
	) {
		return jvmArchiveInspection{}, fmt.Errorf(
			"%w: cumulative compression ratio limit", ErrJVMArchiveLimit,
		)
	}
	multiRelease := false
	if manifest := byName["META-INF/MANIFEST.MF"]; manifest != nil {
		if manifest.UncompressedSize64 > jvmMaximumManifestBytes {
			return jvmArchiveInspection{}, fmt.Errorf(
				"%w: manifest byte limit", ErrJVMArchiveLimit,
			)
		}
		payload, readErr := readJVMZIPEntry(ctx, manifest, jvmMaximumManifestBytes)
		if readErr != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return jvmArchiveInspection{}, contextErr
			}
			return jvmArchiveInspection{}, unsafeJVMArchive("manifest cannot be read")
		}
		multiRelease = jvmManifestIsMultiRelease(payload)
	}
	selected := make(map[string]jvmArchiveCandidate)
	nested := make([]*zip.File, 0)
	for _, file := range archive.File {
		name := file.Name
		if strings.HasSuffix(name, "/") {
			continue
		}
		if isJVMNestedArchive(name) {
			nested = append(nested, file)
		}
		if !strings.HasSuffix(name, ".class") {
			continue
		}
		release, logicalPath, versioned := parseJVMVersionedPath(name)
		if versioned {
			if logicalPath == "" || !multiRelease ||
				release > budget.config.TargetJavaRelease {
				continue
			}
		} else {
			release = 0
			logicalPath = name
		}
		if file.UncompressedSize64 > uint64(budget.config.MaxClassBytes) {
			return jvmArchiveInspection{}, fmt.Errorf(
				"%w: class byte limit", ErrJVMArchiveLimit,
			)
		}
		candidate := jvmArchiveCandidate{
			entryPath: name, logicalPath: logicalPath, release: release, file: file,
		}
		current, exists := selected[logicalPath]
		if !exists || current.release < release {
			selected[logicalPath] = candidate
		}
	}
	inspection := jvmArchiveInspection{
		selected: make([]jvmArchiveCandidate, 0, len(selected)),
		nested:   nested,
	}
	for _, candidate := range selected {
		inspection.selected = append(inspection.selected, candidate)
	}
	sort.Slice(inspection.selected, func(left, right int) bool {
		if inspection.selected[left].logicalPath != inspection.selected[right].logicalPath {
			return inspection.selected[left].logicalPath <
				inspection.selected[right].logicalPath
		}
		return inspection.selected[left].entryPath < inspection.selected[right].entryPath
	})
	sort.Slice(inspection.nested, func(left, right int) bool {
		return inspection.nested[left].Name < inspection.nested[right].Name
	})
	return inspection, nil
}

func isJVMNestedArchive(name string) bool {
	extension := path.Ext(name)
	return strings.EqualFold(extension, ".jar") ||
		strings.EqualFold(extension, ".war") ||
		strings.EqualFold(extension, ".ear")
}

func appendArchiveIdentity(ancestry []string, value string) []string {
	result := make([]string, len(ancestry)+1)
	copy(result, ancestry)
	result[len(ancestry)] = value
	return result
}

func encodeJVMArchiveIdentity(segments ...string) string {
	var encoded strings.Builder
	for _, segment := range segments {
		encoded.WriteString(strconv.Itoa(len(segment)))
		encoded.WriteByte(':')
		encoded.WriteString(segment)
	}
	return encoded.String()
}

func joinJVMArchivePath(ancestry []string, leaf string) (string, error) {
	components := ancestry
	if leaf != "" {
		components = appendArchiveIdentity(ancestry, leaf)
	}
	escaped := make([]string, len(components))
	for index, component := range components {
		escaped[index] = strings.ReplaceAll(component, "!", "!!")
	}
	joined := strings.Join(escaped, "!/")
	if joined == "" || len(joined) > jvmMaximumArchivePathBytes {
		return "", fmt.Errorf("%w: archive path byte limit", ErrJVMArchiveLimit)
	}
	return joined, nil
}

func newJVMArchiveScratch(workspace string) (*jvmArchiveScratch, error) {
	directory, err := os.MkdirTemp(workspace, ".jvm-archive-")
	if err != nil {
		return nil, fmt.Errorf("create nested JVM archive workspace: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return nil, fmt.Errorf("protect nested JVM archive workspace: %w", err)
	}
	return &jvmArchiveScratch{directory: directory}, nil
}

func (scratch *jvmArchiveScratch) ensureSpool() error {
	if scratch.spool != nil {
		return nil
	}
	spool, err := os.CreateTemp(scratch.directory, "class-spool-*")
	if err != nil {
		return fmt.Errorf("create JVM class spool: %w", err)
	}
	if err := spool.Chmod(0o600); err != nil {
		path := spool.Name()
		_ = spool.Close()
		_ = os.Remove(path)
		return fmt.Errorf("protect JVM class spool: %w", err)
	}
	spoolPath := spool.Name()
	if err := os.Remove(spoolPath); err != nil {
		_ = spool.Close()
		_ = os.Remove(spoolPath)
		return fmt.Errorf("unlink JVM class spool: %w", err)
	}
	scratch.spool = spool
	return nil
}

func (scratch *jvmArchiveScratch) spoolEntry(
	ctx context.Context,
	entry *zip.File,
) (int64, int64, error) {
	if err := scratch.ensureSpool(); err != nil {
		return 0, 0, err
	}
	start := scratch.spoolSize
	if _, err := scratch.spool.Seek(start, io.SeekStart); err != nil {
		return 0, 0, fmt.Errorf("position JVM class spool: %w", err)
	}
	if err := copyJVMZIPEntry(ctx, entry, scratch.spool); err != nil {
		if truncateErr := scratch.spool.Truncate(start); truncateErr != nil {
			return 0, 0, fmt.Errorf("rollback JVM class spool: %w", truncateErr)
		}
		return 0, 0, err
	}
	length := int64(entry.UncompressedSize64)
	scratch.spoolSize += length
	return start, length, nil
}

func (scratch *jvmArchiveScratch) materializeArchive(
	ctx context.Context,
	entry *zip.File,
) (*os.File, error) {
	temporary, err := os.CreateTemp(scratch.directory, "nested-archive-*")
	if err != nil {
		return nil, fmt.Errorf("create nested JVM archive: %w", err)
	}
	path := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = temporary.Close()
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("protect nested JVM archive: %w", err)
	}
	if err := copyJVMZIPEntry(ctx, entry, temporary); err != nil {
		return nil, err
	}
	if info, statErr := temporary.Stat(); statErr != nil ||
		!info.Mode().IsRegular() || info.Size() != int64(entry.UncompressedSize64) {
		return nil, fmt.Errorf("validate nested JVM archive workspace")
	}
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("unlink nested JVM archive: %w", err)
	}
	keep = true
	return temporary, nil
}

func copyJVMZIPEntry(ctx context.Context, entry *zip.File, target io.Writer) error {
	if entry == nil || entry.UncompressedSize64 > math.MaxInt64 {
		return fmt.Errorf("%w: invalid entry size", errJVMZIPEntryRead)
	}
	source, err := entry.Open()
	if err != nil {
		return fmt.Errorf("%w: open entry", errJVMZIPEntryRead)
	}
	closed := false
	defer func() {
		if !closed {
			_ = source.Close()
		}
	}()
	remaining := int64(entry.UncompressedSize64)
	buffer := make([]byte, 64<<10)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		count, readErr := source.Read(buffer[:int(readSize)])
		if count > 0 {
			written, writeErr := target.Write(buffer[:count])
			if writeErr != nil {
				return fmt.Errorf("write JVM archive workspace: %w", writeErr)
			}
			if written != count {
				return io.ErrShortWrite
			}
			remaining -= int64(count)
		}
		if readErr != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			if errors.Is(readErr, io.EOF) && remaining == 0 {
				if closeErr := source.Close(); closeErr != nil {
					return fmt.Errorf("%w: close entry", errJVMZIPEntryRead)
				}
				closed = true
				return nil
			}
			return fmt.Errorf("%w: entry is truncated", errJVMZIPEntryRead)
		}
		if count == 0 {
			return fmt.Errorf("%w: entry made no progress", errJVMZIPEntryRead)
		}
	}
	var extra [1]byte
	count, tailErr := source.Read(extra[:])
	if count != 0 || !errors.Is(tailErr, io.EOF) {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("%w: entry size or checksum differs", errJVMZIPEntryRead)
	}
	if closeErr := source.Close(); closeErr != nil {
		return fmt.Errorf("%w: close entry", errJVMZIPEntryRead)
	}
	closed = true
	return nil
}

func (scratch *jvmArchiveScratch) cleanup() {
	if scratch == nil {
		return
	}
	if scratch.spool != nil {
		_ = scratch.spool.Close()
		scratch.spool = nil
	}
	_ = os.Remove(scratch.directory)
}

func validateJVMZIPEntry(file *zip.File) (string, bool, error) {
	if file == nil || file.Name == "" || len(file.Name) > jvmMaximumArchivePathBytes ||
		!utf8.ValidString(file.Name) || strings.IndexByte(file.Name, 0) >= 0 ||
		strings.Contains(file.Name, "\\") || strings.HasPrefix(file.Name, "/") {
		return "", false, unsafeJVMArchive("ZIP entry path is invalid")
	}
	directory := strings.HasSuffix(file.Name, "/")
	canonical := strings.TrimSuffix(file.Name, "/")
	if canonical == "" || path.Clean(canonical) != canonical ||
		strings.HasPrefix(canonical, "../") || canonical == ".." ||
		looksLikeJVMDrivePath(canonical) {
		return "", false, unsafeJVMArchive("ZIP entry path escapes its root")
	}
	for _, component := range strings.Split(canonical, "/") {
		if component == "" || component == "." || component == ".." {
			return "", false, unsafeJVMArchive("ZIP entry path is not canonical")
		}
	}
	mode := file.Mode()
	if directory {
		if !file.FileInfo().IsDir() || file.UncompressedSize64 != 0 {
			return "", false, unsafeJVMArchive("ZIP directory entry is invalid")
		}
	} else if mode&os.ModeType != 0 || file.FileInfo().IsDir() {
		return "", false, unsafeJVMArchive("ZIP special entry is unsupported")
	}
	if file.Flags&0x1 != 0 {
		return "", false, unsafeJVMArchive("encrypted ZIP entry is unsupported")
	}
	return canonical, directory, nil
}

func looksLikeJVMDrivePath(value string) bool {
	return len(value) >= 2 && value[1] == ':' &&
		((value[0] >= 'A' && value[0] <= 'Z') ||
			(value[0] >= 'a' && value[0] <= 'z'))
}

func exceedsJVMCompressionRatio(uncompressed, compressed, ratio uint64) bool {
	if uncompressed == 0 {
		return false
	}
	if compressed == 0 || ratio == 0 {
		return true
	}
	quotient := uncompressed / compressed
	return quotient > ratio ||
		(quotient == ratio && uncompressed%compressed != 0)
}

func parseJVMVersionedPath(name string) (int, string, bool) {
	const prefix = "META-INF/versions/"
	if !strings.HasPrefix(name, prefix) {
		return 0, name, false
	}
	remainder := strings.TrimPrefix(name, prefix)
	separator := strings.IndexByte(remainder, '/')
	if separator <= 0 || separator == len(remainder)-1 {
		return 0, "", true
	}
	versionText := remainder[:separator]
	if len(versionText) > 1 && versionText[0] == '0' {
		return 0, "", true
	}
	release, err := strconv.Atoi(versionText)
	if err != nil || release < 9 || release > 999 {
		return 0, "", true
	}
	logicalPath := remainder[separator+1:]
	if !strings.HasSuffix(logicalPath, ".class") ||
		path.Clean(logicalPath) != logicalPath {
		return 0, "", true
	}
	return release, logicalPath, true
}

func jvmManifestIsMultiRelease(payload []byte) bool {
	if !utf8.Valid(payload) || strings.IndexByte(string(payload), 0) >= 0 {
		return false
	}
	normalized := strings.ReplaceAll(string(payload), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	logicalLines := make([]string, 0)
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, " ") && len(logicalLines) > 0 {
			logicalLines[len(logicalLines)-1] += strings.TrimPrefix(line, " ")
			continue
		}
		logicalLines = append(logicalLines, line)
	}
	for _, line := range logicalLines {
		name, value, found := strings.Cut(line, ":")
		if found && strings.EqualFold(strings.TrimSpace(name), "Multi-Release") &&
			strings.EqualFold(strings.TrimSpace(value), "true") {
			return true
		}
	}
	return false
}

func readJVMZIPEntry(
	ctx context.Context,
	file *zip.File,
	maximum uint64,
) ([]byte, error) {
	if file == nil || file.UncompressedSize64 > maximum ||
		file.UncompressedSize64 > uint64(math.MaxInt) {
		return nil, ErrJVMArchiveLimit
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	payload := make([]byte, int(file.UncompressedSize64))
	_, readErr := io.ReadFull(&contextReader{ctx: ctx, reader: reader}, payload)
	if readErr == nil {
		var extra [1]byte
		count, tailErr := (&contextReader{ctx: ctx, reader: reader}).Read(extra[:])
		if count != 0 || !errors.Is(tailErr, io.EOF) {
			if tailErr != nil {
				readErr = tailErr
			} else {
				readErr = errors.New("ZIP entry is larger than declared")
			}
		}
	}
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return payload, nil
}

func preflightJVMZIP(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	maxEntries uint64,
) (uint64, error) {
	if ctx == nil || reader == nil || size < jvmZIPEndLength {
		return 0, unsafeJVMArchive("ZIP end record is missing")
	}
	end, err := readJVMZIPEnd(ctx, reader, size)
	if err != nil {
		return 0, err
	}
	if end.directorySize > jvmZIPMaximumDirectoryBytes {
		return 0, fmt.Errorf("%w: directory metadata limit", ErrJVMArchiveLimit)
	}
	if end.directorySize > uint64(end.directoryEnd) {
		return 0, unsafeJVMArchive("ZIP directory size is invalid")
	}
	directoryStart := uint64(end.directoryEnd) - end.directorySize
	if end.directoryOffset > directoryStart {
		return 0, unsafeJVMArchive("ZIP directory offset is invalid")
	}
	baseOffset := directoryStart - end.directoryOffset
	if baseOffset > math.MaxInt64 {
		return 0, unsafeJVMArchive("ZIP base offset is invalid")
	}
	if baseOffset > 0 {
		var signature [4]byte
		if err := readJVMZIPAt(
			ctx, reader, signature[:], int64(end.directoryOffset),
		); err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint32(signature[:]) ==
			jvmZIPDirectoryHeaderSignature {
			return 0, unsafeJVMArchive("ZIP directory base is ambiguous")
		}
	}
	actual, err := scanJVMZIPDirectory(
		ctx, reader, int64(directoryStart), end.directorySize, maxEntries,
	)
	if err != nil {
		return 0, err
	}
	if actual != end.directoryRecords {
		return 0, unsafeJVMArchive("ZIP entry count is inconsistent")
	}
	return actual, nil
}

func readJVMZIPEnd(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
) (jvmZIPEndRecord, error) {
	tailLength := int64(jvmZIPEndLength + jvmZIPMaximumCommentLength)
	if tailLength > size {
		tailLength = size
	}
	tail := make([]byte, int(tailLength))
	if err := readJVMZIPAt(ctx, reader, tail, size-tailLength); err != nil {
		return jvmZIPEndRecord{}, err
	}
	index := -1
	for candidate := len(tail) - jvmZIPEndLength; candidate >= 0; candidate-- {
		if err := ctx.Err(); err != nil {
			return jvmZIPEndRecord{}, err
		}
		if binary.LittleEndian.Uint32(tail[candidate:candidate+4]) !=
			jvmZIPDirectoryEndSignature {
			continue
		}
		commentLength := int(binary.LittleEndian.Uint16(
			tail[candidate+20 : candidate+22],
		))
		if candidate+jvmZIPEndLength+commentLength == len(tail) {
			index = candidate
			break
		}
	}
	if index < 0 {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP end record is invalid")
	}
	record := tail[index : index+jvmZIPEndLength]
	eocdOffset := size - tailLength + int64(index)
	disk := binary.LittleEndian.Uint16(record[4:6])
	directoryDisk := binary.LittleEndian.Uint16(record[6:8])
	recordsOnDisk := binary.LittleEndian.Uint16(record[8:10])
	records := binary.LittleEndian.Uint16(record[10:12])
	directorySize := binary.LittleEndian.Uint32(record[12:16])
	directoryOffset := binary.LittleEndian.Uint32(record[16:20])
	if disk != 0 || directoryDisk != 0 {
		return jvmZIPEndRecord{}, unsafeJVMArchive("multi-volume ZIP is unsupported")
	}
	usesZIP64 := records == math.MaxUint16 || directorySize == math.MaxUint16 ||
		directoryOffset == math.MaxUint32
	if !usesZIP64 {
		if recordsOnDisk != records {
			return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP entry counts differ")
		}
		return jvmZIPEndRecord{
			directoryEnd:     eocdOffset,
			directorySize:    uint64(directorySize),
			directoryOffset:  uint64(directoryOffset),
			directoryRecords: uint64(records),
		}, nil
	}
	return readJVMZIP64End(
		ctx, reader, eocdOffset, recordsOnDisk, records,
		directorySize, directoryOffset,
	)
}

func readJVMZIP64End(
	ctx context.Context,
	reader io.ReaderAt,
	eocdOffset int64,
	recordsOnDisk16 uint16,
	records16 uint16,
	directorySize32 uint32,
	directoryOffset32 uint32,
) (jvmZIPEndRecord, error) {
	locatorOffset := eocdOffset - jvmZIP64LocatorLength
	if locatorOffset < 0 {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 locator is missing")
	}
	locator := make([]byte, jvmZIP64LocatorLength)
	if err := readJVMZIPAt(ctx, reader, locator, locatorOffset); err != nil {
		return jvmZIPEndRecord{}, err
	}
	if binary.LittleEndian.Uint32(locator[0:4]) !=
		jvmZIP64DirectoryLocatorSignature ||
		binary.LittleEndian.Uint32(locator[4:8]) != 0 ||
		binary.LittleEndian.Uint32(locator[16:20]) != 1 {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 locator is invalid")
	}
	recordOffset64 := binary.LittleEndian.Uint64(locator[8:16])
	if recordOffset64 > math.MaxInt64 {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 record offset is invalid")
	}
	recordOffset := int64(recordOffset64)
	if recordOffset < 0 || recordOffset > locatorOffset-jvmZIP64EndMinimumLength {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 end record is misplaced")
	}
	record := make([]byte, jvmZIP64EndMinimumLength)
	if err := readJVMZIPAt(ctx, reader, record, recordOffset); err != nil {
		return jvmZIPEndRecord{}, err
	}
	if binary.LittleEndian.Uint32(record[0:4]) != jvmZIP64DirectoryEndSignature {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 end record is invalid")
	}
	payloadSize := binary.LittleEndian.Uint64(record[4:12])
	if payloadSize < jvmZIP64EndMinimumLength-12 ||
		payloadSize > math.MaxInt64-12 ||
		recordOffset > math.MaxInt64-int64(payloadSize)-12 ||
		recordOffset+int64(payloadSize)+12 != locatorOffset {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 end size is invalid")
	}
	disk := binary.LittleEndian.Uint32(record[16:20])
	directoryDisk := binary.LittleEndian.Uint32(record[20:24])
	recordsOnDisk := binary.LittleEndian.Uint64(record[24:32])
	records := binary.LittleEndian.Uint64(record[32:40])
	directorySize := binary.LittleEndian.Uint64(record[40:48])
	directoryOffset := binary.LittleEndian.Uint64(record[48:56])
	if disk != 0 || directoryDisk != 0 || recordsOnDisk != records {
		return jvmZIPEndRecord{}, unsafeJVMArchive("multi-volume ZIP64 is unsupported")
	}
	if records16 != math.MaxUint16 && uint64(records16) != records ||
		recordsOnDisk16 != math.MaxUint16 && uint64(recordsOnDisk16) != records ||
		directorySize32 != math.MaxUint16 && directorySize32 != math.MaxUint32 &&
			uint64(directorySize32) != directorySize ||
		directoryOffset32 != math.MaxUint32 && uint64(directoryOffset32) != directoryOffset {
		return jvmZIPEndRecord{}, unsafeJVMArchive("ZIP64 compatibility fields differ")
	}
	return jvmZIPEndRecord{
		directoryEnd: recordOffset, directorySize: directorySize,
		directoryOffset: directoryOffset, directoryRecords: records,
	}, nil
}

func scanJVMZIPDirectory(
	ctx context.Context,
	reader io.ReaderAt,
	offset int64,
	size uint64,
	maxEntries uint64,
) (uint64, error) {
	if offset < 0 || size > math.MaxInt64 ||
		offset > math.MaxInt64-int64(size) {
		return 0, unsafeJVMArchive("ZIP directory bounds are invalid")
	}
	remaining := size
	position := offset
	var records uint64
	header := make([]byte, jvmZIPDirectoryHeaderLength)
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if remaining < jvmZIPDirectoryHeaderLength {
			return 0, unsafeJVMArchive("ZIP directory header is truncated")
		}
		if err := readJVMZIPAt(ctx, reader, header, position); err != nil {
			return 0, err
		}
		if binary.LittleEndian.Uint32(header[0:4]) !=
			jvmZIPDirectoryHeaderSignature {
			return 0, unsafeJVMArchive("ZIP directory record is invalid")
		}
		nameLength := uint64(binary.LittleEndian.Uint16(header[28:30]))
		extraLength := uint64(binary.LittleEndian.Uint16(header[30:32]))
		commentLength := uint64(binary.LittleEndian.Uint16(header[32:34]))
		recordLength := uint64(jvmZIPDirectoryHeaderLength) +
			nameLength + extraLength + commentLength
		if recordLength > remaining || recordLength > math.MaxInt64 {
			return 0, unsafeJVMArchive("ZIP directory record is truncated")
		}
		records++
		if records > maxEntries {
			return 0, fmt.Errorf("%w: entry count limit", ErrJVMArchiveLimit)
		}
		position += int64(recordLength)
		remaining -= recordLength
	}
	return records, nil
}

func readJVMZIPAt(
	ctx context.Context,
	reader io.ReaderAt,
	payload []byte,
	offset int64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	count, err := reader.ReadAt(payload, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return unsafeJVMArchive("ZIP metadata cannot be read")
	}
	if count != len(payload) {
		return unsafeJVMArchive("ZIP metadata is truncated")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func unsafeJVMArchive(message string) error {
	return fmt.Errorf("%w: %s", ErrUnsafeJVMArchive, message)
}
