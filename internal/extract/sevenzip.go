package extract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultSevenZipMaxDuration    = 30 * time.Minute
	defaultSevenZipGrace          = 10 * time.Second
	defaultSevenZipStreamBytes    = int64(1 << 20)
	maxSevenZipStreamBytes        = int64(16 << 20)
	sevenZipMonitorInterval       = 25 * time.Millisecond
	sevenZipStagedArchiveFilename = "archive.bin"
)

var (
	errSevenZipUnsafeOutput = errors.New("trusted 7zz helper produced an unsafe output tree")
	errSevenZipTimedOut     = errors.New("trusted 7zz helper timed out")
	errSevenZipOutputLimit  = errors.New("trusted 7zz helper diagnostic output limit exceeded")
	errSevenZipFailed       = errors.New("trusted 7zz helper failed")
)

// TrustedSevenZipConfig opts into a trusted 7zz helper used only for 7Z and
// CAB extraction. The helper is not confined by this package: it runs with the
// worker's OS identity and must be sandboxed by the deployment before this
// adapter is enabled. PATH lookup and shell command strings are unsupported.
type TrustedSevenZipConfig struct {
	Executable       string
	MaxDuration      time.Duration
	TerminationGrace time.Duration
	MaxStdoutBytes   int64
	MaxStderrBytes   int64
}

type trustedSevenZipAdapter struct {
	config         TrustedSevenZipConfig
	executableInfo os.FileInfo
}

func newTrustedSevenZipAdapter(
	config TrustedSevenZipConfig,
) (*trustedSevenZipAdapter, error) {
	if config.MaxDuration == 0 {
		config.MaxDuration = defaultSevenZipMaxDuration
	}
	if config.TerminationGrace == 0 {
		config.TerminationGrace = defaultSevenZipGrace
	}
	if config.MaxStdoutBytes == 0 {
		config.MaxStdoutBytes = defaultSevenZipStreamBytes
	}
	if config.MaxStderrBytes == 0 {
		config.MaxStderrBytes = defaultSevenZipStreamBytes
	}
	if config.MaxDuration <= 0 || config.MaxDuration > 24*time.Hour ||
		config.TerminationGrace <= 0 || config.TerminationGrace > time.Minute ||
		config.MaxStdoutBytes <= 0 ||
		config.MaxStdoutBytes > maxSevenZipStreamBytes ||
		config.MaxStderrBytes <= 0 ||
		config.MaxStderrBytes > maxSevenZipStreamBytes {
		return nil, errors.New("extract: trusted 7zz helper limits are invalid")
	}
	info, err := validateSevenZipExecutable(config.Executable, nil)
	if err != nil {
		return nil, err
	}
	return &trustedSevenZipAdapter{config: config, executableInfo: info}, nil
}

func validateSevenZipExecutable(
	executable string,
	expected os.FileInfo,
) (os.FileInfo, error) {
	if executable == "" || !filepath.IsAbs(executable) ||
		filepath.Clean(executable) != executable ||
		executable == string(filepath.Separator) {
		return nil, errors.New("extract: trusted 7zz helper executable must be a canonical absolute path")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || resolved != executable {
		return nil, errors.New("extract: trusted 7zz helper executable path must not contain symbolic links")
	}
	before, err := os.Lstat(executable)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("extract: trusted 7zz helper is not a regular executable file")
	}
	opened, err := os.Open(executable)
	if err != nil {
		return nil, fmt.Errorf("extract: open trusted 7zz helper: %w", err)
	}
	after, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(before, after) {
		return nil, errors.New("extract: trusted 7zz helper changed during validation")
	}
	if expected != nil && !os.SameFile(expected, after) {
		return nil, errors.New("extract: trusted 7zz helper was replaced")
	}
	return after, nil
}

type sevenZipStage struct {
	path        string
	inputPath   string
	outputPath  string
	runPath     string
	root        *os.Root
	inputRoot   *os.Root
	outputRoot  *os.Root
	runRoot     *os.Root
	stageInfo   os.FileInfo
	inputInfo   os.FileInfo
	outputInfo  os.FileInfo
	runInfo     os.FileInfo
	archiveInfo os.FileInfo
	cleanupOnce sync.Once
}

// prepareSevenZipStage separates helper input, output, and cwd to make
// validation deterministic. The 0700/0400 modes prevent accidental sharing;
// they do not confine a helper running under the same OS identity.
func prepareSevenZipStage(
	ctx context.Context,
	source *os.File,
	sourceSize int64,
	workDir string,
) (_ *sevenZipStage, returnedErr error) {
	stagePath, err := os.MkdirTemp(workDir, ".7zz-")
	if err != nil {
		return nil, fmt.Errorf("extract: create 7zz stage: %w", err)
	}
	stage := &sevenZipStage{
		path:       stagePath,
		inputPath:  filepath.Join(stagePath, "input"),
		outputPath: filepath.Join(stagePath, "output"),
		runPath:    filepath.Join(stagePath, "run"),
	}
	defer func() {
		if returnedErr != nil {
			_ = stage.cleanup()
		}
	}()
	if err := os.Chmod(stagePath, 0o700); err != nil {
		return nil, fmt.Errorf("extract: chmod 7zz stage: %w", err)
	}
	for _, directory := range []string{
		stage.inputPath,
		stage.outputPath,
		stage.runPath,
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, fmt.Errorf("extract: create 7zz private directory: %w", err)
		}
	}
	stage.stageInfo, err = os.Lstat(stage.path)
	if err != nil {
		return nil, fmt.Errorf("extract: stat 7zz stage: %w", err)
	}
	stage.inputInfo, err = os.Lstat(stage.inputPath)
	if err != nil {
		return nil, fmt.Errorf("extract: stat 7zz input directory: %w", err)
	}
	stage.outputInfo, err = os.Lstat(stage.outputPath)
	if err != nil {
		return nil, fmt.Errorf("extract: stat 7zz output directory: %w", err)
	}
	stage.runInfo, err = os.Lstat(stage.runPath)
	if err != nil {
		return nil, fmt.Errorf("extract: stat 7zz run directory: %w", err)
	}
	stage.root, err = os.OpenRoot(stage.path)
	if err != nil {
		return nil, fmt.Errorf("extract: open 7zz stage: %w", err)
	}
	stage.inputRoot, err = stage.root.OpenRoot("input")
	if err != nil {
		return nil, fmt.Errorf("extract: open 7zz input directory: %w", err)
	}
	stage.outputRoot, err = stage.root.OpenRoot("output")
	if err != nil {
		return nil, fmt.Errorf("extract: open 7zz output directory: %w", err)
	}
	stage.runRoot, err = stage.root.OpenRoot("run")
	if err != nil {
		return nil, fmt.Errorf("extract: open 7zz run directory: %w", err)
	}

	archive, err := stage.inputRoot.OpenFile(
		sevenZipStagedArchiveFilename,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("extract: create staged 7zz input: %w", err)
	}
	copyErr := copySevenZipSource(ctx, archive, source, sourceSize)
	chmodErr := archive.Chmod(0o400)
	closeErr := archive.Close()
	if copyErr != nil || chmodErr != nil || closeErr != nil {
		return nil, errors.Join(copyErr, chmodErr, closeErr)
	}
	stage.archiveInfo, err = stage.inputRoot.Lstat(
		sevenZipStagedArchiveFilename,
	)
	if err != nil || !stage.archiveInfo.Mode().IsRegular() ||
		stage.archiveInfo.Size() != sourceSize || fileLinkCount(stage.archiveInfo) != 1 {
		return nil, errors.New("extract: staged 7zz input is invalid")
	}
	if err := stage.validateLayout(true); err != nil {
		return nil, err
	}
	return stage, nil
}

func copySevenZipSource(
	ctx context.Context,
	destination *os.File,
	source *os.File,
	sourceSize int64,
) error {
	if sourceSize < 0 {
		return errors.New("extract: negative 7zz source size")
	}
	before, err := source.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != sourceSize {
		return errors.New("extract: 7zz source changed before staging")
	}
	reader := io.NewSectionReader(source, 0, sourceSize)
	buffer := make([]byte, streamBufferSize)
	var copied int64
	for copied < sourceSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		maximum := int64(len(buffer))
		if remaining := sourceSize - copied; remaining < maximum {
			maximum = remaining
		}
		count, readErr := reader.Read(buffer[:maximum])
		if count > 0 {
			written, writeErr := destination.Write(buffer[:count])
			if writeErr != nil {
				return fmt.Errorf("extract: write staged 7zz input: %w", writeErr)
			}
			if written != count {
				return io.ErrShortWrite
			}
			copied += int64(written)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && copied == sourceSize {
				break
			}
			return fmt.Errorf("extract: read 7zz source: %w", readErr)
		}
		if count == 0 {
			return errors.New("extract: 7zz source read stalled")
		}
	}
	after, err := source.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != sourceSize {
		return errors.New("extract: 7zz source changed while staging")
	}
	return nil
}

func (stage *sevenZipStage) cleanup() error {
	var cleanupErr error
	stage.cleanupOnce.Do(func() {
		for _, root := range []*os.Root{
			stage.runRoot,
			stage.outputRoot,
			stage.inputRoot,
			stage.root,
		} {
			if root != nil {
				cleanupErr = errors.Join(cleanupErr, root.Close())
			}
		}
		cleanupErr = errors.Join(cleanupErr, os.RemoveAll(stage.path))
	})
	return cleanupErr
}

func (stage *sevenZipStage) validateLayout(requireEmptyOutput bool) error {
	if err := validateRootIdentity(stage.path, stage.root, stage.stageInfo); err != nil {
		return fmt.Errorf("%w: stage directory changed: %v", errSevenZipUnsafeOutput, err)
	}
	children, err := fs.ReadDir(stage.root.FS(), ".")
	if err != nil {
		return fmt.Errorf("%w: inspect stage directory: %v", errSevenZipUnsafeOutput, err)
	}
	names := make([]string, 0, len(children))
	for _, child := range children {
		names = append(names, child.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "input,output,run" {
		return fmt.Errorf("%w: stage contains unexpected entries", errSevenZipUnsafeOutput)
	}
	for _, item := range []struct {
		name     string
		absolute string
		root     *os.Root
		info     os.FileInfo
	}{
		{"input", stage.inputPath, stage.inputRoot, stage.inputInfo},
		{"output", stage.outputPath, stage.outputRoot, stage.outputInfo},
		{"run", stage.runPath, stage.runRoot, stage.runInfo},
	} {
		childInfo, childErr := stage.root.Lstat(item.name)
		if childErr != nil || !childInfo.IsDir() ||
			childInfo.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(item.info, childInfo) {
			return fmt.Errorf("%w: %s directory changed", errSevenZipUnsafeOutput, item.name)
		}
		if err := validateRootIdentity(item.absolute, item.root, item.info); err != nil {
			return fmt.Errorf("%w: %s directory changed: %v", errSevenZipUnsafeOutput, item.name, err)
		}
	}
	inputEntries, err := fs.ReadDir(stage.inputRoot.FS(), ".")
	if err != nil || len(inputEntries) != 1 ||
		inputEntries[0].Name() != sevenZipStagedArchiveFilename {
		return fmt.Errorf("%w: staged input directory changed", errSevenZipUnsafeOutput)
	}
	archiveInfo, err := stage.inputRoot.Lstat(sevenZipStagedArchiveFilename)
	if err != nil || !archiveInfo.Mode().IsRegular() ||
		archiveInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(stage.archiveInfo, archiveInfo) ||
		archiveInfo.Size() != stage.archiveInfo.Size() ||
		fileLinkCount(archiveInfo) != 1 {
		return fmt.Errorf("%w: staged input file changed", errSevenZipUnsafeOutput)
	}
	runEntries, err := fs.ReadDir(stage.runRoot.FS(), ".")
	if err != nil || len(runEntries) != 0 {
		return fmt.Errorf("%w: run directory is not empty", errSevenZipUnsafeOutput)
	}
	if requireEmptyOutput {
		outputEntries, readErr := fs.ReadDir(stage.outputRoot.FS(), ".")
		if readErr != nil || len(outputEntries) != 0 {
			return fmt.Errorf("%w: output directory is not empty", errSevenZipUnsafeOutput)
		}
	}
	return nil
}

func validateRootIdentity(
	absolute string,
	root *os.Root,
	expected os.FileInfo,
) error {
	if root == nil || expected == nil {
		return errors.New("missing directory identity")
	}
	pathInfo, err := os.Lstat(absolute)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(expected, pathInfo) {
		return errors.New("directory path identity mismatch")
	}
	rootInfo, err := root.Lstat(".")
	if err != nil || !rootInfo.IsDir() ||
		rootInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, rootInfo) {
		return errors.New("opened directory identity mismatch")
	}
	return nil
}

type sevenZipTreeEntry struct {
	name string
	info os.FileInfo
	dir  bool
	size int64
}

func snapshotSevenZipTree(
	ctx context.Context,
	stage *sevenZipStage,
	maximumEntries int,
) ([]sevenZipTreeEntry, error) {
	if err := validateRootIdentity(
		stage.outputPath,
		stage.outputRoot,
		stage.outputInfo,
	); err != nil {
		return nil, fmt.Errorf("%w: output root changed: %v", errSevenZipUnsafeOutput, err)
	}
	rootDevice, deviceOK := fileDevice(stage.outputInfo)
	entries := make([]sevenZipTreeEntry, 0)
	err := fs.WalkDir(stage.outputRoot.FS(), ".", func(
		name string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return fmt.Errorf("%w: walk output: %v", errSevenZipUnsafeOutput, walkErr)
		}
		if name == "." {
			return nil
		}
		if maximumEntries >= 0 && len(entries) >= maximumEntries {
			return &limitError{code: LimitMaxNodes, global: true}
		}
		info, err := stage.outputRoot.Lstat(name)
		if err != nil {
			return fmt.Errorf("%w: stat output entry: %v", errSevenZipUnsafeOutput, err)
		}
		mode := info.Mode()
		isDirectory := mode.IsDir()
		if _, err := validateArchivePath(name, isDirectory); err != nil {
			return fmt.Errorf("%w: invalid extracted path %q", errSevenZipUnsafeOutput, boundedText(name, 256))
		}
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symbolic link %q", errSevenZipUnsafeOutput, boundedText(name, 256))
		}
		if !isDirectory && !mode.IsRegular() {
			return fmt.Errorf("%w: special file %q", errSevenZipUnsafeOutput, boundedText(name, 256))
		}
		if mode.IsRegular() && fileLinkCount(info) != 1 {
			return fmt.Errorf("%w: hard link %q", errSevenZipUnsafeOutput, boundedText(name, 256))
		}
		if device, ok := fileDevice(info); deviceOK && ok && device != rootDevice {
			return fmt.Errorf("%w: output crosses a filesystem boundary", errSevenZipUnsafeOutput)
		}
		if info.Size() < 0 {
			return fmt.Errorf("%w: negative output size", errSevenZipUnsafeOutput)
		}
		entries = append(entries, sevenZipTreeEntry{
			name: name,
			info: info,
			dir:  isDirectory,
			size: info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func compareSevenZipTrees(
	before []sevenZipTreeEntry,
	after []sevenZipTreeEntry,
) error {
	if len(before) != len(after) {
		return fmt.Errorf("%w: output entry count changed", errSevenZipUnsafeOutput)
	}
	for index := range before {
		left, right := before[index], after[index]
		if left.name != right.name || left.dir != right.dir ||
			left.size != right.size ||
			left.info.Mode() != right.info.Mode() ||
			!left.info.ModTime().Equal(right.info.ModTime()) ||
			!os.SameFile(left.info, right.info) {
			return fmt.Errorf("%w: output entry %q changed", errSevenZipUnsafeOutput, boundedText(left.name, 256))
		}
	}
	return nil
}

func fileLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func fileDevice(info os.FileInfo) (uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(stat.Dev), true
}

func (state *operationState) extractWithTrustedSevenZip(
	source *os.File,
	sourceSize int64,
	format string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	stage, err := prepareSevenZipStage(
		state.ctx,
		source,
		sourceSize,
		state.workDir,
	)
	if err != nil {
		return err
	}
	defer stage.cleanup()

	capacity, capacityCode, capacityGlobal := state.sevenZipCapacity(budget)
	err = state.engine.trustedSevenZip.run(
		state.ctx,
		stage,
		func(ctx context.Context) error {
			return monitorSevenZipOutput(
				ctx,
				stage,
				state.engine.limits.MaxNodes-len(state.nodes),
				state.engine.limits.MaxEntryBytes,
				capacity,
				capacityCode,
				capacityGlobal,
			)
		},
	)
	if err != nil {
		var limit *limitError
		switch {
		case errors.As(err, &limit):
			return limit
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return err
		default:
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				sevenZipErrorCode(err, format),
				err,
			)
		}
	}
	// Everything below is post-extraction validation. It prevents unsafe
	// materialized entries from entering the node model, but cannot undo side
	// effects a same-UID helper may already have caused outside this stage.
	if err := stage.validateLayout(false); err != nil {
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_trusted_helper_output_unsafe",
			err,
		)
	}
	maximumEntries := state.engine.limits.MaxNodes - len(state.nodes)
	first, err := snapshotSevenZipTree(state.ctx, stage, maximumEntries)
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			return limit
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_trusted_helper_output_unsafe",
			err,
		)
	}
	second, err := snapshotSevenZipTree(state.ctx, stage, maximumEntries)
	if err == nil {
		err = compareSevenZipTrees(first, second)
	}
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			return limit
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_trusted_helper_output_changed",
			err,
		)
	}
	if err := state.importSevenZipTree(
		stage,
		second,
		format,
		"7zz",
		parentID,
		prefix,
		parentDepth,
		budget,
	); err != nil {
		var limit *limitError
		switch {
		case errors.As(err, &limit):
			return limit
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, errSevenZipUnsafeOutput):
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				format+"_trusted_helper_output_changed",
				err,
			)
		}
		return err
	}
	finalTree, err := snapshotSevenZipTree(
		state.ctx,
		stage,
		state.engine.limits.MaxNodes,
	)
	if err == nil {
		err = compareSevenZipTrees(second, finalTree)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_trusted_helper_output_changed",
			err,
		)
	}
	return nil
}

func (state *operationState) sevenZipCapacity(
	container *containerBudget,
) (int64, string, bool) {
	capacity := state.engine.limits.MaxExpandedBytes - state.expandedBytes
	code := LimitMaxExpandedBytes
	global := true
	apply := func(remaining int64, candidate string, candidateGlobal bool) {
		if remaining < 0 {
			remaining = 0
		}
		if remaining < capacity {
			capacity = remaining
			code = candidate
			global = candidateGlobal
		}
	}
	apply(
		ratioCapacity(state.rootSize, state.engine.limits.MaxRatio)-state.expandedBytes,
		LimitMaxRatio,
		true,
	)
	apply(
		ratioCapacity(container.sourceSize, state.engine.limits.MaxRatio)-container.expanded,
		LimitMaxRatio,
		false,
	)
	if capacity < 0 {
		capacity = 0
	}
	return capacity, code, global
}

func monitorSevenZipOutput(
	ctx context.Context,
	stage *sevenZipStage,
	maximumEntries int,
	maximumEntryBytes int64,
	maximumTotalBytes int64,
	totalLimitCode string,
	totalLimitGlobal bool,
) error {
	// This periodic check is a best-effort early-stop guard. It is reactive:
	// bytes and filesystem objects may be created before the next poll. The
	// deployment sandbox and storage quota are the authoritative containment.
	entries, err := snapshotSevenZipTree(ctx, stage, maximumEntries)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.dir {
			continue
		}
		if entry.size > maximumEntryBytes {
			return &limitError{code: LimitMaxEntryBytes}
		}
		if entry.size > math.MaxInt64-total ||
			total+entry.size > maximumTotalBytes {
			return &limitError{code: totalLimitCode, global: totalLimitGlobal}
		}
		total += entry.size
	}
	return nil
}

func sevenZipErrorCode(err error, format string) string {
	switch {
	case errors.Is(err, errSevenZipUnsafeOutput):
		return format + "_trusted_helper_output_unsafe"
	case errors.Is(err, errSevenZipTimedOut):
		return format + "_trusted_helper_timeout"
	case errors.Is(err, errSevenZipOutputLimit):
		return format + "_trusted_helper_diagnostic_limit"
	default:
		return format + "_trusted_helper_failed"
	}
}

func (state *operationState) importSevenZipTree(
	stage *sevenZipStage,
	entries []sevenZipTreeEntry,
	format string,
	helper string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	for _, entry := range entries {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}
		location, prepared, err := state.prepareEntryWithNameSuffix(
			prefix,
			entry.name,
			entry.dir,
			parentID,
			parentDepth,
		)
		if err != nil {
			return fmt.Errorf("%w: import path %q: %v", errSevenZipUnsafeOutput, boundedText(entry.name, 256), err)
		}
		if !prepared {
			continue
		}
		metadata := map[string]any{
			"archive":        format,
			"trusted_helper": helper,
			"mode":           uint32(entry.info.Mode().Perm()),
		}
		if entry.dir {
			if location.directoryNode >= 0 {
				directory := &state.nodes[location.directoryNode]
				metadata["synthetic"] = false
				state.applyNamespaceCollision(location, directory, metadata)
				directory.MetadataJSON = metadataJSON(metadata)
			}
			continue
		}
		metadata["declared_bytes"] = entry.size
		node := Node{
			ParentLocalID: location.parentID,
			LogicalPath:   location.logical,
			DisplayName:   location.display,
			NodeType:      NodeTypeFile,
			Depth:         location.depth,
			SizeBytes:     entry.size,
			MetadataJSON:  metadataJSON(metadata),
		}
		state.applyNamespaceCollision(location, &node, metadata)
		if entry.size > state.engine.limits.MaxEntryBytes {
			limit, limitErr := state.limitDeclaredRegular(
				node,
				metadata,
				entry.size,
				budget,
			)
			if limitErr != nil {
				return limitErr
			}
			if limit != nil {
				return limit
			}
			continue
		}
		input, err := openSevenZipEntry(stage.outputRoot, entry)
		if err != nil {
			return err
		}
		nodeLocalID := state.nextID
		limit, extractErr := state.extractRegular(input, node, metadata, budget)
		postErr := validateOpenSevenZipEntry(stage.outputRoot, input, entry)
		closeErr := input.Close()
		if postErr != nil || closeErr != nil {
			if extracted := state.nodeByLocalID(nodeLocalID); extracted != nil {
				extracted.ExtractionStatus = StatusCorrupt
				extracted.ErrorCode = "trusted_helper_entry_changed"
				extracted.ErrorMessage = "trusted helper output changed while it was consumed"
				extracted.SHA256 = ""
			}
			state.partial = true
			return errors.Join(postErr, closeErr)
		}
		if extractErr != nil {
			return extractErr
		}
		if limit != nil {
			return limit
		}
	}
	return nil
}

func openSevenZipEntry(
	root *os.Root,
	entry sevenZipTreeEntry,
) (*os.File, error) {
	current, err := root.Lstat(entry.name)
	if err != nil || !sameSevenZipEntry(entry, current) {
		return nil, fmt.Errorf("%w: output entry %q changed before open", errSevenZipUnsafeOutput, boundedText(entry.name, 256))
	}
	opened, err := root.Open(entry.name)
	if err != nil {
		return nil, fmt.Errorf("%w: open output entry: %v", errSevenZipUnsafeOutput, err)
	}
	openedInfo, err := opened.Stat()
	if err != nil || !sameSevenZipEntry(entry, openedInfo) {
		_ = opened.Close()
		return nil, fmt.Errorf("%w: output entry changed while opening", errSevenZipUnsafeOutput)
	}
	return opened, nil
}

func validateOpenSevenZipEntry(
	root *os.Root,
	opened *os.File,
	entry sevenZipTreeEntry,
) error {
	openedInfo, err := opened.Stat()
	if err != nil || !sameSevenZipEntry(entry, openedInfo) {
		return fmt.Errorf("%w: opened output entry changed", errSevenZipUnsafeOutput)
	}
	current, err := root.Lstat(entry.name)
	if err != nil || !sameSevenZipEntry(entry, current) {
		return fmt.Errorf("%w: output path changed after read", errSevenZipUnsafeOutput)
	}
	return nil
}

func sameSevenZipEntry(entry sevenZipTreeEntry, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && fileLinkCount(info) == 1 &&
		info.Size() == entry.size && info.Mode() == entry.info.Mode() &&
		info.ModTime().Equal(entry.info.ModTime()) &&
		os.SameFile(entry.info, info)
}

// run starts a directly addressed trusted helper with fixed argv and a clean
// cwd. The process group is only a best-effort cleanup mechanism: a helper can
// create a new session and escape it. Callers must not enable this adapter
// without an OS sandbox/cgroup that owns every descendant process.
func (adapter *trustedSevenZipAdapter) run(
	ctx context.Context,
	stage *sevenZipStage,
	monitor func(context.Context) error,
) error {
	if ctx == nil {
		return errors.New("extract: nil 7zz context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := validateSevenZipExecutable(
		adapter.config.Executable,
		adapter.executableInfo,
	); err != nil {
		return err
	}
	if err := stage.validateLayout(true); err != nil {
		return err
	}
	arguments := []string{
		"x",
		"-y",
		"-aoa",
		"-bd",
		"-bb0",
		"-bso0",
		"-bsp0",
		"-spf-",
		"-o" + stage.outputPath,
		"--",
		filepath.Join(stage.inputPath, sevenZipStagedArchiveFilename),
	}
	overflow := make(chan string, 2)
	stdout := newSevenZipCapture("stdout", adapter.config.MaxStdoutBytes, overflow)
	stderr := newSevenZipCapture("stderr", adapter.config.MaxStderrBytes, overflow)
	runCtx, cancel := context.WithTimeout(ctx, adapter.config.MaxDuration)
	defer cancel()
	command := exec.Command(adapter.config.Executable, arguments...)
	command.Dir = stage.runPath
	command.Env = []string{
		"HOME=" + stage.runPath,
		"TMPDIR=" + stage.runPath,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/nonexistent",
	}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// WaitDelay prevents an escaped descendant that inherited a diagnostic fd
	// from keeping Cmd.Wait blocked forever. It does not terminate or contain
	// that descendant. Per-child rlimits are not safely portable through
	// os/exec without a launcher; production resource limits belong to cgroup.
	command.WaitDelay = adapter.config.TerminationGrace
	if err := command.Start(); err != nil {
		return fmt.Errorf("%w: start: %v", errSevenZipFailed, err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ticker := time.NewTicker(sevenZipMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case waitErr := <-done:
			if stdout.exceededOutput() || stderr.exceededOutput() {
				return errSevenZipOutputLimit
			}
			if waitErr != nil {
				return fmt.Errorf(
					"%w: %v; stderr=%q",
					errSevenZipFailed,
					waitErr,
					boundedText(stderr.String(), 2048),
				)
			}
			if _, err := validateSevenZipExecutable(
				adapter.config.Executable,
				adapter.executableInfo,
			); err != nil {
				return err
			}
			return nil
		case <-overflow:
			_ = terminateSevenZipProcessGroup(
				command,
				done,
				adapter.config.TerminationGrace,
			)
			return errSevenZipOutputLimit
		case <-ticker.C:
			if monitor != nil {
				if err := monitor(runCtx); err != nil {
					_ = terminateSevenZipProcessGroup(
						command,
						done,
						adapter.config.TerminationGrace,
					)
					if parentErr := ctx.Err(); parentErr != nil {
						return parentErr
					}
					if errors.Is(err, context.DeadlineExceeded) &&
						errors.Is(runCtx.Err(), context.DeadlineExceeded) {
						return errSevenZipTimedOut
					}
					return err
				}
			}
		case <-runCtx.Done():
			select {
			case waitErr := <-done:
				if stdout.exceededOutput() || stderr.exceededOutput() {
					return errSevenZipOutputLimit
				}
				if waitErr != nil {
					return fmt.Errorf(
						"%w: %v; stderr=%q",
						errSevenZipFailed,
						waitErr,
						boundedText(stderr.String(), 2048),
					)
				}
				return nil
			default:
			}
			_ = terminateSevenZipProcessGroup(
				command,
				done,
				adapter.config.TerminationGrace,
			)
			if err := ctx.Err(); err != nil {
				return err
			}
			return errSevenZipTimedOut
		}
	}
}

func terminateSevenZipProcessGroup(
	command *exec.Cmd,
	done <-chan error,
	grace time.Duration,
) error {
	if command.Process == nil {
		return nil
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	return <-done
}

type sevenZipCapture struct {
	mu       sync.Mutex
	name     string
	maximum  int64
	buffer   bytes.Buffer
	exceeded bool
	once     sync.Once
	notify   chan<- string
}

func newSevenZipCapture(
	name string,
	maximum int64,
	notify chan<- string,
) *sevenZipCapture {
	return &sevenZipCapture{name: name, maximum: maximum, notify: notify}
}

func (capture *sevenZipCapture) Write(value []byte) (int, error) {
	capture.mu.Lock()
	remaining := capture.maximum - int64(capture.buffer.Len())
	if remaining < 0 {
		remaining = 0
	}
	toWrite := int64(len(value))
	if toWrite > remaining {
		toWrite = remaining
		capture.exceeded = true
	}
	if toWrite > 0 {
		_, _ = capture.buffer.Write(value[:toWrite])
	}
	exceeded := capture.exceeded
	capture.mu.Unlock()
	if exceeded {
		capture.once.Do(func() { capture.notify <- capture.name })
	}
	return len(value), nil
}

func (capture *sevenZipCapture) exceededOutput() bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.exceeded
}

func (capture *sevenZipCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String()
}
