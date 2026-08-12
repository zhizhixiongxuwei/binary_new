package extract

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ExternalEngineSevenZip   = "7zz"
	ExternalEngineLibarchive = "libarchive"
)

// ExternalArchiveRequest is the complete bounded request sent to the
// no-network archive sandbox. Paths never cross this interface.
type ExternalArchiveRequest struct {
	Engine             string
	Format             string
	MaxEntries         int
	MaxEntryBytes      int64
	MaxExpandedBytes   int64
	MaxDurationSeconds int64
}

// ExternalArchiveSession exposes a read-only sandbox output tree until Close.
// Close acknowledges import completion and asks the sandbox to remove it.
type ExternalArchiveSession interface {
	OutputPath() string
	Close() error
}

// ExternalArchiveRootSession pins the sandbox output by descriptor. Linux
// implementations should provide this instead of asking the consumer to
// reopen a /proc/self/fd path, whose directory entry is intentionally a
// symlink even though the descriptor itself names a real directory.
type ExternalArchiveRootSession interface {
	OpenOutputRoot() (*os.Root, os.FileInfo, error)
}

// ExternalArchiveAdapter executes archive tools in an independently confined
// service. Implementations must stage the source into a read-only sandbox
// input and expose output through a separate capacity-limited mount.
type ExternalArchiveAdapter interface {
	Extract(
		context.Context,
		*os.File,
		int64,
		ExternalArchiveRequest,
	) (ExternalArchiveSession, error)
}

// NewEngineWithArchiveSandbox enables production 7Z and CAB extraction. 7Z is
// routed to 7zz; CAB is routed to libarchive with its secure extraction flags.
func NewEngineWithArchiveSandbox(
	detector Detector,
	limits Limits,
	adapter ExternalArchiveAdapter,
) (*Engine, error) {
	if adapter == nil {
		return nil, errors.New("extract: archive sandbox adapter is required")
	}
	engine := newEngine(detector, limits)
	engine.externalArchive = adapter
	return engine, nil
}

func (state *operationState) extractWithArchiveSandbox(
	source *os.File,
	sourceSize int64,
	format string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	engineName := ExternalEngineSevenZip
	if format == "cab" {
		engineName = ExternalEngineLibarchive
	}
	capacity, capacityCode, capacityGlobal := state.sevenZipCapacity(budget)
	session, err := state.engine.externalArchive.Extract(
		state.ctx,
		source,
		sourceSize,
		ExternalArchiveRequest{
			Engine:             engineName,
			Format:             format,
			MaxEntries:         state.engine.limits.MaxNodes - len(state.nodes),
			MaxEntryBytes:      state.engine.limits.MaxEntryBytes,
			MaxExpandedBytes:   capacity,
			MaxDurationSeconds: int64(defaultSevenZipMaxDuration.Seconds()),
		},
	)
	if err != nil {
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_sandbox_failed",
			err,
		)
	}
	defer session.Close()

	outputPath := session.OutputPath()
	var (
		root            *os.Root
		info            os.FileInfo
		descriptorBound bool
	)
	if rootSession, ok := session.(ExternalArchiveRootSession); ok {
		root, info, err = rootSession.OpenOutputRoot()
		descriptorBound = true
	} else {
		if outputPath == "" || !filepath.IsAbs(outputPath) ||
			filepath.Clean(outputPath) != outputPath ||
			outputPath == string(filepath.Separator) {
			err = errors.New("archive sandbox returned an unsafe output path")
		} else {
			info, err = os.Lstat(outputPath)
			if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
				err = errors.New("archive sandbox output root is not a directory")
			}
			if err == nil {
				root, err = os.OpenRoot(outputPath)
			}
		}
	}
	if err != nil || root == nil || info == nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 {
		if root != nil {
			_ = root.Close()
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_sandbox_output_unsafe",
			fmt.Errorf("archive sandbox output root is invalid: %w", err),
		)
	}
	defer root.Close()
	stage := &sevenZipStage{
		outputPath:            outputPath,
		outputRoot:            root,
		outputInfo:            info,
		outputDescriptorBound: descriptorBound,
	}
	maximumEntries := state.engine.limits.MaxNodes - len(state.nodes)
	first, err := snapshotSevenZipTree(state.ctx, stage, maximumEntries)
	if err == nil {
		var second []sevenZipTreeEntry
		second, err = snapshotSevenZipTree(
			state.ctx,
			stage,
			maximumEntries,
		)
		if err == nil {
			err = compareSevenZipTrees(first, second)
		}
		if err == nil {
			err = state.importSevenZipTree(
				stage,
				second,
				format,
				engineName,
				parentID,
				prefix,
				parentDepth,
				budget,
			)
		}
	}
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			if limit.code == "" {
				limit.code = capacityCode
				limit.global = capacityGlobal
			}
			return limit
		}
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			format+"_sandbox_output_unsafe",
			err,
		)
	}
	return nil
}
