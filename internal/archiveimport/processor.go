package archiveimport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"binaryscan/internal/extract"
)

type ProcessorConfig struct {
	WorkRoot          string
	LeaseDuration     time.Duration
	HeartbeatInterval time.Duration
	Logger            *slog.Logger
	StorageGuard      StorageGuard
}

type StorageGuard interface {
	ReservePlan(context.Context, StoragePlan) (func(), error)
}

type StoragePlan struct {
	SourceBytes   int64
	ExpandedBytes int64
}

type Processor struct {
	repository *MySQLRepository
	engine     *extract.Engine
	storage    *BlobStorage
	workspaces *safeWorkspaceRoot
	config     ProcessorConfig
}

type ProcessingError struct {
	Code      string
	Message   string
	Retryable bool
	Cause     error
}

func (err *ProcessingError) Error() string {
	if err.Cause != nil {
		return err.Message + ": " + err.Cause.Error()
	}
	return err.Message
}

func (err *ProcessingError) Unwrap() error { return err.Cause }

func NewProcessor(
	repository *MySQLRepository,
	engine *extract.Engine,
	storage *BlobStorage,
	config ProcessorConfig,
) (*Processor, error) {
	if repository == nil || engine == nil || storage == nil {
		return nil, errors.New("archive import processor dependencies are required")
	}
	if !filepath.IsAbs(config.WorkRoot) ||
		filepath.Clean(config.WorkRoot) == string(filepath.Separator) {
		return nil, errors.New("archive import work root must be an absolute subdirectory")
	}
	if config.LeaseDuration <= 0 || config.HeartbeatInterval <= 0 ||
		config.HeartbeatInterval >= config.LeaseDuration {
		return nil, errors.New("archive import lease timings are invalid")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	config.WorkRoot = filepath.Clean(config.WorkRoot)
	workspaces, err := newSafeWorkspaceRoot(config.WorkRoot)
	if err != nil {
		return nil, err
	}
	return &Processor{
		repository: repository, engine: engine, storage: storage,
		workspaces: workspaces, config: config,
	}, nil
}

func (processor *Processor) Process(ctx context.Context, lease Lease) error {
	workCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(processor.config.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				if err := processor.repository.Heartbeat(
					workCtx, lease, processor.config.LeaseDuration,
				); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	defer func() {
		cancel(nil)
		<-heartbeatDone
	}()

	releaseStorage := func() {}
	if processor.config.StorageGuard != nil {
		plan, err := archiveStoragePlan(lease)
		if err != nil {
			return processingFailure("archive_import_storage_plan_invalid", false, err)
		}
		releaseStorage, err = processor.config.StorageGuard.ReservePlan(workCtx, plan)
		if err != nil {
			return processingFailure(
				"archive_import_storage_low", true,
				errors.New("archive import is paused below the storage low-water mark"),
			)
		}
		if releaseStorage == nil {
			return processingFailure(
				"archive_import_storage_guard_failed", true,
				errors.New("archive import storage guard returned no release function"),
			)
		}
	}
	defer releaseStorage()

	released, err := processor.repository.ResetForProcessing(workCtx, lease)
	if err != nil {
		return err
	}
	if err := processor.storage.DeleteReleased(workCtx, processor.repository, released); err != nil {
		return processingFailure("archive_import_storage_cleanup_failed", true, err)
	}

	source, err := processor.storage.OpenVerified(
		workCtx, lease.SourceKey, lease.SourceSize, lease.SourceSHA,
	)
	if err != nil {
		return processingFailure("archive_import_source_unavailable", true, err)
	}
	defer source.Close()

	workspace, err := processor.workspaces.Create(lease)
	if err != nil {
		return processingFailure("archive_import_workspace_failed", true, err)
	}
	workspaceOpen := true
	defer func() {
		if workspaceOpen {
			_ = workspace.Close()
		}
	}()
	engine := processor.engine.WithLimits(extract.Limits{
		MaxExpandedBytes: lease.Limits.MaxExpandedBytes,
		MaxEntryBytes:    lease.Limits.MaxEntryBytes,
		MaxNodes:         lease.Limits.MaxEntries,
		MaxRatio:         lease.Limits.MaxArchiveRatio,
		MaxDepth:         lease.Limits.MaxDepth,
	})
	result, err := engine.ExtractLogicalPackageInDirectory(
		workCtx, source, lease.RootFormat, workspace.Directory(),
	)
	if err != nil {
		if cause := context.Cause(workCtx); cause != nil &&
			!errors.Is(cause, context.Canceled) {
			return cause
		}
		return processingFailure("archive_import_extract_failed", true, err)
	}
	if isGlobalLimit(result.LimitCode) {
		return processingFailure(result.LimitCode, false,
			fmt.Errorf("archive import exceeded %s", result.LimitCode))
	}

	materialized := make(map[int]string, len(result.MaterializedFiles))
	for _, file := range result.MaterializedFiles {
		materialized[file.LocalID] = file.WorkPath
	}
	hasChildren := make(map[int]bool)
	for _, node := range result.Nodes {
		if node.ParentLocalID > 0 {
			hasChildren[node.ParentLocalID] = true
		}
	}
	extractedRegular := false
	ordinal := uint32(0)
	for _, node := range result.Nodes {
		if err := workCtx.Err(); err != nil {
			if cause := context.Cause(workCtx); cause != nil {
				return cause
			}
			return err
		}
		wrapper := hasChildren[node.LocalID]
		if node.NodeType == extract.NodeTypeFile && node.ExtractionStatus == extract.StatusExtracted {
			extractedRegular = true
		}
		if !persistablePreviewNode(node, wrapper) {
			continue
		}
		entry, candidatePath := classifyNode(node, wrapper, materialized)
		entry.PublicID, err = newUUID()
		if err != nil {
			return processingFailure("archive_import_id_generation_failed", true, err)
		}
		ordinal++
		entry.Ordinal = ordinal
		if entry.Status == EntryEligible {
			persistErr := processor.repository.WithBlobFence(
				workCtx, entry.SHA256, func() error {
					storageKey, publishErr := processor.storage.Publish(
						workCtx, candidatePath, entry.Size, entry.SHA256,
					)
					if publishErr != nil {
						return fmt.Errorf("publish archive entry blob: %w", publishErr)
					}
					entry.BlobStorageKey = storageKey
					return processor.repository.PersistEntry(workCtx, lease, entry)
				},
			)
			if persistErr != nil {
				return processingFailure("archive_import_blob_publish_failed", true, persistErr)
			}
			continue
		}
		if err := processor.repository.PersistEntry(workCtx, lease, entry); err != nil {
			return processingFailure("archive_import_entry_persist_failed", true, err)
		}
	}
	if !extractedRegular && rootArchiveFatal(result.Nodes) {
		return processingFailure("archive_import_invalid_archive", false,
			errors.New("outer archive is corrupt, encrypted, split, or otherwise unreadable"))
	}
	if cause := context.Cause(workCtx); cause != nil {
		return cause
	}
	if err := workspace.Close(); err != nil {
		return processingFailure("archive_import_workspace_cleanup_failed", true, err)
	}
	workspaceOpen = false
	if err := processor.repository.CompleteLease(workCtx, lease, result.ExpandedBytes); err != nil {
		return err
	}
	return nil
}

func archiveStoragePlan(lease Lease) (StoragePlan, error) {
	// Worst case on the work capacity domain: client staging + server private
	// input snapshots, then sandbox output + descriptor-bound materialization.
	// Repository peak adds the verified source snapshot and every eligible
	// member being durably published.
	if lease.Limits.MaxExpandedBytes < 0 || lease.Limits.MaxArchiveRatio <= 0 {
		return StoragePlan{}, errors.New("archive expansion storage plan is invalid")
	}
	expandedBytes := lease.Limits.MaxExpandedBytes
	ratioBytes, ratioOK := checkedArchiveBytes(
		lease.SourceSize, lease.Limits.MaxArchiveRatio,
	)
	if ratioOK && ratioBytes < expandedBytes {
		expandedBytes = ratioBytes
	}
	if lease.SourceSize < 0 || expandedBytes < 0 ||
		lease.SourceSize > math.MaxInt64-expandedBytes {
		return StoragePlan{}, errors.New("archive storage plan overflows")
	}
	return StoragePlan{
		SourceBytes: lease.SourceSize, ExpandedBytes: expandedBytes,
	}, nil
}

func checkedArchiveBytes(value int64, multiplier int64) (int64, bool) {
	if value < 0 || multiplier <= 0 || value > math.MaxInt64/multiplier {
		return 0, false
	}
	return value * multiplier, true
}

// Preview rows represent task candidates and security-relevant rejected
// members. Structural directories and successfully traversed logical-package
// wrappers are omitted so they do not dilute eligible/skipped counters.
func persistablePreviewNode(node extract.Node, wrapper bool) bool {
	if node.NodeType == extract.NodeTypeDirectory {
		return node.ErrorCode != "" ||
			(node.ExtractionStatus != extract.StatusRecorded &&
				node.ExtractionStatus != extract.StatusExtracted)
	}
	if node.NodeType == extract.NodeTypeFile && wrapper &&
		node.ExtractionStatus == extract.StatusExtracted && node.ErrorCode == "" {
		return false
	}
	return true
}

func classifyNode(
	node extract.Node,
	wrapper bool,
	materialized map[int]string,
) (PersistEntry, string) {
	relativePath, pathReason := relativeLogicalPath(node.LogicalPath)
	entry := PersistEntry{
		LogicalPath:  relativePath,
		Size:         node.SizeBytes,
		SHA256:       node.SHA256,
		Format:       node.Format,
		Status:       EntrySkipped,
		ErrorCode:    node.ErrorCode,
		ErrorMessage: node.ErrorMessage,
	}
	entry.LogicalPathHash = logicalPathDigest(relativePath)
	if pathReason != "" {
		// Quarantined extract nodes still have a canonical safe logical ID.
		// If the logical ID itself is malformed, use a deterministic non-empty
		// diagnostic key rather than persisting attacker-controlled raw names.
		if relativePath == "" {
			relativePath = fmt.Sprintf("__invalid__/%d", node.LocalID)
			entry.LogicalPath = relativePath
			entry.LogicalPathHash = logicalPathDigest(relativePath)
		}
		entry.SkipReason = pathReason
		return entry, ""
	}
	if node.NodeType != extract.NodeTypeFile {
		switch node.NodeType {
		case extract.NodeTypeDirectory:
			entry.SkipReason = "directory"
		case extract.NodeTypeSymlink:
			entry.SkipReason = "symlink"
		case extract.NodeTypeHardlink:
			entry.SkipReason = "hardlink"
		default:
			entry.SkipReason = "special_file"
		}
		return entry, ""
	}
	if node.ExtractionStatus != extract.StatusExtracted || node.ErrorCode != "" {
		entry.SkipReason = extractionSkipReason(node)
		return entry, ""
	}
	if wrapper {
		entry.SkipReason = "logical_wrapper"
		return entry, ""
	}
	category, eligible := categoryForFormat(node.Format)
	if !eligible {
		if isArchiveFormat(node.Format) {
			entry.SkipReason = "nested_archive"
		} else {
			entry.SkipReason = "unsupported_format"
		}
		return entry, ""
	}
	candidatePath, retained := materialized[node.LocalID]
	if !retained || node.SHA256 == "" || node.SizeBytes < 0 {
		entry.SkipReason = "source_unavailable"
		return entry, ""
	}
	entry.Status = EntryEligible
	entry.SkipReason = ""
	entry.Category = category
	return entry, candidatePath
}

func extractionSkipReason(node extract.Node) string {
	switch node.ExtractionStatus {
	case extract.StatusPasswordRequired:
		return "encrypted"
	case extract.StatusInvalidPath:
		if node.ErrorCode == "duplicate_logical_path" {
			return "duplicate_path"
		}
		return "invalid_path"
	case extract.StatusLimitExceeded:
		if node.ErrorCode == extract.LimitMaxEntryBytes {
			return "entry_too_large"
		}
		return "limit_exceeded"
	case extract.StatusCorrupt:
		return "corrupt_entry"
	case extract.StatusUnsupported:
		return "unsupported_format"
	case extract.StatusCancelled:
		return "cancelled"
	default:
		if node.ErrorCode != "" {
			return node.ErrorCode
		}
		return "not_extractable"
	}
}

func relativeLogicalPath(value string) (string, string) {
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') ||
		!strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		path.Clean(value) != value || value == "/" {
		return "", "invalid_path"
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", "invalid_path"
		}
	}
	relative := strings.TrimPrefix(value, "/")
	if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative ||
		relative == "." || relative == ".." || strings.HasPrefix(relative, "../") ||
		len(relative) > 2048 || utf8.RuneCountInString(relative) > 2048 {
		return "", "invalid_path"
	}
	return relative, ""
}

func categoryForFormat(format string) (string, bool) {
	switch format {
	case "pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat",
		"java-class", "jar", "war", "ear", "dex", "apk", "pyc":
		return CategoryBinary, true
	case "docker-tar", "oci-tar":
		return CategoryContainer, true
	default:
		return "", false
	}
}

func isArchiveFormat(format string) bool {
	switch format {
	case "zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd",
		"cab", "cpio", "ar", "deb", "rpm", "iso9660":
		return true
	default:
		return false
	}
}

func isGlobalLimit(code string) bool {
	switch code {
	case extract.LimitMaxExpandedBytes, extract.LimitMaxRatio, extract.LimitMaxNodes:
		return true
	default:
		return false
	}
}

func rootArchiveFatal(nodes []extract.Node) bool {
	for _, node := range nodes {
		if node.ErrorCode == "" {
			continue
		}
		code := strings.ToLower(node.ErrorCode)
		if strings.Contains(code, "archive_corrupt") ||
			strings.Contains(code, "password") ||
			strings.Contains(code, "encrypted") ||
			strings.Contains(code, "multi_volume") ||
			strings.Contains(code, "split") {
			return true
		}
	}
	return false
}

func processingFailure(code string, retryable bool, cause error) error {
	return &ProcessingError{
		Code: code, Message: "Archive import processing failed",
		Retryable: retryable, Cause: cause,
	}
}
