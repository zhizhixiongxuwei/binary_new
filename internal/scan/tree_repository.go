package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"

	"binaryscan/internal/extract"
	"binaryscan/internal/queue"

	"golang.org/x/text/unicode/norm"
)

const (
	maxPublishedFileNodes = 100_000
	maxPublishedTreeNodes = maxPublishedFileNodes - 1
	maxTreeInsertBatch    = 500
	maxPublishedTreeDepth = 10
	maxPublishedNodeSize  = int64(50 * 1024 * 1024 * 1024)
)

var (
	databaseExtractionStatuses = map[string]struct{}{
		"indexed":       {},
		"extracted":     {},
		"skipped":       {},
		"unsupported":   {},
		"limit_reached": {},
		"failed":        {},
	}
	nodeTypes = map[string]struct{}{
		extract.NodeTypeFile:      {},
		extract.NodeTypeDirectory: {},
		extract.NodeTypeSymlink:   {},
		extract.NodeTypeHardlink:  {},
		extract.NodeTypeSpecial:   {},
	}
	sourceContainerFormats = map[string]struct{}{
		"zip": {}, "jar": {}, "war": {}, "ear": {}, "apk": {},
		"tar": {}, "docker-tar": {}, "oci-tar": {},
		"gzip": {}, "bzip2": {}, "xz": {}, "zstd": {}, "lzma": {},
		"ar": {}, "deb": {}, "rpm": {}, "cpio": {}, "rar": {},
		"7z": {}, "cab": {},
		"ext2": {}, "ext3": {}, "ext4": {}, "gpt-img": {},
		"iso9660": {}, "mbr-img": {}, "squashfs": {}, "udf": {},
	}
	nodeExtractionStatuses = map[string]string{
		"indexed":                      "indexed",
		extract.StatusRecorded:         "indexed",
		extract.StatusExtracted:        "extracted",
		"skipped":                      "skipped",
		extract.StatusUnsupported:      "unsupported",
		"limit_reached":                "limit_reached",
		extract.StatusDepthLimited:     "limit_reached",
		extract.StatusLimitExceeded:    "limit_reached",
		"failed":                       "failed",
		extract.StatusPasswordRequired: "failed",
		extract.StatusInvalidPath:      "failed",
		extract.StatusCorrupt:          "failed",
		extract.StatusCancelled:        "failed",
	}
)

type validatedTreeNode struct {
	node             extract.Node
	logicalPathHash  [sha256.Size]byte
	extractionStatus string
}

// PublishTree atomically replaces a task's extracted descendants while
// retaining the root file node created during identification.
func (r *MySQLRepository) PublishTree(
	ctx context.Context,
	lease queue.Lease,
	rootExtractionStatus string,
	nodes []extract.Node,
) error {
	validated, err := validateTree(rootExtractionStatus, nodes)
	if err != nil {
		return err
	}
	if lease.Kind != queue.KindScan || lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	if err := validateTreePublishingState(ctx, r.db, lease); err != nil {
		return err
	}

	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin extracted tree publication: %w", err)
	}
	defer transaction.Rollback()

	// The root node is the tree publication domain lock. It serializes retries
	// and duplicate publishers without holding the jobs row throughout the
	// potentially large descendant replacement.
	rootID, found, err := findRootNode(ctx, transaction, lease.TaskID)
	if err != nil {
		return err
	}
	if !found {
		return queue.ErrInconsistentState
	}
	revivableBlobIDs, err := releaseTreeBlobReferences(
		ctx,
		transaction,
		lease.TaskID,
	)
	if err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `
DELETE FROM file_nodes
WHERE task_id = ? AND id <> ?`, lease.TaskID, rootID); err != nil {
		return fmt.Errorf("delete previous extracted file tree: %w", err)
	}

	if len(validated) > 0 {
		databaseIDs, err := insertTreeNodes(
			ctx, transaction, lease.TaskID, rootID, validated,
		)
		if err != nil {
			return err
		}
		if err := retainTreeBlobs(
			ctx,
			transaction,
			lease.TaskID,
			validated,
			databaseIDs,
			revivableBlobIDs,
		); err != nil {
			return err
		}
	}
	// Lock and validate the live lease only after the long tree write. This
	// keeps heartbeats and cancellation responsive while ensuring a stale
	// publisher cannot commit any of the replacement.
	if err := lockTreePublishingLease(ctx, transaction, lease); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE file_nodes
SET extraction_status = ?,
    error_code = NULL,
    error_message = NULL
WHERE id = ?
  AND task_id = ?
  AND parent_id IS NULL
  AND depth = 0`,
		rootExtractionStatus, rootID, lease.TaskID,
	)
	if err != nil {
		return fmt.Errorf("publish root extraction status: %w", err)
	}
	if err := requireAtMostOne(result, "inspect root extraction status publication"); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit extracted tree publication: %w", err)
	}
	return nil
}

func validateTree(
	rootExtractionStatus string,
	nodes []extract.Node,
) ([]validatedTreeNode, error) {
	if _, valid := databaseExtractionStatuses[rootExtractionStatus]; !valid {
		return nil, invalidTree("invalid root extraction status %q", rootExtractionStatus)
	}
	if len(nodes) > maxPublishedTreeNodes {
		return nil, invalidTree(
			"node count %d exceeds maximum %d", len(nodes), maxPublishedTreeNodes,
		)
	}

	validated := make([]validatedTreeNode, 0, len(nodes))
	seen := make(map[int]int, len(nodes))
	logicalPaths := make(map[string]struct{}, len(nodes))
	for index, node := range nodes {
		if node.LocalID <= 0 {
			return nil, invalidTree("node %d has a non-positive local id", index)
		}
		if _, duplicate := seen[node.LocalID]; duplicate {
			return nil, invalidTree("node %d duplicates local id %d", index, node.LocalID)
		}
		if node.ParentLocalID < 0 {
			return nil, invalidTree("node %d has a negative parent local id", index)
		}
		if node.SourceContainerLocalID < 0 {
			return nil, invalidTree(
				"node %d has a negative source container local id", index,
			)
		}
		if node.SourceContainerLocalID != 0 {
			sourceIndex, sourceSeen := seen[node.SourceContainerLocalID]
			if !sourceSeen {
				return nil, invalidTree(
					"node %d source container %d does not precede it",
					index,
					node.SourceContainerLocalID,
				)
			}
			source := validated[sourceIndex].node
			if source.NodeType != extract.NodeTypeFile {
				return nil, invalidTree(
					"node %d source container %d is not a file",
					index,
					node.SourceContainerLocalID,
				)
			}
			if _, supported := sourceContainerFormats[source.Format]; !supported {
				return nil, invalidTree(
					"node %d source container %d has unsupported format %q",
					index,
					node.SourceContainerLocalID,
					source.Format,
				)
			}
		}
		if node.Depth < 1 || node.Depth > maxPublishedTreeDepth {
			return nil, invalidTree("node %d has invalid depth %d", index, node.Depth)
		}
		if _, valid := nodeTypes[node.NodeType]; !valid {
			return nil, invalidTree("node %d has invalid type %q", index, node.NodeType)
		}
		extractionStatus, valid := nodeExtractionStatuses[node.ExtractionStatus]
		if !valid {
			return nil, invalidTree(
				"node %d has invalid extraction status %q",
				index, node.ExtractionStatus,
			)
		}
		if err := validateTreeNodeFields(index, node); err != nil {
			return nil, err
		}
		if node.ParentLocalID == 0 {
			if node.Depth != 1 {
				return nil, invalidTree("node %d is not one level below the root", index)
			}
			if path.Dir(node.LogicalPath) != "/" {
				return nil, invalidTree(
					"node %d path is not directly below the root", index,
				)
			}
		} else {
			parentIndex, parentSeen := seen[node.ParentLocalID]
			if !parentSeen {
				return nil, invalidTree(
					"node %d parent %d does not precede it", index, node.ParentLocalID,
				)
			}
			if node.Depth != validated[parentIndex].node.Depth+1 {
				return nil, invalidTree(
					"node %d depth does not follow parent %d",
					index, node.ParentLocalID,
				)
			}
			parent := validated[parentIndex].node
			if path.Dir(node.LogicalPath) != parent.LogicalPath {
				return nil, invalidTree(
					"node %d path is not directly below parent %d",
					index, node.ParentLocalID,
				)
			}
			switch parent.NodeType {
			case extract.NodeTypeSymlink, extract.NodeTypeHardlink, extract.NodeTypeSpecial:
				return nil, invalidTree(
					"node %d has non-container parent %d of type %q",
					index, node.ParentLocalID, parent.NodeType,
				)
			}
		}
		if _, duplicate := logicalPaths[node.LogicalPath]; duplicate {
			return nil, invalidTree(
				"node %d duplicates logical path %q", index, node.LogicalPath,
			)
		}
		validated = append(validated, validatedTreeNode{
			node:             node,
			logicalPathHash:  sha256.Sum256([]byte(node.LogicalPath)),
			extractionStatus: extractionStatus,
		})
		seen[node.LocalID] = len(validated) - 1
		logicalPaths[node.LogicalPath] = struct{}{}
	}
	return validated, nil
}

func validateTreeNodeFields(index int, node extract.Node) error {
	if !validLogicalPath(node.LogicalPath) {
		return invalidTree("node %d has an invalid logical path", index)
	}
	if err := validateUTF8Field("display name", index, node.DisplayName, 512, true); err != nil {
		return err
	}
	if !norm.NFC.IsNormalString(node.LogicalPath) ||
		!norm.NFC.IsNormalString(node.DisplayName) {
		return invalidTree("node %d path and display name must use NFC", index)
	}
	if node.DisplayName != path.Base(node.LogicalPath) {
		return invalidTree("node %d display name does not match its path", index)
	}
	if !validArchiveNameID(node.ArchiveNameID) {
		return invalidTree("node %d has an invalid archive name identifier", index)
	}
	if node.SizeBytes < 0 || node.SizeBytes > maxPublishedNodeSize {
		return invalidTree("node %d has an invalid size", index)
	}
	if err := validateASCIIField("format", index, node.Format, 64); err != nil {
		return err
	}
	if err := validateASCIIField("MIME type", index, node.MIMEType, 255); err != nil {
		return err
	}
	if err := validateASCIIField("architecture", index, node.Architecture, 64); err != nil {
		return err
	}
	if node.SHA256 != "" && !lowercaseSHA256Pattern.MatchString(node.SHA256) {
		return invalidTree("node %d has an invalid SHA-256", index)
	}
	if node.StorageKey != "" {
		if node.NodeType != extract.NodeTypeFile ||
			(node.Format != "docker-tar" && node.Format != "oci-tar") ||
			node.SizeBytes <= 0 ||
			!lowercaseSHA256Pattern.MatchString(node.SHA256) ||
			node.StorageKey != "blobs/sha256/"+
				node.SHA256[:2]+"/"+node.SHA256 {
			return invalidTree(
				"node %d has invalid retained container storage", index,
			)
		}
	}
	if len(node.MetadataJSON) > 0 && !json.Valid(node.MetadataJSON) {
		return invalidTree("node %d has invalid metadata JSON", index)
	}
	if err := validateASCIIField("error code", index, node.ErrorCode, 128); err != nil {
		return err
	}
	return validateUTF8Field("error message", index, node.ErrorMessage, 2048, false)
}

func validArchiveNameID(value string) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "sha256:") {
		return lowercaseSHA256Pattern.MatchString(
			strings.TrimPrefix(value, "sha256:"),
		)
	}
	if !strings.HasPrefix(value, "b64:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "b64:")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil &&
		len(raw) <= 2048 &&
		base64.StdEncoding.EncodeToString(raw) == encoded
}

func validLogicalPath(value string) bool {
	if !utf8.ValidString(value) || value == "/" || len(value) == 0 ||
		!path.IsAbs(value) || path.Clean(value) != value ||
		strings.Contains(value, "\\") || utf8.RuneCountInString(value) > 2048 {
		return false
	}
	for _, character := range value {
		if character == 0 || character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validateUTF8Field(
	field string,
	index int,
	value string,
	maximum int,
	required bool,
) error {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum ||
		(required && value == "") || containsControlCharacter(value) {
		return invalidTree("node %d has an invalid %s", index, field)
	}
	return nil
}

func validateASCIIField(field string, index int, value string, maximum int) error {
	if len(value) > maximum {
		return invalidTree("node %d has an overlong %s", index, field)
	}
	for _, character := range []byte(value) {
		if character > 0x7f || character < 0x20 || character == 0x7f {
			return invalidTree("node %d has a non-ASCII %s", index, field)
		}
	}
	return nil
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func invalidTree(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTree, fmt.Sprintf(format, arguments...))
}

func validateTreePublishingState(
	ctx context.Context,
	database *sql.DB,
	lease queue.Lease,
) error {
	if lease.TaskAttemptID == nil {
		return queue.ErrLeaseLost
	}
	var valid int
	err := database.QueryRowContext(ctx, `
SELECT 1
FROM jobs job
JOIN task_attempts attempt
  ON attempt.id = job.task_attempt_id
 AND attempt.task_id = job.task_id
JOIN tasks task ON task.id = job.task_id
WHERE job.id = ?
  AND job.task_id = ?
  AND job.task_attempt_id = ?
  AND job.kind = 'scan'
  AND job.status = 'running'
  AND job.lease_owner = ?
  AND job.fencing_token = ?
  AND job.lease_until > UTC_TIMESTAMP(6)
  AND job.cancel_requested_at IS NULL
  AND attempt.status = 'running'
  AND attempt.fencing_token = ?
  AND task.status = 'INDEXING'
  AND task.sample_deleted_at IS NULL
  AND task.deleted_at IS NULL`,
		lease.JobID, lease.TaskID, *lease.TaskAttemptID,
		lease.Owner, lease.FencingToken, lease.FencingToken,
	).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("validate tree publishing state: %w", err)
	}
	return nil
}

func lockTreePublishingLease(
	ctx context.Context,
	transaction *sql.Tx,
	lease queue.Lease,
) error {
	var attemptID sql.NullInt64
	err := transaction.QueryRowContext(ctx, `
SELECT task_attempt_id
FROM jobs
WHERE id = ?
  AND task_id = ?
  AND kind = 'scan'
  AND status = 'running'
  AND lease_owner = ?
  AND fencing_token = ?
  AND lease_until > UTC_TIMESTAMP(6)
  AND cancel_requested_at IS NULL
FOR UPDATE`,
		lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
	).Scan(&attemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock tree publishing scan job: %w", err)
	}
	if !attemptID.Valid || attemptID.Int64 <= 0 ||
		lease.TaskAttemptID == nil ||
		uint64(attemptID.Int64) != *lease.TaskAttemptID {
		return queue.ErrLeaseLost
	}

	var attemptFence uint64
	err = transaction.QueryRowContext(ctx, `
SELECT fencing_token
FROM task_attempts
WHERE id = ?
  AND task_id = ?
  AND status = 'running'
  AND fencing_token = ?
FOR UPDATE`,
		*lease.TaskAttemptID, lease.TaskID, lease.FencingToken,
	).Scan(&attemptFence)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock tree publishing task attempt: %w", err)
	}
	if attemptFence != lease.FencingToken {
		return queue.ErrLeaseLost
	}

	var taskStatus string
	err = transaction.QueryRowContext(ctx, `
SELECT status
FROM tasks
WHERE id = ?
  AND status = 'INDEXING'
  AND sample_deleted_at IS NULL
  AND deleted_at IS NULL
FOR UPDATE`, lease.TaskID).Scan(&taskStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("lock tree publishing scan task: %w", err)
	}
	return nil
}

func insertTreeNodes(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	rootID uint64,
	nodes []validatedTreeNode,
) (map[int]uint64, error) {
	databaseIDs := map[int]uint64{0: rootID}
	pending := append([]validatedTreeNode(nil), nodes...)
	for len(pending) > 0 {
		batch := make([]validatedTreeNode, 0, maxTreeInsertBatch)
		remaining := make([]validatedTreeNode, 0, len(pending))
		for _, node := range pending {
			_, parentReady := databaseIDs[node.node.ParentLocalID]
			_, sourceReady := databaseIDs[node.node.SourceContainerLocalID]
			if parentReady && sourceReady && len(batch) < maxTreeInsertBatch {
				batch = append(batch, node)
				continue
			}
			remaining = append(remaining, node)
		}
		if len(batch) == 0 {
			return nil, queue.ErrInconsistentState
		}
		if err := insertTreeNodeBatch(
			ctx, transaction, taskID, batch, databaseIDs,
		); err != nil {
			return nil, err
		}
		pending = remaining
	}
	return databaseIDs, nil
}

func insertTreeNodeBatch(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	nodes []validatedTreeNode,
	databaseIDs map[int]uint64,
) error {
	var statement strings.Builder
	statement.WriteString(`
INSERT INTO file_nodes (
    task_id, parent_id, source_container_id, logical_path, logical_path_hash,
    display_name, archive_name_id, node_type, depth, format, mime_type,
    architecture, size_bytes, sha256, extraction_status, metadata_json,
    error_code, error_message
) VALUES `)
	arguments := make([]any, 0, len(nodes)*18)
	parentIDs := make([]uint64, len(nodes))
	sourceContainerIDs := make([]uint64, len(nodes))
	for index, validated := range nodes {
		if index > 0 {
			statement.WriteByte(',')
		}
		statement.WriteString(
			"(?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, NULLIF(?, ''), " +
				"NULLIF(?, ''), NULLIF(?, ''), ?, NULLIF(?, ''), ?, ?, " +
				"NULLIF(?, ''), NULLIF(?, ''))",
		)
		parentID, found := databaseIDs[validated.node.ParentLocalID]
		if !found {
			return queue.ErrInconsistentState
		}
		parentIDs[index] = parentID
		sourceContainerID, found := databaseIDs[validated.node.SourceContainerLocalID]
		if !found {
			return queue.ErrInconsistentState
		}
		sourceContainerIDs[index] = sourceContainerID
		var metadata any
		if len(validated.node.MetadataJSON) > 0 {
			metadata = []byte(validated.node.MetadataJSON)
		}
		arguments = append(arguments,
			taskID, parentID, sourceContainerID, validated.node.LogicalPath,
			validated.logicalPathHash[:], validated.node.DisplayName,
			validated.node.ArchiveNameID, validated.node.NodeType,
			validated.node.Depth,
			validated.node.Format, validated.node.MIMEType,
			validated.node.Architecture, validated.node.SizeBytes,
			validated.node.SHA256, validated.extractionStatus, metadata,
			validated.node.ErrorCode, validated.node.ErrorMessage,
		)
	}
	result, err := transaction.ExecContext(ctx, statement.String(), arguments...)
	if err != nil {
		return fmt.Errorf("insert extracted file node batch: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect extracted file node batch size: %w", err)
	}
	if affected != int64(len(nodes)) {
		return queue.ErrInconsistentState
	}
	firstSigned, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("read extracted file node batch first id: %w", err)
	}
	if firstSigned <= 0 {
		return queue.ErrInconsistentState
	}
	if err := verifyInsertedTreeBatch(
		ctx,
		transaction,
		taskID,
		nodes,
		parentIDs,
		sourceContainerIDs,
		databaseIDs,
	); err != nil {
		return err
	}
	return nil
}

func verifyInsertedTreeBatch(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	nodes []validatedTreeNode,
	parentIDs []uint64,
	sourceContainerIDs []uint64,
	databaseIDs map[int]uint64,
) error {
	var statement strings.Builder
	statement.WriteString(`
SELECT id, parent_id, source_container_id, logical_path, logical_path_hash
FROM file_nodes
WHERE task_id = ? AND (`)
	arguments := make([]any, 0, len(nodes)*2+1)
	arguments = append(arguments, taskID)
	expected := make(map[string]int, len(nodes))
	for index, node := range nodes {
		if index > 0 {
			statement.WriteString(" OR ")
		}
		statement.WriteString("(logical_path_hash = ? AND logical_path = ?)")
		arguments = append(
			arguments, node.logicalPathHash[:], node.node.LogicalPath,
		)
		expected[node.node.LogicalPath] = index
	}
	statement.WriteByte(')')
	rows, err := transaction.QueryContext(ctx, statement.String(), arguments...)
	if err != nil {
		return fmt.Errorf("verify extracted file node id reservation: %w", err)
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(nodes))
	for rows.Next() {
		var id, parentID, sourceContainerID uint64
		var logicalPath string
		var logicalPathHash []byte
		if err := rows.Scan(
			&id,
			&parentID,
			&sourceContainerID,
			&logicalPath,
			&logicalPathHash,
		); err != nil {
			return fmt.Errorf("scan extracted file node id reservation: %w", err)
		}
		index, expectedPath := expected[logicalPath]
		if !expectedPath || id == 0 ||
			parentID != parentIDs[index] ||
			sourceContainerID != sourceContainerIDs[index] ||
			!bytes.Equal(logicalPathHash, nodes[index].logicalPathHash[:]) {
			return queue.ErrInconsistentState
		}
		if _, duplicate := found[logicalPath]; duplicate {
			return queue.ErrInconsistentState
		}
		found[logicalPath] = struct{}{}
		databaseIDs[nodes[index].node.LocalID] = id
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate extracted file node id reservation: %w", err)
	}
	if len(found) != len(nodes) {
		return queue.ErrInconsistentState
	}
	return nil
}

func releaseTreeBlobReferences(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
) (map[uint64]struct{}, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT reference.file_node_id, reference.blob_id
FROM file_node_blob_refs reference
JOIN file_nodes node
  ON node.task_id = reference.task_id
 AND node.id = reference.file_node_id
WHERE reference.task_id = ?
ORDER BY reference.file_node_id
FOR UPDATE`, taskID)
	if err != nil {
		return nil, fmt.Errorf("lock previous nested image references: %w", err)
	}
	var references []struct {
		fileNodeID uint64
		blobID     uint64
	}
	for rows.Next() {
		var reference struct {
			fileNodeID uint64
			blobID     uint64
		}
		if err := rows.Scan(&reference.fileNodeID, &reference.blobID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan nested image reference: %w", err)
		}
		references = append(references, reference)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate nested image references: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close nested image references: %w", err)
	}
	revivable := make(map[uint64]struct{}, len(references))
	for _, reference := range references {
		if err := releaseTreeBlobReference(
			ctx,
			transaction,
			reference.blobID,
		); err != nil {
			return nil, err
		}
		revivable[reference.blobID] = struct{}{}
	}
	if len(references) > 0 {
		if _, err := transaction.ExecContext(ctx, `
DELETE FROM file_node_blob_refs
WHERE task_id = ?`, taskID); err != nil {
			return nil, fmt.Errorf("delete previous nested image references: %w", err)
		}
	}
	return revivable, nil
}

func releaseTreeBlobReference(
	ctx context.Context,
	transaction *sql.Tx,
	blobID uint64,
) error {
	var (
		referenceCount uint64
		state          string
	)
	err := transaction.QueryRowContext(ctx, `
SELECT reference_count, state
FROM blobs
WHERE id = ?
FOR UPDATE`, blobID).Scan(&referenceCount, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return queue.ErrInconsistentState
	}
	if err != nil {
		return fmt.Errorf("lock previous nested image blob: %w", err)
	}
	if referenceCount == 0 || state != "available" {
		return queue.ErrInconsistentState
	}
	nextState := "available"
	if referenceCount == 1 {
		nextState = "deleting"
	}
	result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET state = ?,
    reference_count = reference_count - 1
WHERE id = ?
  AND state = 'available'
  AND reference_count = ?`, nextState, blobID, referenceCount)
	if err != nil {
		return fmt.Errorf("release previous nested image blob: %w", err)
	}
	return requireOneTrivy(result, "release previous nested image blob")
}

func retainTreeBlobs(
	ctx context.Context,
	transaction *sql.Tx,
	taskID string,
	nodes []validatedTreeNode,
	databaseIDs map[int]uint64,
	revivableBlobIDs map[uint64]struct{},
) error {
	for _, validated := range nodes {
		node := validated.node
		if node.StorageKey == "" {
			continue
		}
		fileNodeID, found := databaseIDs[node.LocalID]
		if !found || fileNodeID == 0 {
			return queue.ErrInconsistentState
		}
		blobID, err := acquireTreeBlobReference(
			ctx,
			transaction,
			node,
			revivableBlobIDs,
		)
		if err != nil {
			return err
		}
		result, err := transaction.ExecContext(ctx, `
UPDATE file_nodes
SET storage_key = ?
WHERE id = ?
  AND task_id = ?
  AND logical_path_hash = ?
  AND logical_path = ?
  AND node_type = 'file'
  AND format = ?
  AND sha256 = ?
  AND size_bytes = ?`,
			node.StorageKey,
			fileNodeID,
			taskID,
			validated.logicalPathHash[:],
			node.LogicalPath,
			node.Format,
			node.SHA256,
			node.SizeBytes,
		)
		if err != nil {
			return fmt.Errorf("bind nested image storage key: %w", err)
		}
		if err := requireOneTrivy(
			result,
			"bind nested image storage key",
		); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, `
INSERT INTO file_node_blob_refs (task_id, file_node_id, blob_id)
VALUES (?, ?, ?)`, taskID, fileNodeID, blobID); err != nil {
			return fmt.Errorf("insert nested image blob reference: %w", err)
		}
	}
	return nil
}

func acquireTreeBlobReference(
	ctx context.Context,
	transaction *sql.Tx,
	node extract.Node,
	revivableBlobIDs map[uint64]struct{},
) (uint64, error) {
	result, err := transaction.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, ?, ?, 0, 'available', UTC_TIMESTAMP(6))
ON DUPLICATE KEY UPDATE
    id = LAST_INSERT_ID(id)`,
		node.SHA256,
		node.SizeBytes,
		node.StorageKey,
	)
	if err != nil {
		return 0, fmt.Errorf("publish nested image blob record: %w", err)
	}
	signedBlobID, err := result.LastInsertId()
	if err != nil || signedBlobID <= 0 {
		return 0, queue.ErrInconsistentState
	}
	blobID := uint64(signedBlobID)
	var (
		sizeBytes      uint64
		storageKey     string
		referenceCount uint64
		state          string
		deletedAt      sql.NullTime
	)
	err = transaction.QueryRowContext(ctx, `
SELECT size_bytes, storage_key, reference_count, state, deleted_at
FROM blobs
WHERE id = ?
FOR UPDATE`, blobID).Scan(
		&sizeBytes,
		&storageKey,
		&referenceCount,
		&state,
		&deletedAt,
	)
	if err != nil {
		return 0, fmt.Errorf("verify nested image blob record: %w", err)
	}
	if sizeBytes > uint64(^uint64(0)>>1) ||
		int64(sizeBytes) != node.SizeBytes ||
		storageKey != node.StorageKey {
		return 0, queue.ErrInconsistentState
	}
	if state != "available" || deletedAt.Valid {
		if _, allowed := revivableBlobIDs[blobID]; !allowed ||
			state != "deleting" || referenceCount != 0 {
			return 0, queue.ErrInconsistentState
		}
		result, err := transaction.ExecContext(ctx, `
UPDATE blobs
SET state = 'available',
    deleted_at = NULL,
    verified_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND state = 'deleting'
  AND reference_count = 0`, blobID)
		if err != nil {
			return 0, fmt.Errorf("reactivate nested image blob: %w", err)
		}
		if err := requireOneTrivy(
			result,
			"reactivate nested image blob",
		); err != nil {
			return 0, err
		}
	}
	result, err = transaction.ExecContext(ctx, `
UPDATE blobs
SET reference_count = reference_count + 1,
    verified_at = UTC_TIMESTAMP(6)
WHERE id = ?
  AND state = 'available'
  AND deleted_at IS NULL`, blobID)
	if err != nil {
		return 0, fmt.Errorf("reference nested image blob: %w", err)
	}
	if err := requireOneTrivy(
		result,
		"reference nested image blob",
	); err != nil {
		return 0, err
	}
	return blobID, nil
}
