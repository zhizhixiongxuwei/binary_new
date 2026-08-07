package filetree

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const maxFileNodeSizeBytes = uint64(50 << 30)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) List(
	ctx context.Context,
	query ListQuery,
) (page Page, returnErr error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return Page{}, fmt.Errorf("begin file tree snapshot: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		if err := transaction.Rollback(); err != nil &&
			!errors.Is(err, sql.ErrTxDone) {
			rollbackErr := fmt.Errorf("rollback file tree snapshot: %w", err)
			if returnErr == nil {
				page = Page{}
				returnErr = rollbackErr
				return
			}
			returnErr = errors.Join(returnErr, rollbackErr)
		}
	}()

	if err := requireRow(ctx, transaction, `
SELECT 1
FROM tasks
WHERE id = ? AND deleted_at IS NULL
LIMIT 1`, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Page{}, ErrNotFound
		}
		return Page{}, fmt.Errorf("find file tree task: %w", err)
	}

	if query.ParentID != nil {
		if err := requireRow(ctx, transaction, `
SELECT 1
FROM file_nodes
WHERE task_id = ? AND id = ?
LIMIT 1`, query.TaskID, *query.ParentID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Page{}, ErrNotFound
			}
			return Page{}, fmt.Errorf("find file tree parent: %w", err)
		}
	}

	whereParent := "n.parent_id IS NULL"
	arguments := []any{query.TaskID}
	if query.ParentID != nil {
		whereParent = "n.parent_id = ?"
		arguments = append(arguments, *query.ParentID)
	}
	arguments = append(arguments, query.Cursor, query.PageSize+1)
	rows, err := transaction.QueryContext(ctx, `
SELECT n.id, n.parent_id, n.logical_path, n.display_name, n.archive_name_id,
       n.node_type, n.depth, n.format, n.mime_type, n.architecture, n.size_bytes,
       n.sha256, n.extraction_status, n.error_code, n.error_message,
       source.id, source.logical_path, source.format,
       EXISTS (
           SELECT 1
           FROM file_nodes child FORCE INDEX (idx_file_nodes_parent)
           WHERE child.task_id = n.task_id AND child.parent_id = n.id
       ) AS has_children
FROM file_nodes n FORCE INDEX (idx_file_nodes_parent)
LEFT JOIN file_nodes source
       ON source.task_id = n.task_id AND source.id = n.source_container_id
WHERE n.task_id = ? AND `+whereParent+` AND n.id > ?
ORDER BY n.id ASC
LIMIT ?`, arguments...)
	if err != nil {
		return Page{}, fmt.Errorf("list file tree nodes: %w", err)
	}
	defer rows.Close()

	items := make([]Node, 0, query.PageSize+1)
	for rows.Next() {
		value, err := scanNode(rows)
		if err != nil {
			return Page{}, fmt.Errorf("scan file tree node: %w", err)
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate file tree nodes: %w", err)
	}

	page = Page{Items: items}
	if len(page.Items) > query.PageSize {
		page.NextCursor = page.Items[query.PageSize-1].ID
		page.Items = page.Items[:query.PageSize]
	}
	finished = true
	if err := transaction.Commit(); err != nil {
		return Page{}, fmt.Errorf("commit file tree snapshot: %w", err)
	}
	return page, nil
}

func (r *MySQLRepository) Get(
	ctx context.Context,
	query GetQuery,
) (detail Detail, returnErr error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		return Detail{}, fmt.Errorf("begin file detail snapshot: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		if err := transaction.Rollback(); err != nil &&
			!errors.Is(err, sql.ErrTxDone) {
			rollbackErr := fmt.Errorf("rollback file detail snapshot: %w", err)
			if returnErr == nil {
				detail = Detail{}
				returnErr = rollbackErr
				return
			}
			returnErr = errors.Join(returnErr, rollbackErr)
		}
	}()

	if err := requireRow(ctx, transaction, `
SELECT 1
FROM tasks
WHERE id = ? AND deleted_at IS NULL
LIMIT 1`, query.TaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Detail{}, ErrTaskNotFound
		}
		return Detail{}, fmt.Errorf("find file detail task: %w", err)
	}

	detail, err = scanDetail(transaction.QueryRowContext(ctx, `
SELECT n.id, n.parent_id, n.logical_path, n.display_name, n.archive_name_id,
       n.node_type, n.depth, n.format, n.mime_type, n.architecture, n.size_bytes,
       n.sha256, n.extraction_status, n.error_code, n.error_message,
       source.id, source.logical_path, source.format,
       EXISTS (
           SELECT 1
           FROM file_nodes child FORCE INDEX (idx_file_nodes_parent)
           WHERE child.task_id = n.task_id AND child.parent_id = n.id
       ) AS has_children,
       n.metadata_json, parent.logical_path
FROM file_nodes n
LEFT JOIN file_nodes parent
       ON parent.task_id = n.task_id AND parent.id = n.parent_id
LEFT JOIN file_nodes source
       ON source.task_id = n.task_id AND source.id = n.source_container_id
WHERE n.task_id = ? AND n.id = ?
LIMIT 1`, query.TaskID, query.FileID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Detail{}, ErrNodeNotFound
		}
		return Detail{}, fmt.Errorf("scan file detail node: %w", err)
	}

	finished = true
	if err := transaction.Commit(); err != nil {
		return Detail{}, fmt.Errorf("commit file detail snapshot: %w", err)
	}
	return detail, nil
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireRow(
	ctx context.Context,
	querier rowQuerier,
	query string,
	arguments ...any,
) error {
	var marker uint8
	return querier.QueryRowContext(ctx, query, arguments...).Scan(&marker)
}

type rowScanner interface {
	Scan(...any) error
}

func scanNode(scanner rowScanner) (Node, error) {
	var value Node
	var id uint64
	var parentID sql.Null[uint64]
	var sizeBytes sql.Null[uint64]
	var format sql.NullString
	var mimeType sql.NullString
	var architecture sql.NullString
	var archiveNameID sql.NullString
	var sha256 sql.NullString
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var sourceID sql.Null[uint64]
	var sourceLogicalPath sql.NullString
	var sourceFormat sql.NullString
	if err := scanner.Scan(
		&id, &parentID, &value.LogicalPath, &value.DisplayName, &archiveNameID,
		&value.NodeType, &value.Depth, &format, &mimeType, &architecture,
		&sizeBytes, &sha256, &value.ExtractionStatus, &errorCode,
		&errorMessage, &sourceID, &sourceLogicalPath, &sourceFormat,
		&value.HasChildren,
	); err != nil {
		return Node{}, err
	}
	if id == 0 {
		return Node{}, errors.New("file tree node ID is outside accepted bounds")
	}
	value.ID = strconv.FormatUint(id, 10)
	if parentID.Valid {
		if parentID.V == 0 {
			return Node{}, errors.New("file tree parent ID is outside accepted bounds")
		}
		parent := strconv.FormatUint(parentID.V, 10)
		value.ParentID = &parent
	}
	if sizeBytes.Valid {
		if sizeBytes.V > maxFileNodeSizeBytes {
			return Node{}, errors.New("file tree node size is outside accepted bounds")
		}
		size := sizeBytes.V
		value.SizeBytes = &size
	}
	value.Format = format.String
	value.MIMEType = mimeType.String
	value.Architecture = architecture.String
	value.ArchiveNameID = archiveNameID.String
	if !validArchiveNameID(value.ArchiveNameID) {
		return Node{}, errors.New("file tree archive name identifier is invalid")
	}
	value.SHA256 = sha256.String
	value.ErrorCode = errorCode.String
	value.ErrorMessage = errorMessage.String
	if err := setSourceContainer(
		&value,
		sourceID,
		sourceLogicalPath,
		sourceFormat,
	); err != nil {
		return Node{}, err
	}
	return value, nil
}

func scanDetail(scanner rowScanner) (Detail, error) {
	var value Node
	var id uint64
	var parentID sql.Null[uint64]
	var sizeBytes sql.Null[uint64]
	var format sql.NullString
	var mimeType sql.NullString
	var architecture sql.NullString
	var archiveNameID sql.NullString
	var sha256 sql.NullString
	var errorCode sql.NullString
	var errorMessage sql.NullString
	var sourceID sql.Null[uint64]
	var sourceLogicalPath sql.NullString
	var sourceFormat sql.NullString
	var metadataJSON sql.NullString
	var parentLogicalPath sql.NullString
	if err := scanner.Scan(
		&id, &parentID, &value.LogicalPath, &value.DisplayName, &archiveNameID,
		&value.NodeType, &value.Depth, &format, &mimeType, &architecture,
		&sizeBytes, &sha256, &value.ExtractionStatus, &errorCode,
		&errorMessage, &sourceID, &sourceLogicalPath, &sourceFormat,
		&value.HasChildren, &metadataJSON, &parentLogicalPath,
	); err != nil {
		return Detail{}, err
	}
	if id == 0 {
		return Detail{}, errors.New("file detail node ID is outside accepted bounds")
	}
	value.ID = strconv.FormatUint(id, 10)
	if parentID.Valid {
		if parentID.V == 0 || !parentLogicalPath.Valid ||
			parentLogicalPath.String == "" {
			return Detail{}, errors.New("file detail parent is inconsistent")
		}
		parent := strconv.FormatUint(parentID.V, 10)
		value.ParentID = &parent
	} else if parentLogicalPath.Valid {
		return Detail{}, errors.New("file detail parent is inconsistent")
	}
	if sizeBytes.Valid {
		if sizeBytes.V > maxFileNodeSizeBytes {
			return Detail{}, errors.New("file detail node size is outside accepted bounds")
		}
		size := sizeBytes.V
		value.SizeBytes = &size
	}
	value.Format = format.String
	value.MIMEType = mimeType.String
	value.Architecture = architecture.String
	value.ArchiveNameID = archiveNameID.String
	if !validArchiveNameID(value.ArchiveNameID) {
		return Detail{}, errors.New("file detail archive name identifier is invalid")
	}
	value.SHA256 = sha256.String
	value.ErrorCode = errorCode.String
	value.ErrorMessage = errorMessage.String
	if err := setSourceContainer(
		&value,
		sourceID,
		sourceLogicalPath,
		sourceFormat,
	); err != nil {
		return Detail{}, err
	}

	rawMetadata := json.RawMessage("null")
	if metadataJSON.Valid {
		normalized := strings.TrimSpace(metadataJSON.String)
		if !json.Valid([]byte(normalized)) {
			return Detail{}, errors.New("file detail metadata is not valid JSON")
		}
		if normalized != "null" {
			var object map[string]json.RawMessage
			if err := json.Unmarshal([]byte(normalized), &object); err != nil ||
				object == nil {
				return Detail{}, errors.New(
					"file detail metadata is not a JSON object",
				)
			}
		}
		rawMetadata = append(json.RawMessage(nil), normalized...)
	}
	detail := Detail{
		Node:         value,
		MetadataJSON: rawMetadata,
	}
	if value.ParentID != nil {
		detail.SourceParent = &SourceParent{
			ID:          *value.ParentID,
			LogicalPath: parentLogicalPath.String,
		}
	}
	return detail, nil
}

func setSourceContainer(
	value *Node,
	id sql.Null[uint64],
	logicalPath sql.NullString,
	format sql.NullString,
) error {
	if !id.Valid {
		if logicalPath.Valid || format.Valid {
			return errors.New("file node source container is inconsistent")
		}
		return nil
	}
	if id.V == 0 ||
		!logicalPath.Valid ||
		logicalPath.String == "" ||
		!format.Valid ||
		format.String == "" {
		return errors.New("file node source container is inconsistent")
	}
	value.SourceContainer = &SourceContainer{
		ID:          strconv.FormatUint(id.V, 10),
		LogicalPath: logicalPath.String,
		Format:      format.String,
	}
	return nil
}

func validArchiveNameID(value string) bool {
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "sha256:") {
		digest := strings.TrimPrefix(value, "sha256:")
		if len(digest) != 64 {
			return false
		}
		for _, character := range []byte(digest) {
			if (character < '0' || character > '9') &&
				(character < 'a' || character > 'f') {
				return false
			}
		}
		return true
	}
	if !strings.HasPrefix(value, "b64:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "b64:")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && len(raw) <= 2048 &&
		base64.StdEncoding.EncodeToString(raw) == encoded
}
