package scan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	"binaryscan/internal/extract"
	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryPublishesTreeByDepthAndMapsParentIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	nodes := []extract.Node{
		treeNode(1, 0, 1, "/outer.zip", extract.StatusRecorded),
		treeNode(2, 1, 2, "/outer.zip/secret.bin", extract.StatusPasswordRequired),
		treeNode(3, 0, 1, "/peer.bin", extract.StatusExtracted),
	}
	nodes[0].Format = "zip"
	nodes[1].SourceContainerLocalID = 1

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*task_id = \?.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 7))
	expectTreeInsertBatch(
		mock,
		lease.TaskID,
		[]uint64{31, 31},
		[]uint64{31, 31},
		[]extract.Node{nodes[0], nodes[2]},
		[]string{"indexed", "extracted"},
		[]uint64{100, 102},
	)
	expectTreeInsertBatch(
		mock,
		lease.TaskID,
		[]uint64{100},
		[]uint64{100},
		[]extract.Node{nodes[1]},
		[]string{"failed"},
		[]uint64{104},
	)
	expectTreeFinalLocks(mock, lease, nil)
	expectRootExtractionUpdate(mock, lease.TaskID, 31, "extracted")
	mock.ExpectCommit()

	if err := repository.PublishTree(
		context.Background(), lease, "extracted", nodes,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishesSourceBeforeSameDepthDependentNode(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	source := treeNode(1, 0, 1, "/source.zip", extract.StatusExtracted)
	source.Format = "zip"
	derived := treeNode(2, 0, 1, "/derived.bin", extract.StatusExtracted)
	derived.SourceContainerLocalID = source.LocalID

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectTreeInsertBatch(
		mock,
		lease.TaskID,
		[]uint64{31},
		[]uint64{31},
		[]extract.Node{source},
		[]string{"extracted"},
		[]uint64{100},
	)
	expectTreeInsertBatch(
		mock,
		lease.TaskID,
		[]uint64{31},
		[]uint64{100},
		[]extract.Node{derived},
		[]string{"extracted"},
		[]uint64{101},
	)
	expectTreeFinalLocks(mock, lease, nil)
	expectRootExtractionUpdate(mock, lease.TaskID, 31, "extracted")
	mock.ExpectCommit()

	if err := repository.PublishTree(
		context.Background(),
		lease,
		"extracted",
		[]extract.Node{source, derived},
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishesTreeInBatchesOfAtMostFiveHundred(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	nodes := make([]extract.Node, maxTreeInsertBatch+1)
	for index := range nodes {
		nodes[index] = treeNode(
			index+1, 0, 1, fmt.Sprintf("/entry-%03d", index+1),
			extract.StatusRecorded,
		)
	}

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	firstIDs := sequentialIDs(1000, maxTreeInsertBatch)
	firstParents := repeatedID(31, maxTreeInsertBatch)
	firstStatuses := repeatedString("indexed", maxTreeInsertBatch)
	expectTreeInsertBatch(
		mock, lease.TaskID, firstParents, firstParents, nodes[:maxTreeInsertBatch],
		firstStatuses, firstIDs,
	)
	expectTreeInsertBatch(
		mock, lease.TaskID, []uint64{31}, []uint64{31},
		nodes[maxTreeInsertBatch:],
		[]string{"indexed"}, []uint64{1500},
	)
	expectTreeFinalLocks(mock, lease, nil)
	expectRootExtractionUpdate(mock, lease.TaskID, 31, "limit_reached")
	mock.ExpectCommit()

	if err := repository.PublishTree(
		context.Background(), lease, "limit_reached", nodes,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeRejectsStaleFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	expectTreePublishingPreflight(mock, lease, sql.ErrNoRows)

	err = repository.PublishTree(context.Background(), lease, "extracted", nil)
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("PublishTree() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeRollsBackWhenLeaseExpiresBeforeRootUpdate(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 4))
	expectTreeFinalLocks(mock, lease, sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.PublishTree(context.Background(), lease, "extracted", nil)
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("PublishTree() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeRetryReplacesPreviousChildren(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	node := treeNode(1, 0, 1, "/entry.bin", extract.StatusExtracted)

	for attempt, firstID := range []uint64{200, 300} {
		expectTreePublicationStart(mock, lease)
		expectTreeRoot(mock, lease.TaskID, 31)
		mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
			WithArgs(lease.TaskID, uint64(31)).
			WillReturnResult(sqlmock.NewResult(0, int64(attempt)))
		expectTreeInsertBatch(
			mock, lease.TaskID, []uint64{31}, []uint64{31},
			[]extract.Node{node},
			[]string{"extracted"}, []uint64{firstID},
		)
		expectTreeFinalLocks(mock, lease, nil)
		expectRootExtractionUpdate(mock, lease.TaskID, 31, "extracted")
		mock.ExpectCommit()
	}

	for attempt := 0; attempt < 2; attempt++ {
		if err := repository.PublishTree(
			context.Background(), lease, "extracted", []extract.Node{node},
		); err != nil {
			t.Fatalf("PublishTree() attempt %d error = %v", attempt+1, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeReleasesRemovedNestedBlobReferences(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()

	expectTreePublicationStart(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*parent_id IS NULL.*depth = 0.*LIMIT 2.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint64(31)))
	mock.ExpectQuery(`(?s)SELECT reference\.file_node_id, reference\.blob_id.*FROM file_node_blob_refs reference.*WHERE reference\.task_id = \?.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"file_node_id", "blob_id"}).
			AddRow(uint64(200), uint64(42)))
	mock.ExpectQuery(`(?s)SELECT reference_count, state.*FROM blobs.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(uint64(42)).
		WillReturnRows(sqlmock.NewRows([]string{"reference_count", "state"}).
			AddRow(uint64(1), "available"))
	mock.ExpectExec(`(?s)UPDATE blobs.*SET state = \?.*reference_count = reference_count - 1.*WHERE id = \?.*reference_count = \?`).
		WithArgs("deleting", uint64(42), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)DELETE FROM file_node_blob_refs.*WHERE task_id = \?`).
		WithArgs(lease.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTreeFinalLocks(mock, lease, nil)
	expectRootExtractionUpdate(mock, lease.TaskID, 31, "extracted")
	mock.ExpectCommit()

	if err := repository.PublishTree(
		context.Background(),
		lease,
		"extracted",
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeRetainsNestedContainerBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	digest := strings.Repeat("a", 64)
	node := treeNode(1, 0, 1, "/nested.tar", extract.StatusExtracted)
	node.Format = "docker-tar"
	node.SizeBytes = 4096
	node.SHA256 = digest
	node.StorageKey = "blobs/sha256/aa/" + digest

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	expectTreeInsertBatch(
		mock,
		lease.TaskID,
		[]uint64{31},
		[]uint64{31},
		[]extract.Node{node},
		[]string{"extracted"},
		[]uint64{200},
	)
	mock.ExpectExec(`(?s)INSERT INTO blobs.*ON DUPLICATE KEY UPDATE.*LAST_INSERT_ID`).
		WithArgs(node.SHA256, node.SizeBytes, node.StorageKey).
		WillReturnResult(sqlmock.NewResult(42, 1))
	mock.ExpectQuery(`(?s)SELECT size_bytes, storage_key, reference_count, state, deleted_at.*FROM blobs.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(uint64(42)).
		WillReturnRows(sqlmock.NewRows([]string{
			"size_bytes", "storage_key", "reference_count", "state", "deleted_at",
		}).AddRow(node.SizeBytes, node.StorageKey, uint64(0), "available", nil))
	mock.ExpectExec(`(?s)UPDATE blobs.*reference_count = reference_count \+ 1.*WHERE id = \?.*state = 'available'`).
		WithArgs(uint64(42)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	pathHash := sha256.Sum256([]byte(node.LogicalPath))
	mock.ExpectExec(`(?s)UPDATE file_nodes.*SET storage_key = \?.*WHERE id = \?.*task_id = \?.*logical_path_hash = \?.*logical_path = \?.*format = \?.*sha256 = \?.*size_bytes = \?`).
		WithArgs(
			node.StorageKey,
			uint64(200),
			lease.TaskID,
			pathHash[:],
			node.LogicalPath,
			node.Format,
			node.SHA256,
			node.SizeBytes,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO file_node_blob_refs.*VALUES \(\?, \?, \?\)`).
		WithArgs(lease.TaskID, uint64(200), uint64(42)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectTreeFinalLocks(mock, lease, nil)
	expectRootExtractionUpdate(mock, lease.TaskID, 31, "extracted")
	mock.ExpectCommit()

	if err := repository.PublishTree(
		context.Background(),
		lease,
		"extracted",
		[]extract.Node{node},
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryPublishTreeRejectsAmbiguousPathMapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	nodes := []extract.Node{
		treeNode(1, 0, 1, "/first", extract.StatusRecorded),
		treeNode(2, 0, 1, "/second", extract.StatusRecorded),
	}

	expectTreePublicationStart(mock, lease)
	expectTreeRoot(mock, lease.TaskID, 31)
	mock.ExpectExec(`(?s)DELETE FROM file_nodes.*id <> \?`).
		WithArgs(lease.TaskID, uint64(31)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)INSERT INTO file_nodes.*extraction_status.*VALUES`).
		WithArgs(expectedTreeInsertArguments(
			lease.TaskID, []uint64{31, 31}, []uint64{31, 31}, nodes,
			[]string{"indexed", "indexed"},
		)...).
		WillReturnResult(sqlmock.NewResult(100, 2))
	mock.ExpectQuery(`(?s)SELECT id, parent_id, source_container_id, logical_path, logical_path_hash.*FROM file_nodes.*logical_path_hash = \?.*logical_path = \?`).
		WithArgs(expectedTreeVerificationArguments(
			lease.TaskID, nodes,
		)...).
		WillReturnRows(sqlmock.NewRows(
			[]string{
				"id", "parent_id", "source_container_id",
				"logical_path", "logical_path_hash",
			},
		).AddRow(
			uint64(100), uint64(31), uint64(31), "/first",
			logicalPathHash("/first"),
		).AddRow(
			uint64(102), uint64(31), uint64(31), "/first",
			logicalPathHash("/first"),
		))
	mock.ExpectRollback()

	err = repository.PublishTree(context.Background(), lease, "extracted", nodes)
	if !errors.Is(err, queue.ErrInconsistentState) {
		t.Fatalf("PublishTree() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPublishTreeMapsExtractionStatuses(t *testing.T) {
	tests := map[string]string{
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
	for input, expected := range tests {
		t.Run(input, func(t *testing.T) {
			validated, err := validateTree(
				"extracted",
				[]extract.Node{treeNode(1, 0, 1, "/entry", input)},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(validated) != 1 || validated[0].extractionStatus != expected {
				t.Fatalf("mapped status = %+v, want %q", validated, expected)
			}
		})
	}
}

func TestPublishTreeRejectsInvalidInputBeforeBeginningTransaction(t *testing.T) {
	valid := treeNode(1, 0, 1, "/entry", extract.StatusRecorded)
	tests := []struct {
		name       string
		rootStatus string
		nodes      []extract.Node
	}{
		{name: "root status", rootStatus: "recorded", nodes: []extract.Node{valid}},
		{
			name: "non-positive local id", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.LocalID = 0
			})},
		},
		{
			name: "duplicate local id", rootStatus: "extracted",
			nodes: []extract.Node{
				valid,
				withTreeNode(valid, func(node *extract.Node) {
					node.LogicalPath = "/other"
				}),
			},
		},
		{
			name: "duplicate logical path", rootStatus: "extracted",
			nodes: []extract.Node{
				valid,
				withTreeNode(valid, func(node *extract.Node) {
					node.LocalID = 2
				}),
			},
		},
		{
			name: "parent follows child", rootStatus: "extracted",
			nodes: []extract.Node{
				treeNode(2, 1, 2, "/parent/child", extract.StatusRecorded),
				treeNode(1, 0, 1, "/parent", extract.StatusRecorded),
			},
		},
		{
			name: "source container follows child", rootStatus: "extracted",
			nodes: []extract.Node{
				withTreeNode(valid, func(node *extract.Node) {
					node.SourceContainerLocalID = 2
				}),
				withTreeNode(valid, func(node *extract.Node) {
					node.LocalID = 2
					node.LogicalPath = "/source.zip"
					node.DisplayName = "source.zip"
					node.Format = "zip"
				}),
			},
		},
		{
			name: "source container is directory", rootStatus: "extracted",
			nodes: []extract.Node{
				withTreeNode(valid, func(node *extract.Node) {
					node.NodeType = extract.NodeTypeDirectory
					node.Format = "zip"
				}),
				withTreeNode(valid, func(node *extract.Node) {
					node.LocalID = 2
					node.LogicalPath = "/child"
					node.DisplayName = "child"
					node.SourceContainerLocalID = 1
				}),
			},
		},
		{
			name: "source container format unsupported", rootStatus: "extracted",
			nodes: []extract.Node{
				valid,
				withTreeNode(valid, func(node *extract.Node) {
					node.LocalID = 2
					node.LogicalPath = "/child"
					node.DisplayName = "child"
					node.SourceContainerLocalID = 1
				}),
			},
		},
		{
			name: "wrong depth", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.Depth = 2
			})},
		},
		{
			name: "root child path", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.LogicalPath = "/directory/entry"
			})},
		},
		{
			name: "child path does not follow parent", rootStatus: "extracted",
			nodes: []extract.Node{
				treeNode(1, 0, 1, "/parent", extract.StatusRecorded),
				treeNode(2, 1, 2, "/elsewhere/child", extract.StatusRecorded),
			},
		},
		{
			name: "display name does not match path", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.DisplayName = "different"
			})},
		},
		{
			name: "non-NFC path", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.LogicalPath = "/cafe\u0301"
				node.DisplayName = "cafe\u0301"
			})},
		},
		{
			name: "archive name identifier", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.ArchiveNameID = "b64:not canonical!"
			})},
		},
		{
			name: "symlink parent", rootStatus: "extracted",
			nodes: treeWithParentType(extract.NodeTypeSymlink),
		},
		{
			name: "hardlink parent", rootStatus: "extracted",
			nodes: treeWithParentType(extract.NodeTypeHardlink),
		},
		{
			name: "special parent", rootStatus: "extracted",
			nodes: treeWithParentType(extract.NodeTypeSpecial),
		},
		{
			name: "type", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.NodeType = "socket"
			})},
		},
		{
			name: "node status", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.ExtractionStatus = "mystery"
			})},
		},
		{
			name: "JSON", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.MetadataJSON = json.RawMessage(`{"broken"`)
			})},
		},
		{
			name: "overlong field", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.Format = strings.Repeat("a", 65)
			})},
		},
		{
			name: "control in ASCII field", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.ErrorCode = "unsafe\ncode"
			})},
		},
		{
			name: "control in error message", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.ErrorMessage = "unsafe\u007fmessage"
			})},
		},
		{
			name: "size above expanded limit", rootStatus: "extracted",
			nodes: []extract.Node{withTreeNode(valid, func(node *extract.Node) {
				node.SizeBytes = maxPublishedNodeSize + 1
			})},
		},
		{
			name: "too many nodes", rootStatus: "extracted",
			nodes: make([]extract.Node, maxPublishedTreeNodes+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			err = repository.PublishTree(
				context.Background(), scanLease(), test.rootStatus, test.nodes,
			)
			if !errors.Is(err, ErrInvalidTree) {
				t.Fatalf("PublishTree() error = %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("database was touched for invalid input: %v", err)
			}
		})
	}
}

func expectTreePublicationStart(mock sqlmock.Sqlmock, lease queue.Lease) {
	expectTreePublishingPreflight(mock, lease, nil)
	mock.ExpectBegin()
}

func expectTreePublishingPreflight(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	result error,
) {
	expectation := mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*JOIN task_attempts attempt.*JOIN tasks task.*job\.task_attempt_id = \?.*job\.kind = 'scan'.*job\.status = 'running'.*job\.lease_owner = \?.*job\.fencing_token = \?.*job\.lease_until > UTC_TIMESTAMP.*job\.cancel_requested_at IS NULL.*attempt\.status = 'running'.*attempt\.fencing_token = \?.*task\.status = 'INDEXING'.*sample_deleted_at IS NULL.*deleted_at IS NULL`).
		WithArgs(
			lease.JobID, lease.TaskID, *lease.TaskAttemptID,
			lease.Owner, lease.FencingToken, lease.FencingToken,
		)
	if result != nil {
		expectation.WillReturnError(result)
		return
	}
	expectation.WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
}

func expectTreeFinalLocks(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	jobResult error,
) {
	jobExpectation := mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*kind = 'scan'.*status = 'running'.*lease_owner = \?.*fencing_token = \?.*lease_until > UTC_TIMESTAMP.*cancel_requested_at IS NULL.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken)
	if jobResult != nil {
		jobExpectation.WillReturnError(jobResult)
		return
	}
	jobExpectation.WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
		AddRow(int64(*lease.TaskAttemptID)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*fencing_token = \?.*FOR UPDATE`).
		WithArgs(*lease.TaskAttemptID, lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"fencing_token"}).
			AddRow(lease.FencingToken))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*status = 'INDEXING'.*sample_deleted_at IS NULL.*deleted_at IS NULL.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("INDEXING"))
}

func expectTreeRoot(mock sqlmock.Sqlmock, taskID string, rootID uint64) {
	mock.ExpectQuery(`(?s)SELECT id.*FROM file_nodes.*parent_id IS NULL.*depth = 0.*LIMIT 2.*FOR UPDATE`).
		WithArgs(taskID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(rootID))
	mock.ExpectQuery(`(?s)SELECT reference\.file_node_id, reference\.blob_id.*FROM file_node_blob_refs reference.*WHERE reference\.task_id = \?.*ORDER BY reference\.file_node_id.*FOR UPDATE`).
		WithArgs(taskID).
		WillReturnRows(sqlmock.NewRows([]string{"file_node_id", "blob_id"}))
}

func expectTreeInsertBatch(
	mock sqlmock.Sqlmock,
	taskID string,
	parentIDs []uint64,
	sourceContainerIDs []uint64,
	nodes []extract.Node,
	statuses []string,
	ids []uint64,
) {
	if len(parentIDs) != len(nodes) ||
		len(sourceContainerIDs) != len(nodes) ||
		len(statuses) != len(nodes) ||
		len(ids) != len(nodes) {
		panic("invalid tree insert test fixture")
	}
	mock.ExpectExec(`(?s)INSERT INTO file_nodes.*extraction_status.*VALUES`).
		WithArgs(expectedTreeInsertArguments(
			taskID,
			parentIDs,
			sourceContainerIDs,
			nodes,
			statuses,
		)...).
		WillReturnResult(sqlmock.NewResult(int64(ids[0]), int64(len(nodes))))
	rows := sqlmock.NewRows(
		[]string{
			"id", "parent_id", "source_container_id",
			"logical_path", "logical_path_hash",
		},
	)
	for index, node := range nodes {
		rows.AddRow(
			ids[index], parentIDs[index], sourceContainerIDs[index],
			node.LogicalPath,
			logicalPathHash(node.LogicalPath),
		)
	}
	mock.ExpectQuery(`(?s)SELECT id, parent_id, source_container_id, logical_path, logical_path_hash.*FROM file_nodes.*logical_path_hash = \?.*logical_path = \?`).
		WithArgs(expectedTreeVerificationArguments(taskID, nodes)...).
		WillReturnRows(rows)
}

func expectRootExtractionUpdate(
	mock sqlmock.Sqlmock,
	taskID string,
	rootID uint64,
	status string,
) {
	mock.ExpectExec(`(?s)UPDATE file_nodes.*extraction_status = \?.*error_code = NULL.*parent_id IS NULL.*depth = 0`).
		WithArgs(status, rootID, taskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectedTreeInsertArguments(
	taskID string,
	parentIDs []uint64,
	sourceContainerIDs []uint64,
	nodes []extract.Node,
	statuses []string,
) []driver.Value {
	arguments := make([]driver.Value, 0, len(nodes)*18)
	for index, node := range nodes {
		pathHash := sha256.Sum256([]byte(node.LogicalPath))
		var metadata driver.Value
		if len(node.MetadataJSON) > 0 {
			metadata = []byte(node.MetadataJSON)
		}
		arguments = append(arguments,
			taskID, parentIDs[index], sourceContainerIDs[index],
			node.LogicalPath, pathHash[:],
			node.DisplayName, node.ArchiveNameID, node.NodeType,
			node.Depth, node.Format,
			node.MIMEType, node.Architecture, node.SizeBytes, node.SHA256,
			statuses[index], metadata, node.ErrorCode, node.ErrorMessage,
		)
	}
	return arguments
}

func expectedTreeVerificationArguments(
	taskID string,
	nodes []extract.Node,
) []driver.Value {
	arguments := make([]driver.Value, 0, len(nodes)*2+1)
	arguments = append(arguments, taskID)
	for _, node := range nodes {
		arguments = append(
			arguments, logicalPathHash(node.LogicalPath), node.LogicalPath,
		)
	}
	return arguments
}

func logicalPathHash(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func treeNode(
	localID int,
	parentLocalID int,
	depth int,
	logicalPath string,
	status string,
) extract.Node {
	return extract.Node{
		LocalID: localID, ParentLocalID: parentLocalID,
		LogicalPath: logicalPath, DisplayName: path.Base(logicalPath),
		NodeType: extract.NodeTypeFile, Depth: depth,
		Format: "unknown", MIMEType: "application/octet-stream",
		SizeBytes: 1, ExtractionStatus: status,
		MetadataJSON: json.RawMessage(`{"source":"test"}`),
	}
}

func withTreeNode(
	node extract.Node,
	change func(*extract.Node),
) extract.Node {
	change(&node)
	return node
}

func treeWithParentType(nodeType string) []extract.Node {
	parent := treeNode(1, 0, 1, "/parent", extract.StatusRecorded)
	parent.NodeType = nodeType
	return []extract.Node{
		parent,
		treeNode(2, 1, 2, "/parent/child", extract.StatusRecorded),
	}
}

func sequentialIDs(first uint64, count int) []uint64 {
	result := make([]uint64, count)
	for index := range result {
		result[index] = first + uint64(index)
	}
	return result
}

func repeatedID(value uint64, count int) []uint64 {
	result := make([]uint64, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func repeatedString(value string, count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = value
	}
	return result
}
