package orphanreaper

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectBlobFenceStart(mock sqlmock.Sqlmock, sha256 string) {
	mock.ExpectQuery(regexp.QuoteMeta("SELECT GET_LOCK(?, ?)")).
		WithArgs("binaryscan_blob_sha256_"+sha256[:40], 30).
		WillReturnRows(sqlmock.NewRows([]string{"acquired"}).AddRow(1))
}

func expectBlobFenceEnd(mock sqlmock.Sqlmock, sha256 string) {
	mock.ExpectExec(regexp.QuoteMeta("SELECT RELEASE_LOCK(?)")).
		WithArgs("binaryscan_blob_sha256_" + sha256[:40]).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func TestMySQLRepositoryUsesDurableBlobProtections(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	blob := BlobCandidate{
		SHA256:     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		StorageKey: "blobs/sha256/dd/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		SizeBytes:  4,
	}
	upload := UploadCandidate{ID: "123e4567-e89b-42d3-a456-426614174001"}

	// Live blob records and every authoritative owner protect the file. A
	// released deleted tombstone does not.
	blobProtectionQuery := `(?s)SELECT EXISTS.*FROM blobs b.*state <> 'deleted'.*FROM uploads.*FROM tasks.*FROM file_node_blob_refs.*FROM archive_imports.*source_blob_reference_released_at IS NULL.*FROM archive_import_entries.*blob_reference_released_at IS NULL`
	mock.ExpectQuery(blobProtectionQuery).
		WithArgs(blob.SHA256, blob.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err := repository.BlobReferenced(context.Background(), blob)
	if err != nil || !referenced {
		t.Fatalf("BlobReferenced() = (%v, %v)", referenced, err)
	}
	mock.ExpectQuery(blobProtectionQuery).
		WithArgs(blob.SHA256, blob.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	referenced, err = repository.BlobReferenced(context.Background(), blob)
	if err != nil || referenced {
		t.Fatalf("released tombstone BlobReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1\s*FROM uploads\s*WHERE id = \?`).
		WithArgs(upload.ID).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err = repository.UploadReferenced(context.Background(), upload)
	if err != nil || !referenced {
		t.Fatalf("UploadReferenced() = (%v, %v)", referenced, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRechecksAndFencesBlobDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StorageKey: "blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes:  7, ModifiedAt: time.Now().Add(-48 * time.Hour),
	}

	expectBlobFenceStart(mock, candidate.SHA256)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id", "state"}).AddRow(uint64(9), "available"))
	mock.ExpectCommit()
	expectBlobFenceEnd(mock, candidate.SHA256)
	called := false
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || removed || called {
		t.Fatalf("protected DeleteOrphanBlob() = (%v, %v), callback=%v", removed, err, called)
	}

	expectBlobFenceStart(mock, candidate.SHA256)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnError(sqlmock.ErrCancelled)
	mock.ExpectRollback()
	expectBlobFenceEnd(mock, candidate.SHA256)
	removed, err = repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error { return nil },
	)
	if err == nil || removed {
		t.Fatalf("failed lock DeleteOrphanBlob() = (%v, %v)", removed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryLockRecheckProtectsArchiveBlobOwners(t *testing.T) {
	tests := []struct {
		name          string
		archiveSource bool
		archiveEntry  bool
	}{
		{name: "archive source", archiveSource: true},
		{name: "archive entry", archiveEntry: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			candidate := BlobCandidate{
				SHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				StorageKey: "blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				SizeBytes:  7,
			}

			expectBlobFenceStart(mock, candidate.SHA256)
			mock.ExpectBegin()
			mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
				WithArgs(candidate.SHA256).
				WillReturnRows(sqlmock.NewRows([]string{"id", "state"}).AddRow(uint64(9), "deleted"))
			mock.ExpectQuery(`(?s)SELECT.*FROM uploads.*FROM tasks.*FROM file_node_blob_refs.*FROM archive_imports.*source_blob_reference_released_at IS NULL.*FROM archive_import_entries.*blob_reference_released_at IS NULL`).
				WithArgs(uint64(9), uint64(9), uint64(9), uint64(9), uint64(9)).
				WillReturnRows(sqlmock.NewRows([]string{
					"upload", "task", "file_node", "archive_source", "archive_entry",
				}).AddRow(false, false, false, test.archiveSource, test.archiveEntry))
			mock.ExpectCommit()
			expectBlobFenceEnd(mock, candidate.SHA256)
			called := false
			removed, err := repository.DeleteOrphanBlob(
				context.Background(), candidate,
				func(context.Context) error {
					called = true
					return nil
				},
			)
			if err != nil || removed || called {
				t.Fatalf("DeleteOrphanBlob() = (%v, %v), callback=%v", removed, err, called)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMySQLRepositoryDeletesPhysicalBlobBehindReleasedTombstone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		StorageKey: "blobs/sha256/ee/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		SizeBytes:  8,
	}

	expectBlobFenceStart(mock, candidate.SHA256)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id", "state"}).AddRow(uint64(10), "deleted"))
	mock.ExpectQuery(`(?s)SELECT.*FROM uploads.*FROM tasks.*FROM file_node_blob_refs.*FROM archive_imports.*source_blob_reference_released_at IS NULL.*FROM archive_import_entries.*blob_reference_released_at IS NULL`).
		WithArgs(uint64(10), uint64(10), uint64(10), uint64(10), uint64(10)).
		WillReturnRows(sqlmock.NewRows([]string{
			"upload", "task", "file_node", "archive_source", "archive_entry",
		}).AddRow(false, false, false, false, false))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM blobs b.*storage_key = \?.*state <> 'deleted'.*archive_imports.*source_blob_reference_released_at IS NULL.*archive_import_entries.*blob_reference_released_at IS NULL`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	expectBlobFenceEnd(mock, candidate.SHA256)
	called := false
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || !removed || !called {
		t.Fatalf("DeleteOrphanBlob() = (%v, %v), callback=%v", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDeletesAndAuditsOrphanBlob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		StorageKey: "blobs/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SizeBytes:  6,
	}

	expectBlobFenceStart(mock, candidate.SHA256)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id", "state"}))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM blobs b.*storage_key = \?.*state <> 'deleted'.*archive_imports.*archive_import_entries`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_blob_removed", "blob",
			candidate.SHA256, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	expectBlobFenceEnd(mock, candidate.SHA256)
	called := 0
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf("DeleteOrphanBlob() = (%v, %v), callbacks=%d", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReportsAuditFailureAfterFilesystemDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobCandidate{
		SHA256:     "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		StorageKey: "blobs/sha256/cc/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		SizeBytes:  3,
	}
	auditErr := errors.New("audit unavailable")
	expectBlobFenceStart(mock, candidate.SHA256)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT stored_blob[.]id, stored_blob[.]state\s+FROM blobs stored_blob FORCE INDEX \(uq_blobs_sha256\).*FOR UPDATE`).
		WithArgs(candidate.SHA256).
		WillReturnRows(sqlmock.NewRows([]string{"id", "state"}))
	mock.ExpectQuery(`SELECT EXISTS`).WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	mock.ExpectExec(`INSERT INTO audit_logs`).WillReturnError(auditErr)
	mock.ExpectRollback()
	expectBlobFenceEnd(mock, candidate.SHA256)
	deleted := false
	removed, err := repository.DeleteOrphanBlob(
		context.Background(), candidate,
		func(context.Context) error {
			deleted = true
			return nil
		},
	)
	if !deleted || removed || !errors.Is(err, auditErr) {
		t.Fatalf("audit failure = (%v, %v), deleted=%v", removed, err, deleted)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryFencesUploadDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := UploadCandidate{ID: "123e4567-e89b-42d3-a456-426614174000"}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM uploads.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_upload_removed", "upload",
			candidate.ID, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanUpload(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf("DeleteOrphanUpload() = (%v, %v), callbacks=%d", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRetriesSoftDeletedSourceProjectCompletion(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := PendingSourceProject{
		ID:            "113e4567-e89b-42d3-a456-426614174017",
		TaskID:        "213e4567-e89b-42d3-a456-426614174018",
		LayoutVersion: "project-v1",
	}
	rootKey := "source-projects/" + candidate.ID

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"layout_version", "root_storage_key", "active_deletion"},
		).AddRow("project-v1", rootKey, false))
	mock.ExpectExec(`(?s)UPDATE decompile_results.*source_offset_bytes = NULL.*analyzer_run_id = \?`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(`(?s)UPDATE decompile_source_projects.*storage_deleted_at = UTC_TIMESTAMP`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceProjectAudit(
		mock, "maintenance.deleted_source_project_cleaned", candidate.ID,
	)
	mock.ExpectCommit()
	callbackCalls := 0
	completed, err := repository.CleanupPendingSourceProject(
		context.Background(), candidate,
		func(_ context.Context, target SourceProjectCleanupTarget) error {
			callbackCalls++
			if target.ProjectID != candidate.ID || target.TaskID != candidate.TaskID ||
				target.LayoutVersion != "project-v1" ||
				len(target.LegacyResultIDs) != 0 {
				t.Fatalf("cleanup target = %+v", target)
			}
			// Missing directories are intentionally idempotent: this represents a
			// crash after filesystem removal but before database completion.
			return nil
		},
	)
	if err != nil || !completed || callbackCalls != 1 {
		t.Fatalf(
			"CleanupPendingSourceProject() = (%v, %v), callbacks=%d",
			completed, err, callbackCalls,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryCompletesPendingLegacySourceProjectCleanup(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := PendingSourceProject{
		ID:            "123e4567-e89b-42d3-a456-426614174010",
		TaskID:        "223e4567-e89b-42d3-a456-426614174011",
		LayoutVersion: "legacy-v1",
	}
	resultIDs := []string{
		"323e4567-e89b-42d3-a456-426614174012",
		"423e4567-e89b-42d3-a456-426614174013",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"layout_version", "root_storage_key", "active_deletion"},
		).AddRow("legacy-v1", nil, false))
	mock.ExpectQuery(`(?s)SELECT id.*FROM decompile_results.*analyzer_run_id = \?.*FOR UPDATE`).
		WithArgs(candidate.TaskID, candidate.ID, maxDirectoryEntries+1).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).
			AddRow(resultIDs[0]).AddRow(resultIDs[1]))
	mock.ExpectExec(`(?s)UPDATE decompile_results.*source_offset_bytes = NULL.*analyzer_run_id = \?`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(`(?s)UPDATE decompile_source_projects.*storage_deleted_at = UTC_TIMESTAMP`).
		WithArgs(candidate.TaskID, candidate.ID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectSourceProjectAudit(
		mock, "maintenance.deleted_source_project_cleaned", candidate.ID,
	)
	mock.ExpectCommit()
	var target SourceProjectCleanupTarget
	completed, err := repository.CleanupPendingSourceProject(
		context.Background(), candidate,
		func(_ context.Context, value SourceProjectCleanupTarget) error {
			target = value
			return nil
		},
	)
	if err != nil || !completed || target.LayoutVersion != "legacy-v1" ||
		len(target.LegacyResultIDs) != 2 ||
		target.LegacyResultIDs[0] != resultIDs[0] ||
		target.LegacyResultIDs[1] != resultIDs[1] {
		t.Fatalf(
			"CleanupPendingSourceProject() = (%+v, %v, %v)",
			target, completed, err,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryProtectsActiveAndDeletesUnpublishedSourceProject(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := SourceProjectCandidate{
		ID:         "523e4567-e89b-42d3-a456-426614174014",
		StorageKey: "source-projects/523e4567-e89b-42d3-a456-426614174014",
	}

	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM decompile_source_projects.*root_storage_key = \?.*deleted_at IS NULL`).
		WithArgs(candidate.ID, candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err := repository.SourceProjectReferenced(
		context.Background(), candidate,
	)
	if err != nil || !referenced {
		t.Fatalf("SourceProjectReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]task_id, project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"task_id", "layout_version", "root_storage_key", "deleted_at", "storage_deleted_at", "active_deletion"},
		).AddRow(
			"623e4567-e89b-42d3-a456-426614174015", "project-v1",
			candidate.StorageKey, nil, nil, false,
		))
	mock.ExpectCommit()
	called := false
	removed, err := repository.DeleteOrphanSourceProject(
		context.Background(), candidate,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || removed || called {
		t.Fatalf("protected source project = (%v, %v), callback=%v", removed, err, called)
	}

	orphan := SourceProjectCandidate{
		ID:         "723e4567-e89b-42d3-a456-426614174016",
		StorageKey: "source-projects/723e4567-e89b-42d3-a456-426614174016",
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]task_id, project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FROM decompile_source_projects project.*FOR UPDATE`).
		WithArgs(orphan.ID).
		WillReturnError(sql.ErrNoRows)
	expectSourceProjectAudit(
		mock, "maintenance.orphan_source_project_removed", orphan.ID,
	)
	mock.ExpectCommit()
	called = false
	removed, err = repository.DeleteOrphanSourceProject(
		context.Background(), orphan,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || !removed || !called {
		t.Fatalf("orphan source project = (%v, %v), callback=%v", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryProtectsActiveSourceProjectDeletionFromBothSweepPaths(
	t *testing.T,
) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := SourceProjectCandidate{
		ID:         "823e4567-e89b-42d3-a456-426614174020",
		StorageKey: "source-projects/823e4567-e89b-42d3-a456-426614174020",
	}
	taskID := "923e4567-e89b-42d3-a456-426614174021"
	pending := PendingSourceProject{
		ID: candidate.ID, TaskID: taskID, LayoutVersion: "project-v1",
	}

	mock.ExpectQuery(`(?s)FROM decompile_source_projects project.*NOT EXISTS.*source_project_deletion_operations.*active_project_id = project[.]id`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "task_id", "layout_version"},
		))
	projects, err := repository.ListPendingSourceProjects(context.Background(), 10)
	if err != nil || len(projects) != 0 {
		t.Fatalf("ListPendingSourceProjects() = (%v, %v)", projects, err)
	}

	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM decompile_source_projects project.*project[.]deleted_at IS NULL OR.*source_project_deletion_operations.*active_project_id = project[.]id`).
		WithArgs(candidate.ID, candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err := repository.SourceProjectReferenced(
		context.Background(), candidate,
	)
	if err != nil || !referenced {
		t.Fatalf("SourceProjectReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FOR UPDATE`).
		WithArgs(taskID, candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"layout_version", "root_storage_key", "active_deletion",
		}).AddRow("project-v1", candidate.StorageKey, true))
	mock.ExpectCommit()
	called := false
	completed, err := repository.CleanupPendingSourceProject(
		context.Background(), pending,
		func(context.Context, SourceProjectCleanupTarget) error {
			called = true
			return nil
		},
	)
	if err != nil || completed || called {
		t.Fatalf(
			"protected CleanupPendingSourceProject() = (%v, %v), callback=%v",
			completed, err, called,
		)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT project[.]task_id, project[.]layout_version, project[.]root_storage_key,.*active_project_id.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "layout_version", "root_storage_key", "deleted_at",
			"storage_deleted_at", "active_deletion",
		}).AddRow(
			taskID, "project-v1", candidate.StorageKey,
			time.Now().UTC(), nil, true,
		))
	mock.ExpectCommit()
	removed, err := repository.DeleteOrphanSourceProject(
		context.Background(), candidate,
		func(context.Context) error {
			called = true
			return nil
		},
	)
	if err != nil || removed || called {
		t.Fatalf(
			"protected DeleteOrphanSourceProject() = (%v, %v), callback=%v",
			removed, err, called,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReconcilesArchiveImportBlobReferences(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobReferenceCandidate{ID: 42}
	createdAt := time.Now().Add(-48 * time.Hour)

	mock.ExpectQuery(`SELECT id\s+FROM blobs\s+WHERE id > \? AND state <> 'deleted'`).
		WithArgs(uint64(0), 10).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uint64(42)))
	candidates, err := repository.ListBlobReferenceCandidates(
		context.Background(), 0, 10,
	)
	if err != nil || len(candidates) != 1 || candidates[0] != candidate {
		t.Fatalf("ListBlobReferenceCandidates() = (%v, %v)", candidates, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT reference_count, state, created_at\s+FROM blobs.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"reference_count", "state", "created_at"},
		).AddRow(uint64(9), "available", createdAt))
	mock.ExpectQuery(`SELECT\s+\(SELECT COUNT\(\*\) FROM uploads.*file_node_blob_refs.*archive_imports.*archive_import_entries`).
		WithArgs(candidate.ID, candidate.ID, candidate.ID, candidate.ID, candidate.ID).
		// One unreleased archive source and one unreleased eligible entry.
		WillReturnRows(sqlmock.NewRows([]string{"actual_count"}).AddRow(uint64(2)))
	mock.ExpectExec(`UPDATE blobs\s+SET reference_count = \?.*state = \?`).
		WithArgs(uint64(2), "available", "available", candidate.ID, "available", uint64(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.blob_reference_reconciled", "blob",
			"42", "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	result, err := repository.ReconcileBlobReference(
		context.Background(), candidate, time.Now().Add(-24*time.Hour), false,
	)
	if err != nil || !result.Drifted || !result.Corrected ||
		result.PreviousCount != 9 || result.ActualCount != 2 ||
		result.CurrentState != "available" {
		t.Fatalf("ReconcileBlobReference() = (%+v, %v)", result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryMakesBlobDeletableAfterArchiveReferencesRelease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := BlobReferenceCandidate{ID: 43}
	createdAt := time.Now().Add(-48 * time.Hour)

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT reference_count, state, created_at\s+FROM blobs.*FOR UPDATE`).
		WithArgs(candidate.ID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"reference_count", "state", "created_at"},
		).AddRow(uint64(2), "available", createdAt))
	mock.ExpectQuery(`SELECT\s+\(SELECT COUNT\(\*\) FROM uploads.*archive_imports.*archive_import_entries`).
		WithArgs(candidate.ID, candidate.ID, candidate.ID, candidate.ID, candidate.ID).
		WillReturnRows(sqlmock.NewRows([]string{"actual_count"}).AddRow(uint64(0)))
	mock.ExpectExec(`UPDATE blobs\s+SET reference_count = \?.*state = \?`).
		WithArgs(uint64(0), "deleting", "deleting", candidate.ID, "available", uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.blob_reference_reconciled", "blob",
			"43", "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	result, err := repository.ReconcileBlobReference(
		context.Background(), candidate, time.Now().Add(-24*time.Hour), false,
	)
	if err != nil || result.ActualCount != 0 || result.CurrentState != "deleting" ||
		!result.Corrected {
		t.Fatalf("ReconcileBlobReference() = (%+v, %v)", result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectSourceProjectAudit(
	mock sqlmock.Sqlmock,
	action string,
	projectID string,
) {
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, action, "decompile_source_project", projectID,
			"success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

func TestMySQLRepositoryRechecksAndAuditsStoredFileDeletion(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	candidate := StoredFileCandidate{
		Kind: StoredFileReport,
		StorageKey: "reports/123e4567-e89b-42d3-a456-426614174000/" +
			"223e4567-e89b-42d3-a456-426614174000.json",
		SHA256: strings.Repeat("a", 64), SizeBytes: 12,
	}

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT id\s+FROM reports FORCE INDEX`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(false))
	referenced, err := repository.StoredFileReferenced(context.Background(), candidate)
	if err != nil || referenced {
		t.Fatalf("StoredFileReferenced() = (%v, %v)", referenced, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT id\s+FROM reports FORCE INDEX.*FOR UPDATE`).
		WithArgs(candidate.StorageKey).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_stored_file_removed", "report",
			candidate.SHA256, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanStoredFile(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf(
			"DeleteOrphanStoredFile() = (%v, %v), callbacks=%d",
			removed, err, called,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryProtectsActiveReportStagingAndDeletesOrphan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	taskID := "323e4567-e89b-42d3-a456-426614174000"
	reportID := "423e4567-e89b-42d3-a456-426614174000"
	candidate := StoredFileCandidate{
		Kind: StoredFileReportStaging,
		StorageKey: "reports/" + taskID + "/." + reportID + "." +
			strings.Repeat("b", 24) + ".staging",
		SHA256: strings.Repeat("c", 64), SizeBytes: 31,
	}

	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM reports.*task_id = \?.*id = \?.*snapshot_state = 'staged'.*status IN`).
		WithArgs(taskID, reportID).
		WillReturnRows(sqlmock.NewRows([]string{"referenced"}).AddRow(true))
	referenced, err := repository.StoredFileReferenced(context.Background(), candidate)
	if err != nil || !referenced {
		t.Fatalf("active report staging reference = (%v, %v)", referenced, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id.*FROM reports.*task_id = \?.*id = \?.*FOR UPDATE`).
		WithArgs(taskID, reportID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(reportID))
	mock.ExpectCommit()
	called := 0
	removed, err := repository.DeleteOrphanStoredFile(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || removed || called != 0 {
		t.Fatalf("protected report staging = (%v, %v), callbacks=%d", removed, err, called)
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id.*FROM reports.*task_id = \?.*id = \?.*FOR UPDATE`).
		WithArgs(taskID, reportID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			nil, nil, "maintenance.orphan_stored_file_removed", "report-staging",
			candidate.SHA256, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	removed, err = repository.DeleteOrphanStoredFile(
		context.Background(), candidate,
		func(context.Context) error {
			called++
			return nil
		},
	)
	if err != nil || !removed || called != 1 {
		t.Fatalf("orphan report staging = (%v, %v), callbacks=%d", removed, err, called)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
