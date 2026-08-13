package scan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"binaryscan/internal/queue"
	"binaryscan/internal/trivyhandoff"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnqueueTrivyCreatesFencedAttemptHandoff(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	payload := validTrivyPayload(false)

	mock.ExpectBegin()
	expectTrivyHandoffLocks(mock, lease)
	mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, kind, status, attempt, max_attempts,.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(lease.TaskID, "trivy:attempt:19").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO jobs.*kind, status, priority, payload.*'trivy', 'queued'.*0, \?, \?, \?`).
		WithArgs(
			sqlmock.AnyArg(), lease.TaskID, uint64(19), sqlmock.AnyArg(),
			trivyJobMaxAttempts, lease.FencingToken, "trivy:attempt:19",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.EnqueueTrivy(
		context.Background(), lease, payload,
	); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueTrivyReplayIsStableAndRefreshesOnlyFence(t *testing.T) {
	tests := []struct {
		name          string
		existingFence uint64
		wantRefresh   bool
	}{
		{name: "same fence", existingFence: 7},
		{name: "recovered scan fence", existingFence: 6, wantRefresh: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			lease := scanLease()
			payload := validTrivyPayload(true)
			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}

			mock.ExpectBegin()
			expectTrivyHandoffLocks(mock, lease)
			mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, kind, status, attempt, max_attempts,.*FROM jobs.*FOR UPDATE`).
				WithArgs(lease.TaskID, "trivy:attempt:19").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_attempt_id", "kind", "status", "attempt",
					"max_attempts", "fencing_token", "payload",
				}).AddRow(
					"223e4567-e89b-42d3-a456-426614174000",
					uint64(19), "trivy", "queued", 0, 3,
					test.existingFence, encoded,
				))
			if test.wantRefresh {
				mock.ExpectExec(`(?s)UPDATE jobs.*SET fencing_token = \?.*kind = 'trivy'.*status = 'queued'.*attempt = 0.*fencing_token = \?`).
					WithArgs(
						lease.FencingToken,
						"223e4567-e89b-42d3-a456-426614174000",
						lease.TaskID, uint64(19), test.existingFence,
					).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectCommit()

			if err := repository.EnqueueTrivy(
				context.Background(), lease, payload,
			); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnqueueTrivyRejectsPayloadDriftAndAdvancedExistingJob(t *testing.T) {
	tests := []struct {
		name    string
		status  string
		attempt uint32
		mutate  func(*TrivyJobPayload)
	}{
		{
			name: "payload drift", status: "queued",
			mutate: func(payload *TrivyJobPayload) {
				payload.UpstreamPartial = true
			},
		},
		{name: "already running", status: "running", attempt: 1},
		{name: "already terminal", status: "succeeded", attempt: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			lease := scanLease()
			payload := validTrivyPayload(false)
			existingPayload := payload
			if test.mutate != nil {
				test.mutate(&existingPayload)
			}
			encoded, err := json.Marshal(existingPayload)
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectBegin()
			expectTrivyHandoffLocks(mock, lease)
			mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, kind, status, attempt, max_attempts,.*FROM jobs.*FOR UPDATE`).
				WithArgs(lease.TaskID, "trivy:attempt:19").
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_attempt_id", "kind", "status", "attempt",
					"max_attempts", "fencing_token", "payload",
				}).AddRow(
					"223e4567-e89b-42d3-a456-426614174000",
					uint64(19), "trivy", test.status, test.attempt, 3,
					lease.FencingToken, encoded,
				))
			mock.ExpectRollback()

			err = repository.EnqueueTrivy(context.Background(), lease, payload)
			if !errors.Is(err, queue.ErrInconsistentState) {
				t.Fatalf("EnqueueTrivy() error = %v, want inconsistent state", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnqueueTrivyAcceptsVMImageRootFormat(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	payload := TrivyJobPayload{
		SchemaVersion: TrivyJobPayloadSchemaVersion,
		Sources: []TrivySource{{
			Format:           trivyhandoff.FormatVMImage,
			SourceStorageKey: "blobs/sha256/bb/" + digest,
			SourceSHA256:     digest,
			SourceSizeBytes:  32 << 20,
			ImageLogicalPath: "/",
		}},
		MaxExpandedBytes: 50 * 1024 * 1024 * 1024,
		MaxArchiveRatio:  100,
	}

	mock.ExpectBegin()
	expectTrivyHandoffLocksWithRootFormat(mock, lease, "ext2", payload)
	mock.ExpectQuery(`(?s)SELECT id, task_attempt_id, kind, status, attempt, max_attempts,.*FROM jobs.*idempotency_key = \?.*FOR UPDATE`).
		WithArgs(lease.TaskID, "trivy:attempt:19").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`(?s)INSERT INTO jobs.*kind, status, priority, payload.*'trivy', 'queued'.*0, \?, \?, \?`).
		WithArgs(
			sqlmock.AnyArg(), lease.TaskID, uint64(19), sqlmock.AnyArg(),
			trivyJobMaxAttempts, lease.FencingToken, "trivy:attempt:19",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := repository.EnqueueTrivy(
		context.Background(), lease, payload,
	); err != nil {
		t.Fatalf("EnqueueTrivy() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueTrivyRejectsVMImageRootWithNonVMFormat(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	digest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	payload := TrivyJobPayload{
		SchemaVersion: TrivyJobPayloadSchemaVersion,
		Sources: []TrivySource{{
			Format:           trivyhandoff.FormatVMImage,
			SourceStorageKey: "blobs/sha256/cc/" + digest,
			SourceSHA256:     digest,
			SourceSizeBytes:  1 << 20,
			ImageLogicalPath: "/",
		}},
		MaxExpandedBytes: 50 * 1024 * 1024 * 1024,
		MaxArchiveRatio:  100,
	}

	mock.ExpectBegin()
	expectTrivyHandoffLocksWithRootFormat(mock, lease, "iso9660", payload)
	mock.ExpectRollback()

	err = repository.EnqueueTrivy(context.Background(), lease, payload)
	if !errors.Is(err, queue.ErrInconsistentState) {
		t.Fatalf("EnqueueTrivy() error = %v, want inconsistent state", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// expectTrivyHandoffLocksWithRootFormat is expectTrivyHandoffLocks with an
// explicit root-node format, which differs from the handoff format for
// vm-image sources.
func expectTrivyHandoffLocksWithRootFormat(
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	rootFormat string,
	payload TrivyJobPayload,
) {
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*kind = 'scan'.*status = 'running'.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
			AddRow(uint64(19)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*FOR UPDATE`).
		WithArgs(uint64(19), lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"fencing_token"}).
			AddRow(lease.FencingToken))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*status = 'INDEXING'.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("INDEXING"))
	source := payload.Sources[0]
	mock.ExpectQuery(`(?s)SELECT format, storage_key, sha256, size_bytes.*FROM file_nodes.*parent_id IS NULL.*depth = 0.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"format", "storage_key", "sha256", "size_bytes",
		}).AddRow(
			rootFormat, source.SourceStorageKey,
			source.SourceSHA256, source.SourceSizeBytes,
		))
}

func TestEnqueueTrivyRejectsInvalidPayloadBeforeDatabaseMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := validTrivyPayload(false)
	payload.Sources[0].Format = "tar"

	err = repository.EnqueueTrivy(context.Background(), scanLease(), payload)
	if !errors.Is(err, ErrInvalidTrivyJob) {
		t.Fatalf("EnqueueTrivy() error = %v, want ErrInvalidTrivyJob", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestEnqueueTrivyRejectsSourceThatDoesNotMatchPublishedRoot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := scanLease()
	payload := validTrivyPayload(false)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*kind = 'scan'.*status = 'running'.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
			AddRow(uint64(19)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*FOR UPDATE`).
		WithArgs(uint64(19), lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"fencing_token"}).
			AddRow(lease.FencingToken))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*status = 'INDEXING'.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("INDEXING"))
	mock.ExpectQuery(`(?s)SELECT format, storage_key, sha256, size_bytes.*FROM file_nodes.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"format", "storage_key", "sha256", "size_bytes",
		}).AddRow(
			"oci-tar", payload.Sources[0].SourceStorageKey,
			payload.Sources[0].SourceSHA256,
			payload.Sources[0].SourceSizeBytes,
		))
	mock.ExpectRollback()

	err = repository.EnqueueTrivy(context.Background(), lease, payload)
	if !errors.Is(err, queue.ErrInconsistentState) {
		t.Fatalf("EnqueueTrivy() error = %v, want inconsistent state", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectTrivyHandoffLocks(mock sqlmock.Sqlmock, lease queue.Lease) {
	mock.ExpectQuery(`(?s)SELECT task_attempt_id.*FROM jobs.*kind = 'scan'.*status = 'running'.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"task_attempt_id"}).
			AddRow(uint64(19)))
	mock.ExpectQuery(`(?s)SELECT fencing_token.*FROM task_attempts.*status = 'running'.*FOR UPDATE`).
		WithArgs(uint64(19), lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"fencing_token"}).
			AddRow(lease.FencingToken))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*status = 'INDEXING'.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("INDEXING"))
	payload := validTrivyPayload(false)
	source := payload.Sources[0]
	mock.ExpectQuery(`(?s)SELECT format, storage_key, sha256, size_bytes.*FROM file_nodes.*parent_id IS NULL.*depth = 0.*FOR UPDATE`).
		WithArgs(lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{
			"format", "storage_key", "sha256", "size_bytes",
		}).AddRow(
			source.Format, source.SourceStorageKey,
			source.SourceSHA256, source.SourceSizeBytes,
		))
}

func validTrivyPayload(partial bool) TrivyJobPayload {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return TrivyJobPayload{
		SchemaVersion: TrivyJobPayloadSchemaVersion,
		Sources: []TrivySource{{
			Format:           "docker-tar",
			SourceStorageKey: "blobs/sha256/aa/" + digest,
			SourceSHA256:     digest,
			SourceSizeBytes:  4096,
			ImageLogicalPath: "/",
		}},
		MaxExpandedBytes: 50 * 1024 * 1024 * 1024,
		MaxArchiveRatio:  100,
		UpstreamPartial:  partial,
	}
}
