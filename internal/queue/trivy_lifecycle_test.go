package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestTrivyLifecyclePayloadIsStrictAndRequiresPartialProvenance(
	t *testing.T,
) {
	valid := queueTrivyPayload(false)
	if partial, err := trivyUpstreamPartial(valid); err != nil || partial {
		t.Fatalf("trivyUpstreamPartial(valid) = (%v, %v)", partial, err)
	}
	tests := []string{
		`{"schema_version":1,"format":"docker-tar","source_storage_key":"blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_size_bytes":1,"image_logical_path":"/"}`,
		`{"schema_version":1,"format":"docker-tar","source_storage_key":"../image.tar","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_size_bytes":1,"image_logical_path":"/","upstream_partial":false}`,
		`{"schema_version":1,"format":"docker-tar","source_storage_key":"blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_size_bytes":1,"image_logical_path":"/","upstream_partial":false,"extra":true}`,
	}
	for _, raw := range tests {
		if _, err := trivyUpstreamPartial(
			[]byte(raw),
		); !errors.Is(err, ErrInconsistentState) {
			t.Fatalf("trivyUpstreamPartial(%s) error = %v", raw, err)
		}
	}
}

func TestClaimTrivyRequiresScanningHandoffAndAdvancesAttemptFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	until := time.Now().UTC().Add(time.Minute)
	payload := queueTrivyPayload(false)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j\.id.*j\.kind <> 'trivy'.*task\.status = 'SCANNING'.*attempt\.status = 'running'.*attempt\.fencing_token = j\.fencing_token.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindTrivy).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind", "payload",
			"attempt", "max_attempts", "fencing_token",
			"attempt_fencing_token", "attempt_status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "trivy", payload,
			0, 3, 7, 7, "running",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'leased'.*fencing_token = fencing_token \+ 1`).
		WithArgs(
			"trivy-worker-1", int64(time.Minute/time.Microsecond),
			testJobID, uint32(0), uint64(7),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET fencing_token = \?.*status = 'running'`).
		WithArgs(uint64(8), int64(19), testTaskID, int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT lease_until.*FROM jobs`).
		WithArgs(testJobID).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	lease, found, err := repository.Claim(context.Background(), claimRequest{
		Kind: KindTrivy, Owner: "trivy-worker-1",
		LeaseDurationMicros: int64(time.Minute / time.Microsecond),
	})
	if err != nil || !found {
		t.Fatalf("Claim() = (%+v, %v, %v)", lease, found, err)
	}
	if lease.Kind != KindTrivy || lease.TaskAttemptID == nil ||
		*lease.TaskAttemptID != 19 || lease.FencingToken != 8 ||
		lease.Attempt != 1 || string(lease.Payload) != string(payload) {
		t.Fatalf("Trivy lease = %+v", lease)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStartTrivyValidatesSharedAttemptAndScanningStage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := trivyLease()

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'running'.*lease_until > UTC_TIMESTAMP`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM task_attempts attempt.*JOIN tasks task.*attempt\.status = 'running'.*task\.status = 'SCANNING'.*task\.stage = 'SCANNING'.*FOR UPDATE`).
		WithArgs(uint64(19), lease.TaskID, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
	mock.ExpectCommit()

	if err := repository.Start(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishScanWithQueuedTrivyHandsOffWithoutTerminalizingTask(
	t *testing.T,
) {
	for _, outcome := range []Outcome{
		OutcomeSucceeded,
		OutcomePartialSucceeded,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			lease := testLease()

			mock.ExpectBegin()
			expectFinishingJobLock(mock, lease, "scan", 1, 3)
			mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
				WithArgs(
					"succeeded", "", "", lease.JobID, lease.TaskID,
					lease.Owner, lease.FencingToken,
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`(?s)SELECT EXISTS.*kind = 'trivy'.*status = 'queued'`).
				WithArgs(lease.TaskID, uint64(19)).
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
			mock.ExpectQuery(`(?s)SELECT 1.*FROM task_attempts.*status = 'running'.*FOR UPDATE`).
				WithArgs(uint64(19), lease.TaskID, lease.FencingToken).
				WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
			mock.ExpectExec(`(?s)UPDATE tasks.*status = 'SCANNING'.*stage = 'SCANNING'.*completed_at = NULL.*status NOT IN`).
				WithArgs(uint16(7_000), lease.TaskID).
				WillReturnResult(sqlmock.NewResult(0, 1))
			expectTaskEvent(
				mock, "task.status_changed",
				"Container vulnerability scan queued.",
			)
			mock.ExpectCommit()

			err = repository.Finish(context.Background(), finishRequest{
				Lease: lease, Input: FinishInput{Outcome: outcome},
				SampleRetentionMicros: testSampleRetentionMicros,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFinishTrivyTerminalOutcomesAndUpstreamPartial(t *testing.T) {
	tests := []struct {
		name            string
		outcome         Outcome
		upstreamPartial bool
		errorCode       string
		errorMessage    string
		taskStatus      string
		attemptStatus   string
		progress        uint16
		jobStatus       string
	}{
		{
			name: "complete success", outcome: OutcomeSucceeded,
			taskStatus: "SUCCEEDED", attemptStatus: "succeeded",
			progress: 10_000, jobStatus: "succeeded",
		},
		{
			name: "upstream partial success", outcome: OutcomeSucceeded,
			upstreamPartial: true, taskStatus: "PARTIAL_SUCCEEDED",
			attemptStatus: "succeeded", progress: 10_000,
			jobStatus: "succeeded",
		},
		{
			name: "Trivy partial success", outcome: OutcomePartialSucceeded,
			taskStatus: "PARTIAL_SUCCEEDED", attemptStatus: "succeeded",
			progress: 10_000, jobStatus: "succeeded",
		},
		{
			name: "deterministic failure", outcome: OutcomeDeterministicFailure,
			errorCode: "invalid_image", errorMessage: "Invalid image archive.",
			taskStatus: "FAILED", attemptStatus: "failed",
			jobStatus: "failed",
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
			lease := trivyLease()
			input := FinishInput{
				Outcome: test.outcome, ErrorCode: test.errorCode,
				ErrorMessage: test.errorMessage,
			}

			mock.ExpectBegin()
			expectFinishingJobLock(mock, lease, "trivy", 1, 3)
			mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
				WithArgs(
					test.jobStatus, test.errorCode, test.errorMessage,
					lease.JobID, lease.TaskID, lease.Owner,
					lease.FencingToken,
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`(?s)SELECT payload FROM jobs`).
				WithArgs(lease.JobID, lease.TaskID).
				WillReturnRows(sqlmock.NewRows([]string{"payload"}).
					AddRow(queueTrivyPayload(test.upstreamPartial)))
			mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*completed_at = UTC_TIMESTAMP.*status = 'running'`).
				WithArgs(
					test.attemptStatus, test.errorCode, test.errorMessage,
					uint64(19), lease.TaskID, lease.FencingToken,
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*progress_basis_points = \?.*sample_expires_at = CASE.*status IN \('SCANNING', 'REPORTING'\)`).
				WithArgs(
					test.taskStatus, test.progress, test.errorCode,
					test.errorMessage, testSampleRetentionMicros,
					lease.TaskID,
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			expectTaskEvent(
				mock, "task.status_changed",
				"Container vulnerability scan finished.",
			)
			mock.ExpectCommit()

			err = repository.Finish(context.Background(), finishRequest{
				Lease: lease, Input: input,
				SampleRetentionMicros: testSampleRetentionMicros,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFinishTrivyTransientFailureRequeuesOnlyTrivyStage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := trivyLease()
	input := FinishInput{
		Outcome: OutcomeTransientFailure, ErrorCode: "tool_timeout",
		ErrorMessage: "Trivy timed out.",
	}
	retryMicros := int64(5 * time.Second / time.Microsecond)

	mock.ExpectBegin()
	expectFinishingJobLock(mock, lease, "trivy", 1, 3)
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*available_at = DATE_ADD`).
		WithArgs(
			retryMicros, input.ErrorCode, input.ErrorMessage,
			lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT payload FROM jobs`).
		WithArgs(lease.JobID, lease.TaskID).
		WillReturnRows(sqlmock.NewRows([]string{"payload"}).
			AddRow(queueTrivyPayload(false)))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET error_code = \?.*status = 'running'`).
		WithArgs(
			input.ErrorCode, input.ErrorMessage, uint64(19),
			lease.TaskID, lease.FencingToken,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'SCANNING'.*stage = 'SCANNING'.*completed_at = NULL.*status IN \('SCANNING', 'REPORTING'\)`).
		WithArgs(uint16(7_000), input.ErrorCode, input.ErrorMessage, lease.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed",
		"Container vulnerability scan requeued after a transient failure.",
	)
	mock.ExpectCommit()

	err = repository.Finish(context.Background(), finishRequest{
		Lease: lease, Input: input, RetryDelayMicros: retryMicros,
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredTrivyLeaseRequeuesOrFailsSharedAttempt(t *testing.T) {
	tests := []struct {
		name        string
		attempt     uint32
		maxAttempts uint32
		retry       bool
	}{
		{name: "requeue", attempt: 1, maxAttempts: 3, retry: true},
		{name: "final failure", attempt: 3, maxAttempts: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			retryMicros := int64(time.Second / time.Microsecond)

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_id", "task_attempt_id", "kind",
					"attempt", "max_attempts", "fencing_token", "status",
				}).AddRow(
					testJobID, testTaskID, int64(19), "trivy",
					test.attempt, test.maxAttempts, uint64(8), "running",
				))
			if test.retry {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(retryMicros, testJobID, uint64(8)).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectResourceSlotRelease(mock, testJobID, 8, 2)
				mock.ExpectExec(`(?s)UPDATE task_attempts.*error_code = 'lease_expired'.*status = 'running'`).
					WithArgs(
						expiredMessage(true), int64(19),
						testTaskID, uint64(8),
					).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE tasks.*status = 'SCANNING'.*stage = 'SCANNING'.*status IN \('SCANNING', 'REPORTING'\)`).
					WithArgs(uint16(7_000), expiredMessage(true), testTaskID).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectTaskEvent(
					mock, "task.status_changed",
					"Container vulnerability scan recovered after a worker lease expired.",
				)
			} else {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'failed'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(testJobID, uint64(8)).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectResourceSlotRelease(mock, testJobID, 8, 2)
				mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'failed'.*completed_at = UTC_TIMESTAMP.*status = 'running'`).
					WithArgs(
						expiredMessage(false), int64(19),
						testTaskID, uint64(8),
					).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`(?s)UPDATE tasks.*status = 'FAILED'.*sample_expires_at = CASE.*status IN \('SCANNING', 'REPORTING'\)`).
					WithArgs(
						expiredMessage(false), testSampleRetentionMicros,
						testTaskID,
					).
					WillReturnResult(sqlmock.NewResult(0, 1))
				expectTaskEvent(
					mock, "task.status_changed",
					"Container vulnerability scan failed after its final worker lease expired.",
				)
			}
			mock.ExpectCommit()

			count, err := repository.RecoverExpired(
				context.Background(), 10, retryMicros,
				testSampleRetentionMicros,
			)
			if err != nil || count != 1 {
				t.Fatalf("RecoverExpired() = (%d, %v)", count, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoverCancelledTrivyFinalizesAttemptAndTask(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*cancel_requested.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "trivy",
			1, 3, uint64(8), "cancel_requested",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status = 'cancel_requested'`).
		WithArgs(testJobID, uint64(8)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 8, 2)
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'cancelled'.*fencing_token = \?`).
		WithArgs(int64(19), testTaskID, uint64(8)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs.*status = 'cancel_requested'`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"remaining"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).
			AddRow("CANCEL_REQUESTED"))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'CANCELLED'.*sample_expires_at = CASE.*status = 'CANCEL_REQUESTED'`).
		WithArgs(testSampleRetentionMicros, testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed", "Task cancellation completed.",
	)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, 0, testSampleRetentionMicros,
	)
	if err != nil || count != 1 {
		t.Fatalf("RecoverExpired() = (%d, %v)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func expectFinishingJobLock(
	mock sqlmock.Sqlmock,
	lease Lease,
	kind string,
	attempt uint32,
	maxAttempts uint32,
) {
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
		WithArgs(lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
		}).AddRow(
			lease.TaskID, int64(19), kind, attempt, maxAttempts,
		))
}

func trivyLease() Lease {
	attemptID := uint64(19)
	return Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: KindTrivy, Attempt: 1, MaxAttempts: 3,
		FencingToken: 8, Owner: "trivy-worker-1",
	}
}

func queueTrivyPayload(partial bool) []byte {
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	value, err := json.Marshal(map[string]any{
		"schema_version":     1,
		"format":             "docker-tar",
		"source_storage_key": "blobs/sha256/aa/" + digest,
		"source_sha256":      digest,
		"source_size_bytes":  4096,
		"image_logical_path": "/",
		"upstream_partial":   partial,
	})
	if err != nil {
		panic(err)
	}
	return value
}
