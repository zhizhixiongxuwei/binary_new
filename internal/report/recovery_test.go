package report

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecoverExpiredFencesGeneratorAndReleasesDeletionBarrier(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, generation_fence.*status = 'generating'.*generation_lease_until <= UTC_TIMESTAMP\(6\).*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "task_id", "generation_fence"},
		).AddRow(testReportID, testTaskID, uint64(7)))
	mock.ExpectExec(`(?s)UPDATE reports.*status = 'failed'.*generation_fence = generation_fence \+ 1.*generation_owner = NULL.*generation_lease_until = NULL.*generation_fence = \?.*generation_lease_until <= UTC_TIMESTAMP\(6\)`).
		WithArgs(testReportID, testTaskID, uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(`
INSERT INTO audit_logs (
    actor_user_id, request_id, action, object_type, object_id, outcome,
    client_ip, user_agent, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)).
		WithArgs(
			nil, nil, "report.generation_recovered", "report",
			testReportID, "success", nil, nil, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	recovered, err := repository.RecoverExpired(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != 1 {
		t.Fatalf("RecoverExpired() = %d, want 1", recovered)
	}
}

func TestRenewRejectsStaleReportFence(t *testing.T) {
	repository, mock, cleanup := newReportRepositoryMock(t)
	defer cleanup()
	mock.ExpectExec(`(?s)UPDATE reports report.*generation_owner = \?.*generation_fence = \?`).
		WithArgs(
			int64(60_000_000), testTaskID, testReportID,
			reportTestOwner, uint64(3),
		).
		WillReturnResult(sqlmock.NewResult(0, 0))

	renewed, err := repository.Renew(
		context.Background(), testTaskID, testReportID,
		reportTestOwner, 3, 60_000_000_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if renewed {
		t.Fatal("stale generator renewed a fenced report")
	}
}
