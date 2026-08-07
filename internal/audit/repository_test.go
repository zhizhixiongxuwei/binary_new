package audit

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRepositoryListDoesNotExposeNetworkIdentifiers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows([]string{
		"id", "public_id", "username", "display_name", "request_id",
		"action", "object_type", "object_id", "outcome", "metadata_json",
		"created_at",
	})
	for id := uint64(3); id > 0; id-- {
		rows.AddRow(
			id, "00000000-0000-4000-8000-000000000001", "admin",
			"Administrator", "request-1", "user.update", "user", "target",
			"success", []byte(`{"password":"redacted","role":"reader"}`), now,
		)
	}
	mock.ExpectQuery(regexp.QuoteMeta(`
SELECT a.id, u.public_id, u.username, u.display_name, a.request_id,
       a.action, a.object_type, a.object_id, a.outcome, a.metadata_json,
       a.created_at
FROM audit_logs a
LEFT JOIN users u ON u.id = a.actor_user_id
WHERE 1 = 1
ORDER BY a.id DESC
LIMIT ?`)).
		WithArgs(3).
		WillReturnRows(rows)

	page, err := repository.List(context.Background(), RepositoryListQuery{
		PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("page = %#v", page)
	}
	var metadata map[string]any
	if err := json.Unmarshal(page.Items[0].Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata["password"]; exists || metadata["role"] != "reader" {
		t.Fatalf("read metadata was not sanitized: %s", page.Items[0].Metadata)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAppendOnlyRepositoryUsesInsert(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	actorID := uint64(9)
	mock.ExpectExec(regexp.QuoteMeta(`
INSERT INTO audit_logs (
    actor_user_id, request_id, action, object_type, object_id, outcome,
    client_ip, user_agent, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)).
		WithArgs(
			&actorID, "request-9", "user.create", "user", "target", OutcomeSuccess,
			[]byte{127, 0, 0, 1}, "browser", sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	err = NewMySQLRepository(db).Record(context.Background(), Event{
		ActorUserID: &actorID, RequestID: "request-9", Action: "user.create",
		ObjectType: "user", ObjectID: "target", Outcome: OutcomeSuccess,
		ClientIP: []byte{127, 0, 0, 1}, UserAgent: "browser",
		Metadata: map[string]any{"role": "reader"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
