package audit

import (
	"context"
	"encoding/json"
	"testing"
)

type repositoryStub struct {
	query RepositoryListQuery
	page  Page
	err   error
}

func (r *repositoryStub) Record(context.Context, Event) error { return nil }
func (r *repositoryStub) List(_ context.Context, query RepositoryListQuery) (Page, error) {
	r.query = query
	return r.page, r.err
}

func TestListValidatesAndDecodesOpaqueCursor(t *testing.T) {
	repository := &repositoryStub{page: Page{}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), ListQuery{
		Cursor: encodeCursor("audit", 42), PageSize: 25,
		Action: "user.update", Outcome: "denied", Actor: " admin ",
		CreatedFrom: "2026-07-01T00:00:00Z",
		CreatedTo:   "2026-07-30T23:59:59Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.query.Cursor != 42 || repository.query.Actor != "admin" ||
		repository.query.Outcome != OutcomeDenied ||
		repository.query.CreatedFrom == nil || repository.query.CreatedTo == nil {
		t.Fatalf("repository query = %#v", repository.query)
	}
	if page.Items == nil {
		t.Fatal("empty page must contain a non-nil items array")
	}

	for _, invalid := range []ListQuery{
		{Cursor: "not-canonical", PageSize: 25},
		{PageSize: 0},
		{PageSize: MaxPageSize + 1},
		{PageSize: 25, Outcome: "unknown"},
		{PageSize: 25, Action: "User Update"},
		{
			PageSize: 25, CreatedFrom: "2026-07-30T00:00:00Z",
			CreatedTo: "2026-07-01T00:00:00Z",
		},
	} {
		if _, err := service.List(context.Background(), invalid); err != ErrInvalidInput {
			t.Fatalf("List(%#v) error = %v, want ErrInvalidInput", invalid, err)
		}
	}
}

func TestNormalizeEventRemovesSecretsAndBoundsMetadata(t *testing.T) {
	actorID := uint64(7)
	_, raw, err := normalizeEvent(Event{
		ActorUserID: &actorID,
		RequestID:   "request-1",
		Action:      "user.password_reset",
		ObjectType:  "user",
		ObjectID:    "00000000-0000-4000-8000-000000000001",
		Outcome:     OutcomeSuccess,
		ClientIP:    []byte{127, 0, 0, 1},
		UserAgent:   "browser",
		Metadata: map[string]any{
			"temporary_password": "never-store-this",
			"token":              "never-store-this-either",
			"source_ip":          "127.0.0.1",
			"status":             "active",
			"nested": map[string]any{
				"password_hash": "hidden",
				"reason":        "reset",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["temporary_password"] != nil || metadata["token"] != nil ||
		metadata["source_ip"] != nil {
		t.Fatalf("metadata contains a top-level secret: %s", raw)
	}
	nested := metadata["nested"].(map[string]any)
	if nested["password_hash"] != nil || nested["reason"] != "reset" {
		t.Fatalf("nested metadata was not sanitized: %#v", nested)
	}
}
