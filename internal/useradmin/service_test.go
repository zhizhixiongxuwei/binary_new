package useradmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
)

const testPublicID = "00000000-0000-4000-8000-000000000001"

type repositoryStub struct {
	listQuery RepositoryListQuery
	create    CreateRecord
	update    UpdateRecord
	reset     ResetPasswordRecord
	result    User
	err       error
}

func (r *repositoryStub) List(_ context.Context, query RepositoryListQuery) (Page, error) {
	r.listQuery = query
	return Page{Items: []User{}}, r.err
}
func (r *repositoryStub) Create(_ context.Context, value CreateRecord) (User, error) {
	r.create = value
	return r.result, r.err
}
func (r *repositoryStub) Update(_ context.Context, value UpdateRecord) (User, error) {
	r.update = value
	return r.result, r.err
}
func (r *repositoryStub) ResetPassword(_ context.Context, value ResetPasswordRecord) (User, error) {
	r.reset = value
	return r.result, r.err
}

type auditRecorderStub struct {
	events []audit.Event
}

func (r *auditRecorderStub) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func newTestService(t *testing.T, repository Repository, recorder audit.Recorder) *Service {
	t.Helper()
	service, err := NewService(repository, recorder, ServiceConfig{
		PasswordParameters: auth.PasswordParameters{
			MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1,
			SaltLength: 16, KeyLength: 16,
		},
		Now: func() time.Time {
			return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
		},
		NewID: func() (string, error) { return testPublicID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testAuditContext() AuditContext {
	return AuditContext{
		ActorUserID: 7, RequestID: "request-7",
		ClientIP: []byte{127, 0, 0, 1}, UserAgent: "browser",
	}
}

func TestCreateHashesTemporaryPasswordAndBuildsAtomicAudit(t *testing.T) {
	repository := &repositoryStub{result: User{ID: testPublicID}}
	recorder := &auditRecorderStub{}
	service := newTestService(t, repository, recorder)
	password := []byte("temporary-password")
	user, err := service.Create(
		context.Background(), testAuditContext(), "reader.one", "Reader One",
		auth.RoleReader, password,
	)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != testPublicID || repository.create.PasswordHash == "" ||
		repository.create.PasswordHash == "temporary-password" {
		t.Fatalf("create record/result = %#v / %#v", repository.create, user)
	}
	if repository.create.Audit.Outcome != audit.OutcomeSuccess ||
		repository.create.Audit.ObjectID != testPublicID {
		t.Fatalf("atomic audit event = %#v", repository.create.Audit)
	}
	if len(recorder.events) != 0 {
		t.Fatalf("success audit must be transaction-owned, got %#v", recorder.events)
	}
	for index, value := range password {
		if value != 0 {
			t.Fatalf("password byte %d was not cleared", index)
		}
	}
}

func TestCreateEarlyValidationFailureClearsPasswordAndAuditsDenial(t *testing.T) {
	recorder := &auditRecorderStub{}
	service := newTestService(t, &repositoryStub{}, recorder)
	password := []byte("temporary-password")
	_, err := service.Create(
		context.Background(), testAuditContext(), "invalid username", "Reader",
		auth.RoleReader, password,
	)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Create() error = %v", err)
	}
	for index, value := range password {
		if value != 0 {
			t.Fatalf("password byte %d was not cleared on early return", index)
		}
	}
	if len(recorder.events) != 1 ||
		recorder.events[0].Outcome != audit.OutcomeDenied {
		t.Fatalf("denied events = %#v", recorder.events)
	}
}

func TestRepositoryPolicyErrorsAreAuditedAsDenied(t *testing.T) {
	repository := &repositoryStub{err: ErrLastAdministrator}
	recorder := &auditRecorderStub{}
	service := newTestService(t, repository, recorder)
	role := auth.RoleReader
	_, err := service.Update(
		context.Background(), testAuditContext(), testPublicID, &role, nil,
		"2026-07-30T11:00:00Z",
	)
	if !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("Update() error = %v", err)
	}
	if len(recorder.events) != 1 ||
		recorder.events[0].Outcome != audit.OutcomeDenied ||
		recorder.events[0].Metadata["reason"] != "last_active_administrator" {
		t.Fatalf("events = %#v", recorder.events)
	}
}

func TestListAcceptsLockedFilterAndOpaqueCursor(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestService(t, repository, &auditRecorderStub{})
	_, err := service.List(context.Background(), ListQuery{
		Cursor: encodeCursor(44), PageSize: 20, Keyword: " admin ",
		Role: "administrator", Status: "locked",
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.listQuery.Cursor != 44 ||
		repository.listQuery.Keyword != "admin" ||
		repository.listQuery.Status != "locked" {
		t.Fatalf("query = %#v", repository.listQuery)
	}
}
