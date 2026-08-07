package filetree

import (
	"context"
	"errors"
	"testing"
)

const testTaskID = "123e4567-e89b-42d3-a456-426614174000"

type repositoryStub struct {
	query    ListQuery
	page     Page
	err      error
	calls    int
	getQuery GetQuery
	detail   Detail
	getErr   error
	getCalls int
}

func (s *repositoryStub) List(_ context.Context, query ListQuery) (Page, error) {
	s.calls++
	s.query = query
	return s.page, s.err
}

func (s *repositoryStub) Get(
	_ context.Context,
	query GetQuery,
) (Detail, error) {
	s.getCalls++
	s.getQuery = query
	return s.detail, s.getErr
}

func TestNewServiceRequiresRepository(t *testing.T) {
	if _, err := NewService(nil); err == nil {
		t.Fatal("NewService(nil) error = nil")
	}
}

func TestServiceListValidatesQueryBeforeRepository(t *testing.T) {
	parentZero := uint64(0)
	tests := []struct {
		name  string
		query ListQuery
	}{
		{
			name:  "invalid UUID",
			query: ListQuery{TaskID: "not-a-uuid", PageSize: 100},
		},
		{
			name:  "wrong UUID version",
			query: ListQuery{TaskID: "123e4567-e89b-12d3-a456-426614174000", PageSize: 100},
		},
		{
			name:  "zero page size",
			query: ListQuery{TaskID: testTaskID, PageSize: 0},
		},
		{
			name:  "oversized page",
			query: ListQuery{TaskID: testTaskID, PageSize: MaxPageSize + 1},
		},
		{
			name:  "zero parent",
			query: ListQuery{TaskID: testTaskID, ParentID: &parentZero, PageSize: 100},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{}
			service, err := NewService(repository)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.List(context.Background(), test.query); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("List() error = %v, want ErrInvalidInput", err)
			}
			if repository.calls != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls)
			}
		})
	}
}

func TestServiceListPassesValidatedQueryAndNormalizesItems(t *testing.T) {
	parent := uint64(17)
	query := ListQuery{
		TaskID: testTaskID, ParentID: &parent, Cursor: 23, PageSize: 100,
	}
	repository := &repositoryStub{page: Page{}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(context.Background(), query)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if repository.calls != 1 || repository.query.TaskID != query.TaskID ||
		repository.query.ParentID == nil || *repository.query.ParentID != parent ||
		repository.query.Cursor != query.Cursor || repository.query.PageSize != query.PageSize {
		t.Fatalf("repository query = %#v", repository.query)
	}
	if page.Items == nil {
		t.Fatal("List() returned nil items")
	}
}

func TestServiceListPreservesRepositoryErrors(t *testing.T) {
	repository := &repositoryStub{err: ErrNotFound}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 100,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("List() error = %v, want ErrNotFound", err)
	}
}

func TestServiceGetValidatesQueryBeforeRepository(t *testing.T) {
	tests := []GetQuery{
		{TaskID: "not-a-uuid", FileID: 1},
		{TaskID: "123e4567-e89b-12d3-a456-426614174000", FileID: 1},
		{TaskID: testTaskID, FileID: 0},
	}
	for _, query := range tests {
		repository := &repositoryStub{}
		service, err := NewService(repository)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Get(context.Background(), query); !errors.Is(
			err,
			ErrInvalidInput,
		) {
			t.Fatalf("Get(%#v) error = %v, want ErrInvalidInput", query, err)
		}
		if repository.getCalls != 0 {
			t.Fatalf("Get(%#v) repository calls = %d", query, repository.getCalls)
		}
	}
}

func TestServiceGetPassesValidatedQueryAndPreservesErrors(t *testing.T) {
	query := GetQuery{TaskID: testTaskID, FileID: 51}
	want := Detail{Node: Node{ID: "51"}}
	repository := &repositoryStub{detail: want}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Get(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if repository.getCalls != 1 || repository.getQuery != query ||
		got.ID != want.ID {
		t.Fatalf("query/detail = %#v/%#v", repository.getQuery, got)
	}

	repository.getErr = ErrNodeNotFound
	if _, err := service.Get(context.Background(), query); !errors.Is(
		err,
		ErrNodeNotFound,
	) {
		t.Fatalf("Get() error = %v, want ErrNodeNotFound", err)
	}
}
