package javaanalysis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/report"
)

const (
	testTaskID = "723e4567-e89b-42d3-a456-426614174006"
	testJobID  = "623e4567-e89b-42d3-a456-426614174005"
)

type serviceRepositoryStub struct {
	created CreateRecord
	list    ListQuery
	run     Run
	err     error
}

func (s *serviceRepositoryStub) Create(
	_ context.Context,
	record CreateRecord,
) (Run, bool, error) {
	s.created = record
	return s.run, true, s.err
}

func (s *serviceRepositoryStub) List(
	_ context.Context,
	query ListQuery,
) (RunPage, error) {
	s.list = query
	return RunPage{Items: []Run{s.run}, HasMore: true}, s.err
}

func (s *serviceRepositoryStub) Get(context.Context, RunQuery) (Run, error) {
	return s.run, s.err
}

func (s *serviceRepositoryStub) ListFindings(
	context.Context,
	FindingsQuery,
) (FindingPage, error) {
	return FindingPage{}, s.err
}

func (s *serviceRepositoryStub) Cancel(context.Context, ActionInput) (Run, error) {
	return s.run, s.err
}

type runDeleterStub struct {
	taskID string
	runID  string
	err    error
}

func (s *runDeleterStub) Delete(_ context.Context, taskID, runID string) error {
	s.taskID = taskID
	s.runID = runID
	return s.err
}

func TestServiceCreateHashesIdempotencyAndAllocatesImmutableRun(t *testing.T) {
	repository := &serviceRepositoryStub{run: Run{ID: testRunID}}
	ids := []string{testRunID, testJobID}
	service, err := NewService(repository, Config{
		NewID: func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
		RunDeleter: &runDeleterStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	value, created, err := service.Create(t.Context(), CreateInput{
		TaskID: testTaskID, SourceProjectID: testProjectID,
		IdempotencyKey: "new-analysis-click", UserID: 7,
		Role: auth.RoleOperator,
	})
	if err != nil || !created || value.ID != testRunID {
		t.Fatalf("Create() = %#v, %v, %v", value, created, err)
	}
	if repository.created.RunID != testRunID ||
		repository.created.JobID != testJobID ||
		repository.created.SourceProjectID != testProjectID ||
		!strings.HasPrefix(repository.created.RequestKey, "java_analysis:") ||
		len(repository.created.RequestKey) != len("java_analysis:")+64 {
		t.Fatalf("create record = %#v", repository.created)
	}
}

func TestServiceCreateRejectsReaderAndMalformedIdempotency(t *testing.T) {
	service, err := NewService(&serviceRepositoryStub{}, Config{
		RunDeleter: &runDeleterStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []CreateInput{
		{
			TaskID: testTaskID, SourceProjectID: testProjectID,
			IdempotencyKey: "key", UserID: 1, Role: auth.RoleReader,
		},
		{
			TaskID: testTaskID, SourceProjectID: testProjectID,
			IdempotencyKey: "bad\nkey", UserID: 1, Role: auth.RoleOperator,
		},
	} {
		if _, _, err := service.Create(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Create(%#v) error = %v", input, err)
		}
	}
}

func TestRunCursorRoundTripAndListProjectFilter(t *testing.T) {
	createdAt := time.Date(2026, 8, 10, 12, 30, 0, 123000, time.UTC)
	repository := &serviceRepositoryStub{run: Run{
		ID: testRunID, CreatedAt: createdAt,
	}}
	service, err := NewService(repository, Config{
		RunDeleter: &runDeleterStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	inputCursor, err := EncodeRunCursor(RunCursor{
		CreatedAt: createdAt.Add(time.Minute), ID: testJobID,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRunCursor(inputCursor)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.List(t.Context(), ListQuery{
		TaskID: testTaskID, SourceProjectID: testProjectID,
		After: &decoded, PageSize: 50,
	})
	if err != nil || page.NextCursor == "" ||
		repository.list.SourceProjectID != testProjectID ||
		repository.list.After.ID != testJobID {
		t.Fatalf("List() = %#v / %v, query=%#v", page, err, repository.list)
	}
	outputCursor, err := DecodeRunCursor(page.NextCursor)
	if err != nil || outputCursor.ID != testRunID ||
		!outputCursor.CreatedAt.Equal(createdAt) {
		t.Fatalf("output cursor = %#v / %v", outputCursor, err)
	}
}

func TestDecodeRunCursorRejectsTrailingJSON(t *testing.T) {
	cursor, err := EncodeRunCursor(RunCursor{
		CreatedAt: time.Now().UTC(), ID: testRunID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRunCursor(cursor + "e30"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("DecodeRunCursor() error = %v", err)
	}
}

func TestServiceDeleteDelegatesCascadeAndMapsDomainErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "success"},
		{
			name: "missing", err: report.ErrJavaAnalysisRunNotFound,
			want: ErrRunNotFound,
		},
		{
			name: "active", err: report.ErrJavaAnalysisRunNotTerminal,
			want: ErrRunNotDeletable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			deleter := &runDeleterStub{err: test.err}
			service, err := NewService(&serviceRepositoryStub{}, Config{
				RunDeleter: deleter,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = service.Delete(t.Context(), ActionInput{
				TaskID: testTaskID, RunID: testRunID,
				UserID: 7, Role: auth.RoleOperator,
			})
			if !errors.Is(err, test.want) ||
				deleter.taskID != testTaskID || deleter.runID != testRunID {
				t.Fatalf(
					"Delete() error=%v deleter=%#v, want %v", err, deleter, test.want,
				)
			}
		})
	}
}
