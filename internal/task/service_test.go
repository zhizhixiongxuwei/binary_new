package task

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
)

const (
	testUploadID = "10000000-0000-4000-8000-000000000001"
	testTaskID   = "20000000-0000-4000-8000-000000000002"
	testJobID    = "30000000-0000-4000-8000-000000000003"
)

type repositoryStub struct {
	created         CreateRecord
	createResult    View
	wasCreated      bool
	createErr       error
	listQuery       ListQuery
	listResult      Page
	listErr         error
	getID           string
	getResult       View
	getErr          error
	cancelRecord    MutationRecord
	cancelResult    View
	cancelErr       error
	retryRecord     RetryRecord
	retryResult     View
	retryErr        error
	deleteRecord    MutationRecord
	deleteResult    View
	deleteErr       error
	retentionRecord RetentionRecord
	retentionResult View
	retentionErr    error
}

func (r *repositoryStub) Create(_ context.Context, record CreateRecord) (View, bool, error) {
	r.created = record
	return r.createResult, r.wasCreated, r.createErr
}

func (r *repositoryStub) List(_ context.Context, query ListQuery) (Page, error) {
	r.listQuery = query
	return r.listResult, r.listErr
}

func (r *repositoryStub) Get(_ context.Context, id string) (View, error) {
	r.getID = id
	return r.getResult, r.getErr
}

func (r *repositoryStub) Cancel(_ context.Context, record MutationRecord) (View, error) {
	r.cancelRecord = record
	return r.cancelResult, r.cancelErr
}

func (r *repositoryStub) Retry(_ context.Context, record RetryRecord) (View, error) {
	r.retryRecord = record
	return r.retryResult, r.retryErr
}

func (r *repositoryStub) Delete(_ context.Context, record MutationRecord) (View, error) {
	r.deleteRecord = record
	return r.deleteResult, r.deleteErr
}

func (r *repositoryStub) ExtendRetention(
	_ context.Context,
	record RetentionRecord,
) (View, error) {
	r.retentionRecord = record
	return r.retentionResult, r.retentionErr
}

func testLimits() LimitsSnapshot {
	return LimitsSnapshot{
		MaxUploadBytes: 2 << 30, MaxExpandedBytes: 10 << 30,
		MaxArchiveRatio: 50, MaxDepth: 6, MaxFileNodes: 20_000,
		MaxNestedImages: 3,
	}
}

func TestServiceCreateBuildsAtomicRecord(t *testing.T) {
	now := time.Date(2026, 7, 29, 8, 30, 0, 0, time.FixedZone("CST", 8*60*60))
	repository := &repositoryStub{
		createResult: View{ID: testTaskID}, wasCreated: true,
	}
	ids := []string{testTaskID, testJobID}
	service, err := NewService(repository, ServiceConfig{
		Limits: testLimits(),
		Now:    func() time.Time { return now },
		NewID: func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	result, created, err := service.Create(
		context.Background(), 42, auth.RoleOperator, testUploadID,
		"  release image.tar  ", "request-123",
	)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created || result.ID != testTaskID {
		t.Fatalf("Create() = (%+v, %v), want created task", result, created)
	}
	record := repository.created
	if record.TaskID != testTaskID || record.JobID != testJobID ||
		record.UserID != 42 || record.Administrator ||
		record.UploadID != testUploadID || record.Name != "release image.tar" ||
		record.IdempotencyKey != "request-123" {
		t.Fatalf("unexpected create record: %+v", record)
	}
	if !record.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("CreatedAt = %v, want %v", record.CreatedAt, now.UTC())
	}
	if !record.SampleExpiresAt.Equal(now.UTC().Add(DefaultSampleRetention)) {
		t.Fatalf("SampleExpiresAt = %v", record.SampleExpiresAt)
	}
	var snapshot LimitsSnapshot
	if err := json.Unmarshal(record.LimitsSnapshot, &snapshot); err != nil {
		t.Fatalf("decode limits snapshot: %v", err)
	}
	if snapshot != testLimits() {
		t.Fatalf("limits snapshot = %+v, want %+v", snapshot, testLimits())
	}
}

func TestServiceCreateRejectsUnauthorizedAndInvalidRequests(t *testing.T) {
	service, err := NewService(&repositoryStub{}, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	tests := []struct {
		name   string
		userID uint64
		role   auth.Role
		upload string
		task   string
		key    string
		want   error
	}{
		{
			name: "reader", userID: 1, role: auth.RoleReader,
			upload: testUploadID, task: "task", key: "key", want: ErrForbidden,
		},
		{
			name: "missing user", role: auth.RoleAdministrator,
			upload: testUploadID, task: "task", key: "key", want: ErrForbidden,
		},
		{
			name: "invalid upload", userID: 1, role: auth.RoleOperator,
			upload: "../upload", task: "task", key: "key", want: ErrInvalidInput,
		},
		{
			name: "control in name", userID: 1, role: auth.RoleOperator,
			upload: testUploadID, task: "bad\nname", key: "key", want: ErrInvalidInput,
		},
		{
			name: "empty idempotency key", userID: 1, role: auth.RoleOperator,
			upload: testUploadID, task: "task", want: ErrInvalidInput,
		},
		{
			name: "control in idempotency key", userID: 1, role: auth.RoleOperator,
			upload: testUploadID, task: "task", key: "bad\tkey", want: ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := service.Create(
				context.Background(), test.userID, test.role,
				test.upload, test.task, test.key,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("Create() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestServiceListNormalizesAndBoundsQuery(t *testing.T) {
	repository := &repositoryStub{}
	service, err := NewService(repository, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	page, err := service.List(context.Background(), ListQuery{
		PageSize: 50, Keyword: "  firmware_100%  ",
		Status: "queued", InputType: "ELF",
		Creator: "  张三  ", Tag: "  release  ",
		CreatedFrom: "  2026-07-01  ", CreatedTo: "  2026-07-29  ",
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	want := ListQuery{
		PageSize: 50, Keyword: "firmware_100%",
		Status: "QUEUED", InputType: "elf",
		Creator: "张三", Tag: "release",
		CreatedFrom: "2026-07-01", CreatedTo: "2026-07-29",
	}
	if repository.listQuery != want {
		t.Fatalf("repository query = %+v, want %+v", repository.listQuery, want)
	}
	if page.Items == nil || page.NextCursor != "" {
		t.Fatalf("page metadata/items = %+v", page)
	}

	invalid := []ListQuery{
		{PageSize: 0},
		{PageSize: 101},
		{PageSize: 20, After: &ListCursor{CreatedAt: time.Now(), ID: testTaskID}},
		{PageSize: 20, Cursor: "not_base64url!"},
		{PageSize: 20, Status: "running"},
		{PageSize: 20, InputType: "../image"},
		{PageSize: 20, Keyword: "bad\nkeyword"},
		{PageSize: 20, Creator: "bad\ncreator"},
		{PageSize: 20, Creator: strings.Repeat("界", maxCreatorRunes+1)},
		{PageSize: 20, Tag: "bad\ttag"},
		{PageSize: 20, Tag: strings.Repeat("界", maxTagRunes+1)},
		{PageSize: 20, Creator: string([]byte{0xff})},
		{PageSize: 20, CreatedFrom: "2026-7-01"},
		{PageSize: 20, CreatedFrom: "2026-02-29"},
		{PageSize: 20, CreatedTo: "2026-04-31"},
		{
			PageSize:    20,
			CreatedFrom: "2026-07-30", CreatedTo: "2026-07-29",
		},
	}
	for _, query := range invalid {
		if _, err := service.List(context.Background(), query); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("List(%+v) error = %v, want ErrInvalidInput", query, err)
		}
	}
}

func TestServiceListDecodesAndReturnsCanonicalOpaqueCursor(t *testing.T) {
	createdAt := time.Date(2026, 7, 29, 1, 2, 3, 456000000, time.UTC)
	cursor, err := encodeListCursor(View{ID: testTaskID, CreatedAt: createdAt})
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{listResult: Page{
		Items:   []View{{ID: testTaskID, CreatedAt: createdAt}},
		HasMore: true,
	}}
	service, err := NewService(repository, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}

	page, err := service.List(context.Background(), ListQuery{
		Cursor: cursor, PageSize: 20,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if repository.listQuery.Cursor != cursor || repository.listQuery.After == nil ||
		repository.listQuery.After.ID != testTaskID ||
		!repository.listQuery.After.CreatedAt.Equal(createdAt) {
		t.Fatalf("repository cursor query = %+v", repository.listQuery)
	}
	if page.NextCursor != cursor {
		t.Fatalf("next cursor = %q, want %q", page.NextCursor, cursor)
	}

	for _, invalid := range []string{
		cursor + "=",
		cursor + "A",
		strings.Repeat("A", maxListCursorLength+1),
	} {
		if _, err := service.List(context.Background(), ListQuery{
			Cursor: invalid, PageSize: 20,
		}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("List(cursor=%q) error = %v, want ErrInvalidInput", invalid, err)
		}
	}
}

func TestServiceGetValidatesID(t *testing.T) {
	repository := &repositoryStub{getResult: View{ID: testTaskID}}
	service, err := NewService(repository, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.Get(context.Background(), "not-an-id"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Get(invalid) error = %v", err)
	}
	result, err := service.Get(context.Background(), testTaskID)
	if err != nil || result.ID != testTaskID || repository.getID != testTaskID {
		t.Fatalf("Get(valid) = (%+v, %v), repository id %q", result, err, repository.getID)
	}
}

func TestServiceLifecycleOperationsValidateAndBuildRecords(t *testing.T) {
	repository := &repositoryStub{
		cancelResult: View{ID: testTaskID, Status: StatusCancelRequested},
		retryResult:  View{ID: testTaskID, Status: StatusQueued},
		deleteResult: View{ID: testTaskID, Status: StatusDeleting},
	}
	service, err := NewService(repository, ServiceConfig{
		Limits: testLimits(),
		NewID:  func() (string, error) { return testJobID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, err := service.Cancel(
		context.Background(), 42, auth.RoleOperator, testTaskID, "request-key",
	)
	if err != nil || cancelled.Status != StatusCancelRequested {
		t.Fatalf("Cancel() = (%+v, %v)", cancelled, err)
	}
	if repository.cancelRecord.TaskID != testTaskID ||
		repository.cancelRecord.UserID != 42 ||
		repository.cancelRecord.Administrator ||
		repository.cancelRecord.SampleRetention != DefaultSampleRetention ||
		repository.cancelRecord.IdempotencyKey != lifecycleIdempotencyKey("cancel", "request-key") {
		t.Fatalf("cancel record = %+v", repository.cancelRecord)
	}

	retried, err := service.Retry(
		context.Background(), 7, auth.RoleAdministrator, testTaskID, "request-key",
	)
	if err != nil || retried.Status != StatusQueued {
		t.Fatalf("Retry() = (%+v, %v)", retried, err)
	}
	if repository.retryRecord.TaskID != testTaskID ||
		repository.retryRecord.UserID != 7 ||
		!repository.retryRecord.Administrator ||
		repository.retryRecord.JobID != testJobID ||
		repository.retryRecord.IdempotencyKey != lifecycleIdempotencyKey("retry", "request-key") {
		t.Fatalf("retry record = %+v", repository.retryRecord)
	}
	if repository.retryRecord.IdempotencyKey == repository.cancelRecord.IdempotencyKey {
		t.Fatal("operation-scoped idempotency keys collided")
	}

	deleted, err := service.Delete(
		context.Background(), 42, auth.RoleOperator, testTaskID,
	)
	if err != nil || deleted.Status != StatusDeleting {
		t.Fatalf("Delete() = (%+v, %v)", deleted, err)
	}
	if repository.deleteRecord.TaskID != testTaskID ||
		repository.deleteRecord.UserID != 42 ||
		repository.deleteRecord.Administrator {
		t.Fatalf("delete record = %+v", repository.deleteRecord)
	}
}

func TestServiceLifecycleOperationsRejectReadersAndInvalidInputs(t *testing.T) {
	service, err := NewService(&repositoryStub{}, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Cancel(
		context.Background(), 9, auth.RoleReader, testTaskID, "key",
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader Cancel() error = %v, want ErrForbidden", err)
	}
	if _, err := service.Retry(
		context.Background(), 9, auth.RoleReader, testTaskID, "key",
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader Retry() error = %v, want ErrForbidden", err)
	}
	if _, err := service.Delete(
		context.Background(), 9, auth.RoleReader, testTaskID,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("reader Delete() error = %v, want ErrForbidden", err)
	}
	if _, err := service.Cancel(
		context.Background(), 9, auth.RoleOperator, "bad-id", "key",
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Cancel() error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.Retry(
		context.Background(), 9, auth.RoleOperator, testTaskID, "",
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing Retry key error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.Delete(
		context.Background(), 9, auth.RoleOperator, "bad-id",
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Delete() error = %v, want ErrInvalidInput", err)
	}
}

func TestServiceExtendRetentionNormalizesAndBuildsRecord(t *testing.T) {
	repository := &repositoryStub{
		retentionResult: View{
			ID: testTaskID,
			SampleExpiresAt: time.Date(
				2026, 8, 13, 0, 30, 0, 123456000, time.UTC,
			),
		},
	}
	service, err := NewService(repository, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}

	value, err := service.ExtendRetention(
		context.Background(),
		42,
		auth.RoleAdministrator,
		testTaskID,
		"2026-07-29T08:30:00.123456+08:00",
		"2026-08-13T00:30:00.123456Z",
	)
	if err != nil {
		t.Fatalf("ExtendRetention() error = %v", err)
	}
	expected := time.Date(2026, 7, 29, 0, 30, 0, 123456000, time.UTC)
	requested := expected.Add(DefaultSampleRetention)
	if repository.retentionRecord.TaskID != testTaskID ||
		!repository.retentionRecord.ExpectedSampleExpiresAt.Equal(expected) ||
		!repository.retentionRecord.SampleExpiresAt.Equal(requested) ||
		!value.SampleExpiresAt.Equal(requested) {
		t.Fatalf(
			"retention record/value = (%+v, %+v), want expected %s and requested %s",
			repository.retentionRecord, value, expected, requested,
		)
	}
}

func TestServiceExtendRetentionRejectsUnauthorizedAndInvalidInput(t *testing.T) {
	service, err := NewService(&repositoryStub{}, ServiceConfig{Limits: testLimits()})
	if err != nil {
		t.Fatal(err)
	}
	validExpected := "2026-07-29T00:00:00Z"
	validRequested := "2026-08-13T00:00:00Z"
	tests := []struct {
		name      string
		userID    uint64
		role      auth.Role
		id        string
		expected  string
		requested string
		want      error
	}{
		{
			name: "missing user", role: auth.RoleAdministrator, id: testTaskID,
			expected: validExpected, requested: validRequested, want: ErrForbidden,
		},
		{
			name: "operator", userID: 42, role: auth.RoleOperator, id: testTaskID,
			expected: validExpected, requested: validRequested, want: ErrForbidden,
		},
		{
			name: "invalid task", userID: 42, role: auth.RoleAdministrator, id: "bad-id",
			expected: validExpected, requested: validRequested, want: ErrInvalidInput,
		},
		{
			name: "non RFC3339", userID: 42, role: auth.RoleAdministrator, id: testTaskID,
			expected: "2026-07-29 00:00:00Z", requested: validRequested, want: ErrInvalidInput,
		},
		{
			name: "invalid calendar date", userID: 42, role: auth.RoleAdministrator, id: testTaskID,
			expected: "2026-02-29T00:00:00Z", requested: validRequested, want: ErrInvalidInput,
		},
		{
			name: "excess precision", userID: 42, role: auth.RoleAdministrator, id: testTaskID,
			expected:  "2026-07-29T00:00:00.1234567Z",
			requested: validRequested, want: ErrInvalidInput,
		},
		{
			name: "not exactly 15 days", userID: 42, role: auth.RoleAdministrator, id: testTaskID,
			expected: validExpected, requested: "2026-08-12T23:59:59Z", want: ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.ExtendRetention(
				context.Background(), test.userID, test.role, test.id,
				test.expected, test.requested,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ExtendRetention() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewServiceRequiresPositiveLimits(t *testing.T) {
	if _, err := NewService(&repositoryStub{}, ServiceConfig{}); err == nil {
		t.Fatal("NewService() accepted empty limits")
	}
}
