package decompile

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
)

type repositoryStub struct {
	enqueue       func(context.Context, CreateRecord) (Request, bool, error)
	getRequest    func(context.Context, RequestQuery) (Request, error)
	list          func(context.Context, ListQuery) (Page, error)
	getSource     func(context.Context, SourceQuery) (SourceDescriptor, error)
	enqueueCalled bool
	requestCalled bool
	listCalled    bool
	sourceCalled  bool
}

func (s *repositoryStub) GetRequest(
	ctx context.Context,
	query RequestQuery,
) (Request, error) {
	s.requestCalled = true
	if s.getRequest == nil {
		return Request{}, nil
	}
	return s.getRequest(ctx, query)
}

func sourceSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *repositoryStub) Enqueue(
	ctx context.Context,
	record CreateRecord,
) (Request, bool, error) {
	s.enqueueCalled = true
	if s.enqueue == nil {
		return Request{}, false, nil
	}
	return s.enqueue(ctx, record)
}

func (s *repositoryStub) List(
	ctx context.Context,
	query ListQuery,
) (Page, error) {
	s.listCalled = true
	if s.list == nil {
		return Page{}, nil
	}
	return s.list(ctx, query)
}

func (s *repositoryStub) GetSource(
	ctx context.Context,
	query SourceQuery,
) (SourceDescriptor, error) {
	s.sourceCalled = true
	if s.getSource == nil {
		return SourceDescriptor{}, nil
	}
	return s.getSource(ctx, query)
}

func TestNewServiceValidatesDependenciesAndRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := NewService(nil, Config{RepositoryRoot: root}); err == nil {
		t.Fatal("NewService(nil) error = nil")
	}
	if _, err := NewService(
		&repositoryStub{}, Config{RepositoryRoot: "relative"},
	); err == nil {
		t.Fatal("NewService(relative root) error = nil")
	}
	if _, err := NewService(
		&repositoryStub{}, Config{RepositoryRoot: string(filepath.Separator)},
	); err == nil {
		t.Fatal("NewService(filesystem root) error = nil")
	}
	if _, err := NewService(
		&repositoryStub{}, Config{RepositoryRoot: root},
	); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestServiceCreatesVersionedDecompileRequest(t *testing.T) {
	const (
		jobID     = "423e4567-e89b-42d3-a456-426614174004"
		requestID = "523e4567-e89b-42d3-a456-426614174005"
	)
	ids := []string{jobID, requestID}
	repository := &repositoryStub{
		enqueue: func(
			_ context.Context,
			record CreateRecord,
		) (Request, bool, error) {
			if record.JobID != jobID ||
				record.RequestID != requestID ||
				record.TaskID != testTaskID ||
				record.FileNodeID != 42 ||
				record.UserID != 7 ||
				record.EngineTarget != EngineAuto ||
				string(record.Options) != `{"analysis_mode":"default","symbols":["public"]}` ||
				record.Limits != defaultJobLimits ||
				record.JobRequestKey ==
					"decompile:decompile-request-key" ||
				len(record.JobRequestKey) != len("decompile:")+64 {
				t.Fatalf("Enqueue() record = %#v", record)
			}
			return Request{
				RequestID:  requestID,
				JobID:      jobID,
				TaskID:     testTaskID,
				FileNodeID: "42",
				Status:     "queued",
			}, true, nil
		},
	}
	service, err := NewService(repository, Config{
		RepositoryRoot: t.TempDir(),
		NewID: func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	value, created, err := service.Create(
		context.Background(),
		CreateInput{
			TaskID:     testTaskID,
			FileNodeID: 42,
			UserID:     7,
			Role:       auth.RoleOperator,
			Options: json.RawMessage(
				`{"symbols":["public"],"analysis_mode":"default"}`,
			),
			IdempotencyKey: "decompile-request-key",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created ||
		value.JobID != jobID ||
		value.RequestID != requestID ||
		!repository.enqueueCalled {
		t.Fatalf("Create() = (%+v, %v)", value, created)
	}
}

func TestServiceRejectsInvalidDecompileCreateWithoutRepository(t *testing.T) {
	valid := CreateInput{
		TaskID:         testTaskID,
		FileNodeID:     42,
		UserID:         7,
		Role:           auth.RoleOperator,
		EngineTarget:   EngineAuto,
		Options:        json.RawMessage(`{}`),
		IdempotencyKey: "key",
	}
	tests := []CreateInput{
		func() CreateInput { value := valid; value.TaskID = "bad"; return value }(),
		func() CreateInput { value := valid; value.FileNodeID = 0; return value }(),
		func() CreateInput { value := valid; value.UserID = 0; return value }(),
		func() CreateInput {
			value := valid
			value.Role = auth.RoleReader
			return value
		}(),
		func() CreateInput {
			value := valid
			value.EngineTarget = "shell"
			return value
		}(),
		func() CreateInput {
			value := valid
			value.Options = json.RawMessage(`[]`)
			return value
		}(),
		func() CreateInput {
			value := valid
			value.IdempotencyKey = ""
			return value
		}(),
	}
	for index, input := range tests {
		repository := &repositoryStub{}
		service, err := NewService(
			repository,
			Config{RepositoryRoot: t.TempDir()},
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := service.Create(
			context.Background(),
			input,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("case %d Create() error = %v", index, err)
		}
		if repository.enqueueCalled {
			t.Fatalf("case %d invalid Create() called repository", index)
		}
	}
}

func TestServiceGetsAValidatedDecompileRequest(t *testing.T) {
	repository := &repositoryStub{
		getRequest: func(
			_ context.Context,
			query RequestQuery,
		) (Request, error) {
			if query.TaskID != testTaskID || query.JobID != testJobID {
				t.Fatalf("GetRequest() query = %#v", query)
			}
			return Request{
				JobID: testJobID, TaskID: testTaskID, Status: "running",
			}, nil
		},
	}
	service, err := NewService(
		repository,
		Config{RepositoryRoot: t.TempDir()},
	)
	if err != nil {
		t.Fatal(err)
	}

	value, err := service.GetRequest(context.Background(), RequestQuery{
		TaskID: testTaskID,
		JobID:  testJobID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.Status != "running" || !repository.requestCalled {
		t.Fatalf("GetRequest() = %#v", value)
	}

	repository.requestCalled = false
	for _, query := range []RequestQuery{
		{TaskID: "invalid", JobID: testJobID},
		{TaskID: testTaskID, JobID: "invalid"},
	} {
		if _, err := service.GetRequest(
			context.Background(), query,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("GetRequest(%#v) error = %v", query, err)
		}
	}
	if repository.requestCalled {
		t.Fatal("invalid GetRequest() called repository")
	}
}

func TestServiceListValidatesInputAndNormalizesEmptyItems(t *testing.T) {
	root := t.TempDir()
	repository := &repositoryStub{}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []ListQuery{
		{TaskID: "invalid", PageSize: 1},
		{TaskID: testTaskID, PageSize: 0},
		{TaskID: testTaskID, PageSize: MaxPageSize + 1},
		{TaskID: testTaskID, Cursor: "invalid", PageSize: 1},
	} {
		if _, err := service.List(
			context.Background(), query,
		); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("List(%+v) error = %v", query, err)
		}
	}
	if repository.listCalled {
		t.Fatal("invalid List() called repository")
	}

	page, err := service.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: DefaultPageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Items == nil || len(page.Items) != 0 {
		t.Fatalf("List() items = %#v", page.Items)
	}
}

func TestServiceListGeneratesAndDecodesCompositeCursor(t *testing.T) {
	root := t.TempDir()
	createdAt := time.Date(2026, 7, 30, 2, 3, 4, 123456000, time.UTC)
	laterAt := createdAt.Add(time.Microsecond)
	laterLowerID := "123e4567-e89b-42d3-a456-426614174004"
	repository := &repositoryStub{
		list: func(_ context.Context, query ListQuery) (Page, error) {
			if query.After != nil {
				if !query.After.CreatedAt.Equal(createdAt) ||
					query.After.ID != testResultID {
					t.Fatalf("decoded cursor = %#v", query.After)
				}
				return Page{Items: []Result{
					{ID: nextResultID, CreatedAt: createdAt},
					{ID: laterLowerID, CreatedAt: laterAt},
				}}, nil
			}
			return Page{
				Items: []Result{{
					ID: testResultID, CreatedAt: createdAt,
				}},
				HasMore: true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextCursor == "" ||
		strings.ContainsAny(first.NextCursor, "+/=") {
		t.Fatalf("next cursor is not unpadded base64url: %q", first.NextCursor)
	}
	raw, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := `{"created_at":"2026-07-30T02:03:04.123456Z","id":"` +
		testResultID + `"}`
	if string(raw) != wantPayload {
		t.Fatalf("cursor payload = %s, want %s", raw, wantPayload)
	}

	second, err := service.List(context.Background(), ListQuery{
		TaskID: testTaskID, Cursor: first.NextCursor, PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextCursor != "" {
		t.Fatalf("terminal cursor = %q", second.NextCursor)
	}
	if len(second.Items) != 2 ||
		second.Items[0].ID != nextResultID ||
		second.Items[1].ID != laterLowerID {
		t.Fatalf("second page = %#v", second)
	}
}

func TestServiceListRejectsNonCanonicalOpaqueCursors(t *testing.T) {
	root := t.TempDir()
	repository := &repositoryStub{}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(value))
	}
	tests := []string{
		strings.Repeat("a", maxListCursorLength+1),
		encode(`{"created_at":"2026-07-30T02:03:04Z","id":"invalid"}`),
		encode(`{"created_at":"2026-07-30T10:03:04+08:00","id":"` +
			testResultID + `"}`),
		encode(`{"id":"` + testResultID +
			`","created_at":"2026-07-30T02:03:04Z"}`),
		encode(`{"created_at":"2026-07-30T02:03:04Z","id":"` +
			testResultID + `","extra":true}`),
	}
	for _, cursor := range tests {
		if _, err := service.List(context.Background(), ListQuery{
			TaskID: testTaskID, Cursor: cursor, PageSize: 1,
		}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("List(cursor=%q) error = %v", cursor, err)
		}
	}
	if repository.listCalled {
		t.Fatal("invalid opaque cursor called repository")
	}
}

func TestServiceReadsBoundedSourceChunks(t *testing.T) {
	root := t.TempDir()
	storageKey := filepath.ToSlash(filepath.Join(
		"decompile", testResultID, "source.c",
	))
	path := filepath.Join(root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const source = "hello world"
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sourceSHA256(source)
	repository := &repositoryStub{
		getSource: func(
			_ context.Context,
			_ SourceQuery,
		) (SourceDescriptor, error) {
			return SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: storageKey, SHA256: hash,
				SizeBytes: uint64(len(source)), SizeKnown: true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Content != "hello" || first.Complete ||
		first.NextOffset == nil || *first.NextOffset != 5 ||
		first.Offset != 0 || first.SizeBytes != uint64(len(source)) ||
		first.SHA256 != hash {
		t.Fatalf("first Source() = %#v", first)
	}

	second, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Offset: 6, Limit: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Content != "world" || !second.Complete ||
		second.NextOffset != nil || second.Offset != 6 {
		t.Fatalf("second Source() = %#v", second)
	}

	end, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID,
		Offset: uint64(len(source)), Limit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if end.Content != "" || !end.Complete || end.NextOffset != nil {
		t.Fatalf("end Source() = %#v", end)
	}
}

func TestServiceRejectsSameSizeTamperedSource(t *testing.T) {
	root := t.TempDir()
	const original = "return true;"
	const tampered = "return  nil;"
	if len(original) != len(tampered) {
		t.Fatal("tamper fixture must preserve size")
	}
	if err := os.WriteFile(
		filepath.Join(root, "source.c"), []byte(tampered), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{
		getSource: func(
			_ context.Context,
			_ SourceQuery,
		) (SourceDescriptor, error) {
			return SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "source.c", SHA256: sourceSHA256(original),
				SizeBytes: uint64(len(original)), SizeKnown: true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Limit: 16,
	}); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("Source() error = %v, want ErrSourceUnavailable", err)
	}
}

func TestVerifySourceSHA256HonorsCancelledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.c")
	if err := os.WriteFile(path, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := verifySourceSHA256(
		ctx, file, sourceSHA256("source"),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("verifySourceSHA256() error = %v, want context.Canceled", err)
	}
}

func TestServiceRejectsUnsafeOrUnavailableSource(t *testing.T) {
	root := t.TempDir()
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	regularPath := filepath.Join(root, "safe", "source.c")
	if err := os.MkdirAll(filepath.Dir(regularPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regularPath, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(root, "safe", "link.c")
	if err := os.Symlink(regularPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	symlinkDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(filepath.Join(root, "safe"), symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	directoryPath := filepath.Join(root, "safe", "directory")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		descriptor SourceDescriptor
		offset     uint64
	}{
		{
			name: "absolute storage key",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: regularPath, SHA256: hash,
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "parent traversal",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "../outside", SHA256: hash,
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "symbolic link",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "safe/link.c", SHA256: hash,
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "symbolic link parent",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "linked/source.c", SHA256: hash,
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "directory",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "safe/directory", SHA256: hash,
				SizeBytes: 0, SizeKnown: true,
			},
		},
		{
			name: "size mismatch",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "safe/source.c", SHA256: hash,
				SizeBytes: 7, SizeKnown: true,
			},
		},
		{
			name: "unfinished result",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "running",
				StorageKey: "safe/source.c", SHA256: hash,
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "invalid digest",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "safe/source.c", SHA256: "invalid",
				SizeBytes: 6, SizeKnown: true,
			},
		},
		{
			name: "missing size metadata",
			descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "safe/source.c", SHA256: hash,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{
				getSource: func(
					_ context.Context,
					_ SourceQuery,
				) (SourceDescriptor, error) {
					return test.descriptor, nil
				},
			}
			service, err := NewService(
				repository, Config{RepositoryRoot: root},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Source(context.Background(), SourceQuery{
				TaskID: testTaskID, ResultID: testResultID,
				Offset: test.offset, Limit: 16,
			})
			if !errors.Is(err, ErrSourceUnavailable) {
				t.Fatalf("Source() error = %v, want ErrSourceUnavailable", err)
			}
		})
	}
}

func TestServiceKeepsUTF8ChunkOffsetsLossless(t *testing.T) {
	root := t.TempDir()
	const source = "A中B"
	if err := os.WriteFile(
		filepath.Join(root, "source.c"), []byte(source), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{
		getSource: func(
			_ context.Context,
			_ SourceQuery,
		) (SourceDescriptor, error) {
			return SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "source.c",
				SHA256:     sourceSHA256(source),
				SizeBytes:  uint64(len(source)),
				SizeKnown:  true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Content != "A" || first.NextOffset == nil ||
		*first.NextOffset != 1 {
		t.Fatalf("first UTF-8 chunk = %#v", first)
	}
	second, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Offset: 1, Limit: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Content != "中B" || !second.Complete {
		t.Fatalf("second UTF-8 chunk = %#v", second)
	}

	if _, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Offset: 2, Limit: 4,
	}); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf(
			"mid-rune Source() error = %v, want ErrSourceUnavailable",
			err,
		)
	}
}

func TestServiceRejectsOffsetPastSourceEnd(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "source.c")
	if err := os.WriteFile(path, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{
		getSource: func(
			_ context.Context,
			_ SourceQuery,
		) (SourceDescriptor, error) {
			return SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "source.c",
				SHA256:     sourceSHA256("source"),
				SizeBytes:  6,
				SizeKnown:  true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Source(context.Background(), SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Offset: 7, Limit: 1,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Source() error = %v, want ErrInvalidInput", err)
	}
}

func TestServiceHonorsCancelledContextWithoutRepositoryCall(t *testing.T) {
	root := t.TempDir()
	repository := &repositoryStub{}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.List(ctx, ListQuery{
		TaskID: testTaskID, PageSize: 1,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("List() error = %v, want context.Canceled", err)
	}
	if _, err := service.Source(ctx, SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Limit: 1,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Source() error = %v, want context.Canceled", err)
	}
	if repository.listCalled || repository.sourceCalled {
		t.Fatal("cancelled request called repository")
	}
}

func TestServiceHonorsCancellationRaisedByRepository(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repository := &repositoryStub{
		list: func(
			_ context.Context,
			_ ListQuery,
		) (Page, error) {
			cancel()
			return Page{Items: []Result{}}, nil
		},
		getSource: func(
			_ context.Context,
			_ SourceQuery,
		) (SourceDescriptor, error) {
			cancel()
			return SourceDescriptor{}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(ctx, ListQuery{
		TaskID: testTaskID, PageSize: 1,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("List() error = %v, want context.Canceled", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := service.Source(ctx, SourceQuery{
		TaskID: testTaskID, ResultID: testResultID, Limit: 1,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Source() error = %v, want context.Canceled", err)
	}
}
