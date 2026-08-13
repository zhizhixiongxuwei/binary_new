package upload

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"binaryscan/internal/auth"
	"binaryscan/internal/filetype"
	"binaryscan/internal/inputcategory"
)

func TestCreateRequiresCategoryAndScopesIdempotencyFingerprint(t *testing.T) {
	service, _, _, _ := newTestService(t)
	base := CreateInput{
		Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream",
		CreatedBy: 7, IdempotencyKey: "category-key",
	}
	if _, err := service.Create(context.Background(), base); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Create() without category error = %v, want ErrInvalidInput", err)
	}
	base.InputCategory = inputcategory.Binary
	created, err := service.Create(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if created.InputCategory != inputcategory.Binary ||
		created.ValidationStatus != ValidationPending {
		t.Fatalf("created intake view = %#v", created)
	}
	base.InputCategory = inputcategory.Archive
	if _, err := service.Create(context.Background(), base); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Create() changed-category replay error = %v, want conflict", err)
	}
}

func TestCompleteRejectsCategoryMismatchAndPersistsRecoverableView(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	service.config.Detector = contentDetectorStub{result: filetype.Result{Format: "zip"}}
	view, principal := createIntakeUploadWithContent(
		t, service, inputcategory.Binary, []byte("data"),
	)

	_, err := service.Complete(context.Background(), view.ID, principal)
	var validationErr *CompletionValidationError
	if !errors.Is(err, ErrCategoryMismatch) || !errors.As(err, &validationErr) {
		t.Fatalf("Complete() error = %v, want category mismatch", err)
	}
	if validationErr.DetectedCategory != inputcategory.Archive ||
		validationErr.DetectedFormat != "zip" || repository.prepareCalls != 0 ||
		repository.completeCalls != 0 {
		t.Fatalf("validation error/repository = %#v/%+v", validationErr, repository)
	}
	recovered, getErr := service.Get(context.Background(), view.ID, principal)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if recovered.Status != "failed" || recovered.ValidationStatus != ValidationMismatch ||
		recovered.ValidationError == nil ||
		recovered.ValidationError.Code != "input_category_mismatch" {
		t.Fatalf("recovered mismatch view = %#v", recovered)
	}
	if _, replayErr := service.Complete(context.Background(), view.ID, principal); !errors.Is(replayErr, ErrCategoryMismatch) {
		t.Fatalf("replayed Complete() error = %v", replayErr)
	}
	if err := service.Delete(context.Background(), view.ID, principal); err != nil {
		t.Fatalf("Delete() mismatch error = %v", err)
	}
	if repository.upload.Status != "cancelled" || repository.cancelCalls != 1 {
		t.Fatalf("deleted mismatch upload = %#v", repository.upload)
	}
}

func TestDirectBinaryAndContainerCompletionRemainIdempotent(t *testing.T) {
	for _, test := range []struct {
		name     string
		category inputcategory.Category
		format   string
	}{
		{name: "binary", category: inputcategory.Binary, format: "pe32"},
		{name: "container", category: inputcategory.Container, format: "docker-tar"},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, repository, _, _ := newTestService(t)
			service.config.Detector = contentDetectorStub{result: filetype.Result{Format: test.format}}
			taskID := "823e4567-e89b-42d3-a456-426614174000"
			ensureCalls := 0
			service.config.EnsureDirectTask = func(
				_ context.Context,
				request DirectTaskRequest,
			) (string, error) {
				ensureCalls++
				if request.CreatedBy != 7 || request.InputCategory != test.category ||
					request.DetectedFormat != test.format ||
					request.IdempotencyKey != DirectTaskIdempotencyKey(request.UploadID) ||
					request.TaskName != "sample.bin" {
					t.Fatalf("direct task request = %#v", request)
				}
				repository.taskID = taskID
				return taskID, nil
			}
			view, principal := createIntakeUploadWithContent(t, service, test.category, []byte("data"))
			completed, err := service.Complete(context.Background(), view.ID, principal)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := service.Complete(context.Background(), view.ID, principal)
			if err != nil {
				t.Fatal(err)
			}
			fetched, err := service.Get(context.Background(), view.ID, principal)
			if err != nil {
				t.Fatal(err)
			}
			if completed.ValidationStatus != ValidationValid ||
				completed.DetectedCategory != test.category ||
				completed.DetectedFormat != test.format ||
				completed.TaskID != taskID || replayed.TaskID != taskID || fetched.TaskID != taskID ||
				replayed.SHA256 != completed.SHA256 || repository.completeCalls != 1 ||
				ensureCalls != 2 {
				t.Fatalf("completion/replay = %#v/%#v, finalizes=%d", completed, replayed, repository.completeCalls)
			}
		})
	}
}

func TestCompleteRejectsUnsupportedFormatWithoutPublishingBlob(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	service.config.Detector = contentDetectorStub{result: filetype.Result{Format: "squashfs"}}
	view, principal := createIntakeUploadWithContent(
		t, service, inputcategory.Binary, []byte("data"),
	)
	_, err := service.Complete(context.Background(), view.ID, principal)
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("Complete() error = %v, want unsupported", err)
	}
	if repository.upload.Status != "failed" ||
		repository.upload.IntakeProfile.ValidationStatus != ValidationUnsupported ||
		repository.upload.BlobID != nil || repository.prepareCalls != 0 {
		t.Fatalf("unsupported upload = %#v", repository.upload)
	}
	recovered, getErr := service.Get(context.Background(), view.ID, principal)
	if getErr != nil || recovered.ValidationStatus != ValidationUnsupported ||
		recovered.ValidationError == nil ||
		recovered.ValidationError.Code != "unsupported_input_format" {
		t.Fatalf("recovered unsupported view/error = %#v/%v", recovered, getErr)
	}
	if err := service.Delete(context.Background(), view.ID, principal); err != nil {
		t.Fatalf("Delete() unsupported error = %v", err)
	}
	if repository.upload.Status != "cancelled" || repository.cancelCalls != 1 {
		t.Fatalf("deleted unsupported upload = %#v", repository.upload)
	}
}

func TestArchiveCompletionRetriesCoordinatorAfterDurableCompletion(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	service.config.Detector = contentDetectorStub{result: filetype.Result{Format: "zip"}}
	transient := errors.New("archive queue unavailable")
	ensureCalls := 0
	service.config.EnsureArchiveImport = func(
		_ context.Context,
		request ArchiveImportRequest,
	) (string, error) {
		ensureCalls++
		if request.UploadID == "" || request.DetectedFormat != "zip" ||
			request.SHA256 == "" {
			t.Fatalf("archive request = %#v", request)
		}
		if ensureCalls == 1 {
			return "", transient
		}
		return "323e4567-e89b-42d3-a456-426614174000", nil
	}
	view, principal := createIntakeUploadWithContent(
		t, service, inputcategory.Archive, []byte("data"),
	)
	if _, err := service.Complete(context.Background(), view.ID, principal); !errors.Is(err, transient) {
		t.Fatalf("first Complete() error = %v, want transient callback error", err)
	}
	if repository.upload.Status != "completed" || repository.completeCalls != 1 ||
		repository.upload.IntakeProfile.ValidationStatus != ValidationValid {
		t.Fatalf("durable archive completion = %#v", repository.upload)
	}
	replayed, err := service.Complete(context.Background(), view.ID, principal)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ArchiveImportID != "323e4567-e89b-42d3-a456-426614174000" ||
		ensureCalls != 2 || repository.completeCalls != 1 {
		t.Fatalf("replayed archive completion = %#v, ensure=%d finalize=%d", replayed, ensureCalls, repository.completeCalls)
	}
}

func TestRecoverArchiveImportsContinuesThenRetriesTransientFailureAfterCursorWrap(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	repository.upload = Upload{IntakeProfile: &IntakeProfile{}}
	repository.archiveCandidates = []ArchiveImportCandidate{
		{
			UploadID: "123e4567-e89b-42d3-a456-426614174001", CreatedBy: 7,
			Filename: "first.zip", Size: 4, SHA256: strings.Repeat("a", 64),
			DetectedFormat: "zip",
		},
		{
			UploadID: "223e4567-e89b-42d3-a456-426614174002", CreatedBy: 8,
			Filename: "second.tar", Size: 8, SHA256: strings.Repeat("b", 64),
			DetectedFormat: "tar",
		},
	}
	transientErr := errors.New("archive service unavailable")
	firstAttempts := 0
	service.config.EnsureArchiveImport = func(
		_ context.Context,
		request ArchiveImportRequest,
	) (string, error) {
		if request.UploadID == repository.archiveCandidates[0].UploadID {
			firstAttempts++
			if firstAttempts == 1 {
				return "", transientErr
			}
			return "a23e4567-e89b-42d3-a456-426614174000", nil
		}
		return "b23e4567-e89b-42d3-a456-426614174000", nil
	}

	report, err := service.RecoverArchiveImports(context.Background(), 10)
	if !errors.Is(err, transientErr) || report.Candidates != 2 || report.Ensured != 1 ||
		report.Failures != 1 || len(report.Diagnostics) != 1 ||
		report.Diagnostics[0].UploadID != repository.archiveCandidates[0].UploadID ||
		service.archiveImportRecoveryCursor != repository.archiveCandidates[1].UploadID {
		t.Fatalf("RecoverArchiveImports() = (%+v, %v)", report, err)
	}

	// The successfully associated later upload disappears from the authoritative
	// query. The next cycle wraps and retries the earlier transient failure.
	repository.archiveCandidates = repository.archiveCandidates[:1]
	retried, err := service.RecoverArchiveImports(context.Background(), 10)
	if err != nil || !retried.Wrapped || retried.Candidates != 1 ||
		retried.Ensured != 1 || retried.Failures != 0 || firstAttempts != 2 ||
		service.archiveImportRecoveryCursor != repository.archiveCandidates[0].UploadID {
		t.Fatalf("retried RecoverArchiveImports() = (%+v, %v), attempts=%d", retried, err, firstAttempts)
	}
}

func TestDirectCompletionReplayRecoversCommitAckAmbiguity(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	taskID := "923e4567-e89b-42d3-a456-426614174000"
	ackErr := errors.New("task commit acknowledgement lost")
	calls := 0
	service.config.EnsureDirectTask = func(
		_ context.Context,
		_ DirectTaskRequest,
	) (string, error) {
		calls++
		repository.taskID = taskID
		if calls == 1 {
			return "", ackErr
		}
		return taskID, nil
	}
	view, principal := createIntakeUploadWithContent(
		t, service, inputcategory.Binary, []byte("data"),
	)
	if _, err := service.Complete(context.Background(), view.ID, principal); !errors.Is(err, ackErr) {
		t.Fatalf("first Complete() error = %v, want %v", err, ackErr)
	}
	if repository.upload.Status != "completed" || repository.completeCalls != 1 {
		t.Fatalf("durable upload = status %q, finalize %d", repository.upload.Status, repository.completeCalls)
	}
	fetched, err := service.Get(context.Background(), view.ID, principal)
	if err != nil || fetched.TaskID != taskID {
		t.Fatalf("Get() after ambiguous acknowledgement = (%#v, %v)", fetched, err)
	}
	replayed, err := service.Complete(context.Background(), view.ID, principal)
	if err != nil || replayed.TaskID != taskID || calls != 2 || repository.completeCalls != 1 {
		t.Fatalf(
			"replayed Complete() = (%#v, %v), ensure %d, finalize %d",
			replayed, err, calls, repository.completeCalls,
		)
	}
}

func TestCompletionDoesNotAutoCreateTasksForArchiveMismatchOrDerivedUpload(t *testing.T) {
	t.Run("archive", func(t *testing.T) {
		service, _, _, _ := newTestService(t)
		service.config.Detector = contentDetectorStub{result: filetype.Result{Format: "zip"}}
		directCalls := 0
		service.config.EnsureDirectTask = func(context.Context, DirectTaskRequest) (string, error) {
			directCalls++
			return "", errors.New("unexpected direct task")
		}
		service.config.EnsureArchiveImport = func(
			context.Context, ArchiveImportRequest,
		) (string, error) {
			return "a23e4567-e89b-42d3-a456-426614174000", nil
		}
		view, principal := createIntakeUploadWithContent(
			t, service, inputcategory.Archive, []byte("data"),
		)
		completed, err := service.Complete(context.Background(), view.ID, principal)
		if err != nil || completed.ArchiveImportID == "" || completed.TaskID != "" ||
			directCalls != 0 {
			t.Fatalf("archive Complete() = (%#v, %v), direct calls %d", completed, err, directCalls)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		service, _, _, _ := newTestService(t)
		service.config.Detector = contentDetectorStub{result: filetype.Result{Format: "zip"}}
		directCalls := 0
		service.config.EnsureDirectTask = func(context.Context, DirectTaskRequest) (string, error) {
			directCalls++
			return "", nil
		}
		view, principal := createIntakeUploadWithContent(
			t, service, inputcategory.Binary, []byte("data"),
		)
		if _, err := service.Complete(context.Background(), view.ID, principal); err == nil {
			t.Fatal("mismatched Complete() succeeded")
		}
		if directCalls != 0 {
			t.Fatalf("mismatch direct calls = %d", directCalls)
		}
	})

	t.Run("archive entry", func(t *testing.T) {
		service, _, _, _ := newTestService(t)
		directCalls := 0
		service.config.EnsureDirectTask = func(context.Context, DirectTaskRequest) (string, error) {
			directCalls++
			return "", nil
		}
		view := createDerivedUploadForCleanup(t, service)
		completed, err := service.Complete(context.Background(), view.ID, auth.Principal{
			UserID: 7, Role: auth.RoleOperator,
		})
		if err != nil || completed.TaskID != "" || directCalls != 0 {
			t.Fatalf("derived Complete() = (%#v, %v), direct calls %d", completed, err, directCalls)
		}
	})
}

func TestDirectTaskNameIsRuneSafeAndBounded(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		want      string
		wantRunes int
	}{
		{name: "long ASCII", filename: strings.Repeat("a", 512), wantRunes: 255},
		{name: "long Unicode", filename: strings.Repeat("界", 300), wantRunes: 255},
		{name: "trimmed", filename: "  sample.bin  ", want: "sample.bin", wantRunes: 10},
		{name: "empty after sanitizing", filename: " \n\t ", want: "Uploaded sample", wantRunes: 15},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name := DirectTaskName(test.filename)
			if !utf8.ValidString(name) || utf8.RuneCountInString(name) != test.wantRunes ||
				(test.want != "" && name != test.want) {
				t.Fatalf("DirectTaskName() = %q (%d runes)", name, utf8.RuneCountInString(name))
			}
		})
	}
}

func TestRecoverDirectTasksContinuesThenRetriesTransientFailureAfterCursorWrap(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	repository.directCandidates = []DirectTaskCandidate{
		{
			UploadID: "123e4567-e89b-42d3-a456-426614174001", CreatedBy: 7,
			Filename: "first.bin", InputCategory: inputcategory.Binary, DetectedFormat: "pe32",
		},
		{
			UploadID: "223e4567-e89b-42d3-a456-426614174002", CreatedBy: 8,
			Filename: "second.tar", InputCategory: inputcategory.Container, DetectedFormat: "docker-tar",
		},
	}
	transientErr := errors.New("task service unavailable")
	firstAttempts := 0
	firstTaskID := "a23e4567-e89b-42d3-a456-426614174000"
	secondTaskID := "b23e4567-e89b-42d3-a456-426614174000"
	service.config.EnsureDirectTask = func(
		_ context.Context,
		request DirectTaskRequest,
	) (string, error) {
		if request.UploadID == repository.directCandidates[0].UploadID {
			firstAttempts++
			if firstAttempts == 1 {
				return "", transientErr
			}
			repository.taskID = firstTaskID
			return firstTaskID, nil
		}
		repository.taskID = secondTaskID
		return secondTaskID, nil
	}
	report, err := service.RecoverDirectTasks(context.Background(), 10)
	if !errors.Is(err, transientErr) || report.Candidates != 2 || report.Ensured != 1 ||
		report.Failures != 1 || len(report.Diagnostics) != 1 ||
		report.Diagnostics[0].UploadID != repository.directCandidates[0].UploadID ||
		service.directTaskRecoveryCursor != repository.directCandidates[1].UploadID {
		t.Fatalf("RecoverDirectTasks() = (%+v, %v)", report, err)
	}

	// The successful later candidate disappears from the authoritative query.
	// The next maintenance cycle reaches the end, wraps, and retries the earlier
	// transient failure instead of losing it behind the cursor.
	repository.directCandidates = repository.directCandidates[:1]
	retried, err := service.RecoverDirectTasks(context.Background(), 10)
	if err != nil || !retried.Wrapped || retried.Candidates != 1 ||
		retried.Ensured != 1 || retried.Failures != 0 || firstAttempts != 2 ||
		service.directTaskRecoveryCursor != repository.directCandidates[0].UploadID {
		t.Fatalf("retried RecoverDirectTasks() = (%+v, %v), attempts=%d", retried, err, firstAttempts)
	}
}

func TestRecoverDirectTasksWrapsStableCursorWithoutStarvingEarlierIDs(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	candidate := DirectTaskCandidate{
		UploadID: "123e4567-e89b-42d3-a456-426614174001", CreatedBy: 7,
		Filename: "sample.bin", InputCategory: inputcategory.Binary, DetectedFormat: "pe32",
	}
	repository.directCandidates = []DirectTaskCandidate{candidate}
	service.directTaskRecoveryCursor = "f23e4567-e89b-42d3-a456-426614174000"
	taskID := "c23e4567-e89b-42d3-a456-426614174000"
	service.config.EnsureDirectTask = func(
		context.Context,
		DirectTaskRequest,
	) (string, error) {
		repository.taskID = taskID
		return taskID, nil
	}

	report, err := service.RecoverDirectTasks(context.Background(), 10)
	if err != nil || !report.Wrapped || report.Candidates != 1 || report.Ensured != 1 ||
		len(repository.directCandidateCalls) != 2 ||
		repository.directCandidateCalls[0] != "f23e4567-e89b-42d3-a456-426614174000" ||
		repository.directCandidateCalls[1] != "" {
		t.Fatalf(
			"wrapped RecoverDirectTasks() = (%+v, %v), calls %v",
			report, err, repository.directCandidateCalls,
		)
	}
}

func TestCreateDerivedCompletedIsIdempotentAndBindsProvenance(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	input := DerivedCompletedInput{
		CreatedBy: 7, Filename: "member.bin", ContentType: "application/octet-stream",
		Size: 4, SHA256: hashBytes([]byte("data")), BlobID: 19,
		InputCategory: inputcategory.Binary, DetectedFormat: "pe32",
		ParentUploadID: "123e4567-e89b-42d3-a456-426614174000",
		ArchiveName:    "bundle.zip", EntryPath: "nested/member.bin",
		IdempotencyKey: "archive-entry-42",
	}
	first, created, err := service.CreateDerivedCompleted(context.Background(), input)
	if err != nil || !created {
		t.Fatalf("CreateDerivedCompleted() = %#v/%v/%v", first, created, err)
	}
	if first.Status != "completed" || first.ValidationStatus != ValidationValid ||
		first.InputCategory != inputcategory.Binary ||
		repository.upload.IntakeProfile.SourceEntryPath != input.EntryPath {
		t.Fatalf("derived upload = %#v/%#v", first, repository.upload.IntakeProfile)
	}
	_, created, err = service.CreateDerivedCompleted(context.Background(), input)
	if err != nil || created {
		t.Fatalf("derived replay = created %v, error %v", created, err)
	}
	input.EntryPath = "nested/other.bin"
	if _, _, err := service.CreateDerivedCompleted(context.Background(), input); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed provenance replay error = %v", err)
	}
}

func TestDeleteDerivedCompletedTreatsReleasedExpiredUploadAsCleaned(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view := createDerivedUploadForCleanup(t, service)
	repository.upload.Status = "expired"
	repository.upload.BlobID = nil

	for attempt := 0; attempt < 2; attempt++ {
		if err := service.DeleteDerivedCompleted(
			context.Background(), view.ID, repository.upload.CreatedBy,
		); err != nil {
			t.Fatalf("DeleteDerivedCompleted() replay %d error = %v", attempt, err)
		}
	}
	if repository.upload.Status != "expired" || repository.cancelCalls != 0 ||
		repository.hasTaskCalls != 2 || repository.cleanupCalls != 2 {
		t.Fatalf(
			"expired derived cleanup = status %q, cancel %d, task checks %d, cleanup %d",
			repository.upload.Status, repository.cancelCalls,
			repository.hasTaskCalls, repository.cleanupCalls,
		)
	}
}

func TestDeleteDerivedCompletedRejectsExpiredUploadWithTaskOrBlobReference(t *testing.T) {
	tests := []struct {
		name       string
		retainBlob bool
		hasTask    bool
	}{
		{name: "blob reference not released", retainBlob: true},
		{name: "task retained upload", hasTask: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, repository, _, _ := newTestService(t)
			view := createDerivedUploadForCleanup(t, service)
			repository.upload.Status = "expired"
			if !test.retainBlob {
				repository.upload.BlobID = nil
			}
			repository.hasTask = test.hasTask

			err := service.DeleteDerivedCompleted(
				context.Background(), view.ID, repository.upload.CreatedBy,
			)
			if !errors.Is(err, ErrInvalidState) {
				t.Fatalf("DeleteDerivedCompleted() error = %v, want ErrInvalidState", err)
			}
			if repository.cancelCalls != 0 || repository.cleanupCalls != 0 {
				t.Fatalf(
					"rejected cleanup called cancel %d, cleanup %d",
					repository.cancelCalls, repository.cleanupCalls,
				)
			}
			wantTaskChecks := 0
			if !test.retainBlob {
				wantTaskChecks = 1
			}
			if repository.hasTaskCalls != wantTaskChecks {
				t.Fatalf("task checks = %d, want %d", repository.hasTaskCalls, wantTaskChecks)
			}
		})
	}
}

func TestDeleteDerivedCompletedDoesNotRelaxDirectExpiredUpload(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: 1, ContentType: "application/octet-stream",
		CreatedBy: 7, IdempotencyKey: "direct-expired-derived-cleanup",
		InputCategory: inputcategory.Binary,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.upload.Status = "expired"
	repository.upload.BlobID = nil

	err = service.DeleteDerivedCompleted(context.Background(), view.ID, 7)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteDerivedCompleted() error = %v, want ErrNotFound", err)
	}
	if repository.hasTaskCalls != 0 || repository.cancelCalls != 0 ||
		repository.cleanupCalls != 0 {
		t.Fatalf(
			"direct cleanup called task check %d, cancel %d, cleanup %d",
			repository.hasTaskCalls, repository.cancelCalls, repository.cleanupCalls,
		)
	}
}

func TestDeleteDerivedCompletedDoesNotHideExpiredTaskLookupFailure(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view := createDerivedUploadForCleanup(t, service)
	repository.upload.Status = "expired"
	repository.upload.BlobID = nil
	lookupErr := errors.New("task lookup unavailable")
	repository.hasTaskErr = lookupErr

	err := service.DeleteDerivedCompleted(context.Background(), view.ID, 7)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("DeleteDerivedCompleted() error = %v, want %v", err, lookupErr)
	}
	if repository.cancelCalls != 0 || repository.cleanupCalls != 0 {
		t.Fatalf(
			"failed lookup called cancel %d, cleanup %d",
			repository.cancelCalls, repository.cleanupCalls,
		)
	}
}

func createDerivedUploadForCleanup(t *testing.T, service *Service) View {
	t.Helper()
	view, created, err := service.CreateDerivedCompleted(context.Background(), DerivedCompletedInput{
		CreatedBy: 7, Filename: "member.bin", ContentType: "application/octet-stream",
		Size: 4, SHA256: hashBytes([]byte("data")), BlobID: 19,
		InputCategory: inputcategory.Binary, DetectedFormat: "pe32",
		ParentUploadID: "123e4567-e89b-42d3-a456-426614174000",
		ArchiveName:    "bundle.zip", EntryPath: "nested/member.bin",
		IdempotencyKey: "archive-entry-cleanup",
	})
	if err != nil || !created {
		t.Fatalf("CreateDerivedCompleted() = %#v/%v/%v", view, created, err)
	}
	return view
}

func TestArchiveDeleteRunsCoordinatorBeforeCancellingParent(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "bundle.zip", Size: 1, ContentType: "application/zip",
		CreatedBy: 7, IdempotencyKey: "archive-delete", InputCategory: inputcategory.Archive,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.upload.Status = "completed"
	repository.upload.IntakeProfile.ValidationStatus = ValidationValid
	repository.upload.IntakeProfile.DetectedCategory = inputcategory.Archive
	repository.upload.IntakeProfile.DetectedFormat = "zip"
	callbackCalls := 0
	service.config.DeleteArchiveImport = func(
		_ context.Context,
		request ArchiveImportDeleteRequest,
	) error {
		callbackCalls++
		if request.UploadID != view.ID || request.Actor.UserID != 7 {
			t.Fatalf("delete request = %#v", request)
		}
		if repository.cancelCalls != 0 {
			t.Fatal("parent upload cancelled before archive cleanup")
		}
		return nil
	}
	if err := service.Delete(context.Background(), view.ID, auth.Principal{
		UserID: 7, Role: auth.RoleOperator,
	}); err != nil {
		t.Fatal(err)
	}
	if callbackCalls != 1 || repository.cancelCalls != 1 {
		t.Fatalf("delete calls = coordinator %d, cancel %d", callbackCalls, repository.cancelCalls)
	}
}

func TestExpiredArchiveDeleteStillCascadesImportBeforeCancellation(t *testing.T) {
	service, repository, _, _ := newTestService(t)
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "bundle.zip", Size: 1, ContentType: "application/zip",
		CreatedBy: 7, IdempotencyKey: "expired-archive-delete",
		InputCategory: inputcategory.Archive,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.upload.Status = "completed"
	repository.upload.IntakeProfile.ValidationStatus = ValidationValid
	repository.upload.IntakeProfile.DetectedCategory = inputcategory.Archive
	repository.upload.IntakeProfile.DetectedFormat = "zip"
	repository.upload.IntakeProfile.ArchiveImportID = "323e4567-e89b-42d3-a456-426614174000"

	// Mirror retention: it releases the parent blob and marks the already
	// completed archive session expired before the user asks to delete it.
	cleanedAt := service.config.Now().UTC()
	repository.upload.Status = "expired"
	repository.upload.BlobID = nil
	repository.upload.PartsCleanedAt = &cleanedAt
	cascadeCalls := 0
	service.config.DeleteArchiveImport = func(
		_ context.Context,
		request ArchiveImportDeleteRequest,
	) error {
		cascadeCalls++
		if request.UploadID != view.ID || repository.cancelCalls != 0 {
			t.Fatalf("archive cascade ordering = %#v, cancel calls %d", request, repository.cancelCalls)
		}
		return nil
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	if err := service.Delete(context.Background(), view.ID, principal); err != nil {
		t.Fatal(err)
	}
	if cascadeCalls != 1 || repository.cancelCalls != 1 ||
		repository.upload.Status != "cancelled" {
		t.Fatalf("expired archive delete = cascade %d, cancel %d, status %s", cascadeCalls, repository.cancelCalls, repository.upload.Status)
	}
}

func createIntakeUploadWithContent(
	t *testing.T,
	service *Service,
	category inputcategory.Category,
	content []byte,
) (View, auth.Principal) {
	t.Helper()
	view, err := service.Create(context.Background(), CreateInput{
		Filename: "sample.bin", Size: int64(len(content)),
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "intake-content-key", InputCategory: category,
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := auth.Principal{UserID: 7, Role: auth.RoleOperator}
	if len(content) > 0 {
		if err := service.PutPart(
			context.Background(), view.ID, principal, 1,
			Range{
				Start: 0, End: int64(len(content)) - 1, Total: int64(len(content)),
				Raw: "bytes 0-" + integerString(int64(len(content))-1) + "/" + integerString(int64(len(content))),
			},
			hashBytes(content), bytes.NewReader(content),
		); err != nil {
			t.Fatal(err)
		}
	}
	return view, principal
}

func integerString(value int64) string {
	if value == 0 {
		return "0"
	}
	digits := [20]byte{}
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
