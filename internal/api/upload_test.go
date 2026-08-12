package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/buildinfo"
	"binaryscan/internal/inputcategory"
	"binaryscan/internal/storageguard"
	"binaryscan/internal/upload"
)

type uploadServiceStub struct {
	createCalls  int
	createdInput CreateUploadCapture
	putRange     upload.Range
	putNumber    uint32
	deleteID     string
	deleteUser   auth.Principal
	view         upload.View
	err          error
}

type CreateUploadCapture struct {
	Filename       string
	Size           int64
	ContentType    string
	CreatedBy      uint64
	IdempotencyKey string
	InputCategory  inputcategory.Category
}

func (s *uploadServiceStub) Create(_ context.Context, input upload.CreateInput) (upload.View, error) {
	s.createCalls++
	s.createdInput = CreateUploadCapture{
		Filename: input.Filename, Size: input.Size,
		ContentType: input.ContentType, CreatedBy: input.CreatedBy,
		IdempotencyKey: input.IdempotencyKey,
		InputCategory:  input.InputCategory,
	}
	return s.view, s.err
}
func (s *uploadServiceStub) Get(context.Context, string, auth.Principal) (upload.View, error) {
	return s.view, s.err
}
func (s *uploadServiceStub) PutPart(
	_ context.Context,
	_ string,
	_ auth.Principal,
	number uint32,
	byteRange upload.Range,
	_ string,
	body io.Reader,
) error {
	s.putNumber = number
	s.putRange = byteRange
	_, _ = io.Copy(io.Discard, body)
	return s.err
}
func (s *uploadServiceStub) Complete(context.Context, string, auth.Principal) (upload.View, error) {
	return s.view, s.err
}
func (s *uploadServiceStub) Delete(
	_ context.Context,
	id string,
	principal auth.Principal,
) error {
	s.deleteID = id
	s.deleteUser = principal
	return s.err
}

func TestCreateUploadContractAndRole(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	expires := time.Now().Add(time.Hour)
	service := &uploadServiceStub{view: upload.View{
		ID: "upload-id", PartSize: upload.DefaultPartSize, Status: "created",
		UploadedParts: []uint32{}, ExpiresAt: expires,
	}}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads", strings.NewReader(
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-request-1")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.createdInput != (CreateUploadCapture{
		Filename: "sample.bin", Size: 42,
		ContentType: "application/octet-stream", CreatedBy: 7,
		IdempotencyKey: "upload-request-1", InputCategory: inputcategory.Binary,
	}) {
		t.Fatalf("create input = %#v", service.createdInput)
	}
	var envelope struct {
		Data upload.View `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.ID != "upload-id" ||
		envelope.Data.PartSize != upload.DefaultPartSize ||
		envelope.Data.Status != "created" ||
		envelope.Data.UploadedParts == nil {
		t.Fatalf("response data = %#v", envelope.Data)
	}

	manager.session.User.Role = auth.RoleReader
	denied := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/uploads", strings.NewReader(
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-request-2")
	addAuthAndCSRF(request, csrf)
	router.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("reader status = %d, want 403", denied.Code)
	}
	if service.createCalls != 1 {
		t.Fatalf("reader request reached upload service; calls = %d", service.createCalls)
	}
}

func TestCreateUploadRejectsUnknownJSONField(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads", strings.NewReader(
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary","extra":true}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-request-3")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestCreateUploadRequiresCanonicalInputCategory(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	for _, body := range []string{
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream"}`,
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"Binary"}`,
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"image"}`,
	} {
		service := &uploadServiceStub{}
		router := uploadTestRouter(t, manager, service)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "category-required")
		addAuthAndCSRF(request, csrf)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || service.createCalls != 0 {
			t.Fatalf("body %s response = %d/%s, calls=%d", body, response.Code, response.Body.String(), service.createCalls)
		}
	}
}

func TestCreateUploadRejectsQueryParametersBeforeService(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7,
			Role:   auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/uploads?idempotency_key=must-not-be-accepted",
		strings.NewReader(
			`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-request-query")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || service.createCalls != 0 {
		t.Fatalf(
			"query response = %d/%s, calls=%d",
			response.Code,
			response.Body.String(),
			service.createCalls,
		)
	}
}

func TestCreateUploadRequiresSingleValidIdempotencyKey(t *testing.T) {
	tests := []struct {
		name string
		keys []string
	}{
		{name: "missing"},
		{name: "empty", keys: []string{""}},
		{name: "duplicate", keys: []string{"one", "two"}},
		{name: "space", keys: []string{"contains space"}},
		{name: "control", keys: []string{"contains\ncontrol"}},
		{name: "too long", keys: []string{strings.Repeat("a", 129)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			csrf := "csrf-token"
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 7,
					Role:   auth.RoleOperator,
				}},
				csrfToken: csrf,
			}
			service := &uploadServiceStub{}
			router := uploadTestRouter(t, manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/uploads",
				strings.NewReader(
					`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
				),
			)
			request.Header.Set("Content-Type", "application/json")
			for _, key := range test.keys {
				request.Header.Add("Idempotency-Key", key)
			}
			addAuthAndCSRF(request, csrf)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest ||
				service.createCalls != 0 ||
				!strings.Contains(response.Body.String(), "idempotency_key_required") {
				t.Fatalf(
					"response = %d/%s, calls=%d",
					response.Code,
					response.Body.String(),
					service.createCalls,
				)
			}
		})
	}
}

func TestCreateUploadMapsIdempotencyConflictWithoutLeakingExistingUpload(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7,
			Role:   auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{err: upload.ErrIdempotencyConflict}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/uploads",
		strings.NewReader(
			`{"filename":"different.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-conflict-key")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict ||
		!strings.Contains(response.Body.String(), `"code":"idempotency_conflict"`) ||
		strings.Contains(response.Body.String(), "upload-id") {
		t.Fatalf("response = %d/%s", response.Code, response.Body.String())
	}
}

func TestCreateUploadReturnsInsufficientStorageWithoutLeakingProbeDetails(
	t *testing.T,
) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7,
			Role:   auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{err: storageguard.ErrInsufficientStorage}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/uploads",
		strings.NewReader(
			`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
		),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-request-error")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf(
			"status = %d, want %d; body=%s",
			response.Code,
			http.StatusInsufficientStorage,
			response.Body.String(),
		)
	}
	var body ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "insufficient_storage" ||
		strings.Contains(response.Body.String(), "/data/") {
		t.Fatalf("unexpected storage error response: %s", response.Body.String())
	}
}

func TestPutUploadPartParsesOneBasedRange(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/uploads/123e4567-e89b-42d3-a456-426614174000/parts/2",
		strings.NewReader("data"),
	)
	request.Header.Set("Content-Range", "bytes 04-07/08")
	request.Header.Set("X-Chunk-SHA256", strings.Repeat("a", 64))
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if service.putNumber != 2 || service.putRange.Start != 4 ||
		service.putRange.End != 7 || service.putRange.Total != 8 ||
		service.putRange.Raw != "bytes 4-7/8" {
		t.Fatalf("part capture = %d, %#v", service.putNumber, service.putRange)
	}
}

func TestCompleteUploadRejectsNonEmptyChunkedBody(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/uploads/123e4567-e89b-42d3-a456-426614174000/complete",
		strings.NewReader("unexpected"),
	)
	request.ContentLength = -1
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestCompleteUploadReturnsDetectedCategoryMismatchDetails(t *testing.T) {
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	uploadID := "123e4567-e89b-42d3-a456-426614174000"
	service := &uploadServiceStub{err: &upload.CompletionValidationError{
		UploadID: uploadID, InputCategory: inputcategory.Binary,
		DetectedCategory: inputcategory.Archive, DetectedFormat: "zip",
		Status: upload.ValidationMismatch,
	}}
	router := uploadTestRouter(t, manager, service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads/"+uploadID+"/complete", nil)
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), `"code":"input_category_mismatch"`) ||
		!strings.Contains(response.Body.String(), `"detected_category":"archive"`) ||
		!strings.Contains(response.Body.String(), `"detected_format":"zip"`) {
		t.Fatalf("response = %d/%s", response.Code, response.Body.String())
	}
}

func TestDeleteUploadRequiresCSRFAndReturnsNoContent(t *testing.T) {
	const uploadID = "123e4567-e89b-42d3-a456-426614174000"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session: auth.Session{User: auth.Principal{
			UserID: 7,
			Role:   auth.RoleOperator,
		}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{}
	router := uploadTestRouter(t, manager, service)

	request := httptest.NewRequest(http.MethodDelete, "/api/v1/uploads/"+uploadID, nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	denied := httptest.NewRecorder()
	router.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d, want 403", denied.Code)
	}
	if service.deleteID != "" {
		t.Fatal("request without CSRF reached Delete()")
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/v1/uploads/"+uploadID, nil)
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status/body = %d/%q, want 204/empty", response.Code, response.Body.String())
	}
	if service.deleteID != uploadID ||
		service.deleteUser.UserID != 7 ||
		service.deleteUser.Role != auth.RoleOperator {
		t.Fatalf("Delete() capture = %q/%+v", service.deleteID, service.deleteUser)
	}
}

func TestUploadInternalErrorIsLoggedButNotExposed(t *testing.T) {
	const privateDetail = "mysql upload write failed: secret diagnostic"
	csrf := "csrf-token"
	manager := &authManagerStub{
		session:   auth.Session{User: auth.Principal{UserID: 7, Role: auth.RoleOperator}},
		csrfToken: csrf,
	}
	service := &uploadServiceStub{err: errors.New(privateDetail)}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	router := uploadTestRouterWithLogger(t, manager, service, logger)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/uploads", strings.NewReader(
		`{"filename":"sample.bin","size":42,"content_type":"application/octet-stream","input_category":"binary"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "upload-internal-error")
	addAuthAndCSRF(request, csrf)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), privateDetail) {
		t.Fatal("private upload error leaked into the response")
	}
	if log := logOutput.String(); !strings.Contains(log, privateDetail) ||
		!strings.Contains(log, `"level":"ERROR"`) {
		t.Fatalf("private error was not logged at ERROR level: %s", log)
	}
}

func uploadTestRouter(t *testing.T, manager AuthManager, service UploadService) http.Handler {
	t.Helper()
	return uploadTestRouterWithLogger(
		t, manager, service, slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
}

func uploadTestRouterWithLogger(
	t *testing.T,
	manager AuthManager,
	service UploadService,
	logger *slog.Logger,
) http.Handler {
	t.Helper()
	router, err := NewRouter(Dependencies{
		Logger:   logger,
		Database: readinessStub{}, ReadinessTimeout: time.Second,
		Auth: manager, AuthHTTP: AuthHTTPConfig{SessionTTL: time.Hour},
		Uploads: service,
		Build:   buildinfo.Current(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func addAuthAndCSRF(request *http.Request, csrf string) {
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	request.Header.Set(csrfHeaderName, csrf)
}
