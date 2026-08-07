package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/manualimagescan"

	"github.com/gin-gonic/gin"
)

type manualImageScanServiceStub struct {
	input   manualimagescan.CreateInput
	request manualimagescan.Request
	created bool
	err     error
	calls   int
}

func (stub *manualImageScanServiceStub) Create(
	_ context.Context,
	input manualimagescan.CreateInput,
) (manualimagescan.Request, bool, error) {
	stub.calls++
	stub.input = input
	return stub.request, stub.created, stub.err
}

func TestCreateManualImageScanRequiresWriteRoleCSRFAndStrictBody(t *testing.T) {
	for _, test := range []struct {
		name       string
		role       auth.Role
		body       string
		csrf       bool
		wantStatus int
		wantCalls  int
	}{
		{
			name: "operator", role: auth.RoleOperator, body: `{}`,
			csrf: true, wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "administrator", role: auth.RoleAdministrator, body: `{}`,
			csrf: true, wantStatus: http.StatusCreated, wantCalls: 1,
		},
		{
			name: "reader", role: auth.RoleReader, body: `{}`,
			csrf: true, wantStatus: http.StatusForbidden,
		},
		{
			name: "missing csrf", role: auth.RoleOperator, body: `{}`,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "unknown field", role: auth.RoleOperator,
			body: `{"storage_key":"secret"}`, csrf: true,
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &manualImageScanServiceStub{
				request: manualimagescan.Request{
					JobID:      decompileJobTestID,
					TaskID:     decompileTaskTestID,
					FileNodeID: "42",
					Status:     "queued",
					CreatedAt:  time.Now(),
				},
				created: true,
			}
			manager := &authManagerStub{
				session: auth.Session{User: auth.Principal{
					UserID: 7,
					Role:   test.role,
				}},
				csrfToken: "csrf-token",
			}
			router := manualImageScanTestRouter(manager, service)
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/tasks/"+decompileTaskTestID+
					"/files/42/image-scan",
				strings.NewReader(test.body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "manual-image-intent")
			request.AddCookie(&http.Cookie{
				Name: sessionCookieName, Value: "session-token",
			})
			if test.csrf {
				request.AddCookie(&http.Cookie{
					Name: csrfCookieName, Value: "csrf-token",
				})
				request.Header.Set(csrfHeaderName, "csrf-token")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body=%s",
					response.Code,
					test.wantStatus,
					response.Body.String(),
				)
			}
			if service.calls != test.wantCalls {
				t.Fatalf("service calls = %d, want %d", service.calls, test.wantCalls)
			}
			if test.wantCalls == 1 &&
				(service.input.TaskID != decompileTaskTestID ||
					service.input.FileNodeID != 42 ||
					service.input.UserID != 7 ||
					service.input.IdempotencyKey != "manual-image-intent") {
				t.Fatalf("service input = %#v", service.input)
			}
			if test.wantCalls == 1 {
				var body struct {
					Data manualimagescan.Request `json:"data"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Data.JobID != decompileJobTestID {
					t.Fatalf("response = %#v", body.Data)
				}
			}
		})
	}
}

func manualImageScanTestRouter(
	manager AuthManager,
	service ManualImageScanService,
) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
	)
	registerManualImageScanRoutes(router.Group("/api/v1"), manager, service)
	return router
}

var _ ManualImageScanService = (*manualImageScanServiceStub)(nil)
