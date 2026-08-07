package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"

	"github.com/gin-gonic/gin"
)

type auditRecorderStub struct {
	events     []audit.Event
	err        error
	contextErr error
}

func (r *auditRecorderStub) Record(ctx context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	r.contextErr = ctx.Err()
	return r.err
}

func TestAuditActivityMiddlewareRecordsEnumeratedAuthenticatedAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.POST(
		"/api/v1/tasks/:id/retry",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleOperator,
			}})
			c.Next()
		},
		func(c *gin.Context) {
			Write(c, http.StatusAccepted, gin.H{"ok": true})
		},
	)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/task-public-id/retry",
		nil,
	)
	request.Header.Set("X-Request-ID", "audit-request")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.ActorUserID == nil || *event.ActorUserID != 17 ||
		event.RequestID != "audit-request" ||
		event.Action != "task.retry" ||
		event.ObjectType != "task" ||
		event.ObjectID != "task-public-id" ||
		event.Outcome != audit.OutcomeSuccess {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	if event.Metadata["http_status"] != http.StatusAccepted {
		t.Fatalf("unexpected audit metadata: %#v", event.Metadata)
	}
}

func TestAuditActivityMiddlewareRecordsDecompileIDsWithoutRequestSecrets(
	t *testing.T,
) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.POST(
		"/api/v1/tasks/:id/files/:node_id/decompile",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleOperator,
			}})
			c.Set(decompileAuditJobIDKey, decompileJobTestID)
			c.Set(decompileAuditRequestIDKey, decompileRequestTestID)
			Write(c, http.StatusCreated, gin.H{"ok": true})
		},
	)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/"+decompileTaskTestID+"/files/42/decompile",
		strings.NewReader(
			`{"options":{"password":"must-not-enter-audit"}}`,
		),
	)
	request.Header.Set("Idempotency-Key", "must-not-enter-audit")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "decompile.create" ||
		event.ObjectType != "task" ||
		event.ObjectID != decompileTaskTestID ||
		event.Metadata["file_node_id"] != "42" ||
		event.Metadata["job_id"] != decompileJobTestID ||
		event.Metadata["decompile_request_id"] != decompileRequestTestID {
		t.Fatalf("decompile audit event = %+v", event)
	}
	encoded := fmt.Sprintf("%v", event.Metadata)
	if strings.Contains(encoded, "password") ||
		strings.Contains(encoded, "must-not-enter-audit") {
		t.Fatalf("decompile audit leaked request data: %#v", event.Metadata)
	}
}

func TestAuditActivityMiddlewareRecordsDecompileSourceExportMetadataAndFailure(
	t *testing.T,
) {
	tests := []struct {
		name         string
		streamFailed bool
		outcome      audit.Outcome
	}{
		{name: "success", outcome: audit.OutcomeSuccess},
		{
			name: "stream failure", streamFailed: true,
			outcome: audit.OutcomeFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := &auditRecorderStub{}
			router := gin.New()
			router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
			router.GET(
				"/api/v1/tasks/:id/decompile-sources.zip",
				func(c *gin.Context) {
					c.Set(authSessionKey, auth.Session{User: auth.Principal{
						UserID: 17, Role: auth.RoleReader,
					}})
					c.Set(decompileSourceExportCountKey, 2084)
					if test.streamFailed {
						c.Set(decompileSourceExportStreamFailedKey, true)
					}
					c.Status(http.StatusOK)
				},
			)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tasks/"+decompileTaskTestID+
					"/decompile-sources.zip?combined=true",
				nil,
			)
			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK || len(recorder.events) != 1 {
				t.Fatalf(
					"status/events = %d/%d",
					response.Code,
					len(recorder.events),
				)
			}
			event := recorder.events[0]
			if event.Action != "decompile.source_export" ||
				event.ObjectType != "task" ||
				event.ObjectID != decompileTaskTestID ||
				event.Outcome != test.outcome ||
				event.Metadata["http_status"] != http.StatusOK ||
				event.Metadata["combined"] != true ||
				event.Metadata["result_count"] != 2084 {
				t.Fatalf("decompile source export audit = %+v", event)
			}
		})
	}
}

func TestAuditActivityMiddlewareClassifiesDeniedAndSkipsUnlistedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	setSession := func(c *gin.Context) {
		c.Set(authSessionKey, auth.Session{User: auth.Principal{
			UserID: 9, Role: auth.RoleAdministrator,
		}})
		c.Next()
	}
	router.DELETE("/api/v1/uploads/:id", setSession, func(c *gin.Context) {
		WriteError(c, http.StatusConflict, "upload_busy", "Upload is busy.", nil)
	})
	router.GET("/api/v1/tasks/:id", setSession, func(c *gin.Context) {
		Write(c, http.StatusOK, gin.H{"id": c.Param("id")})
	})

	denied := httptest.NewRecorder()
	router.ServeHTTP(
		denied,
		httptest.NewRequest(http.MethodDelete, "/api/v1/uploads/upload-1", nil),
	)
	unlisted := httptest.NewRecorder()
	router.ServeHTTP(
		unlisted,
		httptest.NewRequest(http.MethodGet, "/api/v1/tasks/task-1", nil),
	)

	if len(recorder.events) != 1 ||
		recorder.events[0].Outcome != audit.OutcomeDenied ||
		recorder.events[0].Action != "upload.cancel" {
		t.Fatalf("unexpected audit events: %+v", recorder.events)
	}
}

func TestAuditActivityMiddlewareSurfacesRecorderFailureWithoutChangingResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{err: errors.New("audit unavailable")}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.POST(
		"/api/v1/uploads",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 1, Role: auth.RoleOperator,
			}})
			c.Next()
		},
		func(c *gin.Context) {
			Write(c, http.StatusCreated, gin.H{"id": "upload"})
		},
	)

	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodPost, "/api/v1/uploads", nil),
	)

	if response.Code != http.StatusCreated || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
}

func TestAuditActivityMiddlewareSurvivesRequestCancellationAndBoundsObjectID(
	t *testing.T,
) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	setSession := func(c *gin.Context) {
		c.Set(authSessionKey, auth.Session{User: auth.Principal{
			UserID: 11, Role: auth.RoleOperator,
		}})
		c.Next()
	}
	var cancelRequest context.CancelFunc
	router.POST(
		"/api/v1/tasks/:id/retry",
		setSession,
		func(c *gin.Context) {
			cancelRequest()
			WriteError(c, http.StatusBadRequest, "invalid_task", "Invalid.", nil)
		},
	)

	longID := strings.Repeat("a", 129)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/"+longID+"/retry",
		nil,
	)
	ctx, cancel := context.WithCancel(request.Context())
	cancelRequest = cancel
	request = request.WithContext(ctx)
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if recorder.contextErr != nil || event.ObjectID != "" ||
		event.Metadata["object_id_omitted"] != true {
		t.Fatalf(
			"context/object sanitization = %v / %#v",
			recorder.contextErr,
			event,
		)
	}
}
