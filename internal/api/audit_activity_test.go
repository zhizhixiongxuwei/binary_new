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

func TestAuditActivityMiddlewareRecordsArchiveTaskBatchWithoutEntryIDs(
	t *testing.T,
) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.POST(
		"/api/v1/archive-imports/:id/task-batches",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleOperator,
			}})
			c.Status(http.StatusCreated)
		},
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/archive-imports/71111111-1111-4111-8111-111111111111/task-batches",
		strings.NewReader(`{"entry_ids":["secret-entry-id"]}`),
	)
	request.Header.Set("Idempotency-Key", "secret-idempotency-key")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "archive_import.task_batch_create" ||
		event.ObjectType != "archive_import" ||
		event.ObjectID != "71111111-1111-4111-8111-111111111111" ||
		event.Outcome != audit.OutcomeSuccess ||
		event.Metadata["http_status"] != http.StatusCreated {
		t.Fatalf("archive import audit event = %+v", event)
	}
	encoded := fmt.Sprintf("%v", event.Metadata)
	for _, secret := range []string{"secret-entry-id", "secret-idempotency-key"} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("archive import audit leaked %q: %#v", secret, event.Metadata)
		}
	}
}

func TestAuditActivityMiddlewareRecordsJavaAnalysisActionsWithoutFindingData(
	t *testing.T,
) {
	tests := []struct {
		name       string
		method     string
		pattern    string
		path       string
		status     int
		action     string
		objectType string
		objectID   string
		outcome    audit.Outcome
	}{
		{
			name: "create success", method: http.MethodPost,
			pattern: "/api/v1/tasks/:id/decompile-projects/:project_id/java-analysis-runs",
			path: "/api/v1/tasks/" + apiJavaAnalysisTaskID +
				"/decompile-projects/" + apiJavaAnalysisProjectID +
				"/java-analysis-runs",
			status: http.StatusCreated, action: "java_analysis.create",
			objectType: "decompile_project", objectID: apiJavaAnalysisProjectID,
			outcome: audit.OutcomeSuccess,
		},
		{
			name: "cancel denied", method: http.MethodPost,
			pattern: "/api/v1/tasks/:id/java-analysis-runs/:run_id/cancel",
			path: "/api/v1/tasks/" + apiJavaAnalysisTaskID +
				"/java-analysis-runs/" + apiJavaAnalysisRunID + "/cancel",
			status: http.StatusConflict, action: "java_analysis.cancel",
			objectType: "java_analysis_run", objectID: apiJavaAnalysisRunID,
			outcome: audit.OutcomeDenied,
		},
		{
			name: "delete success", method: http.MethodDelete,
			pattern: "/api/v1/tasks/:id/java-analysis-runs/:run_id",
			path: "/api/v1/tasks/" + apiJavaAnalysisTaskID +
				"/java-analysis-runs/" + apiJavaAnalysisRunID,
			status: http.StatusNoContent, action: "java_analysis.delete",
			objectType: "java_analysis_run", objectID: apiJavaAnalysisRunID,
			outcome: audit.OutcomeSuccess,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := &auditRecorderStub{}
			router := gin.New()
			router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
			handler := func(c *gin.Context) {
				c.Set(authSessionKey, auth.Session{User: auth.Principal{
					UserID: 17, Role: auth.RoleOperator,
				}})
				c.Status(test.status)
			}
			switch test.method {
			case http.MethodPost:
				router.POST(test.pattern, handler)
			case http.MethodDelete:
				router.DELETE(test.pattern, handler)
			default:
				t.Fatalf("unsupported method %q", test.method)
			}
			request := httptest.NewRequest(
				test.method, test.path,
				strings.NewReader(`{"cwe":"CWE-78","file":"Secret.java","snippet":"secret"}`),
			)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != test.status || len(recorder.events) != 1 {
				t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
			}
			event := recorder.events[0]
			if event.Action != test.action || event.ObjectType != test.objectType ||
				event.ObjectID != test.objectID || event.Outcome != test.outcome ||
				event.Metadata["task_id"] != apiJavaAnalysisTaskID ||
				event.Metadata["http_status"] != test.status {
				t.Fatalf("Java analysis audit event = %+v", event)
			}
			encoded := fmt.Sprintf("%v", event.Metadata)
			for _, secret := range []string{"CWE-78", "Secret.java", "secret", "snippet"} {
				if strings.Contains(encoded, secret) {
					t.Fatalf("Java analysis audit leaked %q: %#v", secret, event.Metadata)
				}
			}
		})
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

func TestAuditActivityMiddlewareRecordsDecompileProjectDeletion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.DELETE(
		"/api/v1/tasks/:id/decompile-projects/:project_id",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleOperator,
			}})
			c.Status(http.StatusNoContent)
		},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodDelete,
		"/api/v1/tasks/"+decompileTaskTestID+
			"/decompile-projects/"+decompileProjectTestID,
		nil,
	))
	if response.Code != http.StatusNoContent || len(recorder.events) != 1 {
		t.Fatalf("status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "decompile.project_delete" ||
		event.ObjectType != "decompile_project" ||
		event.ObjectID != decompileProjectTestID ||
		event.Metadata["task_id"] != decompileTaskTestID ||
		event.Outcome != audit.OutcomeSuccess {
		t.Fatalf("decompile project delete audit = %+v", event)
	}
}

func TestAuditActivityMiddlewareRecordsProjectZipButNotProjectDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.GET(
		"/api/v1/tasks/:id/decompile-projects/:project_id",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleReader,
			}})
			projectID := c.Param("project_id")
			if strings.HasSuffix(projectID, ".zip") {
				c.Set(
					decompileProjectExportAuditIDKey,
					strings.TrimSuffix(projectID, ".zip"),
				)
				c.Set(decompileSourceExportCountKey, 41)
			}
			c.Status(http.StatusOK)
		},
	)
	for _, suffix := range []string{"", ".zip"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(
			http.MethodGet,
			"/api/v1/tasks/"+decompileTaskTestID+
				"/decompile-projects/"+decompileProjectTestID+suffix,
			nil,
		))
		if response.Code != http.StatusOK {
			t.Fatalf("project request %q status = %d", suffix, response.Code)
		}
	}
	if len(recorder.events) != 1 {
		t.Fatalf("project detail/export audit events = %d, want 1", len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "decompile.project_export" ||
		event.ObjectType != "decompile_project" ||
		event.ObjectID != decompileProjectTestID ||
		event.Metadata["task_id"] != decompileTaskTestID ||
		event.Metadata["result_count"] != 41 ||
		event.Outcome != audit.OutcomeSuccess {
		t.Fatalf("decompile project export audit = %+v", event)
	}
}

func TestAuditActivityMiddlewareRecordsDeniedProjectZipQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &auditRecorderStub{}
	router := gin.New()
	router.Use(RequestIDMiddleware(), AuditActivityMiddleware(recorder))
	router.GET(
		"/api/v1/tasks/:id/decompile-projects/:project_id",
		func(c *gin.Context) {
			c.Set(authSessionKey, auth.Session{User: auth.Principal{
				UserID: 17, Role: auth.RoleReader,
			}})
			c.Next()
		},
		getOrDownloadDecompileProjectHandler(&decompileServiceStub{}),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tasks/"+decompileTaskTestID+
			"/decompile-projects/"+decompileProjectTestID+".zip?unexpected=1",
		nil,
	))
	if response.Code != http.StatusBadRequest || len(recorder.events) != 1 {
		t.Fatalf("denied project export status/events = %d/%d", response.Code, len(recorder.events))
	}
	event := recorder.events[0]
	if event.Action != "decompile.project_export" ||
		event.ObjectID != decompileProjectTestID ||
		event.Outcome != audit.OutcomeDenied {
		t.Fatalf("denied project export audit = %+v", event)
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
