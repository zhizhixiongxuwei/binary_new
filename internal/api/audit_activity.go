package api

import (
	"context"
	"net/http"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/audit"

	"github.com/gin-gonic/gin"
)

type auditedRoute struct {
	action               string
	objectType           string
	param                string
	skipHandledUserAdmin bool
	enabled              func(*gin.Context) bool
	objectID             func(*gin.Context) string
	metadata             func(*gin.Context) map[string]any
}

const (
	userAdminAuditHandledKey = "binaryscan.user_admin_audit_handled"
	requestAuditTimeout      = time.Second
)

var auditedRoutes = map[string]auditedRoute{
	"PUT /api/v1/me/password": {
		action: "auth.password_change", objectType: "user",
	},
	"POST /api/v1/auth/logout": {
		action: "auth.logout", objectType: "session",
	},
	"POST /api/v1/uploads": {
		action: "upload.create", objectType: "upload",
	},
	"PUT /api/v1/uploads/:id/parts/:partNumber": {
		action: "upload.part_write", objectType: "upload", param: "id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"part_number": c.Param("partNumber")}
		},
	},
	"POST /api/v1/uploads/:id/complete": {
		action: "upload.complete", objectType: "upload", param: "id",
	},
	"DELETE /api/v1/uploads/:id": {
		action: "upload.cancel", objectType: "upload", param: "id",
	},
	"POST /api/v1/archive-imports/:id/task-batches": {
		action: "archive_import.task_batch_create", objectType: "archive_import",
		param: "id",
	},
	"POST /api/v1/tasks": {
		action: "task.create", objectType: "task",
	},
	"POST /api/v1/tasks/:id/cancel": {
		action: "task.cancel", objectType: "task", param: "id",
	},
	"POST /api/v1/tasks/:id/retry": {
		action: "task.retry", objectType: "task", param: "id",
	},
	"DELETE /api/v1/tasks/:id": {
		action: "task.delete", objectType: "task", param: "id",
	},
	"PATCH /api/v1/tasks/:id/retention": {
		action: "task.retention_extend", objectType: "task", param: "id",
	},
	"POST /api/v1/tasks/:id/files/:node_id/decompile": {
		action: "decompile.create", objectType: "task", param: "id",
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{}
			if nodeID := c.Param("node_id"); nodeID != "" &&
				safeAuditObjectID(nodeID) {
				metadata["file_node_id"] = nodeID
			}
			if jobID := c.GetString(decompileAuditJobIDKey); jobID != "" {
				metadata["job_id"] = jobID
			}
			if requestID := c.GetString(decompileAuditRequestIDKey); requestID != "" {
				metadata["decompile_request_id"] = requestID
			}
			return metadata
		},
	},
	"POST /api/v1/tasks/:id/files/:node_id/image-scan": {
		action: "image_scan.create", objectType: "task", param: "id",
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{}
			if nodeID := c.Param("node_id"); nodeID != "" &&
				safeAuditObjectID(nodeID) {
				metadata["file_node_id"] = nodeID
			}
			if jobID := c.GetString(imageScanAuditJobIDKey); jobID != "" {
				metadata["job_id"] = jobID
			}
			return metadata
		},
	},
	"POST /api/v1/tasks/:id/decompile-projects/:project_id/c-analysis-runs": {
		action: "c_analysis.create", objectType: "decompile_project",
		param: "project_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"POST /api/v1/tasks/:id/c-analysis-runs/:run_id/cancel": {
		action: "c_analysis.cancel", objectType: "c_analysis_run",
		param: "run_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"DELETE /api/v1/tasks/:id/c-analysis-runs/:run_id": {
		action: "c_analysis.delete", objectType: "c_analysis_run",
		param: "run_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"POST /api/v1/tasks/:id/decompile-projects/:project_id/java-analysis-runs": {
		action: "java_analysis.create", objectType: "decompile_project",
		param: "project_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"POST /api/v1/tasks/:id/java-analysis-runs/:run_id/cancel": {
		action: "java_analysis.cancel", objectType: "java_analysis_run",
		param: "run_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"DELETE /api/v1/tasks/:id/java-analysis-runs/:run_id": {
		action: "java_analysis.delete", objectType: "java_analysis_run",
		param: "run_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"POST /api/v1/tasks/:id/reports": {
		action: "report.generate", objectType: "task", param: "id",
	},
	"GET /api/v1/tasks/:id/reports/:report_id/download": {
		action: "report.export", objectType: "report", param: "report_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"GET /api/v1/tasks/:id/decompile-sources.zip": {
		action: "decompile.source_export", objectType: "task", param: "id",
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{
				"combined": c.Query("combined") == "true",
			}
			if count, exists := c.Get(decompileSourceExportCountKey); exists {
				metadata["result_count"] = count
			}
			return metadata
		},
	},
	"GET /api/v1/tasks/:id/decompile-projects/:project_id": {
		action: "decompile.project_export", objectType: "decompile_project",
		enabled: func(c *gin.Context) bool {
			return c.GetString(decompileProjectExportAuditIDKey) != ""
		},
		objectID: func(c *gin.Context) string {
			return c.GetString(decompileProjectExportAuditIDKey)
		},
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{"task_id": c.Param("id")}
			if count, exists := c.Get(decompileSourceExportCountKey); exists {
				metadata["result_count"] = count
			}
			return metadata
		},
	},
	"DELETE /api/v1/tasks/:id/decompile-projects/:project_id": {
		action: "decompile.project_delete", objectType: "decompile_project",
		param: "project_id",
		metadata: func(c *gin.Context) map[string]any {
			return map[string]any{"task_id": c.Param("id")}
		},
	},
	"POST /api/v1/tasks/:id/decompile-projects/:project_id/deletion-preview": {
		action: "decompile.project_delete_preview", objectType: "decompile_project",
		param: "project_id",
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{"task_id": c.Param("id")}
			if counts, exists := c.Get(decompileProjectDeletionCountsAuditKey); exists {
				metadata["impact_counts"] = counts
			}
			return metadata
		},
	},
	"POST /api/v1/tasks/:id/decompile-projects/:project_id/deletion": {
		action: "decompile.project_delete_confirm", objectType: "decompile_project",
		param: "project_id",
		metadata: func(c *gin.Context) map[string]any {
			metadata := map[string]any{"task_id": c.Param("id")}
			if operationID := c.GetString(decompileProjectDeletionOperationAuditKey); operationID != "" {
				metadata["operation_id"] = operationID
			}
			if counts, exists := c.Get(decompileProjectDeletionCountsAuditKey); exists {
				metadata["impact_counts"] = counts
			}
			return metadata
		},
	},
	"GET /api/v1/tasks/:id/sample/download": {
		action: "sample.export", objectType: "task", param: "id",
	},
	"POST /api/v1/admin/users": {
		action: "user.create", objectType: "user",
		skipHandledUserAdmin: true,
	},
	"PATCH /api/v1/admin/users/:id": {
		action: "user.update", objectType: "user", param: "id",
		skipHandledUserAdmin: true,
	},
	"POST /api/v1/admin/users/:id/reset-password": {
		action: "user.password_reset", objectType: "user", param: "id",
		skipHandledUserAdmin: true,
	},
}

// AuditActivityMiddleware records only the explicitly enumerated user actions.
// It runs after the route so authentication context and the final HTTP outcome
// are available, and it never reads request or response bodies.
func AuditActivityMiddleware(recorder AuditRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			recovered := recover()
			recordAuditedActivity(c, recorder, recovered != nil)
			if recovered != nil {
				panic(recovered)
			}
		}()
		c.Next()
	}
}

func recordAuditedActivity(
	c *gin.Context,
	recorder AuditRecorder,
	panicked bool,
) {
	route, ok := auditedRoutes[c.Request.Method+" "+c.FullPath()]
	if !ok {
		return
	}
	if route.enabled != nil && !route.enabled(c) {
		return
	}
	if route.skipHandledUserAdmin &&
		c.GetBool(userAdminAuditHandledKey) {
		return
	}
	if _, authenticated := CurrentSession(c); !authenticated {
		return
	}

	status := c.Writer.Status()
	outcome := audit.OutcomeSuccess
	switch {
	case panicked:
		status = http.StatusInternalServerError
		outcome = audit.OutcomeFailure
	case c.GetBool(sampleExportStreamFailedKey):
		outcome = audit.OutcomeFailure
	case c.GetBool(decompileSourceExportStreamFailedKey):
		outcome = audit.OutcomeFailure
	case status >= http.StatusInternalServerError:
		outcome = audit.OutcomeFailure
	case status >= http.StatusBadRequest:
		outcome = audit.OutcomeDenied
	}
	metadata := map[string]any{"http_status": status}
	if route.metadata != nil {
		for key, value := range route.metadata(c) {
			metadata[key] = value
		}
	}
	objectID := ""
	if route.param != "" || route.objectID != nil {
		rawObjectID := ""
		if route.objectID != nil {
			rawObjectID = route.objectID(c)
		} else {
			rawObjectID = c.Param(route.param)
		}
		if safeAuditObjectID(rawObjectID) {
			objectID = rawObjectID
		} else if rawObjectID != "" {
			metadata["object_id_omitted"] = true
		}
	}
	auditContext, cancel := context.WithTimeout(
		context.WithoutCancel(c.Request.Context()),
		requestAuditTimeout,
	)
	defer cancel()
	if err := RecordRequestAudit(
		auditContext,
		c,
		recorder,
		route.action,
		route.objectType,
		objectID,
		outcome,
		metadata,
	); err != nil {
		_ = c.Error(err).SetType(gin.ErrorTypePrivate)
	}
}

func markUserAdminAuditHandled(c *gin.Context) {
	c.Set(userAdminAuditHandledKey, true)
}

func safeAuditObjectID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return value == ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
