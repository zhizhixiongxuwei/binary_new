package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAccessLogIncludesTaskAndCreatedJobIdentity(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	var output bytes.Buffer
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewJSONHandler(&output, nil))),
	)
	router.POST(
		"/api/v1/tasks/:id/files/:node_id/decompile",
		func(c *gin.Context) {
			c.Set(
				decompileAuditJobIDKey,
				"323e4567-e89b-42d3-a456-426614174002",
			)
			c.Status(http.StatusCreated)
		},
	)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tasks/123e4567-e89b-42d3-a456-426614174000/files/42/decompile",
		nil,
	)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d", response.Code)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["task_id"] != "123e4567-e89b-42d3-a456-426614174000" ||
		record["job_id"] != "323e4567-e89b-42d3-a456-426614174002" {
		t.Fatalf("log identity = %#v", record)
	}
}

func TestAccessLogDoesNotMislabelNonTaskRouteID(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	var output bytes.Buffer
	router := gin.New()
	router.Use(
		RequestIDMiddleware(),
		AccessLogMiddleware(slog.New(slog.NewJSONHandler(&output, nil))),
	)
	router.GET("/api/v1/admin/users/:id", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/users/123e4567-e89b-42d3-a456-426614174000",
		nil,
	)
	router.ServeHTTP(response, request)

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if _, exists := record["task_id"]; exists {
		t.Fatalf("non-task identifier was logged as a task: %#v", record)
	}
}
