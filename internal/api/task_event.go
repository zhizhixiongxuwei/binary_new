package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"binaryscan/internal/taskevent"

	"github.com/gin-gonic/gin"
)

const (
	defaultTaskEventPollInterval      = time.Second
	defaultTaskEventHeartbeatInterval = 15 * time.Second
	defaultTaskEventRetryInterval     = 3 * time.Second
)

type TaskEventService interface {
	List(context.Context, string, uint64, int) ([]taskevent.Event, error)
}

type TaskEventHTTPConfig struct {
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	RetryInterval     time.Duration
	BatchSize         int
}

func registerTaskEventRoutes(
	v1 *gin.RouterGroup,
	manager AuthManager,
	service TaskEventService,
	config TaskEventHTTPConfig,
) {
	routes := v1.Group("/tasks")
	routes.Use(RequireSession(manager))
	routes.GET("/:id/events", taskEventStreamHandler(service, config))
}

func taskEventStreamHandler(
	service TaskEventService,
	config TaskEventHTTPConfig,
) gin.HandlerFunc {
	config = normalizeTaskEventHTTPConfig(config)
	return func(c *gin.Context) {
		if len(c.Request.URL.Query()) != 0 {
			writeTaskEventInvalid(c)
			return
		}
		afterSequence, err := parseLastEventID(c.GetHeader("Last-Event-ID"))
		if err != nil {
			writeTaskEventInvalid(c)
			return
		}

		events, err := service.List(
			c.Request.Context(),
			c.Param("id"),
			afterSequence,
			config.BatchSize,
		)
		if err != nil {
			writeTaskEventError(c, err)
			return
		}

		c.Header("Content-Type", "text/event-stream; charset=utf-8")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")
		c.Status(http.StatusOK)
		c.Writer.WriteHeaderNow()
		if _, err := fmt.Fprintf(
			c.Writer,
			"retry: %d\n\n",
			config.RetryInterval.Milliseconds(),
		); err != nil {
			return
		}
		c.Writer.Flush()

		lastSequence := afterSequence
		pollTimer := time.NewTimer(config.PollInterval)
		defer pollTimer.Stop()
		heartbeatTimer := time.NewTimer(config.HeartbeatInterval)
		defer heartbeatTimer.Stop()

		for {
			for len(events) != 0 {
				for _, event := range events {
					if err := writeTaskEvent(c, event); err != nil {
						return
					}
					lastSequence = event.Sequence
				}
				c.Writer.Flush()
				if len(events) < config.BatchSize {
					events = nil
					break
				}
				events, err = service.List(
					c.Request.Context(),
					c.Param("id"),
					lastSequence,
					config.BatchSize,
				)
				if err != nil {
					c.Error(err).SetType(gin.ErrorTypePrivate)
					return
				}
			}

			select {
			case <-c.Request.Context().Done():
				return
			case <-heartbeatTimer.C:
				if _, err := c.Writer.WriteString(": heartbeat\n\n"); err != nil {
					return
				}
				c.Writer.Flush()
				heartbeatTimer.Reset(config.HeartbeatInterval)
			case <-pollTimer.C:
				events, err = service.List(
					c.Request.Context(),
					c.Param("id"),
					lastSequence,
					config.BatchSize,
				)
				if err != nil {
					c.Error(err).SetType(gin.ErrorTypePrivate)
					return
				}
				pollTimer.Reset(config.PollInterval)
			}
		}
	}
}

func normalizeTaskEventHTTPConfig(config TaskEventHTTPConfig) TaskEventHTTPConfig {
	if config.PollInterval <= 0 {
		config.PollInterval = defaultTaskEventPollInterval
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = defaultTaskEventHeartbeatInterval
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = defaultTaskEventRetryInterval
	}
	if config.BatchSize < 1 || config.BatchSize > taskevent.MaxBatchSize {
		config.BatchSize = taskevent.DefaultBatchSize
	}
	return config
}

func parseLastEventID(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	if !decimalDigits(raw) || (len(raw) > 1 && raw[0] == '0') {
		return 0, taskevent.ErrInvalidInput
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, taskevent.ErrInvalidInput
	}
	return value, nil
}

func writeTaskEvent(c *gin.Context, event taskevent.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode task event: %w", err)
	}
	if _, err := fmt.Fprintf(
		c.Writer,
		"id: %d\nevent: %s\ndata: %s\n\n",
		event.Sequence,
		event.Type,
		data,
	); err != nil {
		return fmt.Errorf("write task event: %w", err)
	}
	return nil
}

func writeTaskEventInvalid(c *gin.Context) {
	WriteError(
		c,
		http.StatusBadRequest,
		"invalid_task_event_request",
		"The task event stream request is invalid.",
		nil,
	)
}

func writeTaskEventError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, taskevent.ErrInvalidInput):
		writeTaskEventInvalid(c)
	case errors.Is(err, taskevent.ErrNotFound):
		WriteError(
			c,
			http.StatusNotFound,
			"task_event_stream_not_found",
			"The task event stream was not found.",
			nil,
		)
	default:
		c.Error(err).SetType(gin.ErrorTypePrivate)
		WriteError(
			c,
			http.StatusInternalServerError,
			"task_event_stream_failed",
			"The task event stream could not be opened.",
			nil,
		)
	}
}
