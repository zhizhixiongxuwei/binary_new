package taskevent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const testTaskID = "123e4567-e89b-42d3-a456-426614174000"

type repositoryStub struct {
	query  Query
	events []Event
	err    error
	calls  int
}

func (s *repositoryStub) List(
	_ context.Context,
	query Query,
) ([]Event, error) {
	s.calls++
	s.query = query
	return s.events, s.err
}

func TestServiceValidatesQueryAndForwardsResumePosition(t *testing.T) {
	repository := &repositoryStub{}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	events, err := service.List(context.Background(), testTaskID, 41, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || repository.calls != 1 ||
		repository.query.TaskID != testTaskID ||
		repository.query.AfterSequence != 41 ||
		repository.query.Limit != 25 {
		t.Fatalf("query/events = %#v/%#v", repository.query, events)
	}

	for _, test := range []struct {
		name   string
		taskID string
		limit  int
	}{
		{name: "malformed uuid", taskID: "not-a-uuid", limit: 1},
		{
			name:   "non v4 uuid",
			taskID: "123e4567-e89b-12d3-a456-426614174000",
			limit:  1,
		},
		{name: "zero limit", taskID: testTaskID, limit: 0},
		{
			name: "oversized limit", taskID: testTaskID,
			limit: MaxBatchSize + 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository.calls = 0
			_, err := service.List(
				context.Background(),
				test.taskID,
				0,
				test.limit,
			)
			if !errors.Is(err, ErrInvalidInput) || repository.calls != 0 {
				t.Fatalf("error/calls = %v/%d", err, repository.calls)
			}
		})
	}
}

func TestServiceNormalizesAndValidatesStoredEvents(t *testing.T) {
	stage := "SCANNING"
	progress := 42.5
	message := "Task progress changed."
	createdAt := time.Date(2026, 7, 30, 8, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	repository := &repositoryStub{events: []Event{{
		Sequence:  12,
		Type:      "task.progress",
		Stage:     &stage,
		Progress:  &progress,
		Severity:  "info",
		Message:   &message,
		Payload:   json.RawMessage(`{"status":"SCANNING"}`),
		CreatedAt: createdAt,
	}}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	events, err := service.List(context.Background(), testTaskID, 11, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].CreatedAt.Location() != time.UTC ||
		string(events[0].Payload) != `{"status":"SCANNING"}` {
		t.Fatalf("events = %#v", events)
	}

	repository.events[0].Payload = nil
	events, err = service.List(context.Background(), testTaskID, 11, 10)
	if err != nil || string(events[0].Payload) != "null" {
		t.Fatalf("nil payload = %q, %v", events[0].Payload, err)
	}
}

func TestServiceRejectsBrokenStoredEventContracts(t *testing.T) {
	now := time.Now().UTC()
	valid := Event{
		Sequence: 2, Type: "task.progress", Severity: "info",
		Payload: json.RawMessage(`{}`), CreatedAt: now,
	}
	tests := []struct {
		name   string
		events []Event
	}{
		{name: "non increasing", events: []Event{valid, valid}},
		{
			name: "event type injection",
			events: []Event{func() Event {
				value := valid
				value.Type = "task.progress\ndata: injected"
				return value
			}()},
		},
		{
			name: "invalid severity",
			events: []Event{func() Event {
				value := valid
				value.Severity = "critical"
				return value
			}()},
		},
		{
			name: "invalid json",
			events: []Event{func() Event {
				value := valid
				value.Payload = json.RawMessage(`{`)
				return value
			}()},
		},
		{
			name: "zero timestamp",
			events: []Event{func() Event {
				value := valid
				value.CreatedAt = time.Time{}
				return value
			}()},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(&repositoryStub{events: test.events})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.List(
				context.Background(), testTaskID, 1, 10,
			); err == nil {
				t.Fatal("List() error = nil, want stored contract error")
			}
		})
	}
}

func TestNewServiceRequiresRepository(t *testing.T) {
	if _, err := NewService(nil); err == nil {
		t.Fatal("NewService(nil) error = nil")
	}
}
