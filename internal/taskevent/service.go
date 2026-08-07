package taskevent

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	eventTypePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type Repository interface {
	List(context.Context, Query) ([]Event, error)
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("task event repository is required")
	}
	return &Service{repository: repository}, nil
}

func (s *Service) List(
	ctx context.Context,
	taskID string,
	afterSequence uint64,
	limit int,
) ([]Event, error) {
	if !uuidPattern.MatchString(taskID) || limit < 1 || limit > MaxBatchSize {
		return nil, ErrInvalidInput
	}
	events, err := s.repository.List(ctx, Query{
		TaskID: taskID, AfterSequence: afterSequence, Limit: limit,
	})
	if err != nil {
		return nil, err
	}
	if events == nil {
		return []Event{}, nil
	}

	previous := afterSequence
	for index := range events {
		event := &events[index]
		if event.Sequence <= previous ||
			!eventTypePattern.MatchString(event.Type) ||
			!validSeverity(event.Severity) ||
			!validOptionalText(event.Stage, 32) ||
			!validOptionalText(event.Message, 2048) ||
			event.CreatedAt.IsZero() {
			return nil, errors.New("stored task event violates the event contract")
		}
		if event.Progress != nil &&
			(*event.Progress < 0 || *event.Progress > 100) {
			return nil, errors.New("stored task event progress is outside accepted bounds")
		}
		if len(event.Payload) == 0 {
			event.Payload = json.RawMessage("null")
		}
		if !json.Valid(event.Payload) {
			return nil, errors.New("stored task event payload is not valid JSON")
		}
		event.Payload = append(json.RawMessage(nil), event.Payload...)
		event.CreatedAt = event.CreatedAt.UTC()
		previous = event.Sequence
	}
	return events, nil
}

func validSeverity(value string) bool {
	switch value {
	case "debug", "info", "warning", "error":
		return true
	default:
		return false
	}
}

func validOptionalText(value *string, maxRunes int) bool {
	if value == nil {
		return true
	}
	if !utf8.ValidString(*value) ||
		utf8.RuneCountInString(*value) > maxRunes {
		return false
	}
	for _, character := range *value {
		if unicode.IsControl(character) && !strings.ContainsRune("\t", character) {
			return false
		}
	}
	return true
}
