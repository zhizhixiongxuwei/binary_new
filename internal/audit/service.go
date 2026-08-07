package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxPageSize      = 100
	maxMetadataBytes = 16 * 1024
)

var (
	actionPattern         = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	uuidPattern           = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	forbiddenMetadataKeys = map[string]struct{}{
		"password": {}, "temporary_password": {}, "current_password": {},
		"new_password": {}, "token": {}, "access_token": {}, "refresh_token": {},
		"session": {}, "session_id": {}, "session_token": {}, "csrf": {},
		"csrf_token": {}, "password_hash": {}, "hash": {}, "secret": {},
		"client_ip": {}, "user_agent": {},
	}
)

type Service struct {
	repository Repository
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("audit repository is required")
	}
	return &Service{repository: repository}, nil
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	query.Action = strings.TrimSpace(query.Action)
	query.Outcome = strings.TrimSpace(query.Outcome)
	query.Actor = strings.TrimSpace(query.Actor)
	if query.PageSize < 1 || query.PageSize > MaxPageSize ||
		(query.Action != "" && !actionPattern.MatchString(query.Action)) ||
		!validText(query.Actor, 128) {
		return Page{}, ErrInvalidInput
	}
	cursor, err := decodeCursor("audit", query.Cursor)
	if err != nil {
		return Page{}, ErrInvalidInput
	}
	outcome := Outcome(query.Outcome)
	if outcome != "" && !outcome.Valid() {
		return Page{}, ErrInvalidInput
	}
	createdFrom, err := parseTimestamp(query.CreatedFrom)
	if err != nil {
		return Page{}, ErrInvalidInput
	}
	createdTo, err := parseTimestamp(query.CreatedTo)
	if err != nil || (createdFrom != nil && createdTo != nil && createdFrom.After(*createdTo)) {
		return Page{}, ErrInvalidInput
	}
	page, err := s.repository.List(ctx, RepositoryListQuery{
		Cursor: cursor, PageSize: query.PageSize, Action: query.Action,
		Outcome: outcome, Actor: query.Actor,
		CreatedFrom: createdFrom, CreatedTo: createdTo,
	})
	if err != nil {
		return Page{}, err
	}
	if page.Items == nil {
		page.Items = []Log{}
	}
	return page, nil
}

func normalizeEvent(event Event) (Event, []byte, error) {
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.Action = strings.TrimSpace(event.Action)
	event.ObjectType = strings.TrimSpace(event.ObjectType)
	event.ObjectID = strings.TrimSpace(event.ObjectID)
	event.UserAgent = strings.TrimSpace(event.UserAgent)
	if event.ActorUserID != nil && *event.ActorUserID == 0 ||
		!validASCII(event.RequestID, 128) ||
		!actionPattern.MatchString(event.Action) ||
		!validASCII(event.ObjectType, 64) ||
		!validText(event.ObjectID, 128) ||
		!event.Outcome.Valid() ||
		(len(event.ClientIP) != 0 && len(event.ClientIP) != 4 && len(event.ClientIP) != 16) ||
		!validText(event.UserAgent, 512) {
		return Event{}, nil, ErrInvalidInput
	}
	cleaned := sanitizeValue(event.Metadata, 0)
	metadata, err := jsonMarshal(cleaned)
	if err != nil || len(metadata) > maxMetadataBytes {
		return Event{}, nil, ErrInvalidInput
	}
	event.ClientIP = append([]byte(nil), event.ClientIP...)
	return event, metadata, nil
}

func sanitizeValue(value any, depth int) any {
	if depth > 4 {
		return "[redacted]"
	}
	switch typed := value.(type) {
	case nil, bool, float64, string:
		if text, ok := typed.(string); ok && len(text) > 1024 {
			return text[:1024]
		}
		return typed
	case float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return typed
	case map[string]any:
		result := make(map[string]any, min(len(typed), 64))
		count := 0
		for key, item := range typed {
			if count == 64 {
				result["truncated"] = true
				break
			}
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			if sensitiveMetadataKey(normalizedKey) || !validText(key, 128) {
				continue
			}
			result[key] = sanitizeValue(item, depth+1)
			count++
		}
		return result
	case []any:
		size := min(len(typed), 64)
		result := make([]any, size)
		for index := range size {
			result[index] = sanitizeValue(typed[index], depth+1)
		}
		return result
	default:
		return "[redacted]"
	}
}

func sensitiveMetadataKey(key string) bool {
	if _, forbidden := forbiddenMetadataKeys[key]; forbidden {
		return true
	}
	normalized := strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(key)
	return strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "token") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "authorization") ||
		strings.Contains(normalized, "cookie") ||
		normalized == "source_ip"
}

func parseTimestamp(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > len(time.RFC3339Nano)+6 {
		return nil, ErrInvalidInput
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil, err
	}
	value = value.UTC()
	return &value, nil
}

func encodeCursor(scope string, id uint64) string {
	raw := scope + ":" + strconv.FormatUint(id, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(scope, raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) > 64 {
		return 0, ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return 0, err
	}
	prefix := scope + ":"
	value := string(decoded)
	if !strings.HasPrefix(value, prefix) {
		return 0, ErrInvalidInput
	}
	idText := strings.TrimPrefix(value, prefix)
	if idText == "" || idText[0] == '0' {
		return 0, ErrInvalidInput
	}
	id, err := strconv.ParseUint(idText, 10, 64)
	if err != nil || id == 0 {
		return 0, ErrInvalidInput
	}
	if encodeCursor(scope, id) != raw {
		return 0, ErrInvalidInput
	}
	return id, nil
}

func validASCII(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validText(value string, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// IsPublicUUID is used by API consumers that accept actor filters.
func IsPublicUUID(value string) bool {
	return uuidPattern.MatchString(value)
}

func jsonMarshal(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode audit metadata: %w", err)
	}
	return data, nil
}
