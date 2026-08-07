package task

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/auth"
)

const (
	DefaultSampleRetention = 15 * 24 * time.Hour
	maxTaskNameRunes       = 255
	maxKeywordRunes        = 255
	maxCreatorRunes        = 128
	maxTagRunes            = 64
	maxPageSize            = 100
	maxListCursorLength    = 256
)

var (
	uuidPattern               = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	inputTypePattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	listDatePattern           = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	retentionTimestampPattern = regexp.MustCompile(
		`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$`,
	)
	validStatuses = map[string]struct{}{
		"UPLOADING": {}, "QUEUED": {}, "VALIDATING": {}, "IDENTIFYING": {},
		"EXTRACTING": {}, "INDEXING": {}, "SCANNING": {}, "REPORTING": {},
		"SUCCEEDED": {}, "PARTIAL_SUCCEEDED": {}, "FAILED": {},
		"CANCEL_REQUESTED": {}, "CANCELLED": {}, "DELETING": {}, "DELETED": {},
	}
)

type Repository interface {
	Create(context.Context, CreateRecord) (View, bool, error)
	List(context.Context, ListQuery) (Page, error)
	Get(context.Context, string) (View, error)
	Cancel(context.Context, MutationRecord) (View, error)
	Retry(context.Context, RetryRecord) (View, error)
	Delete(context.Context, MutationRecord) (View, error)
	ExtendRetention(context.Context, RetentionRecord) (View, error)
}

type ServiceConfig struct {
	Limits          LimitsSnapshot
	SampleRetention time.Duration
	Now             func() time.Time
	NewID           func() (string, error)
}

type Service struct {
	repository Repository
	config     ServiceConfig
}

func NewService(repository Repository, config ServiceConfig) (*Service, error) {
	if repository == nil {
		return nil, errors.New("task repository is required")
	}
	if err := validateLimits(config.Limits); err != nil {
		return nil, err
	}
	if config.SampleRetention == 0 {
		config.SampleRetention = DefaultSampleRetention
	}
	if config.SampleRetention < 0 {
		return nil, errors.New("task sample retention must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{repository: repository, config: config}, nil
}

func (s *Service) Create(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	uploadID string,
	name string,
	idempotencyKey string,
) (View, bool, error) {
	if userID == 0 || (role != auth.RoleAdministrator && role != auth.RoleOperator) {
		return View{}, false, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if !uuidPattern.MatchString(uploadID) || !validTaskName(name) ||
		!validIdempotencyKey(idempotencyKey) {
		return View{}, false, ErrInvalidInput
	}

	taskID, err := s.config.NewID()
	if err != nil {
		return View{}, false, err
	}
	jobID, err := s.config.NewID()
	if err != nil {
		return View{}, false, err
	}
	if !uuidPattern.MatchString(taskID) || !uuidPattern.MatchString(jobID) {
		return View{}, false, errors.New("task ID generator returned an invalid UUID")
	}
	limits, err := json.Marshal(s.config.Limits)
	if err != nil {
		return View{}, false, err
	}
	now := s.config.Now().UTC()
	return s.repository.Create(ctx, CreateRecord{
		TaskID: taskID, JobID: jobID, UserID: userID,
		Administrator: role == auth.RoleAdministrator,
		UploadID:      uploadID, Name: name, IdempotencyKey: idempotencyKey,
		LimitsSnapshot: limits, SampleExpiresAt: now.Add(s.config.SampleRetention),
		CreatedAt: now,
	})
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	query.Keyword = strings.TrimSpace(query.Keyword)
	query.Status = strings.TrimSpace(query.Status)
	query.InputType = strings.TrimSpace(query.InputType)
	query.Creator = strings.TrimSpace(query.Creator)
	query.Tag = strings.TrimSpace(query.Tag)
	query.CreatedFrom = strings.TrimSpace(query.CreatedFrom)
	query.CreatedTo = strings.TrimSpace(query.CreatedTo)
	if query.PageSize < 1 || query.PageSize > maxPageSize || query.After != nil ||
		!validKeyword(query.Keyword) ||
		!validOptionalFilterText(query.Creator, maxCreatorRunes) ||
		!validOptionalFilterText(query.Tag, maxTagRunes) {
		return Page{}, ErrInvalidInput
	}
	if query.Status != "" {
		query.Status = strings.ToUpper(query.Status)
		if _, ok := validStatuses[query.Status]; !ok {
			return Page{}, ErrInvalidInput
		}
	}
	if query.InputType != "" {
		if !inputTypePattern.MatchString(query.InputType) {
			return Page{}, ErrInvalidInput
		}
		query.InputType = strings.ToLower(query.InputType)
	}
	createdFrom, valid := parseListDate(query.CreatedFrom)
	if !valid {
		return Page{}, ErrInvalidInput
	}
	createdTo, valid := parseListDate(query.CreatedTo)
	if !valid || (!createdFrom.IsZero() && !createdTo.IsZero() && createdFrom.After(createdTo)) {
		return Page{}, ErrInvalidInput
	}
	repositoryQuery := query
	if query.Cursor != "" {
		cursor, err := decodeListCursor(query.Cursor)
		if err != nil {
			return Page{}, ErrInvalidInput
		}
		repositoryQuery.After = &cursor
	}
	page, err := s.repository.List(ctx, repositoryQuery)
	if err != nil {
		return Page{}, err
	}
	if page.Items == nil {
		page.Items = []View{}
	}
	page.NextCursor = ""
	if page.HasMore {
		if len(page.Items) == 0 {
			return Page{}, errors.New("task repository returned an empty page with more results")
		}
		cursor, err := encodeListCursor(page.Items[len(page.Items)-1])
		if err != nil {
			return Page{}, err
		}
		page.NextCursor = cursor
	}
	return page, nil
}

type listCursorPayload struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func encodeListCursor(value View) (string, error) {
	if value.CreatedAt.IsZero() || !uuidPattern.MatchString(value.ID) {
		return "", errors.New("task list cursor fields are invalid")
	}
	payload := listCursorPayload{
		CreatedAt: value.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID:        value.ID,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeListCursor(encoded string) (ListCursor, error) {
	if encoded == "" || len(encoded) > maxListCursorLength {
		return ListCursor{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return ListCursor{}, ErrInvalidInput
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload listCursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return ListCursor{}, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ListCursor{}, ErrInvalidInput
	}

	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil ||
		payload.CreatedAt != createdAt.UTC().Format(time.RFC3339Nano) ||
		!uuidPattern.MatchString(payload.ID) {
		return ListCursor{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(canonical) != encoded {
		return ListCursor{}, ErrInvalidInput
	}
	return ListCursor{CreatedAt: createdAt.UTC(), ID: payload.ID}, nil
}

func (s *Service) Get(ctx context.Context, id string) (View, error) {
	if !uuidPattern.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	return s.repository.Get(ctx, id)
}

func (s *Service) Cancel(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	id string,
	idempotencyKey string,
) (View, error) {
	if !canOperateTask(userID, role) {
		return View{}, ErrForbidden
	}
	if !uuidPattern.MatchString(id) || !validIdempotencyKey(idempotencyKey) {
		return View{}, ErrInvalidInput
	}
	return s.repository.Cancel(ctx, MutationRecord{
		TaskID: id, UserID: userID, Administrator: role == auth.RoleAdministrator,
		IdempotencyKey:  lifecycleIdempotencyKey("cancel", idempotencyKey),
		SampleRetention: s.config.SampleRetention,
	})
}

func (s *Service) Retry(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	id string,
	idempotencyKey string,
) (View, error) {
	if !canOperateTask(userID, role) {
		return View{}, ErrForbidden
	}
	if !uuidPattern.MatchString(id) || !validIdempotencyKey(idempotencyKey) {
		return View{}, ErrInvalidInput
	}
	jobID, err := s.config.NewID()
	if err != nil {
		return View{}, err
	}
	if !uuidPattern.MatchString(jobID) {
		return View{}, errors.New("task ID generator returned an invalid UUID")
	}
	return s.repository.Retry(ctx, RetryRecord{
		MutationRecord: MutationRecord{
			TaskID: id, UserID: userID, Administrator: role == auth.RoleAdministrator,
			IdempotencyKey: lifecycleIdempotencyKey("retry", idempotencyKey),
		},
		JobID: jobID,
	})
}

func (s *Service) Delete(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	id string,
) (View, error) {
	if !canOperateTask(userID, role) {
		return View{}, ErrForbidden
	}
	if !uuidPattern.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	return s.repository.Delete(ctx, MutationRecord{
		TaskID: id, UserID: userID, Administrator: role == auth.RoleAdministrator,
	})
}

func (s *Service) ExtendRetention(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	id string,
	expectedSampleExpiresAt string,
	sampleExpiresAt string,
) (View, error) {
	if userID == 0 || role != auth.RoleAdministrator {
		return View{}, ErrForbidden
	}
	if !uuidPattern.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	expected, valid := parseRetentionTimestamp(expectedSampleExpiresAt)
	if !valid {
		return View{}, ErrInvalidInput
	}
	requested, valid := parseRetentionTimestamp(sampleExpiresAt)
	if !valid || !requested.Equal(expected.Add(DefaultSampleRetention)) {
		return View{}, ErrInvalidInput
	}
	return s.repository.ExtendRetention(ctx, RetentionRecord{
		TaskID:                  id,
		ExpectedSampleExpiresAt: expected,
		SampleExpiresAt:         requested,
	})
}

func canOperateTask(userID uint64, role auth.Role) bool {
	return userID != 0 && (role == auth.RoleAdministrator || role == auth.RoleOperator)
}

func lifecycleIdempotencyKey(operation string, value string) string {
	sum := sha256.Sum256([]byte(operation + "\x00" + value))
	return operation + "-" + hex.EncodeToString(sum[:])
}

func validateLimits(limits LimitsSnapshot) error {
	if limits.MaxUploadBytes <= 0 || limits.MaxUploadBytes > 2*1024*1024*1024 ||
		limits.MaxExpandedBytes <= 0 || limits.MaxExpandedBytes > 10*1024*1024*1024 ||
		limits.MaxArchiveRatio <= 0 || limits.MaxArchiveRatio > 50 ||
		limits.MaxDepth <= 0 || limits.MaxDepth > 6 ||
		limits.MaxFileNodes <= 0 || limits.MaxFileNodes > 20_000 ||
		limits.MaxNestedImages <= 0 || limits.MaxNestedImages > 3 {
		return errors.New("task limits are outside accepted bounds")
	}
	return nil
}

func validTaskName(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	if count == 0 || count > maxTaskNameRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validKeyword(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxKeywordRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOptionalFilterText(value string, maxRunes int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func parseListDate(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, true
	}
	if !listDatePattern.MatchString(value) {
		return time.Time{}, false
	}
	parsed, err := time.ParseInLocation("2006-01-02", value, time.UTC)
	return parsed, err == nil
}

func parseRetentionTimestamp(value string) (time.Time, bool) {
	if !retentionTimestampPattern.MatchString(value) {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" +
		encoded[16:20] + "-" + encoded[20:32], nil
}
