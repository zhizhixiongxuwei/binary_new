package useradmin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
)

const MaxPageSize = 100

var (
	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	publicIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
)

type Repository interface {
	List(context.Context, RepositoryListQuery) (Page, error)
	Create(context.Context, CreateRecord) (User, error)
	Update(context.Context, UpdateRecord) (User, error)
	ResetPassword(context.Context, ResetPasswordRecord) (User, error)
}

type ServiceConfig struct {
	PasswordParameters   auth.PasswordParameters
	MinimumPasswordBytes int
	Now                  func() time.Time
	NewID                func() (string, error)
}

type Service struct {
	repository Repository
	audit      audit.Recorder
	config     ServiceConfig
}

func NewService(
	repository Repository,
	auditRecorder audit.Recorder,
	config ServiceConfig,
) (*Service, error) {
	if repository == nil {
		return nil, errors.New("user administration repository is required")
	}
	if auditRecorder == nil {
		return nil, errors.New("user administration audit recorder is required")
	}
	if err := config.PasswordParameters.Validate(); err != nil {
		return nil, err
	}
	if config.MinimumPasswordBytes == 0 {
		config.MinimumPasswordBytes = auth.DefaultMinimumPasswordBytes
	}
	if err := auth.ValidatePasswordMinimum(config.MinimumPasswordBytes); err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{repository: repository, audit: auditRecorder, config: config}, nil
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	query.Keyword = strings.TrimSpace(query.Keyword)
	query.Role = strings.TrimSpace(query.Role)
	query.Status = strings.TrimSpace(query.Status)
	if query.PageSize < 1 || query.PageSize > MaxPageSize ||
		!validText(query.Keyword, 128) {
		return Page{}, ErrInvalidInput
	}
	cursor, err := decodeCursor(query.Cursor)
	if err != nil {
		return Page{}, ErrInvalidInput
	}
	role := auth.Role(query.Role)
	if role != "" && !role.Valid() {
		return Page{}, ErrInvalidInput
	}
	if query.Status != "" && query.Status != "active" &&
		query.Status != "disabled" && query.Status != "locked" {
		return Page{}, ErrInvalidInput
	}
	page, err := s.repository.List(ctx, RepositoryListQuery{
		Cursor: cursor, PageSize: query.PageSize, Keyword: query.Keyword,
		Role: role, Status: query.Status,
	})
	if err != nil {
		return Page{}, err
	}
	if page.Items == nil {
		page.Items = []User{}
	}
	return page, nil
}

func (s *Service) Create(
	ctx context.Context,
	auditContext AuditContext,
	username string,
	displayName string,
	role auth.Role,
	temporaryPassword []byte,
) (User, error) {
	defer zeroBytes(temporaryPassword)
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	baseMetadata := map[string]any{"requested_role": string(role)}
	if !validAuditContext(auditContext) || !usernamePattern.MatchString(username) ||
		!validRequiredText(displayName, 128) || !role.Valid() {
		err := ErrInvalidInput
		s.recordRejected(ctx, auditContext, "user.create", "", err, baseMetadata)
		return User{}, err
	}
	passwordHash, err := auth.HashPasswordWithMinimum(
		temporaryPassword,
		s.config.PasswordParameters,
		s.config.MinimumPasswordBytes,
	)
	if err != nil {
		s.recordRejected(ctx, auditContext, "user.create", "", ErrInvalidInput, baseMetadata)
		return User{}, ErrInvalidInput
	}
	publicID, err := s.config.NewID()
	if err != nil {
		s.recordFailure(ctx, auditContext, "user.create", "", err, baseMetadata)
		return User{}, err
	}
	if !publicIDPattern.MatchString(publicID) {
		err = errors.New("user ID generator returned an invalid UUID")
		s.recordFailure(ctx, auditContext, "user.create", "", err, baseMetadata)
		return User{}, err
	}
	now := s.config.Now().UTC()
	event := auditContext.Event(
		"user.create", publicID, audit.OutcomeSuccess,
		map[string]any{"role": string(role), "status": "active"},
	)
	user, err := s.repository.Create(ctx, CreateRecord{
		PublicID: publicID, Username: username, DisplayName: displayName,
		PasswordHash: passwordHash, Role: role, CreatedAt: now, Audit: event,
	})
	if err != nil {
		s.recordRepositoryError(ctx, auditContext, "user.create", publicID, err, baseMetadata)
		return User{}, err
	}
	return user, nil
}

func (s *Service) Update(
	ctx context.Context,
	auditContext AuditContext,
	publicID string,
	role *auth.Role,
	status *string,
	expectedUpdatedAt string,
) (User, error) {
	publicID = strings.TrimSpace(publicID)
	metadata := map[string]any{}
	if role != nil {
		metadata["requested_role"] = string(*role)
	}
	if status != nil {
		metadata["requested_status"] = *status
	}
	expected, err := parseExpectedTimestamp(expectedUpdatedAt)
	if !validAuditContext(auditContext) || !publicIDPattern.MatchString(publicID) ||
		(role == nil && status == nil) ||
		(role != nil && !role.Valid()) ||
		(status != nil && *status != "active" && *status != "disabled") ||
		err != nil {
		s.recordRejected(ctx, auditContext, "user.update", publicID, ErrInvalidInput, metadata)
		return User{}, ErrInvalidInput
	}
	event := auditContext.Event("user.update", publicID, audit.OutcomeSuccess, metadata)
	user, err := s.repository.Update(ctx, UpdateRecord{
		ActorUserID: auditContext.ActorUserID, PublicID: publicID,
		Role: role, Status: status, ExpectedUpdatedAt: expected,
		UpdatedAt: s.config.Now().UTC(), Audit: event,
	})
	if err != nil {
		s.recordRepositoryError(ctx, auditContext, "user.update", publicID, err, metadata)
		return User{}, err
	}
	return user, nil
}

func (s *Service) ResetPassword(
	ctx context.Context,
	auditContext AuditContext,
	publicID string,
	temporaryPassword []byte,
	expectedUpdatedAt string,
) (User, error) {
	defer zeroBytes(temporaryPassword)
	publicID = strings.TrimSpace(publicID)
	expected, err := parseExpectedTimestamp(expectedUpdatedAt)
	if !validAuditContext(auditContext) || !publicIDPattern.MatchString(publicID) || err != nil {
		s.recordRejected(ctx, auditContext, "user.password_reset", publicID, ErrInvalidInput, nil)
		return User{}, ErrInvalidInput
	}
	passwordHash, err := auth.HashPasswordWithMinimum(
		temporaryPassword,
		s.config.PasswordParameters,
		s.config.MinimumPasswordBytes,
	)
	if err != nil {
		s.recordRejected(ctx, auditContext, "user.password_reset", publicID, ErrInvalidInput, nil)
		return User{}, ErrInvalidInput
	}
	event := auditContext.Event(
		"user.password_reset", publicID, audit.OutcomeSuccess,
		map[string]any{"sessions_revoked": true, "must_change_password": true},
	)
	user, err := s.repository.ResetPassword(ctx, ResetPasswordRecord{
		PublicID: publicID, PasswordHash: passwordHash,
		ExpectedUpdatedAt: expected, UpdatedAt: s.config.Now().UTC(), Audit: event,
	})
	if err != nil {
		s.recordRepositoryError(
			ctx, auditContext, "user.password_reset", publicID, err, nil,
		)
		return User{}, err
	}
	return user, nil
}

func (s *Service) recordRepositoryError(
	ctx context.Context,
	auditContext AuditContext,
	action string,
	objectID string,
	err error,
	metadata map[string]any,
) {
	if action == "user.create" && errors.Is(err, ErrUsernameExists) {
		objectID = ""
	}
	if isDeniedError(err) {
		s.recordRejected(ctx, auditContext, action, objectID, err, metadata)
		return
	}
	s.recordFailure(ctx, auditContext, action, objectID, err, metadata)
}

func (s *Service) recordRejected(
	ctx context.Context,
	auditContext AuditContext,
	action string,
	objectID string,
	reason error,
	metadata map[string]any,
) {
	if !validAuditContext(auditContext) {
		return
	}
	values := cloneMetadata(metadata)
	values["reason"] = publicReason(reason)
	s.recordBestEffort(
		ctx,
		auditContext.Event(action, safeAuditObjectID(objectID), audit.OutcomeDenied, values),
	)
}

func (s *Service) recordFailure(
	ctx context.Context,
	auditContext AuditContext,
	action string,
	objectID string,
	_ error,
	metadata map[string]any,
) {
	if !validAuditContext(auditContext) {
		return
	}
	values := cloneMetadata(metadata)
	values["reason"] = "internal_error"
	s.recordBestEffort(
		ctx,
		auditContext.Event(action, safeAuditObjectID(objectID), audit.OutcomeFailure, values),
	)
}

// Successful mutations append in the repository transaction. Rejected and
// failed operations have no state transaction to share, so they use an
// independent bounded best-effort append and never mask the original result.
func (s *Service) recordBestEffort(ctx context.Context, event audit.Event) {
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_ = s.audit.Record(auditContext, event)
}

func isDeniedError(err error) bool {
	return errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrUsernameExists) || errors.Is(err, ErrCurrentUserGuard) ||
		errors.Is(err, ErrLastAdministrator)
}

func publicReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return "invalid_request"
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrCurrentUserGuard):
		return "self_protection"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrUsernameExists):
		return "username_exists"
	case errors.Is(err, ErrLastAdministrator):
		return "last_active_administrator"
	default:
		return "conflict"
	}
}

func cloneMetadata(source map[string]any) map[string]any {
	result := make(map[string]any, len(source)+1)
	for key, value := range source {
		result[key] = value
	}
	return result
}

func safeAuditObjectID(value string) string {
	if publicIDPattern.MatchString(value) {
		return value
	}
	return ""
}

func validAuditContext(value AuditContext) bool {
	return value.ActorUserID != 0 && len(value.RequestID) <= 128 &&
		(len(value.ClientIP) == 0 || len(value.ClientIP) == 4 || len(value.ClientIP) == 16) &&
		validText(value.UserAgent, 512)
}

func parseExpectedTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 40 {
		return time.Time{}, ErrInvalidInput
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, ErrInvalidInput
	}
	return value.UTC(), nil
}

func validRequiredText(value string, maximum int) bool {
	return value != "" && validText(value, maximum)
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

func encodeCursor(id uint64) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte("user:" + strconv.FormatUint(id, 10)),
	)
}

func decodeCursor(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) > 64 {
		return 0, ErrInvalidInput
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil {
		return 0, ErrInvalidInput
	}
	value := string(decoded)
	if !strings.HasPrefix(value, "user:") {
		return 0, ErrInvalidInput
	}
	number := strings.TrimPrefix(value, "user:")
	if number == "" || number[0] == '0' {
		return 0, ErrInvalidInput
	}
	id, err := strconv.ParseUint(number, 10, 64)
	if err != nil || id == 0 || encodeCursor(id) != raw {
		return 0, ErrInvalidInput
	}
	return id, nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate user UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
