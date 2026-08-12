package javaanalysis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/auth"
	"binaryscan/internal/report"
)

var (
	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cwePattern    = regexp.MustCompile(`^CWE-[1-9][0-9]{0,4}$`)
)

type CreateRecord struct {
	RunID           string
	JobID           string
	TaskID          string
	SourceProjectID string
	UserID          uint64
	RequestKey      string
}

type Repository interface {
	Create(context.Context, CreateRecord) (Run, bool, error)
	List(context.Context, ListQuery) (RunPage, error)
	Get(context.Context, RunQuery) (Run, error)
	ListFindings(context.Context, FindingsQuery) (FindingPage, error)
	Cancel(context.Context, ActionInput) (Run, error)
}

type RunDeleter interface {
	Delete(context.Context, string, string) error
}

type Config struct {
	NewID      func() (string, error)
	RunDeleter RunDeleter
}

type Service struct {
	repository Repository
	newID      func() (string, error)
	runDeleter RunDeleter
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil || config.RunDeleter == nil {
		return nil, errors.New("Java analysis repository and run deleter are required")
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{
		repository: repository, newID: config.NewID,
		runDeleter: config.RunDeleter,
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	input CreateInput,
) (Run, bool, error) {
	if ctx == nil {
		return Run{}, false, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Run{}, false, err
	}
	if !uuidPattern.MatchString(input.TaskID) ||
		!uuidPattern.MatchString(input.SourceProjectID) ||
		input.UserID == 0 || !operatorRole(input.Role) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return Run{}, false, ErrInvalidInput
	}
	runID, err := s.newID()
	if err != nil {
		return Run{}, false, fmt.Errorf("generate Java analysis run ID: %w", err)
	}
	jobID, err := s.newID()
	if err != nil {
		return Run{}, false, fmt.Errorf("generate Java analysis job ID: %w", err)
	}
	if !uuidPattern.MatchString(runID) || !uuidPattern.MatchString(jobID) ||
		runID == jobID {
		return Run{}, false, errors.New(
			"Java analysis ID generator returned invalid or duplicate UUIDs",
		)
	}
	digest := sha256.Sum256([]byte(input.IdempotencyKey))
	return s.repository.Create(ctx, CreateRecord{
		RunID: runID, JobID: jobID, TaskID: input.TaskID,
		SourceProjectID: input.SourceProjectID, UserID: input.UserID,
		RequestKey: "java_analysis:" + hex.EncodeToString(digest[:]),
	})
}

func (s *Service) List(ctx context.Context, query ListQuery) (RunPage, error) {
	if err := validateContext(ctx); err != nil {
		return RunPage{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) ||
		(query.SourceProjectID != "" &&
			!uuidPattern.MatchString(query.SourceProjectID)) ||
		query.PageSize < 1 || query.PageSize > MaxPageSize ||
		(query.After != nil &&
			(!uuidPattern.MatchString(query.After.ID) ||
				query.After.CreatedAt.IsZero())) {
		return RunPage{}, ErrInvalidInput
	}
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return RunPage{}, err
	}
	if page.Items == nil {
		page.Items = []Run{}
	}
	if page.HasMore {
		if len(page.Items) == 0 {
			return RunPage{}, errors.New(
				"Java analysis repository returned an empty page with more results",
			)
		}
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = EncodeRunCursor(RunCursor{
			CreatedAt: last.CreatedAt, ID: last.ID,
		})
		if err != nil {
			return RunPage{}, fmt.Errorf("encode Java analysis cursor: %w", err)
		}
	}
	return page, nil
}

func (s *Service) Get(ctx context.Context, query RunQuery) (Run, error) {
	if err := validateContext(ctx); err != nil {
		return Run{}, err
	}
	if !validRunQuery(query) {
		return Run{}, ErrInvalidInput
	}
	return s.repository.Get(ctx, query)
}

func (s *Service) ListFindings(
	ctx context.Context,
	query FindingsQuery,
) (FindingPage, error) {
	if err := validateContext(ctx); err != nil {
		return FindingPage{}, err
	}
	query.CWE = strings.ToUpper(strings.TrimSpace(query.CWE))
	query.Severity = strings.ToUpper(strings.TrimSpace(query.Severity))
	query.File = strings.TrimSpace(query.File)
	query.Callable = strings.TrimSpace(query.Callable)
	if !validRunQuery(RunQuery{TaskID: query.TaskID, RunID: query.RunID}) ||
		query.PageSize < 1 || query.PageSize > MaxPageSize ||
		(query.CWE != "" && !cwePattern.MatchString(query.CWE)) ||
		(query.Severity != "" && !validSeverity(query.Severity)) ||
		!validFindingFilter(query.File) || !validFindingFilter(query.Callable) {
		return FindingPage{}, ErrInvalidInput
	}
	page, err := s.repository.ListFindings(ctx, query)
	if err != nil {
		return FindingPage{}, err
	}
	if page.Items == nil {
		page.Items = []Finding{}
	}
	return page, nil
}

func (s *Service) Cancel(ctx context.Context, input ActionInput) (Run, error) {
	if err := validateAction(ctx, input); err != nil {
		return Run{}, err
	}
	return s.repository.Cancel(ctx, input)
}

func (s *Service) Delete(ctx context.Context, input ActionInput) error {
	if err := validateAction(ctx, input); err != nil {
		return err
	}
	err := s.runDeleter.Delete(ctx, input.TaskID, input.RunID)
	switch {
	case errors.Is(err, report.ErrJavaAnalysisRunNotFound):
		return ErrRunNotFound
	case errors.Is(err, report.ErrJavaAnalysisRunNotTerminal):
		return ErrRunNotDeletable
	default:
		return err
	}
}

func EncodeRunCursor(cursor RunCursor) (string, error) {
	if cursor.CreatedAt.IsZero() || !uuidPattern.MatchString(cursor.ID) {
		return "", ErrInvalidInput
	}
	raw, err := json.Marshal(struct {
		CreatedAt time.Time `json:"created_at"`
		ID        string    `json:"id"`
	}{cursor.CreatedAt.UTC(), cursor.ID})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeRunCursor(value string) (RunCursor, error) {
	if len(value) == 0 || len(value) > 512 {
		return RunCursor{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > 256 {
		return RunCursor{}, ErrInvalidInput
	}
	var document struct {
		CreatedAt time.Time `json:"created_at"`
		ID        string    `json:"id"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || requireJSONEnd(decoder) != nil ||
		document.CreatedAt.IsZero() || !uuidPattern.MatchString(document.ID) {
		return RunCursor{}, ErrInvalidInput
	}
	return RunCursor{CreatedAt: document.CreatedAt.UTC(), ID: document.ID}, nil
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validRunQuery(query RunQuery) bool {
	return uuidPattern.MatchString(query.TaskID) &&
		uuidPattern.MatchString(query.RunID)
}

func validateAction(ctx context.Context, input ActionInput) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if !validRunQuery(RunQuery{TaskID: input.TaskID, RunID: input.RunID}) ||
		input.UserID == 0 || !operatorRole(input.Role) {
		return ErrInvalidInput
	}
	return nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInput
	}
	return ctx.Err()
}

func operatorRole(role auth.Role) bool {
	return role == auth.RoleAdministrator || role == auth.RoleOperator
}

func validSeverity(value string) bool {
	switch value {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func validFindingFilter(value string) bool {
	if len(value) > 512 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	), nil
}
