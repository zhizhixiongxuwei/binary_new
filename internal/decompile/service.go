package decompile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"binaryscan/internal/auth"
)

const (
	maxListCursorLength = 256
	maxOptionsBytes     = 8 << 10
)

var defaultJobLimits = JobLimits{
	MaxDurationSeconds:     20 * 60,
	MaxOutputBytes:         128 << 20,
	MaxArtifacts:           3_000,
	MaxStandardOutputBytes: 4 << 20,
}

var (
	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Repository interface {
	Enqueue(context.Context, CreateRecord) (Request, bool, error)
	GetRequest(context.Context, RequestQuery) (Request, error)
	List(context.Context, ListQuery) (Page, error)
	GetSource(context.Context, SourceQuery) (SourceDescriptor, error)
}

type Config struct {
	RepositoryRoot string
	JobLimits      JobLimits
	NewID          func() (string, error)
}

type Service struct {
	repository     Repository
	repositoryRoot string
	jobLimits      JobLimits
	newID          func() (string, error)
	now            func() time.Time
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("decompile repository is required")
	}
	root := filepath.Clean(config.RepositoryRoot)
	if !filepath.IsAbs(root) || root == string(filepath.Separator) {
		return nil, errors.New(
			"decompile repository root must be an absolute non-root path",
		)
	}
	if config.JobLimits == (JobLimits{}) {
		config.JobLimits = defaultJobLimits
	}
	if !validJobLimits(config.JobLimits) {
		return nil, errors.New("decompile job limits are invalid")
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{
		repository: repository, repositoryRoot: root,
		jobLimits: config.JobLimits, newID: config.NewID, now: time.Now,
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	input CreateInput,
) (Request, bool, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, false, err
	}
	if !uuidPattern.MatchString(input.TaskID) ||
		input.FileNodeID == 0 ||
		input.UserID == 0 ||
		(input.Role != auth.RoleAdministrator &&
			input.Role != auth.RoleOperator) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return Request{}, false, ErrInvalidInput
	}
	if input.EngineTarget == "" {
		input.EngineTarget = EngineAuto
	}
	if !validEngineTarget(input.EngineTarget) {
		return Request{}, false, ErrInvalidInput
	}
	options, err := canonicalOptions(input.Options)
	if err != nil {
		return Request{}, false, ErrInvalidInput
	}
	jobID, err := s.newID()
	if err != nil {
		return Request{}, false, fmt.Errorf("generate decompile job ID: %w", err)
	}
	requestID, err := s.newID()
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"generate decompile request ID: %w",
			err,
		)
	}
	if !uuidPattern.MatchString(jobID) ||
		!uuidPattern.MatchString(requestID) ||
		jobID == requestID {
		return Request{}, false, errors.New(
			"decompile ID generator returned invalid or duplicate UUIDs",
		)
	}
	keyHash := sha256.Sum256([]byte(input.IdempotencyKey))
	return s.repository.Enqueue(ctx, CreateRecord{
		JobID: jobID, RequestID: requestID,
		TaskID: input.TaskID, FileNodeID: input.FileNodeID,
		UserID: input.UserID, EngineTarget: input.EngineTarget,
		Options: options, Limits: s.jobLimits,
		JobRequestKey: "decompile:" + hex.EncodeToString(keyHash[:]),
	})
}

func (s *Service) GetRequest(
	ctx context.Context,
	query RequestQuery,
) (Request, error) {
	if err := ctx.Err(); err != nil {
		return Request{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) ||
		!uuidPattern.MatchString(query.JobID) {
		return Request{}, ErrInvalidInput
	}
	return s.repository.GetRequest(ctx, query)
}

func validJobLimits(value JobLimits) bool {
	return value.MaxDurationSeconds > 0 &&
		value.MaxDurationSeconds <= int64((20*time.Minute)/time.Second) &&
		value.MaxOutputBytes > 0 &&
		value.MaxOutputBytes <= 128<<20 &&
		value.MaxArtifacts > 0 &&
		value.MaxArtifacts <= 3_000 &&
		value.MaxStandardOutputBytes > 0 &&
		value.MaxStandardOutputBytes <= value.MaxOutputBytes
}

func validEngineTarget(value string) bool {
	switch value {
	case EngineAuto, EngineGhidra, EngineVineflower, EngineJADX,
		EnginePythonBytecode:
		return true
	default:
		return false
	}
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func canonicalOptions(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if len(raw) > maxOptionsBytes || raw[0] != '{' {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > maxOptionsBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) ||
		query.PageSize < 1 || query.PageSize > MaxPageSize ||
		query.After != nil {
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
	if err := ctx.Err(); err != nil {
		return Page{}, err
	}
	if page.Items == nil {
		page.Items = []Result{}
	}
	page.NextCursor = ""
	if page.HasMore {
		if len(page.Items) == 0 {
			return Page{}, errors.New(
				"decompile repository returned an empty page with more results",
			)
		}
		cursor, err := encodeListCursor(page.Items[len(page.Items)-1])
		if err != nil {
			return Page{}, fmt.Errorf("encode decompile result cursor: %w", err)
		}
		page.NextCursor = cursor
	}
	return page, nil
}

type listCursorPayload struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func encodeListCursor(result Result) (string, error) {
	if result.CreatedAt.IsZero() || !uuidPattern.MatchString(result.ID) {
		return "", errors.New("decompile result cursor fields are invalid")
	}
	payload := listCursorPayload{
		CreatedAt: result.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID:        result.ID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeListCursor(encoded string) (ListCursor, error) {
	if encoded == "" || len(encoded) > maxListCursorLength {
		return ListCursor{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil ||
		base64.RawURLEncoding.EncodeToString(raw) != encoded {
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
	if err != nil ||
		base64.RawURLEncoding.EncodeToString(canonical) != encoded {
		return ListCursor{}, ErrInvalidInput
	}
	return ListCursor{CreatedAt: createdAt.UTC(), ID: payload.ID}, nil
}

func (s *Service) Source(
	ctx context.Context,
	query SourceQuery,
) (SourceChunk, error) {
	if err := ctx.Err(); err != nil {
		return SourceChunk{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) ||
		!uuidPattern.MatchString(query.ResultID) ||
		query.Limit < 1 || query.Limit > MaxSourceLimit ||
		query.Offset > math.MaxInt64 {
		return SourceChunk{}, ErrInvalidInput
	}

	descriptor, err := s.repository.GetSource(ctx, query)
	if err != nil {
		return SourceChunk{}, err
	}
	if err := ctx.Err(); err != nil {
		return SourceChunk{}, err
	}
	if err := validateSourceDescriptor(descriptor, query); err != nil {
		return SourceChunk{}, err
	}

	file, info, err := openRepositoryFile(
		ctx, s.repositoryRoot, descriptor.StorageKey,
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return SourceChunk{}, contextErr
		}
		return SourceChunk{}, fmt.Errorf("%w: %v", ErrSourceUnavailable, err)
	}
	defer file.Close()
	if uint64(info.Size()) != descriptor.SizeBytes {
		return SourceChunk{}, fmt.Errorf(
			"%w: stored size does not match metadata",
			ErrSourceUnavailable,
		)
	}
	if query.Offset > descriptor.SizeBytes {
		return SourceChunk{}, ErrInvalidInput
	}
	if err := verifySourceSHA256(ctx, file, descriptor.SHA256); err != nil {
		return SourceChunk{}, err
	}

	remaining := descriptor.SizeBytes - query.Offset
	readSize := uint64(query.Limit)
	if readSize > remaining {
		readSize = remaining
	}
	content := make([]byte, int(readSize))
	if len(content) > 0 {
		read, readErr := file.ReadAt(content, int64(query.Offset))
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return SourceChunk{}, fmt.Errorf(
				"%w: read stored source: %v",
				ErrSourceUnavailable,
				readErr,
			)
		}
		if read != len(content) {
			return SourceChunk{}, fmt.Errorf(
				"%w: stored source ended before its declared size",
				ErrSourceUnavailable,
			)
		}
	}
	if err := ctx.Err(); err != nil {
		return SourceChunk{}, err
	}
	content, err = validUTF8Chunk(content, readSize == remaining)
	if err != nil {
		return SourceChunk{}, err
	}

	next := query.Offset + uint64(len(content))
	complete := next >= descriptor.SizeBytes
	chunk := SourceChunk{
		ResultID:  descriptor.ResultID,
		Offset:    query.Offset,
		Content:   string(content),
		Complete:  complete,
		SHA256:    descriptor.SHA256,
		SizeBytes: descriptor.SizeBytes,
	}
	if !complete {
		chunk.NextOffset = &next
	}
	return chunk, nil
}

func verifySourceSHA256(
	ctx context.Context,
	file *os.File,
	expected string,
) error {
	hasher := sha256.New()
	buffer := make([]byte, 256<<10)
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, readErr := file.ReadAt(buffer, offset)
		if read > 0 {
			_, _ = hasher.Write(buffer[:read])
			offset += int64(read)
		}
		switch {
		case errors.Is(readErr, io.EOF):
			if err := ctx.Err(); err != nil {
				return err
			}
			actual := hex.EncodeToString(hasher.Sum(nil))
			if actual != expected {
				return fmt.Errorf(
					"%w: stored source digest does not match metadata",
					ErrSourceUnavailable,
				)
			}
			return nil
		case readErr != nil:
			return fmt.Errorf(
				"%w: hash stored source: %v",
				ErrSourceUnavailable,
				readErr,
			)
		case read == 0:
			return fmt.Errorf(
				"%w: hash stored source made no progress",
				ErrSourceUnavailable,
			)
		}
	}
}

func validUTF8Chunk(content []byte, reachesEnd bool) ([]byte, error) {
	if utf8.Valid(content) {
		return content, nil
	}
	if reachesEnd {
		return nil, fmt.Errorf(
			"%w: stored source is not valid UTF-8",
			ErrSourceUnavailable,
		)
	}
	for removed := 1; removed < utf8.UTFMax && removed <= len(content); removed++ {
		candidate := content[:len(content)-removed]
		if utf8.Valid(candidate) {
			if len(candidate) == 0 {
				return nil, ErrInvalidInput
			}
			return candidate, nil
		}
	}
	return nil, fmt.Errorf(
		"%w: stored source is not valid UTF-8",
		ErrSourceUnavailable,
	)
}

func validateSourceDescriptor(
	descriptor SourceDescriptor,
	query SourceQuery,
) error {
	if descriptor.ResultID != query.ResultID ||
		descriptor.StorageKey == "" ||
		!sha256Pattern.MatchString(descriptor.SHA256) ||
		!descriptor.SizeKnown ||
		descriptor.SizeBytes > math.MaxInt64 {
		return ErrSourceUnavailable
	}
	switch descriptor.Status {
	case "complete", "partial", "bytecode_only":
		return nil
	default:
		return ErrSourceUnavailable
	}
}

func openRepositoryFile(
	ctx context.Context,
	repositoryRoot string,
	storageKey string,
) (*os.File, os.FileInfo, error) {
	if err := validateStorageKey(storageKey); err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	rootInfo, err := os.Lstat(repositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect repository root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, nil, errors.New("repository root is not a regular directory")
	}
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("open repository root: %w", err)
	}
	defer root.Close()

	components := strings.Split(storageKey, "/")
	current := ""
	for index, component := range components {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		current = path.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect source path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("source path contains a symbolic link")
		}
		if index < len(components)-1 && !info.IsDir() {
			return nil, nil, errors.New("source path parent is not a directory")
		}
		if index == len(components)-1 && !info.Mode().IsRegular() {
			return nil, nil, errors.New("source path is not a regular file")
		}
	}

	file, err := root.Open(storageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("open source file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect opened source file: %w", err)
	}
	finalInfo, err := root.Lstat(storageKey)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("reinspect source path: %w", err)
	}
	if finalInfo.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		!os.SameFile(finalInfo, info) {
		file.Close()
		return nil, nil, errors.New("source path changed during validation")
	}
	return file, info, nil
}

func validateStorageKey(storageKey string) error {
	if storageKey == "" ||
		strings.ContainsRune(storageKey, '\x00') ||
		strings.Contains(storageKey, `\`) ||
		path.IsAbs(storageKey) ||
		filepath.IsAbs(storageKey) ||
		path.Clean(storageKey) != storageKey ||
		storageKey == "." {
		return errors.New("source storage key is not a canonical relative path")
	}
	for _, component := range strings.Split(storageKey, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("source storage key contains an unsafe component")
		}
	}
	return nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" +
		encoded[8:12] + "-" +
		encoded[12:16] + "-" +
		encoded[16:20] + "-" +
		encoded[20:32], nil
}

var _ interface {
	Create(context.Context, CreateInput) (Request, bool, error)
	List(context.Context, ListQuery) (Page, error)
	Source(context.Context, SourceQuery) (SourceChunk, error)
	ExportSources(context.Context, SourceArchiveQuery) (SourceArchive, error)
} = (*Service)(nil)
