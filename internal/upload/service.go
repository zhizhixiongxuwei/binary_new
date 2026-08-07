package upload

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/auth"
)

var (
	uuidPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
	hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

const uploadCreateOperation = "create"

type Config struct {
	UploadsRoot    string
	RepositoryRoot string
	MaxUploadBytes int64
	PartSize       int64
	Retention      time.Duration
	CapacityGuard  CapacityGuard
	PartDeleter    UploadDirectoryDeleter
	Now            func() time.Time
}

type UploadDirectoryDeleter interface {
	Delete(context.Context, string) error
}

type CapacityGuard interface {
	CheckCreate(context.Context, int64) error
	ReservePart(context.Context, int64) (func(), error)
	ReserveAssembly(context.Context, int64) (func(), error)
}

type Service struct {
	repository Repository
	config     Config
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("upload repository is required")
	}
	if !filepath.IsAbs(config.UploadsRoot) || !filepath.IsAbs(config.RepositoryRoot) {
		return nil, errors.New("upload and repository roots must be absolute")
	}
	config.UploadsRoot = filepath.Clean(config.UploadsRoot)
	config.RepositoryRoot = filepath.Clean(config.RepositoryRoot)
	if config.UploadsRoot == string(filepath.Separator) ||
		config.RepositoryRoot == string(filepath.Separator) {
		return nil, errors.New("upload and repository roots must be below the filesystem root")
	}
	if config.MaxUploadBytes <= 0 || config.PartSize <= 0 || config.Retention <= 0 {
		return nil, errors.New("upload limits and retention must be positive")
	}
	if config.PartDeleter == nil {
		return nil, errors.New("upload part deleter is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{repository: repository, config: config}, nil
}

func (s *Service) Create(ctx context.Context, input CreateInput) (View, error) {
	if err := s.validateCreate(input); err != nil {
		return View{}, err
	}
	fingerprint, err := createRequestFingerprint(input)
	if err != nil {
		return View{}, err
	}
	existing, found, err := s.repository.ResolveCreate(
		ctx,
		input.CreatedBy,
		uploadCreateOperation,
		input.IdempotencyKey,
		fingerprint,
	)
	if err != nil {
		return View{}, err
	}
	if found {
		return uploadView(existing, nil), nil
	}
	if s.config.CapacityGuard != nil {
		if capacityErr := s.config.CapacityGuard.CheckCreate(ctx, input.Size); capacityErr != nil {
			// Another request with the same key may have committed while this
			// request was probing capacity. Prefer that durable winner over a
			// transient local capacity result.
			existing, found, err = s.repository.ResolveCreate(
				ctx,
				input.CreatedBy,
				uploadCreateOperation,
				input.IdempotencyKey,
				fingerprint,
			)
			if err != nil {
				return View{}, err
			}
			if found {
				return uploadView(existing, nil), nil
			}
			return View{}, capacityErr
		}
	}
	id, err := newUUID()
	if err != nil {
		return View{}, err
	}
	now := s.config.Now().UTC()
	value := Upload{
		ID: id, CreatedBy: input.CreatedBy, OriginalName: []byte(input.Filename),
		DisplayName: input.Filename, ContentType: input.ContentType,
		DeclaredSize: input.Size, PartSize: s.config.PartSize,
		Status: "created", ExpiresAt: now.Add(s.config.Retention), CreatedAt: now,
	}
	stored, _, err := s.repository.Create(
		ctx,
		value,
		uploadCreateOperation,
		input.IdempotencyKey,
		fingerprint,
	)
	if err != nil {
		return View{}, err
	}
	return uploadView(stored, nil), nil
}

func (s *Service) Get(ctx context.Context, id string, principal auth.Principal) (View, error) {
	if !uuidPattern.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	value, err := s.repository.Get(ctx, id)
	if err != nil {
		return View{}, err
	}
	if principal.Role != auth.RoleAdministrator && value.CreatedBy != principal.UserID {
		return View{}, ErrNotFound
	}
	parts, err := s.repository.ListParts(ctx, id)
	if err != nil {
		return View{}, err
	}
	return uploadView(value, parts), nil
}

func (s *Service) Delete(ctx context.Context, id string, principal auth.Principal) error {
	if !uuidPattern.MatchString(id) {
		return ErrInvalidInput
	}
	if principal.UserID == 0 ||
		(principal.Role != auth.RoleAdministrator && principal.Role != auth.RoleOperator) {
		return ErrForbidden
	}
	return s.repository.WithLock(ctx, id, func(lockCtx context.Context) error {
		value, err := s.repository.Get(lockCtx, id)
		if err != nil {
			return err
		}
		if principal.Role != auth.RoleAdministrator && value.CreatedBy != principal.UserID {
			return ErrNotFound
		}
		switch value.Status {
		case "cancelled":
			// A previous request may have committed the database transition before
			// filesystem cleanup failed. Replays finish that cleanup.
		case "created", "uploading", "assembling", "failed", "expired":
			if err := s.repository.Cancel(lockCtx, id); err != nil {
				return err
			}
		default:
			return ErrInvalidState
		}
		if _, err := s.repository.CleanupParts(
			lockCtx,
			id,
			func() error {
				return s.config.PartDeleter.Delete(lockCtx, id)
			},
		); err != nil {
			return err
		}
		return nil
	})
}

func (s *Service) PutPart(
	ctx context.Context,
	id string,
	principal auth.Principal,
	partNumber uint32,
	byteRange Range,
	expectedHash string,
	body io.Reader,
) error {
	if !uuidPattern.MatchString(id) || partNumber == 0 || !hashPattern.MatchString(expectedHash) {
		return ErrInvalidInput
	}
	return s.repository.WithLock(ctx, id, func(lockCtx context.Context) error {
		value, err := s.repository.Get(lockCtx, id)
		if err != nil {
			return err
		}
		if principal.Role != auth.RoleAdministrator && value.CreatedBy != principal.UserID {
			return ErrNotFound
		}
		if !value.ExpiresAt.After(s.config.Now()) {
			return ErrExpired
		}
		if value.Status != "created" && value.Status != "uploading" {
			return ErrInvalidState
		}
		if err := validatePartLayout(value, partNumber, byteRange); err != nil {
			return err
		}
		parts, err := s.repository.ListParts(lockCtx, id)
		if err != nil {
			return err
		}
		for _, existing := range parts {
			if existing.Number != partNumber {
				continue
			}
			if existing.SHA256 == expectedHash &&
				existing.ContentRange == byteRange.Raw &&
				existing.Size == byteRange.Size() {
				path, err := safeJoin(s.config.UploadsRoot, existing.StorageKey)
				if err != nil {
					return err
				}
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() || info.Size() != existing.Size {
					return ErrIncomplete
				}
				return nil
			}
			return ErrConflict
		}

		releaseCapacity := func() {}
		if s.config.CapacityGuard != nil {
			releaseCapacity, err = s.config.CapacityGuard.ReservePart(
				lockCtx,
				byteRange.Size(),
			)
			if err != nil {
				return err
			}
			if releaseCapacity == nil {
				return errors.New("upload part capacity guard returned no release function")
			}
		}
		defer releaseCapacity()
		part, temporaryPath, finalPath, err := s.writePart(
			lockCtx, value, partNumber, byteRange, expectedHash, body,
		)
		if err != nil {
			return err
		}
		defer os.Remove(temporaryPath)
		published := false
		if err := publishNoReplace(temporaryPath, finalPath); err != nil {
			if errors.Is(err, os.ErrExist) {
				if err := verifyFile(lockCtx, finalPath, part.Size, expectedHash); err != nil {
					return ErrConflict
				}
			} else {
				return fmt.Errorf("publish upload part: %w", err)
			}
		} else {
			published = true
		}
		if err := syncDirectory(filepath.Dir(finalPath)); err != nil {
			if published {
				_ = os.Remove(finalPath)
			}
			return err
		}
		if err := s.repository.InsertPart(lockCtx, part); err != nil {
			if published {
				_ = os.Remove(finalPath)
				_ = syncDirectory(filepath.Dir(finalPath))
			}
			return err
		}
		return nil
	})
}

func (s *Service) Complete(ctx context.Context, id string, principal auth.Principal) (View, error) {
	if !uuidPattern.MatchString(id) {
		return View{}, ErrInvalidInput
	}
	var result View
	err := s.repository.WithLock(ctx, id, func(lockCtx context.Context) error {
		value, err := s.repository.Get(lockCtx, id)
		if err != nil {
			return err
		}
		if principal.Role != auth.RoleAdministrator && value.CreatedBy != principal.UserID {
			return ErrNotFound
		}
		if value.Status == "completed" {
			parts, err := s.repository.ListParts(lockCtx, id)
			if err != nil {
				return err
			}
			result = uploadView(value, parts)
			_, _ = s.cleanupParts(lockCtx, id)
			return nil
		}
		if !value.ExpiresAt.After(s.config.Now()) {
			return ErrExpired
		}
		if value.Status != "created" && value.Status != "uploading" &&
			value.Status != "assembling" {
			return ErrInvalidState
		}
		parts, err := s.repository.ListParts(lockCtx, id)
		if err != nil {
			return err
		}
		if err := validateCompleteLayout(value, parts); err != nil {
			return err
		}
		releaseCapacity := func() {}
		if s.config.CapacityGuard != nil {
			releaseCapacity, err = s.config.CapacityGuard.ReserveAssembly(
				lockCtx,
				value.DeclaredSize,
			)
			if err != nil {
				return err
			}
			if releaseCapacity == nil {
				return errors.New("upload assembly capacity guard returned no release function")
			}
		}
		defer releaseCapacity()
		assembly, err := s.stageAssembly(lockCtx, value, parts)
		if err != nil {
			return err
		}
		defer os.Remove(assembly.StagingPath)
		if err := s.repository.PrepareCompletion(
			lockCtx,
			id,
			assembly.SHA256,
			value.DeclaredSize,
			assembly.StorageKey,
		); err != nil {
			return err
		}
		if err := s.publishAssembly(lockCtx, assembly); err != nil {
			return err
		}
		completedAt := s.config.Now().UTC()
		if err := s.repository.FinalizeCompletion(
			lockCtx, id, assembly.SHA256, completedAt,
		); err != nil {
			return err
		}
		value.Status = "completed"
		value.ActualSHA256 = assembly.SHA256
		value.CompletedAt = &completedAt
		result = uploadView(value, parts)
		// Completion is already durable. A failed best-effort cleanup keeps the
		// terminal upload and part records pending for maintenance or a replay.
		_, _ = s.cleanupParts(lockCtx, id)
		return nil
	})
	return result, err
}

func (s *Service) cleanupParts(ctx context.Context, uploadID string) (bool, error) {
	return s.repository.CleanupParts(
		ctx,
		uploadID,
		func() error {
			return s.config.PartDeleter.Delete(ctx, uploadID)
		},
	)
}

func (s *Service) validateCreate(input CreateInput) error {
	if input.CreatedBy == 0 || input.Size < 0 || input.Size > s.config.MaxUploadBytes {
		return ErrInvalidInput
	}
	if !validUploadIdempotencyKey(input.IdempotencyKey) {
		return ErrInvalidInput
	}
	if !utf8.ValidString(input.Filename) || len(input.Filename) == 0 || len(input.Filename) > 512 {
		return ErrInvalidInput
	}
	if input.Filename == "." || input.Filename == ".." ||
		strings.ContainsAny(input.Filename, `/\:`) {
		return ErrInvalidInput
	}
	for _, character := range input.Filename {
		if unicode.IsControl(character) {
			return ErrInvalidInput
		}
	}
	if len(input.ContentType) == 0 || len(input.ContentType) > 255 || !isASCII(input.ContentType) {
		return ErrInvalidInput
	}
	return nil
}

func validUploadIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func createRequestFingerprint(input CreateInput) (string, error) {
	payload, err := json.Marshal(struct {
		Version     uint8  `json:"version"`
		Operation   string `json:"operation"`
		Filename    string `json:"filename"`
		Size        int64  `json:"size"`
		ContentType string `json:"content_type"`
	}{
		Version: 1, Operation: uploadCreateOperation,
		Filename: input.Filename, Size: input.Size, ContentType: input.ContentType,
	})
	if err != nil {
		return "", fmt.Errorf("encode upload creation fingerprint: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func validatePartLayout(value Upload, number uint32, byteRange Range) error {
	if byteRange.Total != value.DeclaredSize || byteRange.Start < 0 ||
		byteRange.End < byteRange.Start || byteRange.Size() > value.PartSize {
		return ErrRangeMismatch
	}
	expectedStart := int64(number-1) * value.PartSize
	if byteRange.Start != expectedStart || byteRange.End >= value.DeclaredSize {
		return ErrRangeMismatch
	}
	expectedEnd := expectedStart + value.PartSize - 1
	if expectedEnd >= value.DeclaredSize {
		expectedEnd = value.DeclaredSize - 1
	}
	if byteRange.End != expectedEnd {
		return ErrRangeMismatch
	}
	return nil
}

func validateCompleteLayout(value Upload, parts []Part) error {
	expectedParts := uint32(0)
	if value.DeclaredSize > 0 {
		expectedParts = uint32((value.DeclaredSize + value.PartSize - 1) / value.PartSize)
	}
	if uint32(len(parts)) != expectedParts {
		return ErrIncomplete
	}
	for index, part := range parts {
		number := uint32(index + 1)
		expectedStart := int64(index) * value.PartSize
		expectedEnd := expectedStart + value.PartSize - 1
		if expectedEnd >= value.DeclaredSize {
			expectedEnd = value.DeclaredSize - 1
		}
		expectedRange := Range{
			Start: expectedStart, End: expectedEnd, Total: value.DeclaredSize,
			Raw: fmt.Sprintf("bytes %d-%d/%d", expectedStart, expectedEnd, value.DeclaredSize),
		}
		if part.Number != number || part.Size != expectedRange.Size() ||
			part.ContentRange != expectedRange.Raw || !hashPattern.MatchString(part.SHA256) {
			return ErrIncomplete
		}
	}
	return nil
}

func (s *Service) writePart(
	ctx context.Context,
	value Upload,
	number uint32,
	byteRange Range,
	expectedHash string,
	body io.Reader,
) (Part, string, string, error) {
	relativeKey := filepath.ToSlash(filepath.Join(
		value.ID, "parts", fmt.Sprintf("%08d.part", number),
	))
	finalPath, err := safeJoin(s.config.UploadsRoot, relativeKey)
	if err != nil {
		return Part{}, "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o700); err != nil {
		return Part{}, "", "", fmt.Errorf("create upload part directory: %w", err)
	}
	temporaryPath := finalPath + ".tmp." + randomSuffix()
	file, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Part{}, "", "", fmt.Errorf("create temporary upload part: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	hasher := sha256.New()
	written, err := copyWithContext(ctx, io.MultiWriter(file, hasher), body, byteRange.Size())
	if err != nil {
		return Part{}, "", "", err
	}
	if written != byteRange.Size() {
		return Part{}, "", "", ErrRangeMismatch
	}
	extra, err := io.Copy(io.Discard, io.LimitReader(&contextReader{ctx: ctx, reader: body}, 1))
	if err != nil {
		return Part{}, "", "", fmt.Errorf("read trailing upload data: %w", err)
	}
	if extra != 0 {
		return Part{}, "", "", ErrTooLarge
	}
	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
		return Part{}, "", "", ErrHashMismatch
	}
	if err := file.Sync(); err != nil {
		return Part{}, "", "", fmt.Errorf("sync upload part: %w", err)
	}
	if err := file.Close(); err != nil {
		return Part{}, "", "", fmt.Errorf("close upload part: %w", err)
	}
	cleanup = false
	return Part{
		UploadID: value.ID, Number: number, Size: written, SHA256: actualHash,
		ContentRange: byteRange.Raw, StorageKey: relativeKey,
	}, temporaryPath, finalPath, nil
}

type stagedAssembly struct {
	SHA256      string
	StorageKey  string
	StagingPath string
	FinalPath   string
}

func (s *Service) stageAssembly(
	ctx context.Context,
	value Upload,
	parts []Part,
) (stagedAssembly, error) {
	stagingDir := filepath.Join(s.config.RepositoryRoot, ".staging", "uploads")
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return stagedAssembly{}, fmt.Errorf("create repository staging directory: %w", err)
	}
	stagingPath := filepath.Join(stagingDir, value.ID+"."+randomSuffix()+".part")
	output, err := os.OpenFile(stagingPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return stagedAssembly{}, fmt.Errorf("create repository staging file: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.Remove(stagingPath)
		}
	}()
	hasher := sha256.New()
	writer := io.MultiWriter(output, hasher)
	var total int64
	for _, part := range parts {
		path, err := safeJoin(s.config.UploadsRoot, part.StorageKey)
		if err != nil {
			_ = output.Close()
			return stagedAssembly{}, err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != part.Size {
			_ = output.Close()
			return stagedAssembly{}, ErrIncomplete
		}
		input, err := os.Open(path)
		if err != nil {
			_ = output.Close()
			return stagedAssembly{}, fmt.Errorf("open upload part: %w", err)
		}
		partHasher := sha256.New()
		written, copyErr := copyWithContext(ctx, io.MultiWriter(writer, partHasher), input, part.Size)
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil || written != part.Size {
			_ = output.Close()
			if copyErr != nil {
				return stagedAssembly{}, copyErr
			}
			return stagedAssembly{}, ErrIncomplete
		}
		actualPartHash := hex.EncodeToString(partHasher.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(actualPartHash), []byte(part.SHA256)) != 1 {
			_ = output.Close()
			return stagedAssembly{}, ErrHashMismatch
		}
		total += written
	}
	if total != value.DeclaredSize {
		_ = output.Close()
		return stagedAssembly{}, ErrIncomplete
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return stagedAssembly{}, fmt.Errorf("sync assembled upload: %w", err)
	}
	if err := output.Close(); err != nil {
		return stagedAssembly{}, fmt.Errorf("close assembled upload: %w", err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))
	storageKey := filepath.ToSlash(filepath.Join("blobs", "sha256", hash[:2], hash))
	finalPath, err := safeJoin(s.config.RepositoryRoot, storageKey)
	if err != nil {
		return stagedAssembly{}, err
	}
	keepStaging = true
	return stagedAssembly{
		SHA256: hash, StorageKey: storageKey,
		StagingPath: stagingPath, FinalPath: finalPath,
	}, nil
}

func (s *Service) publishAssembly(
	ctx context.Context,
	assembly stagedAssembly,
) error {
	if err := os.MkdirAll(filepath.Dir(assembly.FinalPath), 0o700); err != nil {
		return fmt.Errorf("create blob directory: %w", err)
	}
	if err := publishNoReplace(assembly.StagingPath, assembly.FinalPath); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("publish blob: %w", err)
		}
		info, statErr := os.Lstat(assembly.StagingPath)
		if statErr != nil || !info.Mode().IsRegular() {
			return ErrConflict
		}
		if err := verifyExistingBlob(
			ctx,
			assembly.FinalPath,
			info.Size(),
			assembly.SHA256,
		); err != nil {
			return err
		}
	}
	if err := syncDirectory(filepath.Dir(assembly.FinalPath)); err != nil {
		return err
	}
	return nil
}

func uploadView(value Upload, parts []Part) View {
	partNumbers := make([]uint32, 0, len(parts))
	for _, part := range parts {
		partNumbers = append(partNumbers, part.Number)
	}
	sort.Slice(partNumbers, func(i, j int) bool { return partNumbers[i] < partNumbers[j] })
	view := View{
		ID: value.ID, PartSize: value.PartSize, Status: value.Status,
		UploadedParts: partNumbers, ExpiresAt: value.ExpiresAt,
		SizeBytes: &value.DeclaredSize,
	}
	if value.Status == "completed" {
		view.SHA256 = value.ActualSHA256
	}
	return view
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader, limit int64) (int64, error) {
	reader := &contextReader{ctx: ctx, reader: io.LimitReader(source, limit)}
	written, err := io.Copy(destination, reader)
	if err != nil {
		return written, fmt.Errorf("stream upload data: %w", err)
	}
	return written, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}

func safeJoin(root, key string) (string, error) {
	if filepath.IsAbs(key) {
		return "", ErrInvalidInput
	}
	clean := filepath.Clean(key)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInput
	}
	path := filepath.Join(root, clean)
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", ErrInvalidInput
	}
	return path, nil
}

func publishNoReplace(temporaryPath, finalPath string) error {
	if err := os.Link(temporaryPath, finalPath); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(finalPath)
		return err
	}
	return nil
}

func verifyExistingBlob(ctx context.Context, path string, size int64, expectedHash string) error {
	if err := verifyFile(ctx, path, size, expectedHash); err != nil {
		return errors.New("existing content-addressed blob is invalid")
	}
	return nil
}

func verifyFile(ctx context.Context, path string, size int64, expectedHash string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != size {
		return ErrConflict
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := copyWithContext(ctx, hasher, file, size); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return ErrConflict
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open storage directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync storage directory: %w", err)
	}
	return nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate upload ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func randomSuffix() string {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > unicode.MaxASCII || unicode.IsControl(character) {
			return false
		}
	}
	return true
}
