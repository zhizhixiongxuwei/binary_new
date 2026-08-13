package archiveimport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/auth"
)

var uuidPattern = regexp.MustCompile(
	`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
)

type ServiceConfig struct {
	Limits             Limits
	BatchLeaseDuration time.Duration
	BatchRecoveryAge   time.Duration
	DerivedUploads     DerivedUploadCreator
	DeleteDerived      DerivedUploadDeleter
	Tasks              TaskCreator
	Storage            *BlobStorage
	NewID              func() (string, error)
}

type Service struct {
	repository *MySQLRepository
	config     ServiceConfig
}

func NewService(
	repository *MySQLRepository,
	config ServiceConfig,
) (*Service, error) {
	if repository == nil {
		return nil, errors.New("archive import repository is required")
	}
	if config.Limits == (Limits{}) {
		config.Limits = DefaultLimits()
	}
	if err := validateLimits(config.Limits); err != nil {
		return nil, err
	}
	if config.BatchLeaseDuration == 0 {
		config.BatchLeaseDuration = 2 * time.Minute
	}
	if config.BatchRecoveryAge == 0 {
		config.BatchRecoveryAge = time.Minute
	}
	if config.BatchLeaseDuration <= 0 || config.BatchRecoveryAge <= 0 {
		return nil, errors.New("archive batch timings must be positive")
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{repository: repository, config: config}, nil
}

func (service *Service) EnsureForUpload(
	ctx context.Context,
	input EnsureInput,
) (string, error) {
	if !validEnsureInput(input) || !isRootArchiveFormat(input.DetectedFormat) ||
		input.Size > service.config.Limits.MaxUploadBytes {
		return "", ErrInvalidInput
	}
	limits, err := json.Marshal(service.config.Limits)
	if err != nil {
		return "", fmt.Errorf("encode archive import limits: %w", err)
	}
	id, err := service.config.NewID()
	if err != nil {
		return "", err
	}
	if !uuidPattern.MatchString(id) {
		return "", errors.New("archive import ID generator returned an invalid UUID")
	}
	value, _, err := service.repository.Ensure(ctx, id, input, limits)
	if err != nil {
		return "", err
	}
	return value.ID, nil
}

func (service *Service) Get(
	ctx context.Context,
	id string,
	principal auth.Principal,
) (Import, error) {
	if !uuidPattern.MatchString(id) || !validPrincipal(principal) {
		return Import{}, ErrInvalidInput
	}
	value, err := service.repository.Get(ctx, id)
	if err != nil {
		return Import{}, err
	}
	if principal.Role != auth.RoleAdministrator && value.CreatedBy != principal.UserID {
		return Import{}, ErrNotFound
	}
	return value, nil
}

func (service *Service) ListImports(
	ctx context.Context,
	query ImportListQuery,
	principal auth.Principal,
) (ImportPage, error) {
	if !validPrincipal(principal) || query.PageSize < 1 || query.PageSize > 100 {
		return ImportPage{}, ErrInvalidInput
	}
	var before time.Time
	var beforeID string
	if query.Cursor != "" {
		var err error
		before, beforeID, err = decodeImportCursor(query.Cursor)
		if err != nil {
			return ImportPage{}, ErrInvalidInput
		}
	}
	var owner *uint64
	if principal.Role != auth.RoleAdministrator {
		ownerID := principal.UserID
		owner = &ownerID
	}
	items, more, err := service.repository.ListImports(
		ctx, owner, before, beforeID, query.PageSize,
	)
	if err != nil {
		return ImportPage{}, err
	}
	page := ImportPage{Items: items}
	if page.Items == nil {
		page.Items = []Import{}
	}
	if more {
		if len(items) == 0 {
			return ImportPage{}, errors.New("archive import repository returned an empty page with more data")
		}
		last := items[len(items)-1]
		page.NextCursor = encodeImportCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}

func (service *Service) ListEntries(
	ctx context.Context,
	importID string,
	query EntryListQuery,
	principal auth.Principal,
) (EntryPage, error) {
	if query.PageSize < 1 || query.PageSize > 100 || query.AfterID != 0 ||
		!validEntryFilter(query.Filter) {
		return EntryPage{}, ErrInvalidInput
	}
	if _, err := service.Get(ctx, importID, principal); err != nil {
		return EntryPage{}, err
	}
	afterID := uint64(0)
	if query.Cursor != "" {
		decoded, err := decodeEntryCursor(query.Cursor)
		if err != nil {
			return EntryPage{}, ErrInvalidInput
		}
		afterID = decoded
	}
	items, more, err := service.repository.ListEntries(
		ctx, importID, query.Filter, afterID, query.PageSize,
	)
	if err != nil {
		return EntryPage{}, err
	}
	page := EntryPage{Items: items}
	if page.Items == nil {
		page.Items = []Entry{}
	}
	if more {
		if len(items) == 0 {
			return EntryPage{}, errors.New("archive entry repository returned empty page with more data")
		}
		page.NextCursor = encodeEntryCursor(items[len(items)-1].DatabaseID)
	}
	return page, nil
}

func (service *Service) CreateBatch(
	ctx context.Context,
	input BatchInput,
) (BatchResult, bool, error) {
	if service.config.DerivedUploads == nil || service.config.Tasks == nil {
		return BatchResult{}, false, errors.New("archive batch creators are not configured")
	}
	if !validBatchInput(input) {
		return BatchResult{}, false, ErrInvalidInput
	}
	archive, err := service.Get(ctx, input.ImportID, auth.Principal{
		UserID: input.CreatedBy, Role: input.Role,
	})
	if err != nil {
		return BatchResult{}, false, err
	}
	if archive.Status != StatusReady {
		return BatchResult{}, false, ErrConflict
	}
	fingerprint, err := batchFingerprint(input.EntryIDs)
	if err != nil {
		return BatchResult{}, false, err
	}
	batchID, err := service.config.NewID()
	if err != nil {
		return BatchResult{}, false, err
	}
	if !uuidPattern.MatchString(batchID) {
		return BatchResult{}, false, errors.New("archive batch ID generator returned invalid UUID")
	}
	batch, created, err := service.repository.BeginBatch(
		ctx, batchID, input, fingerprint,
	)
	if err != nil {
		return BatchResult{}, false, err
	}
	if batch.Status == "processing" {
		ownerID, err := service.config.NewID()
		if err != nil {
			return BatchResult{}, false, err
		}
		batch, err = service.processBatch(ctx, batch.ID, "api/"+ownerID)
		if err != nil {
			return BatchResult{}, false, err
		}
	}
	return BatchResult{Items: batch.Items}, created, nil
}

func (service *Service) processBatch(
	ctx context.Context,
	batchID string,
	owner string,
) (Batch, error) {
	for {
		// Facts in uploads/tasks are authoritative across process crashes. Repair
		// entry and batch links before spending another attempt or completing a
		// batch whose last database write was interrupted.
		if err := service.repository.ReconcileBatchFacts(ctx, batchID); err != nil {
			return Batch{}, err
		}
		work, found, err := service.repository.ClaimBatchItem(
			ctx, batchID, owner, service.config.BatchLeaseDuration,
		)
		if err != nil {
			return Batch{}, err
		}
		if !found {
			if err := service.repository.ReconcileBatchFacts(ctx, batchID); err != nil {
				return Batch{}, err
			}
			if err := service.repository.CompleteBatch(ctx, batchID); err != nil {
				return Batch{}, err
			}
			batch, err := service.repository.LoadBatch(ctx, batchID)
			if err != nil {
				return Batch{}, err
			}
			if batch.Status == "completed" {
				return batch, nil
			}
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return Batch{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if err := service.processBatchItem(ctx, work); err != nil {
			if ctx.Err() != nil {
				return Batch{}, ctx.Err()
			}
			fact, reconcileErr := service.repository.ReconcileEntryFact(
				ctx, work.EntryDatabaseID,
			)
			if reconcileErr == nil && fact.TaskID != "" {
				continue
			}
			if reconcileErr != nil {
				err = errors.Join(err, reconcileErr)
			}
			code := "archive_entry_task_creation_failed"
			if _, failErr := service.repository.RetryOrFailBatchItem(
				ctx, work, code, err.Error(),
			); failErr != nil {
				if errors.Is(failErr, ErrLeaseLost) {
					continue
				}
				return Batch{}, errors.Join(err, failErr)
			}
		}
	}
}

func (service *Service) processBatchItem(
	ctx context.Context,
	work BatchWorkItem,
) error {
	fact, err := service.repository.ReconcileEntryFact(ctx, work.EntryDatabaseID)
	if err != nil {
		return err
	}
	if fact.TaskID != "" {
		return nil
	}
	derivedID := fact.DerivedUploadID
	if derivedID == "" {
		derived, _, createErr := service.config.DerivedUploads.CreateDerivedCompleted(
			ctx,
			DerivedUploadInput{
				CreatedBy: work.SourceOwner, Filename: derivedFilename(work.Path),
				ContentType: contentTypeForFormat(work.Format), Size: work.Size,
				SHA256: work.SHA256, BlobID: work.BlobID,
				InputCategory: work.Category, DetectedFormat: work.Format,
				ParentUploadID: work.ParentUploadID, ArchiveName: work.ArchiveName,
				EntryPath:      work.Path,
				IdempotencyKey: "archive-entry-upload:" + work.EntryID,
			},
		)
		if createErr != nil {
			fact, reconcileErr := service.repository.ReconcileEntryFact(
				ctx, work.EntryDatabaseID,
			)
			if reconcileErr != nil {
				return errors.Join(
					fmt.Errorf("create derived archive upload: %w", createErr),
					reconcileErr,
				)
			}
			if fact.TaskID != "" {
				return nil
			}
			if fact.DerivedUploadID == "" {
				return fmt.Errorf("create derived archive upload: %w", createErr)
			}
			derivedID = fact.DerivedUploadID
		} else {
			if !uuidPattern.MatchString(derived.ID) {
				return errors.New("derived upload creator returned invalid UUID")
			}
			derivedID = derived.ID
		}
	}
	if !uuidPattern.MatchString(derivedID) {
		return errors.New("reconciled derived upload has invalid UUID")
	}
	if err := service.repository.SaveDerivedUpload(ctx, work, derivedID); err != nil {
		fact, reconcileErr := service.repository.ReconcileEntryFact(
			ctx, work.EntryDatabaseID,
		)
		if reconcileErr != nil {
			return errors.Join(err, reconcileErr)
		}
		if fact.TaskID != "" {
			return nil
		}
		if fact.DerivedUploadID != derivedID {
			return err
		}
		// Re-check the live fence even when the durable link was recovered.
		if retryErr := service.repository.SaveDerivedUpload(ctx, work, derivedID); retryErr != nil {
			return errors.Join(err, retryErr)
		}
	}
	taskID, created, err := service.config.Tasks.Create(
		ctx, work.SourceOwner, auth.RoleOperator, derivedID,
		ArchiveTaskName(work.ArchiveName, work.Path),
		"archive-entry-task:"+work.EntryID,
	)
	if err != nil {
		fact, reconcileErr := service.repository.ReconcileEntryFact(
			ctx, work.EntryDatabaseID,
		)
		if reconcileErr == nil && fact.TaskID != "" {
			return nil
		}
		if reconcileErr != nil {
			return errors.Join(
				fmt.Errorf("create archive entry task: %w", err), reconcileErr,
			)
		}
		return fmt.Errorf("create archive entry task: %w", err)
	}
	if !uuidPattern.MatchString(taskID) {
		return errors.New("task creator returned invalid UUID")
	}
	released, err := service.repository.FinalizeBatchItem(
		ctx, work, derivedID, taskID, created,
	)
	if err != nil {
		fact, reconcileErr := service.repository.ReconcileEntryFact(
			ctx, work.EntryDatabaseID,
		)
		if reconcileErr == nil && fact.TaskID == taskID {
			return nil
		}
		if reconcileErr != nil {
			return errors.Join(err, reconcileErr)
		}
		return err
	}
	if len(released) > 0 && service.config.Storage != nil {
		// Database finalization is authoritative. A failed physical removal
		// leaves a zero-reference blob in deleting state for maintenance; it
		// must never turn a committed task into a failed batch item.
		_ = service.config.Storage.DeleteReleased(ctx, service.repository, released)
	}
	return nil
}

func (service *Service) DeleteForUpload(
	ctx context.Context,
	uploadID string,
	actor auth.Principal,
) error {
	if !uuidPattern.MatchString(uploadID) || !validPrincipal(actor) {
		return ErrInvalidInput
	}
	if err := service.repository.ReconcileImportFacts(ctx, uploadID); err != nil {
		return err
	}
	plan, err := service.repository.PrepareDeleteForUpload(ctx, uploadID, actor)
	if err != nil || plan.AlreadyDeleted {
		return err
	}
	return service.finishDelete(ctx, uploadID, plan)
}

func (service *Service) finishDelete(
	ctx context.Context,
	uploadID string,
	plan DeletionPlan,
) error {
	if len(plan.DerivedUploads) > 0 && service.config.DeleteDerived == nil {
		return errors.New("derived archive upload deleter is not configured")
	}
	for _, derived := range plan.DerivedUploads {
		if err := service.config.DeleteDerived.DeleteDerivedCompleted(
			ctx, derived.ID, derived.Owner,
		); err != nil {
			return fmt.Errorf("delete orphan derived archive upload: %w", err)
		}
	}
	released, err := service.repository.FinalizeDeleteForUpload(ctx, uploadID)
	if err != nil {
		return err
	}
	if len(released) > 0 && service.config.Storage != nil {
		// Parent deletion may proceed after the database tombstone. Physical
		// cleanup is idempotently retried by maintenance.
		_ = service.config.Storage.DeleteReleased(ctx, service.repository, released)
	}
	return nil
}

func (service *Service) RecoverDeleting(
	ctx context.Context,
	limit int,
) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	uploadIDs, err := service.repository.RecoverDeleting(
		ctx, service.config.BatchRecoveryAge, limit,
	)
	if err != nil {
		return 0, err
	}
	completed := 0
	var itemErrors []error
	for _, uploadID := range uploadIDs {
		if err := service.repository.ReconcileImportFacts(ctx, uploadID); err != nil {
			itemErrors = append(itemErrors, fmt.Errorf("recover deleting archive %s facts: %w", uploadID, err))
			continue
		}
		plan, err := service.repository.LoadDeletingPlan(ctx, uploadID)
		if err != nil {
			itemErrors = append(itemErrors, fmt.Errorf("load deleting archive %s: %w", uploadID, err))
			continue
		}
		if err := service.finishDelete(ctx, uploadID, plan); err != nil {
			itemErrors = append(itemErrors, fmt.Errorf("finish deleting archive %s: %w", uploadID, err))
			continue
		}
		completed++
	}
	return completed, errors.Join(itemErrors...)
}

func (service *Service) ReconcileInactiveParents(
	ctx context.Context,
	limit int,
) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	values, err := service.repository.ListInactiveParentImports(
		ctx, service.config.BatchRecoveryAge, limit,
	)
	if err != nil {
		return 0, err
	}
	completed := 0
	var itemErrors []error
	for _, value := range values {
		err := service.DeleteForUpload(ctx, value.UploadID, auth.Principal{
			UserID: value.Owner,
			Role:   auth.RoleOperator,
		})
		if err != nil {
			itemErrors = append(itemErrors, fmt.Errorf(
				"reconcile inactive archive parent %s: %w", value.UploadID, err,
			))
			continue
		}
		completed++
	}
	return completed, errors.Join(itemErrors...)
}

func (service *Service) RecoverTaskBatches(
	ctx context.Context,
	limit int,
) (int, error) {
	if limit < 1 || limit > 1000 || service.config.DerivedUploads == nil ||
		service.config.Tasks == nil {
		return 0, ErrInvalidInput
	}
	terminal, terminalErr := service.repository.CompleteTerminalBatches(
		ctx, service.config.BatchRecoveryAge, limit,
	)
	ids, err := service.repository.ListRecoverableBatches(
		ctx, service.config.BatchRecoveryAge, limit,
	)
	if err != nil {
		return int(terminal), errors.Join(terminalErr, err)
	}
	completed := int(terminal)
	var itemErrors []error
	for _, id := range ids {
		ownerID, err := service.config.NewID()
		if err != nil {
			itemErrors = append(itemErrors, fmt.Errorf("generate recovery owner for batch %s: %w", id, err))
			continue
		}
		if _, err := service.processBatch(ctx, id, "recovery/"+ownerID); err != nil {
			itemErrors = append(itemErrors, fmt.Errorf("recover archive batch %s: %w", id, err))
			continue
		}
		completed++
	}
	return completed, errors.Join(append([]error{terminalErr}, itemErrors...)...)
}

func ArchiveTaskName(archiveName, entryPath string) string {
	const maximum = 255
	separator := []rune(" :: ")
	archive := []rune(archiveName)
	entry := []rune(entryPath)
	if len(archive)+len(separator)+len(entry) <= maximum {
		return archiveName + " :: " + entryPath
	}
	const archiveMaximum = 80
	if len(archive) > archiveMaximum {
		archive = append(append([]rune{}, archive[:archiveMaximum-3]...), '.', '.', '.')
	}
	remaining := maximum - len(archive) - len(separator)
	if remaining < 4 {
		archive = archive[:maximum-len(separator)-4]
		remaining = 4
	}
	if len(entry) > remaining {
		entry = append([]rune{'.', '.', '.'}, entry[len(entry)-(remaining-3):]...)
	}
	return string(archive) + string(separator) + string(entry)
}

func derivedFilename(entryPath string) string {
	name := path.Base(entryPath)
	if len(name) <= 512 {
		return name
	}
	runes := []rune(name)
	for len(runes) > 1 && len(string(runes)) > 512 {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}

func contentTypeForFormat(format string) string {
	switch format {
	case "jar", "war", "ear":
		return "application/java-archive"
	case "apk":
		return "application/vnd.android.package-archive"
	default:
		return "application/octet-stream"
	}
}

func validEnsureInput(input EnsureInput) bool {
	return uuidPattern.MatchString(input.UploadID) && input.CreatedBy > 0 &&
		input.Size >= 0 && len(input.SHA256) == 64 &&
		isLowerHex(input.SHA256) && validSnapshot(input.Filename, 512)
}

func validateLimits(limits Limits) error {
	defaults := DefaultLimits()
	if limits.MaxUploadBytes <= 0 || limits.MaxUploadBytes > defaults.MaxUploadBytes ||
		limits.MaxExpandedBytes <= 0 || limits.MaxExpandedBytes > defaults.MaxExpandedBytes ||
		limits.MaxArchiveRatio <= 0 || limits.MaxArchiveRatio > defaults.MaxArchiveRatio ||
		limits.MaxEntries <= 0 || limits.MaxEntries > defaults.MaxEntries ||
		limits.MaxEntryBytes <= 0 || limits.MaxEntryBytes > defaults.MaxEntryBytes ||
		limits.MaxDepth <= 0 || limits.MaxDepth > defaults.MaxDepth {
		return errors.New("archive import limits exceed the v1 security contract")
	}
	return nil
}

func validBatchInput(input BatchInput) bool {
	if !uuidPattern.MatchString(input.ImportID) || input.CreatedBy == 0 ||
		(input.Role != auth.RoleAdministrator && input.Role != auth.RoleOperator) ||
		len(input.EntryIDs) == 0 || len(input.EntryIDs) > MaximumBatchEntries ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return false
	}
	seen := make(map[string]struct{}, len(input.EntryIDs))
	for _, id := range input.EntryIDs {
		if !uuidPattern.MatchString(id) {
			return false
		}
		if _, duplicate := seen[id]; duplicate {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

func batchFingerprint(entryIDs []string) (string, error) {
	raw, err := json.Marshal(struct {
		Version  int      `json:"version"`
		EntryIDs []string `json:"entry_ids"`
	}{Version: 1, EntryIDs: entryIDs})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validEntryFilter(value string) bool {
	switch value {
	case "", "all", EntryEligible, EntrySkipped, EntryCreated, EntryFailed:
		return true
	default:
		return false
	}
}

func encodeEntryCursor(id uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(id, 10)))
}

func decodeEntryCursor(value string) (uint64, error) {
	if len(value) == 0 || len(value) > 32 {
		return 0, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > 20 {
		return 0, ErrInvalidInput
	}
	id, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != string(raw) {
		return 0, ErrInvalidInput
	}
	return id, nil
}

func encodeImportCursor(createdAt time.Time, id string) string {
	value := strconv.FormatInt(createdAt.UTC().UnixMicro(), 10) + ":" + id
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}

func decodeImportCursor(value string) (time.Time, string, error) {
	if len(value) == 0 || len(value) > 160 {
		return time.Time{}, "", ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > 96 {
		return time.Time{}, "", ErrInvalidInput
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 || !uuidPattern.MatchString(parts[1]) {
		return time.Time{}, "", ErrInvalidInput
	}
	microseconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || microseconds <= 0 ||
		strconv.FormatInt(microseconds, 10) != parts[0] {
		return time.Time{}, "", ErrInvalidInput
	}
	return time.UnixMicro(microseconds).UTC(), parts[1], nil
}

func validPrincipal(principal auth.Principal) bool {
	return principal.UserID > 0 && (principal.Role == auth.RoleAdministrator ||
		principal.Role == auth.RoleOperator || principal.Role == auth.RoleReader)
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validSnapshot(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func isRootArchiveFormat(format string) bool {
	switch format {
	case "zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd",
		"cab", "cpio", "ar", "deb", "rpm", "iso9660":
		return true
	default:
		return false
	}
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func logicalPathDigest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func bounded(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "?")
	if len(value) <= maximum {
		return value
	}
	for maximum > 0 && !utf8.ValidString(value[:maximum]) {
		maximum--
	}
	return value[:maximum]
}
