package orphanreaper

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"binaryscan/internal/retention"
	"binaryscan/internal/taskcleanup"
)

type Repository interface {
	ListBlobReferenceCandidates(
		context.Context,
		uint64,
		int,
	) ([]BlobReferenceCandidate, error)
	ReconcileBlobReference(
		context.Context,
		BlobReferenceCandidate,
		time.Time,
		bool,
	) (BlobReferenceResult, error)
	BlobReferenced(context.Context, BlobCandidate) (bool, error)
	UploadReferenced(context.Context, UploadCandidate) (bool, error)
	ListPendingSourceProjects(
		context.Context, int,
	) ([]PendingSourceProject, error)
	CleanupPendingSourceProject(
		context.Context,
		PendingSourceProject,
		func(context.Context, SourceProjectCleanupTarget) error,
	) (bool, error)
	SourceProjectReferenced(context.Context, SourceProjectCandidate) (bool, error)
	DeleteOrphanSourceProject(
		context.Context,
		SourceProjectCandidate,
		func(context.Context) error,
	) (bool, error)
	StoredFileReferenced(context.Context, StoredFileCandidate) (bool, error)
	DeleteOrphanBlob(
		context.Context,
		BlobCandidate,
		func(context.Context) error,
	) (bool, error)
	DeleteOrphanUpload(
		context.Context,
		UploadCandidate,
		func(context.Context) error,
	) (bool, error)
	DeleteOrphanStoredFile(
		context.Context,
		StoredFileCandidate,
		func(context.Context) error,
	) (bool, error)
}

type BlobDeleter interface {
	Delete(context.Context, retention.Blob) error
}

type UploadDeleter interface {
	Delete(context.Context, string) error
}

type Config struct {
	RepositoryRoot string
	UploadsRoot    string
	GracePeriod    time.Duration
	DryRun         bool
	Now            func() time.Time
	BlobDeleter    BlobDeleter
	UploadDeleter  UploadDeleter
}

type Sweeper struct {
	repository    Repository
	blobDeleter   BlobDeleter
	uploadDeleter UploadDeleter
	storedDeleter taskcleanup.FileDeleter
	inventory     *inventory
	blobRefCursor uint64
	gracePeriod   time.Duration
	dryRun        bool
	now           func() time.Time
	mu            sync.Mutex
}

func NewSweeper(repository Repository, config Config) (*Sweeper, error) {
	if repository == nil {
		return nil, errors.New("orphan cleanup repository is required")
	}
	if config.BlobDeleter == nil || config.UploadDeleter == nil {
		return nil, errors.New("orphan cleanup file deleters are required")
	}
	if config.GracePeriod <= 0 || config.GracePeriod > 30*24*time.Hour {
		return nil, errors.New("orphan cleanup grace period must be between zero and 30 days")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	cleanRepository := filepath.Clean(config.RepositoryRoot)
	cleanUploads := filepath.Clean(config.UploadsRoot)
	if cleanRepository == cleanUploads {
		return nil, errors.New("repository and upload roots must be distinct")
	}
	inventory, err := newInventory(cleanRepository, cleanUploads)
	if err != nil {
		return nil, err
	}
	storedDeleter, err := taskcleanup.NewRepositoryFileDeleter(cleanRepository)
	if err != nil {
		return nil, fmt.Errorf("initialize stored-file orphan deleter: %w", err)
	}
	return &Sweeper{
		repository: repository, blobDeleter: config.BlobDeleter,
		uploadDeleter: config.UploadDeleter, storedDeleter: storedDeleter,
		inventory:   inventory,
		gracePeriod: config.GracePeriod, dryRun: config.DryRun, now: config.Now,
	}, nil
}

func (s *Sweeper) Sweep(ctx context.Context, limit int) (Report, error) {
	if limit < 1 || limit > MaxSweepBatch {
		return Report{}, fmt.Errorf("orphan cleanup limit must be between 1 and %d", MaxSweepBatch)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	report := Report{DryRun: s.dryRun}
	cutoff := s.now().UTC().Add(-s.gracePeriod)
	referenceCandidates, err := s.repository.ListBlobReferenceCandidates(
		ctx, s.blobRefCursor, limit,
	)
	if err != nil {
		return report, fmt.Errorf("list blob reference reconciliation candidates: %w", err)
	}
	if len(referenceCandidates) == 0 {
		s.blobRefCursor = 0
	} else {
		s.blobRefCursor = referenceCandidates[len(referenceCandidates)-1].ID
	}
	var itemErrors []error
	for _, candidate := range referenceCandidates {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.BlobReferencesScanned++
		result, reconcileErr := s.repository.ReconcileBlobReference(
			ctx, candidate, cutoff, s.dryRun,
		)
		if reconcileErr != nil {
			report.addDiagnostic(
				"blob-reference", fmt.Sprintf("%d", candidate.ID), reconcileErr,
			)
			itemErrors = append(itemErrors, reconcileErr)
			continue
		}
		if result.Drifted {
			report.DriftedBlobReferences++
		}
		if result.Corrected {
			report.CorrectedBlobReferences++
		}
	}
	pendingProjects, err := s.repository.ListPendingSourceProjects(ctx, limit)
	if err != nil {
		return report, errors.Join(
			fmt.Errorf("list pending source project cleanup: %w", err),
			errors.Join(itemErrors...),
		)
	}
	for _, candidate := range pendingProjects {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.PendingSourceProjects++
		if s.dryRun {
			continue
		}
		completed, cleanupErr := s.repository.CleanupPendingSourceProject(
			ctx, candidate, s.deleteSourceProjectTarget,
		)
		if cleanupErr != nil {
			report.addDiagnostic("source-project", candidate.ID, cleanupErr)
			itemErrors = append(itemErrors, cleanupErr)
			continue
		}
		if completed {
			report.CompletedSourceProjects++
		} else {
			report.RecheckProtected++
		}
	}
	blobs, blobDeferred, blobDiagnostics, err := s.inventory.nextBlobs(ctx, limit, cutoff)
	report.DeferredYoungBlobs += blobDeferred
	for _, diagnostic := range blobDiagnostics {
		report.addDiagnostic(diagnostic.Kind, diagnostic.Name, diagnostic.Err)
	}
	if err != nil {
		return report, err
	}
	uploads, uploadDeferred, uploadDiagnostics, err := s.inventory.nextUploads(
		ctx, limit, cutoff,
	)
	report.DeferredYoungUpload += uploadDeferred
	for _, diagnostic := range uploadDiagnostics {
		report.addDiagnostic(diagnostic.Kind, diagnostic.Name, diagnostic.Err)
	}
	if err != nil {
		return report, err
	}
	sourceProjects, sourceProjectDeferred, sourceProjectDiagnostics, err :=
		s.inventory.nextSourceProjects(ctx, limit, cutoff)
	report.DeferredYoungSourceProject += sourceProjectDeferred
	for _, diagnostic := range sourceProjectDiagnostics {
		report.addDiagnostic(diagnostic.Kind, diagnostic.Name, diagnostic.Err)
	}
	if err != nil {
		return report, err
	}
	storedFiles, storedDeferred, storedDiagnostics, err := s.inventory.nextStoredFiles(
		ctx, limit, cutoff,
	)
	report.DeferredYoungStored += storedDeferred
	for _, diagnostic := range storedDiagnostics {
		report.addDiagnostic(diagnostic.Kind, diagnostic.Name, diagnostic.Err)
	}
	if err != nil {
		return report, errors.Join(err, errors.Join(itemErrors...))
	}

	for _, candidate := range blobs {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.BlobFilesScanned++
		referenced, err := s.repository.BlobReferenced(ctx, candidate)
		if err != nil {
			report.addDiagnostic("blob", candidate.SHA256, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if referenced {
			report.ReferencedBlobs++
			continue
		}
		report.OrphanBlobs++
		if s.dryRun {
			continue
		}
		removed, err := s.repository.DeleteOrphanBlob(
			ctx,
			candidate,
			func(deleteCtx context.Context) error {
				if err := s.inventory.revalidateBlob(candidate); err != nil {
					return err
				}
				return s.blobDeleter.Delete(deleteCtx, retention.Blob{
					SHA256: candidate.SHA256, SizeBytes: candidate.SizeBytes,
					StorageKey: candidate.StorageKey,
				})
			},
		)
		if err != nil {
			report.addDiagnostic("blob", candidate.SHA256, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if removed {
			report.RemovedBlobs++
		} else {
			report.RecheckProtected++
		}
	}

	for _, candidate := range uploads {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.UploadDirsScanned++
		referenced, err := s.repository.UploadReferenced(ctx, candidate)
		if err != nil {
			report.addDiagnostic("upload", candidate.ID, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if referenced {
			report.ReferencedUploads++
			continue
		}
		report.OrphanUploads++
		if s.dryRun {
			continue
		}
		removed, err := s.repository.DeleteOrphanUpload(
			ctx,
			candidate,
			func(deleteCtx context.Context) error {
				if err := s.inventory.revalidateUpload(candidate); err != nil {
					return err
				}
				return s.uploadDeleter.Delete(deleteCtx, candidate.ID)
			},
		)
		if err != nil {
			report.addDiagnostic("upload", candidate.ID, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if removed {
			report.RemovedUploads++
		} else {
			report.RecheckProtected++
		}
	}

	for _, candidate := range sourceProjects {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.SourceProjectDirsScanned++
		referenced, err := s.repository.SourceProjectReferenced(ctx, candidate)
		if err != nil {
			report.addDiagnostic("source-project", candidate.ID, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if referenced {
			report.ReferencedSourceProjects++
			continue
		}
		report.OrphanSourceProjects++
		if s.dryRun {
			continue
		}
		removed, err := s.repository.DeleteOrphanSourceProject(
			ctx,
			candidate,
			func(deleteCtx context.Context) error {
				if err := s.inventory.revalidateSourceProject(candidate); err != nil {
					return err
				}
				return s.storedDeleter.DeleteScope(deleteCtx, taskcleanup.Scope{
					Kind:   taskcleanup.FileSourceProject,
					TaskID: candidate.ID, RecordID: candidate.ID,
				})
			},
		)
		if err != nil {
			report.addDiagnostic("source-project", candidate.ID, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if removed {
			report.RemovedSourceProjects++
		} else {
			report.RecheckProtected++
		}
	}

	for _, candidate := range storedFiles {
		if err := ctx.Err(); err != nil {
			return report, errors.Join(err, errors.Join(itemErrors...))
		}
		report.StoredFilesScanned++
		referenced, err := s.repository.StoredFileReferenced(ctx, candidate)
		if err != nil {
			report.addDiagnostic(string(candidate.Kind), candidate.StorageKey, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if referenced {
			report.ReferencedStoredFiles++
			continue
		}
		report.OrphanStoredFiles++
		if s.dryRun {
			continue
		}
		if candidate.Kind == StoredFileReportStaging {
			removed, deleteErr := s.repository.DeleteOrphanStoredFile(
				ctx,
				candidate,
				func(deleteCtx context.Context) error {
					deleted, err := s.inventory.deleteReportStaging(deleteCtx, candidate)
					if err != nil {
						return err
					}
					if !deleted {
						return errors.New("report staging orphan disappeared before deletion")
					}
					return nil
				},
			)
			if deleteErr != nil {
				report.addDiagnostic(string(candidate.Kind), candidate.StorageKey, deleteErr)
				itemErrors = append(itemErrors, deleteErr)
				continue
			}
			if removed {
				report.RemovedStoredFiles++
			} else {
				report.RecheckProtected++
			}
			continue
		}
		descriptor, err := storedFileDescriptor(candidate)
		if err != nil {
			report.addDiagnostic(string(candidate.Kind), candidate.StorageKey, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		removed, err := s.repository.DeleteOrphanStoredFile(
			ctx,
			candidate,
			func(deleteCtx context.Context) error {
				deleted, deleteErr := s.storedDeleter.DeleteFile(deleteCtx, descriptor)
				if deleteErr != nil {
					return deleteErr
				}
				if !deleted {
					return errors.New("stored-file orphan disappeared before deletion")
				}
				return nil
			},
		)
		if err != nil {
			report.addDiagnostic(string(candidate.Kind), candidate.StorageKey, err)
			itemErrors = append(itemErrors, err)
			continue
		}
		if removed {
			report.RemovedStoredFiles++
		} else {
			report.RecheckProtected++
		}
	}
	return report, errors.Join(itemErrors...)
}

func (s *Sweeper) deleteSourceProjectTarget(
	ctx context.Context,
	target SourceProjectCleanupTarget,
) error {
	if !canonicalObjectID.MatchString(target.ProjectID) ||
		!canonicalObjectID.MatchString(target.TaskID) {
		return errors.New("source project cleanup target is invalid")
	}
	switch target.LayoutVersion {
	case "project-v1":
		return s.storedDeleter.DeleteScope(ctx, taskcleanup.Scope{
			Kind:   taskcleanup.FileSourceProject,
			TaskID: target.TaskID, RecordID: target.ProjectID,
		})
	case "legacy-v1":
		for _, resultID := range target.LegacyResultIDs {
			if !canonicalObjectID.MatchString(resultID) {
				return errors.New("legacy source project cleanup target is invalid")
			}
			if err := s.storedDeleter.DeleteScope(ctx, taskcleanup.Scope{
				Kind:   taskcleanup.FileDecompile,
				TaskID: target.TaskID, RecordID: resultID,
			}); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("source project cleanup layout is invalid")
	}
}

func storedFileDescriptor(
	candidate StoredFileCandidate,
) (taskcleanup.StoredFile, error) {
	if !validStoredFileCandidate(candidate) {
		return taskcleanup.StoredFile{}, errors.New("stored-file orphan descriptor is invalid")
	}
	components := strings.Split(candidate.StorageKey, "/")
	descriptor := taskcleanup.StoredFile{
		StorageKey: candidate.StorageKey,
		SHA256:     candidate.SHA256,
		SizeBytes:  candidate.SizeBytes,
	}
	switch candidate.Kind {
	case StoredFileReport:
		if len(components) != 3 || !canonicalObjectID.MatchString(components[1]) {
			return taskcleanup.StoredFile{}, errors.New("report orphan path is not canonical")
		}
		extension := strings.TrimPrefix(path.Ext(components[2]), ".")
		recordID := strings.TrimSuffix(components[2], "."+extension)
		if (extension != "json" && extension != "html") ||
			!canonicalObjectID.MatchString(recordID) {
			return taskcleanup.StoredFile{}, errors.New("report orphan name is not canonical")
		}
		descriptor.Kind = taskcleanup.FileReport
		descriptor.TaskID = components[1]
		descriptor.RecordID = recordID
		descriptor.Format = extension
	case StoredFileArtifact:
		if len(components) < 3 || !canonicalObjectID.MatchString(components[1]) {
			return taskcleanup.StoredFile{}, errors.New("artifact orphan path is not canonical")
		}
		descriptor.Kind = taskcleanup.FileArtifact
		descriptor.TaskID = components[1]
		descriptor.RecordID = components[1]
	case StoredFileDecompile:
		if len(components) != 3 || !canonicalObjectID.MatchString(components[1]) {
			return taskcleanup.StoredFile{}, errors.New("decompile orphan path is not canonical")
		}
		descriptor.Kind = taskcleanup.FileDecompile
		descriptor.TaskID = components[1]
		descriptor.RecordID = components[1]
	default:
		return taskcleanup.StoredFile{}, errors.New("stored-file orphan kind is invalid")
	}
	return descriptor, nil
}
