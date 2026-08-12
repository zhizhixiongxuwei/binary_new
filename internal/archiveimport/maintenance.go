package archiveimport

import (
	"context"
	"errors"
	"time"
)

// MaintenanceRecoverer converges archive-import work that was interrupted
// between durable saga steps. It does not extract archives; queued imports are
// left for the supervised scanner worker after expired leases are requeued.
type MaintenanceRecoverer struct {
	repository *MySQLRepository
	service    *Service
	retryDelay time.Duration
}

func NewMaintenanceRecoverer(
	repository *MySQLRepository,
	service *Service,
	retryDelay time.Duration,
) (*MaintenanceRecoverer, error) {
	if repository == nil || service == nil || retryDelay < 0 {
		return nil, errors.New("archive import maintenance configuration is invalid")
	}
	return &MaintenanceRecoverer{
		repository: repository, service: service, retryDelay: retryDelay,
	}, nil
}

func (recovery *MaintenanceRecoverer) RecoverPending(
	ctx context.Context,
	limit int,
) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInvalidInput
	}
	expired, err := recovery.repository.RecoverExpired(ctx, recovery.retryDelay)
	batches, batchErr := recovery.service.RecoverTaskBatches(ctx, limit)
	deleting, deletingErr := recovery.service.RecoverDeleting(ctx, limit)
	inactive, inactiveErr := recovery.service.ReconcileInactiveParents(ctx, limit)
	return int(expired) + batches + deleting + inactive,
		errors.Join(err, batchErr, deletingErr, inactiveErr)
}
