package archiveimport

import (
	"context"

	"binaryscan/internal/auth"
	"binaryscan/internal/inputcategory"
	"binaryscan/internal/task"
	"binaryscan/internal/upload"
)

type UploadServiceAdapter struct {
	Service *upload.Service
}

func (adapter UploadServiceAdapter) CreateDerivedCompleted(
	ctx context.Context,
	input DerivedUploadInput,
) (DerivedUploadResult, bool, error) {
	category := inputcategory.Category(input.InputCategory)
	value, created, err := adapter.Service.CreateDerivedCompleted(
		ctx,
		upload.DerivedCompletedInput{
			CreatedBy: input.CreatedBy, Filename: input.Filename,
			ContentType: input.ContentType, Size: input.Size, SHA256: input.SHA256,
			BlobID: input.BlobID, InputCategory: category,
			DetectedFormat: input.DetectedFormat, ParentUploadID: input.ParentUploadID,
			ArchiveName: input.ArchiveName, EntryPath: input.EntryPath,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
	return DerivedUploadResult{ID: value.ID}, created, err
}

func (adapter UploadServiceAdapter) DeleteDerivedCompleted(
	ctx context.Context,
	id string,
	owner uint64,
) error {
	return adapter.Service.DeleteDerivedCompleted(ctx, id, owner)
}

type TaskServiceAdapter struct {
	Service *task.Service
}

func (adapter TaskServiceAdapter) Create(
	ctx context.Context,
	userID uint64,
	role auth.Role,
	uploadID string,
	name string,
	idempotencyKey string,
) (string, bool, error) {
	value, created, err := adapter.Service.Create(
		ctx, userID, role, uploadID, name, idempotencyKey,
	)
	return value.ID, created, err
}
