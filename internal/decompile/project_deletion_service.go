package decompile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"binaryscan/internal/auth"
)

func (s *Service) PreviewProjectDeletion(
	ctx context.Context,
	input SourceProjectDeletionPreviewInput,
) (SourceProjectDeletionPreview, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectDeletionPreview{}, err
	}
	if !validProjectDeletionActor(input.TaskID, input.ProjectID, input.UserID, input.Role) {
		return SourceProjectDeletionPreview{}, ErrInvalidInput
	}
	repository, err := s.projectDeletionRepository()
	if err != nil {
		return SourceProjectDeletionPreview{}, err
	}
	var entropy [32]byte
	if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
		return SourceProjectDeletionPreview{}, fmt.Errorf("generate source project deletion token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	digest := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	expiresAt := now.Add(SourceProjectDeletionTokenTTL)
	counts, err := repository.CreateSourceProjectDeletionPreview(
		ctx,
		sourceProjectDeletionPreviewRecord{
			TaskID: input.TaskID, ProjectID: input.ProjectID, UserID: input.UserID,
			TokenHash: hex.EncodeToString(digest[:]), ExpiresAt: expiresAt,
		},
	)
	if err != nil {
		return SourceProjectDeletionPreview{}, err
	}
	return SourceProjectDeletionPreview{
		ProjectID: input.ProjectID, Counts: counts,
		TypedSuffix:       deletionTypedSuffix(input.ProjectID),
		ConfirmationToken: token, ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) ConfirmProjectDeletion(
	ctx context.Context,
	input ConfirmSourceProjectDeletionInput,
) (SourceProjectDeletionOperation, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	if !validProjectDeletionActor(input.TaskID, input.ProjectID, input.UserID, input.Role) ||
		!input.Cascade || input.TypedSuffix != deletionTypedSuffix(input.ProjectID) {
		return SourceProjectDeletionOperation{}, ErrInvalidInput
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(input.ConfirmationToken)
	if err != nil || len(rawToken) != 32 ||
		base64.RawURLEncoding.EncodeToString(rawToken) != input.ConfirmationToken {
		return SourceProjectDeletionOperation{}, ErrDeletionConfirmationInvalid
	}
	repository, err := s.projectDeletionRepository()
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	operationID, err := s.newID()
	if err != nil {
		return SourceProjectDeletionOperation{}, fmt.Errorf("generate source project deletion operation ID: %w", err)
	}
	if !uuidPattern.MatchString(operationID) {
		return SourceProjectDeletionOperation{}, errors.New("source project deletion ID generator returned an invalid UUID")
	}
	digest := sha256.Sum256([]byte(input.ConfirmationToken))
	return repository.ConfirmSourceProjectDeletion(
		ctx,
		sourceProjectDeletionConfirmRecord{
			TaskID: input.TaskID, ProjectID: input.ProjectID, UserID: input.UserID,
			TokenHash: hex.EncodeToString(digest[:]), TypedSuffix: input.TypedSuffix,
			OperationID: operationID, CreatedAt: s.now().UTC(),
		},
	)
}

func (s *Service) GetProjectDeletion(
	ctx context.Context,
	query SourceProjectDeletionOperationQuery,
) (SourceProjectDeletionOperation, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) || !uuidPattern.MatchString(query.OperationID) {
		return SourceProjectDeletionOperation{}, ErrInvalidInput
	}
	repository, err := s.projectDeletionRepository()
	if err != nil {
		return SourceProjectDeletionOperation{}, err
	}
	return repository.GetSourceProjectDeletionOperation(ctx, query)
}

func (s *Service) projectDeletionRepository() (sourceProjectDeletionRepository, error) {
	repository, ok := s.repository.(sourceProjectDeletionRepository)
	if !ok {
		return nil, errors.New("source project deletion repository is unavailable")
	}
	return repository, nil
}

func validProjectDeletionActor(
	taskID string,
	projectID string,
	userID uint64,
	role auth.Role,
) bool {
	return uuidPattern.MatchString(taskID) && uuidPattern.MatchString(projectID) &&
		userID > 0 && (role == auth.RoleAdministrator || role == auth.RoleOperator)
}
