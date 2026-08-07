package manualimagescan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"binaryscan/internal/auth"
)

var uuidPattern = regexp.MustCompile(
	`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
)

type Repository interface {
	Enqueue(context.Context, CreateRecord) (Request, bool, error)
}

type Config struct {
	NewID func() (string, error)
}

type Service struct {
	repository Repository
	newID      func() (string, error)
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("manual image scan repository is required")
	}
	if config.NewID == nil {
		config.NewID = newUUID
	}
	return &Service{repository: repository, newID: config.NewID}, nil
}

func (service *Service) Create(
	ctx context.Context,
	input CreateInput,
) (Request, bool, error) {
	if ctx == nil {
		return Request{}, false, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return Request{}, false, err
	}
	if !uuidPattern.MatchString(input.TaskID) || input.FileNodeID == 0 ||
		input.UserID == 0 ||
		(input.Role != auth.RoleAdministrator &&
			input.Role != auth.RoleOperator) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return Request{}, false, ErrInvalidInput
	}
	jobID, err := service.newID()
	if err != nil {
		return Request{}, false, fmt.Errorf(
			"generate manual image scan job ID: %w",
			err,
		)
	}
	if !uuidPattern.MatchString(jobID) {
		return Request{}, false, errors.New(
			"manual image scan ID generator returned an invalid UUID",
		)
	}
	keyHash := sha256.Sum256([]byte(input.IdempotencyKey))
	return service.repository.Enqueue(ctx, CreateRecord{
		JobID:         jobID,
		TaskID:        input.TaskID,
		FileNodeID:    input.FileNodeID,
		UserID:        input.UserID,
		JobRequestKey: "image:manual:" + hex.EncodeToString(keyHash[:]),
	})
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
