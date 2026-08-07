package manualimagescan

import (
	"context"
	"errors"
	"testing"

	"binaryscan/internal/auth"
)

const (
	testTaskID = "123e4567-e89b-42d3-a456-426614174000"
	testJobID  = "223e4567-e89b-42d3-a456-426614174001"
)

type repositoryStub struct {
	record  CreateRecord
	request Request
	created bool
	err     error
}

func (stub *repositoryStub) Enqueue(
	_ context.Context,
	record CreateRecord,
) (Request, bool, error) {
	stub.record = record
	return stub.request, stub.created, stub.err
}

func TestServiceCreatesBoundedImageJobRecord(t *testing.T) {
	repository := &repositoryStub{created: true}
	service, err := NewService(repository, Config{
		NewID: func() (string, error) { return testJobID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, created, err := service.Create(context.Background(), CreateInput{
		TaskID:         testTaskID,
		FileNodeID:     42,
		UserID:         7,
		Role:           auth.RoleOperator,
		IdempotencyKey: "manual-image-intent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || repository.record.JobID != testJobID ||
		repository.record.TaskID != testTaskID ||
		repository.record.FileNodeID != 42 ||
		repository.record.UserID != 7 ||
		len(repository.record.JobRequestKey) != len("image:manual:")+64 {
		t.Fatalf("enqueue record = %#v", repository.record)
	}
}

func TestServiceRejectsReadOnlyRoleAndMalformedInput(t *testing.T) {
	service, err := NewService(&repositoryStub{}, Config{
		NewID: func() (string, error) { return testJobID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []CreateInput{
		{
			TaskID: testTaskID, FileNodeID: 42, UserID: 7,
			Role: auth.RoleReader, IdempotencyKey: "key",
		},
		{
			TaskID: "invalid", FileNodeID: 42, UserID: 7,
			Role: auth.RoleOperator, IdempotencyKey: "key",
		},
		{
			TaskID: testTaskID, FileNodeID: 0, UserID: 7,
			Role: auth.RoleOperator, IdempotencyKey: "key",
		},
	} {
		if _, _, err := service.Create(context.Background(), input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("Create(%#v) error = %v", input, err)
		}
	}
}
