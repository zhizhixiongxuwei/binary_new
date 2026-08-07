package manualimagescan

import (
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/trivyhandoff"
)

type CreateInput struct {
	TaskID         string
	FileNodeID     uint64
	UserID         uint64
	Role           auth.Role
	IdempotencyKey string
}

type CreateRecord struct {
	JobID         string
	TaskID        string
	FileNodeID    uint64
	UserID        uint64
	JobRequestKey string
}

type Request struct {
	JobID      string    `json:"job_id"`
	TaskID     string    `json:"task_id"`
	FileNodeID string    `json:"file_node_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type target struct {
	Source trivyhandoff.Source
}
