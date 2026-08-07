package scan

import (
	"context"
	"encoding/json"
	"io"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivyhandoff"
)

const TrivyJobPayloadSchemaVersion = trivyhandoff.SchemaVersion

type Sample struct {
	TaskID      string
	UploadID    string
	BlobID      uint64
	DisplayName string
	SizeBytes   int64
	SHA256      string
	StorageKey  string
	Limits      extract.Limits
}

type RootNode struct {
	LogicalPath     string
	LogicalPathHash [32]byte
	DisplayName     string
	Format          string
	MIMEType        string
	Architecture    string
	SizeBytes       int64
	SHA256          string
	StorageKey      string
	MetadataJSON    json.RawMessage
}

type TrivySource = trivyhandoff.Source
type TrivyJobPayload = trivyhandoff.Payload

type Repository interface {
	Load(context.Context, queue.Lease) (Sample, error)
	Publish(context.Context, queue.Lease, RootNode) error
	PublishTree(context.Context, queue.Lease, string, []extract.Node) error
	EnqueueTrivy(context.Context, queue.Lease, TrivyJobPayload) error
}

type ProgressReporter interface {
	TaskProgress(context.Context, queue.Lease, queue.ProgressInput) error
}

type Detector interface {
	Detect(io.ReaderAt, int64) (filetype.Result, error)
}
