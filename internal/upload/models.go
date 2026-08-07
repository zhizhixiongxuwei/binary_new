package upload

import "time"

const DefaultPartSize int64 = 32 * 1024 * 1024

type Upload struct {
	ID             string
	CreatedBy      uint64
	OriginalName   []byte
	DisplayName    string
	ContentType    string
	DeclaredSize   int64
	PartSize       int64
	ExpectedSHA256 string
	ActualSHA256   string
	Status         string
	BlobID         *uint64
	ExpiresAt      time.Time
	CompletedAt    *time.Time
	PartsCleanedAt *time.Time
	CreatedAt      time.Time
}

type Part struct {
	UploadID     string
	Number       uint32
	Size         int64
	SHA256       string
	ContentRange string
	StorageKey   string
	CreatedAt    time.Time
}

type Range struct {
	Start int64
	End   int64
	Total int64
	Raw   string
}

func (r Range) Size() int64 {
	return r.End - r.Start + 1
}

type View struct {
	ID            string    `json:"id"`
	PartSize      int64     `json:"part_size"`
	Status        string    `json:"status"`
	UploadedParts []uint32  `json:"uploaded_parts"`
	ExpiresAt     time.Time `json:"expires_at"`
	SHA256        string    `json:"sha256,omitempty"`
	SizeBytes     *int64    `json:"size_bytes,omitempty"`
}

type CreateInput struct {
	Filename       string
	Size           int64
	ContentType    string
	CreatedBy      uint64
	IdempotencyKey string
}
