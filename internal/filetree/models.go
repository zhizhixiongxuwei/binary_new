package filetree

import "encoding/json"

type Node struct {
	ID               string           `json:"id"`
	ParentID         *string          `json:"parent_id"`
	LogicalPath      string           `json:"logical_path"`
	DisplayName      string           `json:"display_name"`
	ArchiveNameID    string           `json:"archive_name_id"`
	NodeType         string           `json:"node_type"`
	Depth            uint16           `json:"depth"`
	Format           string           `json:"format"`
	MIMEType         string           `json:"mime_type"`
	Architecture     string           `json:"architecture"`
	SizeBytes        *uint64          `json:"size_bytes"`
	SHA256           string           `json:"sha256"`
	ExtractionStatus string           `json:"extraction_status"`
	ErrorCode        string           `json:"error_code"`
	ErrorMessage     string           `json:"error_message"`
	SourceContainer  *SourceContainer `json:"source_container"`
	HasChildren      bool             `json:"has_children"`
}

type ListQuery struct {
	TaskID   string
	ParentID *uint64
	Cursor   uint64
	PageSize int
}

type Page struct {
	Items      []Node `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type GetQuery struct {
	TaskID string
	FileID uint64
}

type SourceParent struct {
	ID          string `json:"id"`
	LogicalPath string `json:"logical_path"`
}

type SourceContainer struct {
	ID          string `json:"id"`
	LogicalPath string `json:"logical_path"`
	Format      string `json:"format"`
}

type Detail struct {
	Node
	MetadataJSON json.RawMessage `json:"metadata_json"`
	SourceParent *SourceParent   `json:"source_parent"`
}
