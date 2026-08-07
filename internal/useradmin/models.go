package useradmin

import (
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"
)

type User struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	Role               auth.Role  `json:"role"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	FailedLoginCount   uint32     `json:"failed_login_count"`
	LockedUntil        *time.Time `json:"locked_until"`
	LastLoginAt        *time.Time `json:"last_login_at"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`

	internalID   uint64
	storedStatus string
}

type ListQuery struct {
	Cursor   string
	PageSize int
	Keyword  string
	Role     string
	Status   string
}

type RepositoryListQuery struct {
	Cursor   uint64
	PageSize int
	Keyword  string
	Role     auth.Role
	Status   string
}

type Page struct {
	Items      []User `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type AuditContext struct {
	ActorUserID uint64
	RequestID   string
	ClientIP    []byte
	UserAgent   string
}

func (c AuditContext) Event(
	action string,
	objectID string,
	outcome audit.Outcome,
	metadata map[string]any,
) audit.Event {
	actorID := c.ActorUserID
	return audit.Event{
		ActorUserID: &actorID,
		RequestID:   c.RequestID,
		Action:      action,
		ObjectType:  "user",
		ObjectID:    objectID,
		Outcome:     outcome,
		ClientIP:    c.ClientIP,
		UserAgent:   c.UserAgent,
		Metadata:    metadata,
	}
}

type CreateRecord struct {
	PublicID     string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         auth.Role
	CreatedAt    time.Time
	Audit        audit.Event
}

type UpdateRecord struct {
	ActorUserID       uint64
	PublicID          string
	Role              *auth.Role
	Status            *string
	ExpectedUpdatedAt time.Time
	UpdatedAt         time.Time
	Audit             audit.Event
}

type ResetPasswordRecord struct {
	PublicID          string
	PasswordHash      string
	ExpectedUpdatedAt time.Time
	UpdatedAt         time.Time
	Audit             audit.Event
}
