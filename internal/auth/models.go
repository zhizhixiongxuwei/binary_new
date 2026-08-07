package auth

import (
	"crypto/sha256"
	"time"
)

type Role string

const (
	RoleAdministrator Role = "administrator"
	RoleOperator      Role = "operator"
	RoleReader        Role = "reader"
)

func (r Role) Valid() bool {
	return r == RoleAdministrator || r == RoleOperator || r == RoleReader
}

type User struct {
	ID                  uint64
	PublicID            string
	Username            string
	DisplayName         string
	PasswordHash        string
	Role                Role
	Status              string
	ForcePasswordChange bool
	FailedLoginCount    uint32
	LockedUntil         *time.Time
}

type Principal struct {
	UserID              uint64 `json:"-"`
	PublicID            string `json:"id"`
	Username            string `json:"username"`
	DisplayName         string `json:"display_name"`
	Role                Role   `json:"role"`
	ForcePasswordChange bool   `json:"must_change_password"`
}

type Session struct {
	ID            string
	User          Principal
	CSRFTokenHash [sha256.Size]byte
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	LastSeenAt    time.Time
}

type NewSession struct {
	ID            string
	UserID        uint64
	TokenHash     [sha256.Size]byte
	CSRFTokenHash [sha256.Size]byte
	ExpiresAt     time.Time
	ClientIP      []byte
	UserAgent     string
}

type LoginResult struct {
	SessionToken string
	CSRFToken    string
	Session      Session
}
