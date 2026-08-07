package useradmin

import "errors"

var (
	ErrInvalidInput      = errors.New("user administration input is invalid")
	ErrForbidden         = errors.New("user administration permission denied")
	ErrNotFound          = errors.New("user was not found")
	ErrConflict          = errors.New("user state changed")
	ErrUsernameExists    = errors.New("username already exists")
	ErrCurrentUserGuard  = errors.New("current administrator cannot disable or demote itself")
	ErrLastAdministrator = errors.New("last active administrator cannot be removed")
)
