package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"binaryscan/internal/requestctx"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUnauthenticated    = errors.New("authentication is required")
	ErrCSRF               = errors.New("CSRF token is invalid")
	ErrPasswordReuse      = errors.New("new password must differ from current password")
	ErrPasswordPolicy     = errors.New("new password does not satisfy password policy")
)

type ServiceConfig struct {
	PasswordParameters   PasswordParameters
	MinimumPasswordBytes int
	SessionTTL           time.Duration
	FailureThreshold     uint32
	LockDuration         time.Duration
	LoginRateLimit       LoginRateLimitPolicy
	LoginAudit           LoginAuditRecorder
}

type Service struct {
	repository Repository
	config     ServiceConfig
	now        func() time.Time
	dummyHash  string
}

func NewService(repository Repository, config ServiceConfig) (*Service, error) {
	if repository == nil {
		return nil, errors.New("auth repository is required")
	}
	if err := config.PasswordParameters.Validate(); err != nil {
		return nil, err
	}
	if config.MinimumPasswordBytes == 0 {
		config.MinimumPasswordBytes = DefaultMinimumPasswordBytes
	}
	if err := ValidatePasswordMinimum(config.MinimumPasswordBytes); err != nil {
		return nil, err
	}
	if config.SessionTTL <= 0 || config.FailureThreshold == 0 || config.LockDuration <= 0 {
		return nil, errors.New("session TTL, failure threshold, and lock duration must be positive")
	}
	if !config.LoginRateLimit.valid() {
		return nil, errors.New("login rate limit policy is invalid")
	}
	// A fixed dummy password produces the same expensive Argon2id work for unknown users.
	dummyHash, err := HashPassword([]byte("binaryscan-dummy-password-never-used"), config.PasswordParameters)
	if err != nil {
		return nil, fmt.Errorf("create dummy password hash: %w", err)
	}
	return &Service{
		repository: repository,
		config:     config,
		now:        time.Now,
		dummyHash:  dummyHash,
	}, nil
}

func (s *Service) Login(
	ctx context.Context,
	username string,
	password []byte,
	clientIP []byte,
	userAgent string,
) (result LoginResult, resultErr error) {
	var auditActorID *uint64
	defer func() {
		if s.config.LoginAudit == nil {
			return
		}
		outcome := "failure"
		reason := "invalid_credentials"
		if resultErr == nil {
			outcome = "success"
			reason = "authenticated"
		} else if errors.Is(resultErr, ErrLoginRateLimited) {
			reason = "rate_limited"
		} else if !errors.Is(resultErr, ErrInvalidCredentials) {
			reason = "internal_error"
		}
		auditContext, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			time.Second,
		)
		defer cancel()
		_ = s.config.LoginAudit.RecordLogin(auditContext, LoginAuditEvent{
			ActorUserID: auditActorID,
			RequestID:   requestctx.RequestID(ctx),
			Outcome:     outcome,
			ClientIP:    append([]byte(nil), clientIP...),
			UserAgent:   auditUserAgent(userAgent),
			Metadata:    map[string]any{"reason": reason},
		})
	}()
	attempt, err := s.repository.BeginLoginAttempt(
		ctx,
		normalizeLoginClientKey(clientIP),
		s.config.LoginRateLimit,
	)
	if err != nil {
		return LoginResult{}, fmt.Errorf(
			"check login rate limit: %w",
			err,
		)
	}
	if attempt.Limited {
		return LoginResult{}, NewLoginRateLimitedError(
			attempt.RetryAfter,
		)
	}
	defer func() {
		finishContext, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			2*time.Second,
		)
		defer cancel()
		err := s.repository.FinishLoginAttempt(
			finishContext,
			attempt,
			errors.Is(resultErr, ErrInvalidCredentials),
			s.config.LoginRateLimit,
		)
		if err != nil && resultErr != nil {
			resultErr = fmt.Errorf(
				"complete login rate limit: %w",
				err,
			)
		}
	}()
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 64 {
		s.performDummyPasswordWork(password)
		return LoginResult{}, ErrInvalidCredentials
	}

	user, err := s.repository.FindUserByUsername(ctx, username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return LoginResult{}, fmt.Errorf("find login user: %w", err)
	}
	valid := false
	if !s.passwordLengthValid(password) {
		s.performDummyPasswordWork(password)
	} else {
		hash := s.dummyHash
		if err == nil {
			hash = user.PasswordHash
		}
		var verifyErr error
		valid, verifyErr = VerifyPassword(password, hash)
		if verifyErr != nil {
			if err == nil {
				return LoginResult{}, fmt.Errorf("verify stored password: %w", verifyErr)
			}
			valid = false
		}
	}
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	actorID := user.ID
	auditActorID = &actorID

	now := s.now().UTC()
	locked := user.LockedUntil != nil && user.LockedUntil.After(now)
	if !valid {
		if user.Status == "active" && !locked {
			if recordErr := s.repository.RecordLoginFailure(
				ctx, user.ID, s.config.FailureThreshold, now, now.Add(s.config.LockDuration),
			); recordErr != nil {
				return LoginResult{}, recordErr
			}
		}
		return LoginResult{}, ErrInvalidCredentials
	}
	if locked || user.Status != "active" || !user.Role.Valid() {
		return LoginResult{}, ErrInvalidCredentials
	}

	sessionToken, tokenHash, err := newToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrfToken, csrfHash, err := newToken()
	if err != nil {
		return LoginResult{}, err
	}
	sessionID, err := newUUID()
	if err != nil {
		return LoginResult{}, err
	}
	session := Session{
		ID: sessionID,
		User: Principal{
			UserID:              user.ID,
			PublicID:            user.PublicID,
			Username:            user.Username,
			DisplayName:         user.DisplayName,
			Role:                user.Role,
			ForcePasswordChange: user.ForcePasswordChange,
		},
		CSRFTokenHash: csrfHash,
		ExpiresAt:     now.Add(s.config.SessionTTL),
		LastSeenAt:    now,
	}
	if err := s.repository.CompleteLogin(ctx, user.ID, user.PasswordHash, NewSession{
		ID: session.ID, UserID: user.ID, TokenHash: tokenHash, CSRFTokenHash: csrfHash,
		ExpiresAt: session.ExpiresAt, ClientIP: clientIP, UserAgent: truncate(userAgent, 512),
	}, now); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionToken: sessionToken, CSRFToken: csrfToken, Session: session}, nil
}

func (s *Service) Authenticate(ctx context.Context, sessionToken string) (Session, error) {
	if sessionToken == "" || len(sessionToken) > 256 {
		return Session{}, ErrUnauthenticated
	}
	tokenHash := sha256.Sum256([]byte(sessionToken))
	session, err := s.repository.FindSessionByTokenHash(ctx, tokenHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrUnauthenticated
	}
	if err != nil {
		return Session{}, fmt.Errorf("find session: %w", err)
	}
	now := s.now().UTC()
	if session.RevokedAt != nil || !session.ExpiresAt.After(now) || !session.User.Role.Valid() {
		return Session{}, ErrUnauthenticated
	}
	renewBefore := now.Add(s.config.SessionTTL / 2)
	if !session.ExpiresAt.After(renewBefore) {
		expiresAt, err := s.repository.RenewSession(
			ctx,
			session.ID,
			now,
			renewBefore,
			now.Add(s.config.SessionTTL),
		)
		if errors.Is(err, ErrUnauthenticated) {
			return Session{}, ErrUnauthenticated
		}
		if err != nil {
			return Session{}, fmt.Errorf("renew session: %w", err)
		}
		session.ExpiresAt = expiresAt
		session.LastSeenAt = now
	} else if err := s.repository.TouchSession(ctx, session.ID, now); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s *Service) ValidateCSRF(session Session, token string) error {
	if token == "" || len(token) > 256 {
		return ErrCSRF
	}
	actual := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(actual[:], session.CSRFTokenHash[:]) != 1 {
		return ErrCSRF
	}
	return nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.repository.RevokeSession(ctx, sessionID, s.now().UTC())
}

func (s *Service) ChangePassword(
	ctx context.Context,
	session Session,
	currentPassword []byte,
	newPassword []byte,
) (Principal, error) {
	user, err := s.repository.FindUserByID(ctx, session.User.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, fmt.Errorf("find password owner: %w", err)
	}
	if user.Status != "active" {
		return Principal{}, ErrUnauthenticated
	}
	if !s.passwordLengthValid(currentPassword) {
		s.performDummyPasswordWork(currentPassword)
		return Principal{}, ErrInvalidCredentials
	}
	currentValid, err := VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil {
		return Principal{}, fmt.Errorf("verify current password: %w", err)
	}
	if !currentValid {
		return Principal{}, ErrInvalidCredentials
	}
	if s.passwordLengthValid(newPassword) {
		if same, err := VerifyPassword(newPassword, user.PasswordHash); err == nil && same {
			return Principal{}, ErrPasswordReuse
		}
	}
	newHash, err := HashPasswordWithMinimum(
		newPassword,
		s.config.PasswordParameters,
		s.config.MinimumPasswordBytes,
	)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrPasswordPolicy, err)
	}
	if err := s.repository.UpdatePassword(
		ctx, user.ID, session.ID, newHash, user.PasswordHash, s.now().UTC(),
	); err != nil {
		return Principal{}, err
	}
	user.ForcePasswordChange = false
	return Principal{
		UserID: user.ID, PublicID: user.PublicID, Username: user.Username,
		DisplayName: user.DisplayName, Role: user.Role, ForcePasswordChange: false,
	}, nil
}

func (s *Service) CreateInitialAdministrator(ctx context.Context, username, displayName string, password []byte) error {
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	if username == "" || len(username) > 64 || displayName == "" || len(displayName) > 128 {
		return errors.New("administrator username or display name is invalid")
	}
	hash, err := HashPasswordWithMinimum(
		password,
		s.config.PasswordParameters,
		s.config.MinimumPasswordBytes,
	)
	if err != nil {
		return err
	}
	publicID, err := newUUID()
	if err != nil {
		return err
	}
	return s.repository.CreateInitialAdministrator(ctx, User{
		PublicID: publicID, Username: username, DisplayName: displayName,
		PasswordHash: hash, Role: RoleAdministrator, Status: "active", ForcePasswordChange: false,
	})
}

func newToken() (string, [sha256.Size]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate authentication token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	return token, sha256.Sum256([]byte(token)), nil
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func (s *Service) passwordLengthValid(password []byte) bool {
	return len(password) >= s.config.MinimumPasswordBytes &&
		len(password) <= MaximumPasswordBytes
}

func (s *Service) performDummyPasswordWork(password []byte) {
	dummy := password
	if !s.passwordLengthValid(dummy) {
		dummy = []byte("binaryscan-invalid-length-dummy")
	}
	_, _ = VerifyPassword(dummy, s.dummyHash)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func auditUserAgent(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	characters := []rune(value)
	if len(characters) > 512 {
		return string(characters[:512])
	}
	return value
}
