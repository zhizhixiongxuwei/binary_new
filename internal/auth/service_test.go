package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type repositoryStub struct {
	loginAttempt        LoginAttempt
	loginAttemptErr     error
	loginAttemptCalls   int
	finishedAttempt     LoginAttempt
	finishedFailed      bool
	finishAttemptCalls  int
	finishAttemptErr    error
	finishContextErr    error
	findUserCalls       int
	user                User
	userErr             error
	failureCalls        int
	completedSession    NewSession
	session             Session
	sessionErr          error
	touched             bool
	renewed             bool
	renewedExpiresAt    time.Time
	revoked             bool
	administrator       User
	passwordUser        User
	updatedPasswordHash string
}

func (r *repositoryStub) BeginLoginAttempt(
	_ context.Context,
	clientKey [sha256.Size]byte,
	_ LoginRateLimitPolicy,
) (LoginAttempt, error) {
	r.loginAttemptCalls++
	attempt := r.loginAttempt
	if attempt.ClientKey == ([sha256.Size]byte{}) {
		attempt.ClientKey = clientKey
	}
	if !attempt.Limited && attempt.WindowStartedAt.IsZero() {
		attempt.WindowStartedAt = time.Date(
			2026, time.July, 31, 0, 0, 0, 0, time.UTC,
		)
	}
	return attempt, r.loginAttemptErr
}
func (r *repositoryStub) FinishLoginAttempt(
	ctx context.Context,
	attempt LoginAttempt,
	failed bool,
	_ LoginRateLimitPolicy,
) error {
	r.finishAttemptCalls++
	r.finishContextErr = ctx.Err()
	r.finishedAttempt = attempt
	r.finishedFailed = failed
	return r.finishAttemptErr
}
func (r *repositoryStub) FindUserByUsername(context.Context, string) (User, error) {
	r.findUserCalls++
	return r.user, r.userErr
}
func (r *repositoryStub) FindUserByID(context.Context, uint64) (User, error) {
	return r.passwordUser, nil
}
func (r *repositoryStub) RecordLoginFailure(context.Context, uint64, uint32, time.Time, time.Time) error {
	r.failureCalls++
	return nil
}
func (r *repositoryStub) CompleteLogin(_ context.Context, _ uint64, _ string, session NewSession, _ time.Time) error {
	r.completedSession = session
	return nil
}
func (r *repositoryStub) FindSessionByTokenHash(context.Context, [sha256.Size]byte) (Session, error) {
	return r.session, r.sessionErr
}
func (r *repositoryStub) TouchSession(context.Context, string, time.Time) error {
	r.touched = true
	return nil
}
func (r *repositoryStub) RenewSession(
	_ context.Context,
	_ string,
	_ time.Time,
	_ time.Time,
	newExpiresAt time.Time,
) (time.Time, error) {
	r.renewed = true
	if !r.renewedExpiresAt.IsZero() {
		return r.renewedExpiresAt, nil
	}
	return newExpiresAt, nil
}
func (r *repositoryStub) RevokeSession(context.Context, string, time.Time) error {
	r.revoked = true
	return nil
}
func (r *repositoryStub) UpdatePassword(_ context.Context, _ uint64, _ string, hash, _ string, _ time.Time) error {
	r.updatedPasswordHash = hash
	return nil
}
func (r *repositoryStub) CreateInitialAdministrator(_ context.Context, user User) error {
	r.administrator = user
	return nil
}

func TestLoginCreatesHashedOpaqueSession(t *testing.T) {
	password := []byte("a-secure-test-password")
	hash, err := HashPassword(password, testPasswordParameters())
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{user: User{
		ID: 42, PublicID: "user-id", Username: "admin", DisplayName: "Admin",
		PasswordHash: hash, Role: RoleAdministrator, Status: "active",
	}}
	service := newTestService(t, repository)

	result, err := service.Login(context.Background(), "admin", password, []byte{127, 0, 0, 1}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if result.SessionToken == "" || result.CSRFToken == "" || repository.completedSession.ID == "" {
		t.Fatalf("incomplete login result: %#v", result)
	}
	if repository.completedSession.TokenHash != sha256.Sum256([]byte(result.SessionToken)) {
		t.Fatal("repository did not receive the session token hash")
	}
	if err := service.ValidateCSRF(result.Session, result.CSRFToken); err != nil {
		t.Fatalf("ValidateCSRF() error = %v", err)
	}
	if repository.finishAttemptCalls != 1 ||
		repository.finishedFailed {
		t.Fatalf(
			"successful rate finish calls/failed = %d/%v",
			repository.finishAttemptCalls,
			repository.finishedFailed,
		)
	}
}

func TestLoginRecordsFailureAndHidesUnknownUsers(t *testing.T) {
	password := []byte("a-secure-test-password")
	hash, err := HashPassword(password, testPasswordParameters())
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{user: User{
		ID: 1, Username: "operator", PasswordHash: hash, Role: RoleOperator, Status: "active",
	}}
	service := newTestService(t, repository)
	_, err = service.Login(context.Background(), "operator", []byte("wrong-password-value"), nil, "")
	if !errors.Is(err, ErrInvalidCredentials) || repository.failureCalls != 1 {
		t.Fatalf("Login() error/calls = %v/%d", err, repository.failureCalls)
	}
	if repository.finishAttemptCalls != 1 || !repository.finishedFailed {
		t.Fatalf(
			"rate limit finish calls/failed = %d/%v",
			repository.finishAttemptCalls,
			repository.finishedFailed,
		)
	}

	repository.userErr = sql.ErrNoRows
	_, err = service.Login(context.Background(), "missing", []byte("wrong-password-value"), nil, "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user error = %v", err)
	}
	if repository.finishAttemptCalls != 2 || !repository.finishedFailed {
		t.Fatalf(
			"unknown user rate finish calls/failed = %d/%v",
			repository.finishAttemptCalls,
			repository.finishedFailed,
		)
	}
}

func TestLoginRateLimitPreflightDoesNotRevealAccountExistence(t *testing.T) {
	retryAfter := 37 * time.Second
	for _, test := range []struct {
		name       string
		repository *repositoryStub
	}{
		{
			name: "known user",
			repository: &repositoryStub{user: User{
				ID: 7, Username: "known", Status: "active",
			}},
		},
		{
			name:       "unknown user",
			repository: &repositoryStub{userErr: sql.ErrNoRows},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.repository.loginAttempt = LoginAttempt{
				Limited: true, RetryAfter: retryAfter,
			}
			service := newTestService(t, test.repository)
			_, err := service.Login(
				context.Background(),
				"known",
				[]byte("a-secure-test-password"),
				[]byte{192, 0, 2, 1},
				"browser",
			)
			if !errors.Is(err, ErrLoginRateLimited) ||
				LoginRateLimitRetryAfter(err) != retryAfter {
				t.Fatalf("Login() error = %v", err)
			}
			if test.repository.findUserCalls != 0 ||
				test.repository.finishAttemptCalls != 0 {
				t.Fatalf(
					"user/finish calls = %d/%d",
					test.repository.findUserCalls,
					test.repository.finishAttemptCalls,
				)
			}
		})
	}
}

func TestLoginRateLimitUsesCanonicalClientKeys(t *testing.T) {
	var keys [][sha256.Size]byte
	for _, clientIP := range [][]byte{
		nil,
		{},
		{192, 0, 2, 9},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 9},
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9},
	} {
		repository := &repositoryStub{userErr: sql.ErrNoRows}
		service := newTestService(t, repository)
		_, err := service.Login(
			context.Background(), "missing",
			[]byte("wrong-password-value"), clientIP, "",
		)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatal(err)
		}
		keys = append(keys, repository.finishedAttempt.ClientKey)
	}
	if keys[0] != keys[1] {
		t.Fatal("nil and empty IP did not use the same sentinel key")
	}
	if keys[2] != keys[3] {
		t.Fatal("IPv4 and IPv4-mapped IPv6 did not use the same key")
	}
	if keys[0] == keys[2] || keys[2] == keys[4] {
		t.Fatal("unrelated client address families shared a key")
	}
}

func TestLoginRateLimitCompletionSurvivesCancelledContext(t *testing.T) {
	repository := &repositoryStub{userErr: sql.ErrNoRows}
	service := newTestService(t, repository)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Login(
		ctx, "missing", []byte("wrong-password-value"), nil, "",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if repository.finishAttemptCalls != 1 ||
		repository.finishContextErr != nil {
		t.Fatalf(
			"finish calls/context error = %d/%v",
			repository.finishAttemptCalls,
			repository.finishContextErr,
		)
	}
}

func TestLoginRateLimitCompletionFailureFailsClosed(t *testing.T) {
	repository := &repositoryStub{
		userErr:          sql.ErrNoRows,
		finishAttemptErr: errors.New("database unavailable"),
	}
	service := newTestService(t, repository)
	_, err := service.Login(
		context.Background(), "missing",
		[]byte("wrong-password-value"), nil, "",
	)
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want internal error", err)
	}
}

func TestShortPasswordCannotAuthenticateAccountUsingOldDummyConstant(t *testing.T) {
	actualPassword := []byte("invalid-password-padding")
	hash, err := HashPassword(actualPassword, testPasswordParameters())
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{user: User{
		ID: 1, Username: "operator", PasswordHash: hash, Role: RoleOperator, Status: "active",
	}}
	service := newTestService(t, repository)
	if _, err := service.Login(context.Background(), "operator", []byte("short"), nil, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("short password Login() error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := service.Login(context.Background(), "operator", actualPassword, nil, ""); err != nil {
		t.Fatalf("correct password Login() error = %v", err)
	}
}

func TestDefaultPolicyAllowsFixedInitialAdministratorCredential(t *testing.T) {
	password := []byte("admin123456")
	hash, err := HashPasswordWithMinimum(
		password,
		testPasswordParameters(),
		MinimumAcceptedPasswordBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	newRepository := func() *repositoryStub {
		return &repositoryStub{user: User{
			ID: 1, Username: "admin", PasswordHash: hash,
			Role: RoleAdministrator, Status: "active",
		}}
	}
	productionService := newTestService(t, newRepository())
	if _, err := productionService.Login(
		context.Background(), "admin", password, nil, "",
	); err != nil {
		t.Fatalf("default Login() error = %v", err)
	}
	developmentService, err := NewService(newRepository(), ServiceConfig{
		PasswordParameters:   testPasswordParameters(),
		MinimumPasswordBytes: MinimumAcceptedPasswordBytes,
		SessionTTL:           time.Hour,
		FailureThreshold:     5,
		LockDuration:         time.Minute,
		LoginRateLimit: LoginRateLimitPolicy{
			Threshold: 10, Window: time.Minute,
			BlockDuration: 5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := developmentService.Login(
		context.Background(), "admin", password, nil, "",
	); err != nil {
		t.Fatalf("development Login() error = %v", err)
	}
}

func TestInitialAdministratorDoesNotRequirePasswordChange(t *testing.T) {
	repository := &repositoryStub{}
	service := newTestService(t, repository)
	if err := service.CreateInitialAdministrator(
		context.Background(), "admin", "Administrator", []byte("admin123456"),
	); err != nil {
		t.Fatal(err)
	}
	if repository.administrator.ForcePasswordChange {
		t.Fatal("initial administrator unexpectedly requires a password change")
	}
}

func TestAuthenticateRejectsExpiredSession(t *testing.T) {
	repository := &repositoryStub{session: Session{
		ID: "session", User: Principal{Role: RoleReader},
		ExpiresAt: time.Now().Add(-time.Minute),
	}}
	service := newTestService(t, repository)
	if _, err := service.Authenticate(context.Background(), "opaque-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if repository.touched {
		t.Fatal("expired session was touched")
	}
}

func TestAuthenticateRenewsSessionInsideSlidingWindow(t *testing.T) {
	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)
	repository := &repositoryStub{session: Session{
		ID: "session", User: Principal{Role: RoleReader},
		ExpiresAt: now.Add(20 * time.Minute),
	}}
	service := newTestService(t, repository)
	service.now = func() time.Time { return now }

	session, err := service.Authenticate(context.Background(), "opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	if !repository.renewed || repository.touched {
		t.Fatalf(
			"renewed/touched = %v/%v, want true/false",
			repository.renewed,
			repository.touched,
		)
	}
	if want := now.Add(time.Hour); !session.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", session.ExpiresAt, want)
	}
}

func TestAuthenticateOnlyTouchesSessionOutsideSlidingWindow(t *testing.T) {
	now := time.Date(2026, time.July, 31, 6, 0, 0, 0, time.UTC)
	repository := &repositoryStub{session: Session{
		ID: "session", User: Principal{Role: RoleReader},
		ExpiresAt: now.Add(31 * time.Minute),
	}}
	service := newTestService(t, repository)
	service.now = func() time.Time { return now }

	if _, err := service.Authenticate(
		context.Background(),
		"opaque-token",
	); err != nil {
		t.Fatal(err)
	}
	if repository.renewed || !repository.touched {
		t.Fatalf(
			"renewed/touched = %v/%v, want false/true",
			repository.renewed,
			repository.touched,
		)
	}
}

func TestChangePasswordClearsForcedChangeAndStoresNewHash(t *testing.T) {
	current := []byte("current-secure-password")
	hash, err := HashPassword(current, testPasswordParameters())
	if err != nil {
		t.Fatal(err)
	}
	repository := &repositoryStub{passwordUser: User{
		ID: 7, PublicID: "public", Username: "admin", DisplayName: "Admin",
		PasswordHash: hash, Role: RoleAdministrator, Status: "active", ForcePasswordChange: true,
	}}
	service := newTestService(t, repository)
	principal, err := service.ChangePassword(
		context.Background(),
		Session{ID: "current-session", User: Principal{UserID: 7}},
		current,
		[]byte("new-secure-password"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ForcePasswordChange || repository.updatedPasswordHash == "" {
		t.Fatalf("password change result = %#v, hash set=%v", principal, repository.updatedPasswordHash != "")
	}
	ok, err := VerifyPassword([]byte("new-secure-password"), repository.updatedPasswordHash)
	if err != nil || !ok {
		t.Fatalf("new password verification = %v, %v", ok, err)
	}
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, ServiceConfig{
		PasswordParameters: testPasswordParameters(),
		SessionTTL:         time.Hour, FailureThreshold: 5, LockDuration: time.Minute,
		LoginRateLimit: LoginRateLimitPolicy{
			Threshold: 10, Window: time.Minute,
			BlockDuration: 5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
