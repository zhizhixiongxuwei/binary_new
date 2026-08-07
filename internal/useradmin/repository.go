package useradmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"binaryscan/internal/audit"
	"binaryscan/internal/auth"

	"github.com/go-sql-driver/mysql"
)

const userSelectColumns = `
SELECT u.id, u.public_id, u.username, u.display_name, u.role, u.status,
       u.force_password_change, u.failed_login_count, u.locked_until,
       u.last_login_at, u.created_at, u.updated_at
FROM users u`

type rowScanner interface {
	Scan(...any) error
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) List(
	ctx context.Context,
	query RepositoryListQuery,
) (Page, error) {
	where := []string{"1 = 1"}
	arguments := make([]any, 0, 7)
	if query.Cursor != 0 {
		where = append(where, "u.id < ?")
		arguments = append(arguments, query.Cursor)
	}
	if query.Keyword != "" {
		keyword := "%" + escapeLike(query.Keyword) + "%"
		where = append(where, `(u.username LIKE ? ESCAPE '\\' OR u.display_name LIKE ? ESCAPE '\\')`)
		arguments = append(arguments, keyword, keyword)
	}
	if query.Role != "" {
		where = append(where, "u.role = ?")
		arguments = append(arguments, query.Role)
	}
	if query.Status != "" {
		switch query.Status {
		case "locked":
			where = append(
				where,
				"u.status = 'active' AND u.locked_until > UTC_TIMESTAMP(6)",
			)
		case "active":
			where = append(
				where,
				"u.status = 'active' AND (u.locked_until IS NULL OR u.locked_until <= UTC_TIMESTAMP(6))",
			)
		default:
			where = append(where, "u.status = ?")
			arguments = append(arguments, query.Status)
		}
	}
	arguments = append(arguments, query.PageSize+1)

	rows, err := r.db.QueryContext(
		ctx,
		userSelectColumns+`
WHERE `+strings.Join(where, " AND ")+`
ORDER BY u.id DESC
LIMIT ?`,
		arguments...,
	)
	if err != nil {
		return Page{}, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	items := make([]User, 0, query.PageSize)
	var continuation uint64
	for rows.Next() {
		item, err := scanUser(rows)
		if err != nil {
			return Page{}, fmt.Errorf("scan user list row: %w", err)
		}
		if len(items) == query.PageSize {
			continuation = items[len(items)-1].internalID
			break
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate users: %w", err)
	}
	page := Page{Items: items}
	if continuation != 0 {
		page.NextCursor = encodeCursor(continuation)
	}
	return page, nil
}

func (r *MySQLRepository) Create(
	ctx context.Context,
	record CreateRecord,
) (User, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user creation transaction: %w", err)
	}
	defer transaction.Rollback()

	result, err := transaction.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, 'active', TRUE, ?, ?)`,
		record.PublicID, record.Username, record.DisplayName, record.PasswordHash,
		record.Role, record.CreatedAt, record.CreatedAt,
	)
	if duplicateKeyName(err, "uq_users_username") {
		return User{}, ErrUsernameExists
	}
	if isDuplicateKey(err) {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	internalID, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("read created user ID: %w", err)
	}
	if internalID <= 0 {
		return User{}, errors.New("created user returned an invalid internal ID")
	}
	if err := audit.Append(ctx, transaction, record.Audit); err != nil {
		return User{}, err
	}
	user, err := queryUserByInternalID(ctx, transaction, uint64(internalID))
	if err != nil {
		return User{}, fmt.Errorf("read created user: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user creation: %w", err)
	}
	return user, nil
}

func (r *MySQLRepository) Update(
	ctx context.Context,
	record UpdateRecord,
) (User, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin user update transaction: %w", err)
	}
	defer transaction.Rollback()

	current, err := queryUserForUpdate(ctx, transaction, record.PublicID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("lock user for update: %w", err)
	}
	if !sameMySQLTimestamp(current.UpdatedAt, record.ExpectedUpdatedAt) {
		return User{}, ErrConflict
	}

	finalRole := current.Role
	if record.Role != nil {
		finalRole = *record.Role
	}
	finalStatus := current.storedStatus
	if record.Status != nil {
		finalStatus = *record.Status
	}
	if current.internalID == record.ActorUserID &&
		(finalStatus == "disabled" || finalRole != auth.RoleAdministrator) {
		return User{}, ErrCurrentUserGuard
	}
	if current.Role == auth.RoleAdministrator && current.storedStatus == "active" &&
		(finalRole != auth.RoleAdministrator || finalStatus != "active") {
		count, err := lockActiveAdministrators(ctx, transaction)
		if err != nil {
			return User{}, err
		}
		if count <= 1 {
			return User{}, ErrLastAdministrator
		}
	}

	stateChanged := finalRole != current.Role || finalStatus != current.storedStatus
	unlockRequested := record.Status != nil && *record.Status == "active" &&
		(current.FailedLoginCount != 0 || current.LockedUntil != nil)
	if stateChanged || unlockRequested {
		if _, err := transaction.ExecContext(ctx, `
UPDATE users
SET role = ?, status = ?,
    failed_login_count = CASE WHEN ? THEN 0 ELSE failed_login_count END,
    locked_until = CASE WHEN ? THEN NULL ELSE locked_until END,
    updated_at = ?
WHERE id = ?`,
			finalRole, finalStatus, unlockRequested, unlockRequested,
			record.UpdatedAt, current.internalID,
		); err != nil {
			return User{}, fmt.Errorf("update user role and status: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE user_id = ? AND revoked_at IS NULL`,
			record.UpdatedAt, current.internalID,
		); err != nil {
			return User{}, fmt.Errorf("revoke sessions after user update: %w", err)
		}
	}
	event := record.Audit
	event.Metadata = cloneAuditMetadata(event.Metadata)
	event.Metadata["previous_role"] = string(current.Role)
	event.Metadata["previous_status"] = current.Status
	event.Metadata["role"] = string(finalRole)
	effectiveStatus := finalStatus
	if !unlockRequested && current.Status == "locked" && finalStatus == "active" {
		effectiveStatus = "locked"
	}
	event.Metadata["status"] = effectiveStatus
	event.Metadata["sessions_revoked"] = stateChanged || unlockRequested
	if err := audit.Append(ctx, transaction, event); err != nil {
		return User{}, err
	}
	updated, err := queryUserByInternalID(ctx, transaction, current.internalID)
	if err != nil {
		return User{}, fmt.Errorf("read updated user: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("commit user update: %w", err)
	}
	return updated, nil
}

func (r *MySQLRepository) ResetPassword(
	ctx context.Context,
	record ResetPasswordRecord,
) (User, error) {
	transaction, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin password reset transaction: %w", err)
	}
	defer transaction.Rollback()

	current, err := queryUserForUpdate(ctx, transaction, record.PublicID)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("lock password reset user: %w", err)
	}
	if !sameMySQLTimestamp(current.UpdatedAt, record.ExpectedUpdatedAt) {
		return User{}, ErrConflict
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE users
SET password_hash = ?, force_password_change = TRUE,
    failed_login_count = 0, locked_until = NULL, updated_at = ?
WHERE id = ?`,
		record.PasswordHash, record.UpdatedAt, current.internalID,
	); err != nil {
		return User{}, fmt.Errorf("reset user password: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, ?)
WHERE user_id = ? AND revoked_at IS NULL`,
		record.UpdatedAt, current.internalID,
	); err != nil {
		return User{}, fmt.Errorf("revoke sessions after password reset: %w", err)
	}
	if err := audit.Append(ctx, transaction, record.Audit); err != nil {
		return User{}, err
	}
	updated, err := queryUserByInternalID(ctx, transaction, current.internalID)
	if err != nil {
		return User{}, fmt.Errorf("read password reset user: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return User{}, fmt.Errorf("commit password reset: %w", err)
	}
	return updated, nil
}

func queryUserForUpdate(
	ctx context.Context,
	transaction *sql.Tx,
	publicID string,
) (User, error) {
	return scanUserRow(transaction.QueryRowContext(
		ctx,
		userSelectColumns+`
WHERE u.public_id = ?
LIMIT 1
FOR UPDATE`,
		publicID,
	))
}

func queryUserByInternalID(
	ctx context.Context,
	querier interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	},
	internalID uint64,
) (User, error) {
	return scanUserRow(querier.QueryRowContext(
		ctx,
		userSelectColumns+`
WHERE u.id = ?
LIMIT 1`,
		internalID,
	))
}

func scanUser(scanner rowScanner) (User, error) {
	return scanUserRow(scanner)
}

func scanUserRow(scanner rowScanner) (User, error) {
	var (
		user User
		role string
	)
	err := scanner.Scan(
		&user.internalID, &user.ID, &user.Username, &user.DisplayName,
		&role, &user.storedStatus, &user.MustChangePassword,
		&user.FailedLoginCount, &user.LockedUntil, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt,
	)
	user.Role = auth.Role(role)
	user.Status = user.storedStatus
	user.CreatedAt = user.CreatedAt.UTC()
	user.UpdatedAt = user.UpdatedAt.UTC()
	if user.LockedUntil != nil {
		value := user.LockedUntil.UTC()
		user.LockedUntil = &value
		if user.Status == "active" && value.After(time.Now().UTC()) {
			user.Status = "locked"
		}
	}
	if user.LastLoginAt != nil {
		value := user.LastLoginAt.UTC()
		user.LastLoginAt = &value
	}
	return user, err
}

func lockActiveAdministrators(
	ctx context.Context,
	transaction *sql.Tx,
) (int, error) {
	rows, err := transaction.QueryContext(ctx, `
SELECT id
FROM users
WHERE status = 'active' AND role = 'administrator'
ORDER BY id
FOR UPDATE`)
	if err != nil {
		return 0, fmt.Errorf("lock active administrators: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return 0, fmt.Errorf("scan active administrator: %w", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate active administrators: %w", err)
	}
	return count, nil
}

func sameMySQLTimestamp(left, right time.Time) bool {
	return left.UTC().Truncate(time.Microsecond).Equal(
		right.UTC().Truncate(time.Microsecond),
	)
}

func isDuplicateKey(err error) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) && mysqlError.Number == 1062
}

func duplicateKeyName(err error, key string) bool {
	var mysqlError *mysql.MySQLError
	return errors.As(err, &mysqlError) &&
		mysqlError.Number == 1062 &&
		strings.Contains(mysqlError.Message, key)
}

func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}

func cloneAuditMetadata(source map[string]any) map[string]any {
	result := make(map[string]any, len(source)+5)
	for key, value := range source {
		result[key] = value
	}
	return result
}
