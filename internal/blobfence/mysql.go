package blobfence

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	lockWaitSeconds = 30
	unlockTimeout   = 5 * time.Second
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// With serializes filesystem publication/deletion and the matching database
// transition for one content address. All blob producers and physical
// deleters must take this fence before taking a blobs row or SHA gap lock.
func With(
	ctx context.Context,
	db *sql.DB,
	sha256 string,
	operation func() error,
) error {
	if ctx == nil || db == nil || !sha256Pattern.MatchString(sha256) || operation == nil {
		return errors.New("invalid blob fence request")
	}
	connection, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open blob fence connection: %w", err)
	}
	defer connection.Close()

	name := LockName(sha256)
	var acquired int
	if err := connection.QueryRowContext(
		ctx, "SELECT GET_LOCK(?, ?)", name, lockWaitSeconds,
	).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire blob fence: %w", err)
	}
	if acquired != 1 {
		return errors.New("blob fence is busy")
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(
			context.Background(), unlockTimeout,
		)
		defer cancel()
		_, _ = connection.ExecContext(
			unlockContext, "SELECT RELEASE_LOCK(?)", name,
		)
	}()
	return operation()
}

func LockName(sha256 string) string {
	if len(sha256) < 40 {
		return ""
	}
	return "binaryscan_blob_sha256_" + sha256[:40]
}
