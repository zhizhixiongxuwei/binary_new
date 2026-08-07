package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"binaryscan/db/migrations"

	"github.com/pressly/goose/v3"
)

const migrationLockName = "binaryscan_schema_migrations"

func Migrate(ctx context.Context, db *sql.DB) error {
	lockConnection, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve migration lock connection: %w", err)
	}
	defer lockConnection.Close()

	var acquired sql.NullInt64
	if err := lockConnection.QueryRowContext(ctx, "SELECT GET_LOCK(?, ?)", migrationLockName, 30).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return errors.New("migration lock was not acquired within 30 seconds")
	}
	defer func() {
		_, _ = lockConnection.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", migrationLockName)
	}()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("mysql"); err != nil {
		return fmt.Errorf("configure migration dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	return nil
}

func MigrationFiles() ([]string, error) {
	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	return entries, nil
}

func LatestMigrationVersion() (int64, error) {
	files, err := MigrationFiles()
	if err != nil {
		return 0, err
	}
	var latest int64
	for _, name := range files {
		base := filepath.Base(name)
		prefix, _, ok := strings.Cut(base, "_")
		if !ok || len(prefix) != 5 || filepath.Ext(base) != ".sql" {
			return 0, fmt.Errorf("invalid embedded migration filename %q", name)
		}
		version, parseErr := strconv.ParseInt(prefix, 10, 64)
		if parseErr != nil || version <= 0 {
			return 0, fmt.Errorf("invalid embedded migration version %q", prefix)
		}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, errors.New("no embedded database migration was found")
	}
	return latest, nil
}
