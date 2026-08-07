package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrSchemaNotReady = errors.New("database schema is not ready")

type Readiness struct {
	ping        func(context.Context) error
	schemaProbe func(context.Context) error
}

func NewReadiness(db *sql.DB) *Readiness {
	return &Readiness{
		ping: db.PingContext,
		schemaProbe: func(ctx context.Context) error {
			expectedVersion, err := LatestMigrationVersion()
			if err != nil {
				return fmt.Errorf("resolve expected migration version: %w", err)
			}
			var version int64
			if err := db.QueryRowContext(ctx, `
SELECT COALESCE(MAX(version_id), 0)
FROM goose_db_version
WHERE is_applied = TRUE`).Scan(&version); err != nil {
				return fmt.Errorf("read migration version: %w", err)
			}
			if version != expectedVersion {
				return fmt.Errorf(
					"%w: migration version is %d, expected %d",
					ErrSchemaNotReady,
					version,
					expectedVersion,
				)
			}
			var tableCount int
			if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN ('users', 'sessions')`).Scan(&tableCount); err != nil {
				return fmt.Errorf("inspect authentication tables: %w", err)
			}
			if tableCount != 2 {
				return fmt.Errorf("%w: authentication tables found %d of 2", ErrSchemaNotReady, tableCount)
			}
			return nil
		},
	}
}

func (r *Readiness) PingContext(ctx context.Context) error {
	if err := r.ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if err := r.schemaProbe(ctx); err != nil {
		return err
	}
	return nil
}
