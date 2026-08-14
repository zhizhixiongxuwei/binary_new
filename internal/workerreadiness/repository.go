package workerreadiness

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	StatusReady = "ready"
	staleRowAge = 7 * 24 * time.Hour
)

var (
	ownerPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$`)
)

type Registration struct {
	Owner           string
	WorkerKind      string
	AnalyzerName    string
	AnalyzerVersion string
	RuntimeName     string
	RuntimeVersion  string
}

type Repository interface {
	Register(context.Context, Registration) error
	Heartbeat(context.Context, string) error
	Remove(context.Context, string) error
	Prune(context.Context, time.Time) error
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) (*MySQLRepository, error) {
	if db == nil {
		return nil, errors.New("worker readiness database is required")
	}
	return &MySQLRepository{db: db}, nil
}

func (r *MySQLRepository) Register(
	ctx context.Context,
	value Registration,
) error {
	if err := validateRegistration(value); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `
INSERT INTO worker_readiness (
    worker_owner, worker_kind, analyzer_name, analyzer_version,
    runtime_name, runtime_version, status, started_at, last_checked_at
) VALUES (?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), 'ready',
          UTC_TIMESTAMP(6), UTC_TIMESTAMP(6))
ON DUPLICATE KEY UPDATE
    worker_kind = VALUES(worker_kind),
    analyzer_name = VALUES(analyzer_name),
    analyzer_version = VALUES(analyzer_version),
    runtime_name = VALUES(runtime_name),
    runtime_version = VALUES(runtime_version),
    status = 'ready',
    started_at = UTC_TIMESTAMP(6),
    last_checked_at = UTC_TIMESTAMP(6)`,
		value.Owner,
		value.WorkerKind,
		value.AnalyzerName,
		value.AnalyzerVersion,
		value.RuntimeName,
		value.RuntimeVersion,
	)
	if err != nil {
		return fmt.Errorf("register worker readiness: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Heartbeat(
	ctx context.Context,
	owner string,
) error {
	if !ownerPattern.MatchString(owner) {
		return errors.New("worker readiness owner is invalid")
	}
	result, err := r.db.ExecContext(ctx, `
UPDATE worker_readiness
SET status = 'ready', last_checked_at = UTC_TIMESTAMP(6)
WHERE worker_owner = ?`, owner)
	if err != nil {
		return fmt.Errorf("heartbeat worker readiness: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect worker readiness heartbeat: %w", err)
	}
	if rows != 1 {
		return errors.New("worker readiness registration was lost")
	}
	return nil
}

func (r *MySQLRepository) Remove(ctx context.Context, owner string) error {
	if !ownerPattern.MatchString(owner) {
		return errors.New("worker readiness owner is invalid")
	}
	if _, err := r.db.ExecContext(
		ctx,
		"DELETE FROM worker_readiness WHERE worker_owner = ?",
		owner,
	); err != nil {
		return fmt.Errorf("remove worker readiness: %w", err)
	}
	return nil
}

func (r *MySQLRepository) Prune(ctx context.Context, before time.Time) error {
	if before.IsZero() || before.After(time.Now().UTC().Add(time.Minute)) {
		return errors.New("worker readiness prune boundary is invalid")
	}
	if _, err := r.db.ExecContext(ctx, `
DELETE FROM worker_readiness
WHERE last_checked_at < ?`, before.UTC()); err != nil {
		return fmt.Errorf("prune worker readiness: %w", err)
	}
	return nil
}

func validateRegistration(value Registration) error {
	value.WorkerKind = strings.TrimSpace(value.WorkerKind)
	value.AnalyzerName = strings.TrimSpace(value.AnalyzerName)
	value.AnalyzerVersion = strings.TrimSpace(value.AnalyzerVersion)
	value.RuntimeName = strings.TrimSpace(value.RuntimeName)
	value.RuntimeVersion = strings.TrimSpace(value.RuntimeVersion)
	if !ownerPattern.MatchString(value.Owner) ||
		!versionPattern.MatchString(value.AnalyzerVersion) ||
		len(value.RuntimeVersion) > 256 ||
		strings.ContainsAny(value.RuntimeVersion, "\r\n\x00") {
		return errors.New("worker readiness registration identity is invalid")
	}
	if value.RuntimeName != "" &&
		(!ownerPattern.MatchString(value.RuntimeName) || len(value.RuntimeName) > 64) {
		return errors.New("worker readiness runtime identity is invalid")
	}
	switch value.WorkerKind {
	case "native":
		if value.AnalyzerName != "ghidra" ||
			value.RuntimeName == "" || value.RuntimeVersion == "" {
			return errors.New("native readiness requires Ghidra and runtime identity")
		}
	case "image", "trivy":
		if value.AnalyzerName != "trivy" {
			return errors.New("image readiness requires Trivy identity")
		}
	case "bytecode":
		if value.AnalyzerName != "go-bytecode-router" &&
			value.AnalyzerName != "vineflower-cfr-jadx" {
			return errors.New("bytecode readiness requires a bytecode analyzer identity")
		}
	case "c_analysis":
		if value.AnalyzerName != "binaryscan-c-checker" {
			return errors.New("C analysis readiness requires the C checker identity")
		}
	case "java_analysis":
		if value.AnalyzerName != "binaryscan-java-checker" {
			return errors.New("Java analysis readiness requires the Java checker identity")
		}
	case "python_analysis":
		if value.AnalyzerName != "binaryscan-python-checker" {
			return errors.New("Python analysis readiness requires the Python checker identity")
		}
	default:
		return errors.New("worker readiness kind is invalid")
	}
	return nil
}

func StaleBefore(now time.Time) time.Time {
	return now.UTC().Add(-staleRowAge)
}
