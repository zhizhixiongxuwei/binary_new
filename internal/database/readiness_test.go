package database

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReadinessRequiresPingAndSchema(t *testing.T) {
	pingError := errors.New("database down")
	schemaError := errors.New("migration incomplete")
	tests := []struct {
		name      string
		pingErr   error
		schemaErr error
		wantErr   error
	}{
		{name: "ready"},
		{name: "ping fails", pingErr: pingError, wantErr: pingError},
		{name: "schema fails", schemaErr: schemaError, wantErr: schemaError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			readiness := &Readiness{
				ping: func(context.Context) error { return tt.pingErr },
				schemaProbe: func(context.Context) error {
					return tt.schemaErr
				},
			}
			err := readiness.PingContext(context.Background())
			if tt.wantErr == nil && err != nil {
				t.Fatalf("PingContext() error = %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("PingContext() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestReadinessRequiresExactEmbeddedSchemaVersion(t *testing.T) {
	latest, err := LatestMigrationVersion()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		version int64
		wantErr bool
	}{
		{name: "exact version", version: int64(latest)},
		{name: "older version", version: int64(latest - 1), wantErr: true},
		{name: "newer incompatible version", version: int64(latest + 1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(
				sqlmock.MonitorPingsOption(true),
			)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectPing()
			mock.ExpectQuery(`SELECT COALESCE\(MAX\(version_id\), 0\)`).
				WillReturnRows(
					sqlmock.NewRows([]string{"version_id"}).
						AddRow(tt.version),
				)
			if !tt.wantErr {
				mock.ExpectQuery(`SELECT COUNT\(\*\).*information_schema\.tables`).
					WillReturnRows(
						sqlmock.NewRows([]string{"count"}).AddRow(2),
					)
			}

			err = NewReadiness(db).PingContext(context.Background())
			if tt.wantErr && !errors.Is(err, ErrSchemaNotReady) {
				t.Fatalf("PingContext() error = %v, want schema error", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("PingContext() error = %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
