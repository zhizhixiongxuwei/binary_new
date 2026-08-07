package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"binaryscan/internal/config"

	"github.com/go-sql-driver/mysql"
)

func Open(cfg config.Config) (*sql.DB, error) {
	driverConfig, err := mysql.ParseDSN(cfg.MySQLDSN)
	if err != nil {
		return nil, fmt.Errorf("parse MySQL DSN: %w", err)
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	if driverConfig.Timeout == 0 {
		driverConfig.Timeout = cfg.DatabasePingTimeout
	}
	if driverConfig.ReadTimeout == 0 {
		driverConfig.ReadTimeout = 30 * time.Second
	}
	if driverConfig.WriteTimeout == 0 {
		driverConfig.WriteTimeout = 30 * time.Second
	}

	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open MySQL connection pool: %w", err)
	}
	db.SetMaxOpenConns(cfg.MySQLMaxOpenConns)
	db.SetMaxIdleConns(cfg.MySQLMaxIdleConns)
	db.SetConnMaxLifetime(cfg.MySQLConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.MySQLConnMaxIdleTime)
	return db, nil
}

func Ping(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("ping MySQL: %w", err)
	}
	return nil
}
