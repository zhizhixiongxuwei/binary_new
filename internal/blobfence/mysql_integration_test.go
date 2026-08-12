package blobfence

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLFenceSerializesDeleteBeforePublish(t *testing.T) {
	rawDSN := strings.TrimSpace(os.Getenv("BINARYSCAN_MYSQL_MIGRATION_ROUNDTRIP_DSN"))
	if rawDSN == "" {
		t.Skip("BINARYSCAN_MYSQL_MIGRATION_ROUNDTRIP_DSN is not set")
	}
	configuration, err := mysql.ParseDSN(rawDSN)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ParseTime = true
	db, err := sql.Open("mysql", configuration.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	digest := "d91f5b63821064ab8fbb20500295c3e12cd28f8a8f5604d509f7df9007f10f4a"
	deleteEntered := make(chan struct{})
	releaseDelete := make(chan struct{})
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- With(ctx, db, digest, func() error {
			close(deleteEntered)
			<-releaseDelete
			return nil
		})
	}()
	select {
	case <-deleteEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var published atomic.Bool
	publishDone := make(chan error, 1)
	go func() {
		publishDone <- With(ctx, db, digest, func() error {
			published.Store(true)
			return nil
		})
	}()
	time.Sleep(150 * time.Millisecond)
	if published.Load() {
		t.Fatal("publisher crossed the deletion content-address fence")
	}
	close(releaseDelete)
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if err := <-publishDone; err != nil {
		t.Fatal(err)
	}
	if !published.Load() {
		t.Fatal("publisher did not run after deletion committed")
	}
}
