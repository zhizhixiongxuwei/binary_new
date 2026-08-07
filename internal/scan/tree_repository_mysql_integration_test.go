package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/database"
	"binaryscan/internal/extract"
	"binaryscan/internal/filetree"
	"binaryscan/internal/queue"

	"github.com/go-sql-driver/mysql"
)

const scanIntegrationDSNFile = "BINARYSCAN_SCAN_INTEGRATION_DSN_FILE"

type scanIntegrationFixture struct {
	taskID    string
	uploadID  string
	blobID    uint64
	attemptID uint64
	rootID    uint64
	lease     queue.Lease
}

func TestMySQLPublishTreeLeaseIntegration(t *testing.T) {
	db := openScanIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate integration database: %v", err)
	}

	userID := seedScanIntegrationUser(t, ctx, db)
	t.Cleanup(func() {
		cleanupScanIntegrationUser(t, db, userID)
	})
	queueService, err := queue.NewService(queue.NewMySQLRepository(db), queue.Config{
		LeaseDuration: 5 * time.Second,
		RetryDelay:    0,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMySQLRepository(db)

	t.Run("heartbeats continue throughout a multi-batch publication", func(t *testing.T) {
		fixture := seedScanIntegrationFixture(t, ctx, db, queueService, userID, false)
		nodes := scanIntegrationTreeNodes(5_001)
		blocker := lockScanIntegrationRoot(t, ctx, db, fixture)
		defer blocker.Rollback()
		published := make(chan error, 1)
		go func() {
			published <- repository.PublishTree(
				ctx, fixture.lease, "extracted", nodes,
			)
		}()
		waitForBlockedTreePublisher(t, db, published)

		lease := fixture.lease
		started := time.Now()
		renewed, err := heartbeatWithShortDeadline(queueService, lease)
		blockedHeartbeatDuration := time.Since(started)
		if err != nil {
			_ = blocker.Rollback()
			t.Fatalf(
				"heartbeat while tree publisher waited on its domain lock: %v",
				err,
			)
		}
		if blockedHeartbeatDuration >= 700*time.Millisecond {
			_ = blocker.Rollback()
			t.Fatalf(
				"heartbeat took %s while tree publication was active",
				blockedHeartbeatDuration,
			)
		}
		if !renewed.LeaseUntil.After(lease.LeaseUntil) {
			_ = blocker.Rollback()
			t.Fatalf(
				"heartbeat did not renew lease: before=%s after=%s",
				lease.LeaseUntil, renewed.LeaseUntil,
			)
		}
		lease = renewed
		if err := blocker.Rollback(); err != nil {
			t.Fatalf("release root publication blocker: %v", err)
		}

		heartbeatsDuringWrite := 0
		publicationComplete := false
		for !publicationComplete {
			select {
			case err := <-published:
				if err != nil {
					t.Fatalf("PublishTree(): %v", err)
				}
				publicationComplete = true
				continue
			default:
			}
			started = time.Now()
			renewed, err = heartbeatWithShortDeadline(queueService, lease)
			if err != nil {
				t.Fatalf("heartbeat during descendant writes: %v", err)
			}
			if elapsed := time.Since(started); elapsed >= 700*time.Millisecond {
				t.Fatalf("heartbeat during descendant writes took %s", elapsed)
			}
			lease = renewed
			heartbeatsDuringWrite++
			time.Sleep(5 * time.Millisecond)
		}
		if heartbeatsDuringWrite == 0 {
			t.Fatal("publication completed before a heartbeat overlapped descendant writes")
		}
		t.Logf(
			"published %d descendants with %d overlapping heartbeats; "+
				"heartbeat while publisher was blocked took %s",
			len(nodes), heartbeatsDuringWrite, blockedHeartbeatDuration,
		)
		assertPublishedScanIntegrationTree(t, ctx, db, fixture, len(nodes))
	})

	t.Run("Trivy handoff is fenced and idempotent", func(t *testing.T) {
		fixture := seedScanIntegrationFixture(
			t, ctx, db, queueService, userID, false,
		)
		if _, err := db.ExecContext(ctx, `
UPDATE file_nodes
SET format = 'docker-tar'
WHERE id = ? AND task_id = ?`, fixture.rootID, fixture.taskID); err != nil {
			t.Fatalf("prepare container root: %v", err)
		}
		var storageKey, digest string
		var sizeBytes int64
		if err := db.QueryRowContext(ctx, `
SELECT storage_key, sha256, size_bytes
FROM file_nodes
WHERE id = ? AND task_id = ?`, fixture.rootID, fixture.taskID).Scan(
			&storageKey, &digest, &sizeBytes,
		); err != nil {
			t.Fatalf("read container root: %v", err)
		}
		payload := TrivyJobPayload{
			SchemaVersion: TrivyJobPayloadSchemaVersion,
			Sources: []TrivySource{{
				Format:           "docker-tar",
				SourceStorageKey: storageKey,
				SourceSHA256:     digest,
				SourceSizeBytes:  sizeBytes,
				ImageLogicalPath: "/",
			}},
			MaxExpandedBytes: 50 * 1024 * 1024 * 1024,
			MaxArchiveRatio:  100,
			UpstreamPartial:  true,
		}
		for replay := 0; replay < 2; replay++ {
			if err := repository.EnqueueTrivy(
				ctx, fixture.lease, payload,
			); err != nil {
				t.Fatalf("EnqueueTrivy() replay %d: %v", replay, err)
			}
		}
		var count int
		var attemptID, fence uint64
		var format string
		var upstreamPartial bool
		if err := db.QueryRowContext(ctx, `
SELECT COUNT(*), MAX(task_attempt_id), MAX(fencing_token),
       MAX(COALESCE(
           JSON_UNQUOTE(JSON_EXTRACT(payload, '$.sources[0].format')),
           JSON_UNQUOTE(JSON_EXTRACT(payload, '$.format'))
       )),
       MAX(JSON_EXTRACT(payload, '$.upstream_partial') = TRUE)
FROM jobs
WHERE task_id = ?
  AND kind = 'trivy'
  AND idempotency_key = ?`,
			fixture.taskID,
			fmt.Sprintf("trivy:attempt:%d", fixture.attemptID),
		).Scan(
			&count, &attemptID, &fence, &format, &upstreamPartial,
		); err != nil {
			t.Fatalf("read Trivy handoff: %v", err)
		}
		if count != 1 || attemptID != fixture.attemptID ||
			fence != fixture.lease.FencingToken ||
			format != "docker-tar" || !upstreamPartial {
			t.Fatalf(
				"Trivy handoff = count=%d attempt=%d fence=%d format=%s partial=%v",
				count, attemptID, fence, format, upstreamPartial,
			)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(context.Context, *sql.DB, scanIntegrationFixture) error
	}{
		{
			name: "cancellation",
			mutate: func(
				ctx context.Context,
				db *sql.DB,
				fixture scanIntegrationFixture,
			) error {
				_, err := db.ExecContext(ctx, `
UPDATE jobs
SET cancel_requested_at = UTC_TIMESTAMP(6)
WHERE id = ? AND task_id = ?`,
					fixture.lease.JobID, fixture.taskID,
				)
				return err
			},
		},
		{
			name: "stale fence",
			mutate: func(
				ctx context.Context,
				db *sql.DB,
				fixture scanIntegrationFixture,
			) error {
				transaction, err := db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer transaction.Rollback()
				if _, err := transaction.ExecContext(ctx, `
UPDATE jobs
SET fencing_token = fencing_token + 1
WHERE id = ? AND task_id = ?`,
					fixture.lease.JobID, fixture.taskID,
				); err != nil {
					return err
				}
				if _, err := transaction.ExecContext(ctx, `
UPDATE task_attempts
SET fencing_token = fencing_token + 1
WHERE id = ? AND task_id = ?`,
					fixture.attemptID, fixture.taskID,
				); err != nil {
					return err
				}
				return transaction.Commit()
			},
		},
	} {
		t.Run(test.name+" rolls back the replacement", func(t *testing.T) {
			fixture := seedScanIntegrationFixture(
				t, ctx, db, queueService, userID, true,
			)
			nodes := scanIntegrationTreeNodes(1)
			nodes[0].LogicalPath = "/new.bin"
			nodes[0].DisplayName = "new.bin"
			blocker := lockScanIntegrationRoot(t, ctx, db, fixture)
			defer blocker.Rollback()
			published := make(chan error, 1)
			go func() {
				published <- repository.PublishTree(
					ctx, fixture.lease, "extracted", nodes,
				)
			}()
			waitForBlockedTreePublisher(t, db, published)

			mutationCtx, mutationCancel := context.WithTimeout(
				context.Background(), 750*time.Millisecond,
			)
			mutationErr := test.mutate(mutationCtx, db, fixture)
			mutationCancel()
			if mutationErr != nil {
				_ = blocker.Rollback()
				t.Fatalf("mutate live lease while publication is active: %v", mutationErr)
			}
			if err := blocker.Rollback(); err != nil {
				t.Fatalf("release root publication blocker: %v", err)
			}
			select {
			case err := <-published:
				if !errors.Is(err, queue.ErrLeaseLost) {
					t.Fatalf("PublishTree() error = %v, want ErrLeaseLost", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("PublishTree did not finish after releasing its domain lock")
			}
			assertOldScanIntegrationTree(t, ctx, db, fixture)
		})
	}
}

func TestMySQLFileTreeScaleIntegration(t *testing.T) {
	db := openScanIntegrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate integration database: %v", err)
	}

	userID := seedScanIntegrationUser(t, ctx, db)
	t.Cleanup(func() {
		cleanupScanIntegrationUser(t, db, userID)
	})
	queueService, err := queue.NewService(queue.NewMySQLRepository(db), queue.Config{
		LeaseDuration: 5 * time.Minute,
		RetryDelay:    0,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := seedScanIntegrationFixture(t, ctx, db, queueService, userID, false)
	nodes := scanIntegrationTreeNodes(99_999)

	publishStarted := time.Now()
	if err := NewMySQLRepository(db).PublishTree(
		ctx, fixture.lease, "extracted", nodes,
	); err != nil {
		t.Fatalf("publish 100,000-node tree: %v", err)
	}
	publishDuration := time.Since(publishStarted)
	assertPublishedScanIntegrationTree(t, ctx, db, fixture, len(nodes))

	var explainJSON string
	if err := db.QueryRowContext(ctx, `
EXPLAIN FORMAT=JSON
SELECT n.id,
       EXISTS (
           SELECT 1
           FROM file_nodes child FORCE INDEX (idx_file_nodes_parent)
           WHERE child.task_id = n.task_id AND child.parent_id = n.id
       ) AS has_children
FROM file_nodes n FORCE INDEX (idx_file_nodes_parent)
WHERE n.task_id = ? AND n.parent_id = ? AND n.id > ?
ORDER BY n.id
LIMIT 201`, fixture.taskID, fixture.rootID, 0).Scan(&explainJSON); err != nil {
		t.Fatalf("explain indexed file-tree page: %v", err)
	}
	if strings.Count(explainJSON, "idx_file_nodes_parent") < 2 {
		t.Fatalf("file-tree query plan does not use idx_file_nodes_parent: %s", explainJSON)
	}

	cursors := []uint64{
		0,
		scanIntegrationCursorAtOffset(t, ctx, db, fixture, 49_899),
		scanIntegrationCursorAtOffset(t, ctx, db, fixture, 99_798),
	}
	treeRepository := filetree.NewMySQLRepository(db)
	var slowest time.Duration
	for _, cursor := range cursors {
		for replay := 0; replay < 3; replay++ {
			started := time.Now()
			page, err := treeRepository.List(ctx, filetree.ListQuery{
				TaskID: fixture.taskID, ParentID: &fixture.rootID,
				Cursor: cursor, PageSize: 200,
			})
			elapsed := time.Since(started)
			if elapsed > slowest {
				slowest = elapsed
			}
			if err != nil {
				t.Fatalf("list 100,000-node tree at cursor %d: %v", cursor, err)
			}
			if len(page.Items) == 0 || len(page.Items) > 200 {
				t.Fatalf(
					"file-tree page at cursor %d contains %d items",
					cursor, len(page.Items),
				)
			}
		}
	}
	if slowest > 5*time.Second {
		t.Fatalf("slowest indexed file-tree page took %s, limit is 5s", slowest)
	}
	t.Logf(
		"published the 100,000-node boundary in %s; slowest indexed page was %s",
		publishDuration, slowest,
	)
}

func openScanIntegrationDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsnPath := strings.TrimSpace(os.Getenv(scanIntegrationDSNFile))
	if dsnPath == "" {
		t.Skip(scanIntegrationDSNFile + " is not set")
	}
	rawDSN, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatalf("read integration DSN: %v", err)
	}
	driverConfig, err := mysql.ParseDSN(strings.TrimSpace(string(rawDSN)))
	if err != nil {
		t.Fatalf("parse integration DSN: %v", err)
	}
	driverConfig.ParseTime = true
	driverConfig.Loc = time.UTC
	db, err := sql.Open("mysql", driverConfig.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("close integration database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping integration database: %v", err)
	}
	return db
}

func seedScanIntegrationUser(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
) uint64 {
	t.Helper()
	publicID := scanIntegrationUUID(t)
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Scan Integration', 'not-used', 'operator', 'active', FALSE)`,
		publicID, "scan-integration-"+strings.ReplaceAll(publicID[:18], "-", ""),
	)
	if err != nil {
		t.Fatalf("seed integration user: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil || id <= 0 {
		t.Fatalf("integration user ID = %d, %v", id, err)
	}
	return uint64(id)
}

func seedScanIntegrationFixture(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	queueService *queue.Service,
	userID uint64,
	withOldChild bool,
) scanIntegrationFixture {
	t.Helper()
	fixture := scanIntegrationFixture{
		taskID: scanIntegrationUUID(t), uploadID: scanIntegrationUUID(t),
	}
	fixture.lease.JobID = scanIntegrationUUID(t)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(fixture.taskID)))
	blobResult, err := db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, 1, ?, 2, 'available', UTC_TIMESTAMP(6))`,
		hash, "blobs/sha256/"+hash[:2]+"/"+hash,
	)
	if err != nil {
		t.Fatalf("seed integration blob: %v", err)
	}
	blobID, err := blobResult.LastInsertId()
	if err != nil || blobID <= 0 {
		t.Fatalf("integration blob ID = %d, %v", blobID, err)
	}
	fixture.blobID = uint64(blobID)
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, actual_sha256, status, blob_id,
    expires_at, completed_at
) VALUES (?, ?, ?, 'fixture.bin', 'application/octet-stream', 1, 33554432, ?,
          'completed', ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY),
          UTC_TIMESTAMP(6))`,
		fixture.uploadID, userID, []byte("fixture.bin"), hash, blobID,
	); err != nil {
		t.Fatalf("seed integration upload: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status,
    progress_basis_points, risk_level, limits_snapshot, sample_expires_at
) VALUES (?, ?, ?, ?, 'Scan tree integration', JSON_ARRAY(), 'QUEUED', 0,
          'UNKNOWN',
          JSON_OBJECT(
              'max_expanded_bytes', 53687091200,
              'max_archive_ratio', 100,
              'max_depth', 10,
              'max_file_nodes', 100000
          ),
          DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))`,
		fixture.taskID, fixture.uploadID, blobID, userID,
	); err != nil {
		t.Fatalf("seed integration task: %v", err)
	}
	attemptResult, err := db.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status
) VALUES (?, 1, 1, 'queued')`, fixture.taskID)
	if err != nil {
		t.Fatalf("seed integration task attempt: %v", err)
	}
	attemptID, err := attemptResult.LastInsertId()
	if err != nil || attemptID <= 0 {
		t.Fatalf("integration task attempt ID = %d, %v", attemptID, err)
	}
	fixture.attemptID = uint64(attemptID)
	if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, priority, payload,
    available_at, attempt, max_attempts, fencing_token, idempotency_key
) VALUES (?, ?, ?, 'scan', 'queued', 32767, JSON_OBJECT('task_id', ?),
          UTC_TIMESTAMP(6), 0, 3, 1, ?)`,
		fixture.lease.JobID, fixture.taskID, fixture.attemptID, fixture.taskID,
		"scan-integration-"+fixture.taskID,
	); err != nil {
		t.Fatalf("seed integration job: %v", err)
	}

	lease, found, err := queueService.Claim(
		ctx, queue.KindScan, "scan-integration-worker",
	)
	if err != nil || !found {
		t.Fatalf("claim integration job = (_, %v, %v)", found, err)
	}
	if lease.JobID != fixture.lease.JobID {
		t.Fatalf("claimed job %s, want %s", lease.JobID, fixture.lease.JobID)
	}
	if err := queueService.Start(ctx, lease); err != nil {
		t.Fatalf("start integration job: %v", err)
	}
	if err := queueService.TaskProgress(ctx, lease, queue.ProgressInput{
		TaskStatus: "INDEXING",
		Stage:      "INDEXING",
	}); err != nil {
		t.Fatalf("advance integration task to INDEXING: %v", err)
	}
	fixture.lease = lease

	rootHash := sha256.Sum256([]byte("/"))
	rootResult, err := db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, mime_type, size_bytes, sha256, storage_key,
    extraction_status, metadata_json
) VALUES (?, NULL, '/', ?, 'fixture.bin', 'file', 0, 'unknown',
          'application/octet-stream', 1, ?, ?, 'indexed',
          JSON_OBJECT('source', 'integration'))`,
		fixture.taskID, rootHash[:], hash,
		"blobs/sha256/"+hash[:2]+"/"+hash,
	)
	if err != nil {
		t.Fatalf("seed integration root node: %v", err)
	}
	rootID, err := rootResult.LastInsertId()
	if err != nil || rootID <= 0 {
		t.Fatalf("integration root node ID = %d, %v", rootID, err)
	}
	fixture.rootID = uint64(rootID)
	if withOldChild {
		oldHash := sha256.Sum256([]byte("/old.bin"))
		if _, err := db.ExecContext(ctx, `
INSERT INTO file_nodes (
    task_id, parent_id, logical_path, logical_path_hash, display_name,
    node_type, depth, format, mime_type, size_bytes, extraction_status
) VALUES (?, ?, '/old.bin', ?, 'old.bin', 'file', 1, 'unknown',
          'application/octet-stream', 1, 'extracted')`,
			fixture.taskID, fixture.rootID, oldHash[:],
		); err != nil {
			t.Fatalf("seed previous extracted child: %v", err)
		}
	}
	t.Cleanup(func() {
		cleanupScanIntegrationFixture(t, db, fixture)
	})
	return fixture
}

func scanIntegrationTreeNodes(count int) []extract.Node {
	nodes := make([]extract.Node, count)
	for index := range nodes {
		logicalPath := fmt.Sprintf("/entry-%05d.bin", index+1)
		nodes[index] = extract.Node{
			LocalID:          index + 1,
			ParentLocalID:    0,
			LogicalPath:      logicalPath,
			DisplayName:      path.Base(logicalPath),
			NodeType:         extract.NodeTypeFile,
			Depth:            1,
			Format:           "unknown",
			MIMEType:         "application/octet-stream",
			SizeBytes:        1,
			ExtractionStatus: extract.StatusRecorded,
		}
	}
	return nodes
}

func lockScanIntegrationRoot(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	fixture scanIntegrationFixture,
) *sql.Tx {
	t.Helper()
	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin root publication blocker: %v", err)
	}
	var rootID uint64
	if err := transaction.QueryRowContext(ctx, `
SELECT id
FROM file_nodes
WHERE task_id = ? AND id = ?
FOR UPDATE`, fixture.taskID, fixture.rootID).Scan(&rootID); err != nil {
		_ = transaction.Rollback()
		t.Fatalf("lock root publication domain: %v", err)
	}
	return transaction
}

func waitForBlockedTreePublisher(
	t *testing.T,
	db *sql.DB,
	published <-chan error,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var continuouslyInUseSince time.Time
	for time.Now().Before(deadline) {
		select {
		case err := <-published:
			t.Fatalf("tree publisher returned before domain lock release: %v", err)
		default:
		}
		if db.Stats().InUse >= 2 {
			if continuouslyInUseSince.IsZero() {
				continuouslyInUseSince = time.Now()
			}
			if time.Since(continuouslyInUseSince) >= 75*time.Millisecond {
				return
			}
		} else {
			continuouslyInUseSince = time.Time{}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("tree publisher did not block on the root publication domain")
}

func heartbeatWithShortDeadline(
	service *queue.Service,
	lease queue.Lease,
) (queue.Lease, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	return service.Heartbeat(ctx, lease)
}

func assertPublishedScanIntegrationTree(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	fixture scanIntegrationFixture,
	descendantCount int,
) {
	t.Helper()
	var count int
	var rootStatus string
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*), MAX(
    CASE WHEN id = ? AND parent_id IS NULL THEN extraction_status ELSE NULL END
)
FROM file_nodes
WHERE task_id = ?`, fixture.rootID, fixture.taskID).Scan(
		&count, &rootStatus,
	); err != nil {
		t.Fatalf("read published integration tree: %v", err)
	}
	if count != descendantCount+1 || rootStatus != "extracted" {
		t.Fatalf(
			"published tree count/status = %d/%s, want %d/extracted",
			count, rootStatus, descendantCount+1,
		)
	}
}

func assertOldScanIntegrationTree(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	fixture scanIntegrationFixture,
) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
SELECT logical_path
FROM file_nodes
WHERE task_id = ? AND parent_id IS NOT NULL
ORDER BY id`, fixture.taskID)
	if err != nil {
		t.Fatalf("read descendants after rejected publication: %v", err)
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var logicalPath string
		if err := rows.Scan(&logicalPath); err != nil {
			t.Fatalf("scan descendant after rejected publication: %v", err)
		}
		paths = append(paths, logicalPath)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate descendants after rejected publication: %v", err)
	}
	var rootStatus string
	if err := db.QueryRowContext(ctx, `
SELECT extraction_status
FROM file_nodes
WHERE task_id = ? AND id = ?`, fixture.taskID, fixture.rootID).Scan(
		&rootStatus,
	); err != nil {
		t.Fatalf("read root after rejected publication: %v", err)
	}
	if len(paths) != 1 || paths[0] != "/old.bin" || rootStatus != "indexed" {
		t.Fatalf(
			"tree after rejected publication = paths %v, root status %s",
			paths, rootStatus,
		)
	}
}

func scanIntegrationCursorAtOffset(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	fixture scanIntegrationFixture,
	offset int,
) uint64 {
	t.Helper()
	var id uint64
	if err := db.QueryRowContext(ctx, `
SELECT id
FROM file_nodes FORCE INDEX (idx_file_nodes_parent)
WHERE task_id = ? AND parent_id = ?
ORDER BY id
LIMIT 1 OFFSET ?`, fixture.taskID, fixture.rootID, offset).Scan(&id); err != nil {
		t.Fatalf("read file-tree cursor at offset %d: %v", offset, err)
	}
	return id
}

func cleanupScanIntegrationFixture(
	t *testing.T,
	db *sql.DB,
	fixture scanIntegrationFixture,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, statement := range []struct {
		query     string
		arguments []any
	}{
		{
			query: `UPDATE job_resource_slots
SET job_id = NULL,
    job_fencing_token = NULL,
    lease_owner = NULL,
    acquired_at = NULL
WHERE job_id = ?`,
			arguments: []any{fixture.lease.JobID},
		},
		{query: "DELETE FROM tasks WHERE id = ?", arguments: []any{fixture.taskID}},
		{query: "DELETE FROM uploads WHERE id = ?", arguments: []any{fixture.uploadID}},
		{query: "DELETE FROM blobs WHERE id = ?", arguments: []any{fixture.blobID}},
	} {
		if _, err := db.ExecContext(ctx, statement.query, statement.arguments...); err != nil {
			t.Logf("integration cleanup %q: %v", statement.query, err)
		}
	}
}

func cleanupScanIntegrationUser(t *testing.T, db *sql.DB, userID uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID); err != nil {
		t.Logf("integration cleanup user: %v", err)
	}
}

func scanIntegrationUUID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate integration UUID: %v", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	)
}
