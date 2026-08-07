package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	taskdomain "binaryscan/internal/task"
	"binaryscan/internal/workspace"

	"github.com/go-sql-driver/mysql"
)

const queueIntegrationDSNFile = "BINARYSCAN_QUEUE_INTEGRATION_DSN_FILE"

type integrationJob struct {
	jobID     string
	taskID    string
	uploadID  string
	blobID    uint64
	attemptID uint64
}

func TestMySQLQueueLeaseIntegration(t *testing.T) {
	dsnPath := strings.TrimSpace(os.Getenv(queueIntegrationDSNFile))
	if dsnPath == "" {
		t.Skip(queueIntegrationDSNFile + " is not set")
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
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("close integration database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping integration database: %v", err)
	}

	userID := seedIntegrationUser(t, ctx, db)
	t.Cleanup(func() {
		cleanupIntegrationUser(t, db, userID)
	})
	service, err := NewService(NewMySQLRepository(db), Config{
		LeaseDuration:   5 * time.Minute,
		RetryDelay:      0,
		SampleRetention: taskdomain.DefaultSampleRetention,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureResourceLimits(ctx); err != nil {
		t.Fatalf("configure resource limits: %v", err)
	}

	t.Run("global heavy capacity is enforced and released", func(t *testing.T) {
		jobs := []integrationJob{
			seedIntegrationJob(t, ctx, db, userID, 110),
			seedIntegrationJob(t, ctx, db, userID, 111),
			seedIntegrationJob(t, ctx, db, userID, 112),
		}
		results := claimKindConcurrently(
			t,
			ctx,
			service,
			KindScan,
			"queue-capacity-a",
			"queue-capacity-b",
			"queue-capacity-c",
		)
		claimed := make([]Lease, 0, 2)
		for _, result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.found {
				claimed = append(claimed, result.lease)
			}
		}
		if len(claimed) != 2 {
			t.Fatalf("heavy claims = %d, want 2", len(claimed))
		}
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 2)

		finishIntegrationLease(t, ctx, service, claimed[0])
		replacement, found, err := service.Claim(
			ctx,
			KindScan,
			"queue-capacity-replacement",
		)
		if err != nil || !found {
			t.Fatalf("replacement capacity Claim() = (%+v, %v, %v)", replacement, found, err)
		}
		queuedJob := false
		for _, job := range jobs {
			if replacement.JobID == job.jobID {
				queuedJob = true
			}
		}
		if !queuedJob {
			t.Fatalf("replacement job %s was not one of the seeded jobs", replacement.JobID)
		}
		finishIntegrationLease(t, ctx, service, claimed[1])
		finishIntegrationLease(t, ctx, service, replacement)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 0)
	})

	t.Run("Trivy has an independent one-slot ceiling", func(t *testing.T) {
		_, firstScan, _ := prepareIntegrationTrivyHandoff(
			t, ctx, db, service, userID, 113, false,
		)
		_, secondScan, _ := prepareIntegrationTrivyHandoff(
			t, ctx, db, service, userID, 114, false,
		)
		if err := service.Finish(ctx, firstScan, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatal(err)
		}
		if err := service.Finish(ctx, secondScan, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatal(err)
		}
		results := claimKindConcurrently(
			t,
			ctx,
			service,
			KindTrivy,
			"queue-trivy-capacity-a",
			"queue-trivy-capacity-b",
		)
		var first Lease
		foundCount := 0
		for _, result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.found {
				first = result.lease
				foundCount++
			}
		}
		if foundCount != 1 {
			t.Fatalf("Trivy claims = %d, want 1", foundCount)
		}
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 1)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolTrivy, 1)
		finishIntegrationLease(t, ctx, service, first)

		second, found, err := service.Claim(
			ctx,
			KindTrivy,
			"queue-trivy-capacity-replacement",
		)
		if err != nil || !found {
			t.Fatalf("second Trivy Claim() = (%+v, %v, %v)", second, found, err)
		}
		finishIntegrationLease(t, ctx, service, second)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 0)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolTrivy, 0)
	})

	t.Run("native ceiling is independent and survives lease recovery", func(t *testing.T) {
		seedIntegrationNativeDecompileJob(t, ctx, db, userID, 120)
		seedIntegrationNativeDecompileJob(t, ctx, db, userID, 121)
		_, scanLease, _ := prepareIntegrationTrivyHandoff(
			t, ctx, db, service, userID, 122, false,
		)
		if err := service.Finish(ctx, scanLease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatal(err)
		}

		results := claimNativeConcurrently(
			t,
			ctx,
			service,
			"queue-native-capacity-a",
			"queue-native-capacity-b",
		)
		var nativeLease Lease
		foundCount := 0
		for _, result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.found {
				nativeLease = result.lease
				foundCount++
			}
		}
		if foundCount != 1 {
			t.Fatalf("native claims = %d, want 1", foundCount)
		}
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 1)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolNative, 1)

		trivyLease, found, err := service.Claim(
			ctx,
			KindTrivy,
			"queue-native-parallel-trivy",
		)
		if err != nil || !found {
			t.Fatalf("parallel Trivy Claim() = (%+v, %v, %v)", trivyLease, found, err)
		}
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 2)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolNative, 1)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolTrivy, 1)
		finishIntegrationLease(t, ctx, service, trivyLease)
		finishIntegrationLease(t, ctx, service, nativeLease)

		replacement, found, err := service.ClaimDecompileWorker(
			ctx,
			KindNative,
			"queue-native-recovery",
		)
		if err != nil || !found {
			t.Fatalf("replacement native Claim() = (%+v, %v, %v)", replacement, found, err)
		}
		if replacement.TaskAttemptID == nil {
			t.Fatal("native lease did not retain its task attempt identity")
		}
		nativeWorkspace := workspace.Identity{
			JobID: replacement.JobID, TaskID: replacement.TaskID,
			TaskAttemptID: *replacement.TaskAttemptID,
			FencingToken:  replacement.FencingToken,
			Kind:          string(replacement.Kind),
		}
		active, err := service.WorkspaceLeaseActive(ctx, nativeWorkspace)
		if err != nil || !active {
			t.Fatalf(
				"native WorkspaceLeaseActive() = (%v, %v), want true",
				active, err,
			)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND)
WHERE id = ? AND fencing_token = ?`,
			replacement.JobID,
			replacement.FencingToken,
		); err != nil {
			t.Fatal(err)
		}
		recovered, err := service.RecoverExpired(ctx, 10)
		if err != nil || recovered != 1 {
			t.Fatalf("native RecoverExpired() = (%d, %v)", recovered, err)
		}
		active, err = service.WorkspaceLeaseActive(ctx, nativeWorkspace)
		if err != nil || active {
			t.Fatalf(
				"recovered native WorkspaceLeaseActive() = (%v, %v), want false",
				active, err,
			)
		}
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 0)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolNative, 0)

		restarted, found, err := service.ClaimDecompileWorker(
			ctx,
			KindNative,
			"queue-native-after-restart",
		)
		if err != nil || !found || restarted.JobID != replacement.JobID {
			t.Fatalf("restarted native Claim() = (%+v, %v, %v)", restarted, found, err)
		}
		finishIntegrationLease(t, ctx, service, restarted)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, 0)
		assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolNative, 0)
	})

	t.Run("four mixed claimers respect two-slot ceiling and release", func(t *testing.T) {
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cleanupCancel()
			if err := releaseIntegrationResourceSlotsForUser(
				cleanupCtx,
				db,
				userID,
			); err != nil {
				t.Errorf("release two-slot integration leases: %v", err)
			}
		})
		_, trivyParent, trivyJobID := prepareIntegrationTrivyHandoff(
			t, ctx, db, service, userID, 123, false,
		)
		if err := service.Finish(ctx, trivyParent, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish mixed Trivy parent: %v", err)
		}
		scanJob := seedIntegrationJob(t, ctx, db, userID, 124)
		nativeJob := seedIntegrationNativeDecompileJob(t, ctx, db, userID, 125)
		bytecodeJob := seedIntegrationBytecodeDecompileJob(
			t, ctx, db, userID, 126,
		)

		requests := []integrationMixedClaimRequest{
			{name: "scan", kind: KindScan},
			{name: "trivy", kind: KindTrivy},
			{name: "native", kind: KindDecompile, workerKind: KindNative},
			{name: "bytecode", kind: KindDecompile, workerKind: KindBytecode},
		}
		expectedJobs := map[string]string{
			scanJob.jobID:     "scan",
			trivyJobID:        "trivy",
			nativeJob.jobID:   "native",
			bytecodeJob.jobID: "bytecode",
		}
		claimedJobs := make(map[string]struct{}, len(expectedJobs))

		for round := 1; round <= 2; round++ {
			results := claimMixedConcurrently(
				t,
				ctx,
				service,
				fmt.Sprintf("queue-mixed-round-%d", round),
				requests...,
			)
			active := collectIntegrationMixedClaims(
				t, results, expectedJobs, claimedJobs,
			)
			if len(active) != 2 {
				t.Fatalf("mixed claims in round %d = %d, want 2", round, len(active))
			}
			assertIntegrationMixedSlotCounts(t, ctx, db, active)

			assertIntegrationMixedClaimsBlocked(
				t,
				claimMixedConcurrently(
					t,
					ctx,
					service,
					fmt.Sprintf("queue-mixed-blocked-%d", round),
					requests...,
				),
				"while both global slots were occupied",
			)

			for len(active) > 0 {
				finishIntegrationLease(t, ctx, service, active[0].lease)
				active = active[1:]
				assertIntegrationMixedSlotCounts(t, ctx, db, active)
			}
		}

		if len(claimedJobs) != len(expectedJobs) {
			t.Fatalf("unique mixed jobs claimed = %d, want %d", len(claimedJobs), len(expectedJobs))
		}
	})

	t.Run("four mixed jobs fill four slots and preserve specialist ceilings", func(t *testing.T) {
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cleanupCancel()
			if err := releaseIntegrationResourceSlotsForUser(
				cleanupCtx,
				db,
				userID,
			); err != nil {
				t.Errorf("release four-slot integration leases: %v", err)
			}
			if err := updateIntegrationResourceLimits(
				cleanupCtx,
				db,
				2,
				1,
				1,
			); err != nil {
				t.Errorf("restore integration resource limits: %v", err)
			}
		})

		setIntegrationResourceLimits(t, ctx, db, 4, 1, 1)
		fourSlotService, err := NewService(NewMySQLRepository(db), Config{
			LeaseDuration:   5 * time.Minute,
			RetryDelay:      0,
			SampleRetention: taskdomain.DefaultSampleRetention,
			HeavySlotLimit:  4,
			TrivySlotLimit:  1,
			NativeSlotLimit: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := fourSlotService.ConfigureResourceLimits(ctx); err != nil {
			t.Fatalf("verify four-slot resource limits: %v", err)
		}

		_, firstTrivyParent, firstTrivyJobID := prepareIntegrationTrivyHandoff(
			t, ctx, db, fourSlotService, userID, 127, false,
		)
		if err := fourSlotService.Finish(ctx, firstTrivyParent, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish first four-slot Trivy parent: %v", err)
		}
		_, secondTrivyParent, secondTrivyJobID := prepareIntegrationTrivyHandoff(
			t, ctx, db, fourSlotService, userID, 128, false,
		)
		if err := fourSlotService.Finish(ctx, secondTrivyParent, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish second four-slot Trivy parent: %v", err)
		}
		scanJob := seedIntegrationJob(t, ctx, db, userID, 129)
		firstNativeJob := seedIntegrationNativeDecompileJob(
			t, ctx, db, userID, 130,
		)
		secondNativeJob := seedIntegrationNativeDecompileJob(
			t, ctx, db, userID, 131,
		)
		bytecodeJob := seedIntegrationBytecodeDecompileJob(
			t, ctx, db, userID, 132,
		)

		requests := []integrationMixedClaimRequest{
			{name: "scan", kind: KindScan},
			{name: "trivy", kind: KindTrivy},
			{name: "native", kind: KindDecompile, workerKind: KindNative},
			{name: "bytecode", kind: KindDecompile, workerKind: KindBytecode},
		}
		specialistRequests := []integrationMixedClaimRequest{
			{name: "trivy", kind: KindTrivy},
			{name: "native", kind: KindDecompile, workerKind: KindNative},
		}
		expectedJobs := map[string]string{
			scanJob.jobID:         "scan",
			firstTrivyJobID:       "trivy",
			secondTrivyJobID:      "trivy",
			firstNativeJob.jobID:  "native",
			secondNativeJob.jobID: "native",
			bytecodeJob.jobID:     "bytecode",
		}
		claimedJobs := make(map[string]struct{}, len(expectedJobs))

		active := collectIntegrationMixedClaims(
			t,
			claimMixedConcurrently(
				t, ctx, fourSlotService, "queue-mixed-four", requests...,
			),
			expectedJobs,
			claimedJobs,
		)
		if len(active) != 4 {
			t.Fatalf("four-slot mixed claims = %d, want 4", len(active))
		}
		assertIntegrationMixedSlotCounts(t, ctx, db, active)
		assertIntegrationMixedClaimsBlocked(
			t,
			claimMixedConcurrently(
				t, ctx, fourSlotService, "queue-mixed-four-full", requests...,
			),
			"while all four global slots were occupied",
		)

		active = finishIntegrationMixedLeaseByName(
			t, ctx, db, fourSlotService, active, "scan",
		)
		active = finishIntegrationMixedLeaseByName(
			t, ctx, db, fourSlotService, active, "bytecode",
		)
		assertIntegrationMixedClaimsBlocked(
			t,
			claimMixedConcurrently(
				t,
				ctx,
				fourSlotService,
				"queue-mixed-specialist-full",
				specialistRequests...,
			),
			"while the Trivy and native specialist slots were occupied",
		)
		assertIntegrationMixedSlotCounts(t, ctx, db, active)

		active = finishIntegrationMixedLeaseByName(
			t, ctx, db, fourSlotService, active, "trivy",
		)
		active = finishIntegrationMixedLeaseByName(
			t, ctx, db, fourSlotService, active, "native",
		)
		if len(active) != 0 {
			t.Fatalf("active mixed leases after release = %d, want 0", len(active))
		}

		active = collectIntegrationMixedClaims(
			t,
			claimMixedConcurrently(
				t,
				ctx,
				fourSlotService,
				"queue-mixed-specialist-released",
				specialistRequests...,
			),
			expectedJobs,
			claimedJobs,
		)
		if len(active) != 2 {
			t.Fatalf("released specialist claims = %d, want 2", len(active))
		}
		assertIntegrationMixedSlotCounts(t, ctx, db, active)
		for len(active) > 0 {
			finishIntegrationLease(t, ctx, fourSlotService, active[0].lease)
			active = active[1:]
			assertIntegrationMixedSlotCounts(t, ctx, db, active)
		}
		if len(claimedJobs) != len(expectedJobs) {
			t.Fatalf(
				"unique four-slot jobs claimed = %d, want %d",
				len(claimedJobs),
				len(expectedJobs),
			)
		}

		setIntegrationResourceLimits(t, ctx, db, 2, 1, 1)
		if err := service.ConfigureResourceLimits(ctx); err != nil {
			t.Fatalf("verify restored two-slot resource limits: %v", err)
		}
	})

	t.Run("workspace lease stays active across heartbeat MVCC and cancellation", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 6)
		lease, ok, err := service.Claim(ctx, KindScan, "queue-worker-mvcc")
		if err != nil || !ok || lease.JobID != job.jobID {
			t.Fatalf("Claim() = (%+v, %v, %v)", lease, ok, err)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("Start(): %v", err)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 SECOND),
    cancel_requested_at = UTC_TIMESTAMP(6)
WHERE id = ?`, lease.JobID); err != nil {
			t.Fatal(err)
		}

		heartbeat, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer heartbeat.Rollback()
		result, err := heartbeat.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 5 MINUTE)
WHERE id = ?
  AND task_id = ?
  AND lease_owner = ?
  AND fencing_token = ?
  AND status IN ('leased', 'running')
  AND lease_until > UTC_TIMESTAMP(6)`,
			lease.JobID, lease.TaskID, lease.Owner, lease.FencingToken,
		)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			t.Fatalf("heartbeat rows = %d, %v", updated, err)
		}

		time.Sleep(1200 * time.Millisecond)
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		active, err := service.WorkspaceLeaseActive(
			checkCtx,
			workspace.Identity{
				JobID: lease.JobID, TaskID: lease.TaskID,
				TaskAttemptID: *lease.TaskAttemptID,
				FencingToken:  lease.FencingToken,
				Kind:          string(lease.Kind),
			},
		)
		if err != nil || !active {
			t.Fatalf("WorkspaceLeaseActive() = (%v, %v), want true", active, err)
		}
		if err := heartbeat.Commit(); err != nil {
			t.Fatalf("commit heartbeat: %v", err)
		}
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish MVCC lease: %v", err)
		}
	})

	t.Run("single winner recovery and stale fencing", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 1)
		results := claimConcurrently(t, ctx, service, "queue-worker-a", "queue-worker-b")
		var lease Lease
		found := 0
		for _, result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.found {
				found++
				lease = result.lease
			}
		}
		if found != 1 || lease.JobID != job.jobID {
			t.Fatalf("concurrent claims found=%d lease=%+v", found, lease)
		}
		if lease.Attempt != 1 || lease.FencingToken != 2 {
			t.Fatalf("first lease counters = attempt %d fence %d", lease.Attempt, lease.FencingToken)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("start first lease: %v", err)
		}

		stale := lease
		stale.FencingToken--
		if _, err := service.Heartbeat(ctx, stale); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale heartbeat error = %v, want ErrLeaseLost", err)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND)
WHERE id = ?`, lease.JobID); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Heartbeat(ctx, lease); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("expired heartbeat error = %v, want ErrLeaseLost", err)
		}
		recovered, err := service.RecoverExpired(ctx, 10)
		if err != nil || recovered != 1 {
			t.Fatalf("RecoverExpired() = (%d, %v), want (1, nil)", recovered, err)
		}

		replacement, ok, err := service.Claim(ctx, KindScan, "queue-worker-c")
		if err != nil || !ok {
			t.Fatalf("replacement Claim() = (_, %v, %v)", ok, err)
		}
		if replacement.JobID != lease.JobID || replacement.Attempt != 2 ||
			replacement.FencingToken <= lease.FencingToken {
			t.Fatalf("replacement lease = %+v, previous = %+v", replacement, lease)
		}
		if err := service.Start(ctx, replacement); err != nil {
			t.Fatalf("start replacement lease: %v", err)
		}
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("old worker Finish() error = %v, want ErrLeaseLost", err)
		}
		if err := service.Finish(ctx, replacement, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("replacement Finish(): %v", err)
		}
		assertIntegrationState(
			t, ctx, db, job,
			"succeeded", "SUCCEEDED", "succeeded", 2, replacement.FencingToken,
		)
	})

	t.Run("child job preserves parent scan fence", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 5)
		scanLease, ok, err := service.Claim(ctx, KindScan, "queue-worker-parent")
		if err != nil || !ok || scanLease.JobID != job.jobID {
			t.Fatalf("parent Claim() = (%+v, %v, %v)", scanLease, ok, err)
		}
		if err := service.Start(ctx, scanLease); err != nil {
			t.Fatalf("start parent scan: %v", err)
		}

		childJobID := integrationUUID(59)
		if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key
) VALUES (?, ?, ?, 'native', 'queued', JSON_OBJECT('node_id', 7),
          UTC_TIMESTAMP(6), 0, 3, 0, 'queue-integration-child')`,
			childJobID, job.taskID, job.attemptID,
		); err != nil {
			t.Fatalf("seed child job: %v", err)
		}
		childLease, ok, err := service.Claim(ctx, KindNative, "queue-worker-child")
		if err != nil || !ok || childLease.JobID != childJobID {
			t.Fatalf("child Claim() = (%+v, %v, %v)", childLease, ok, err)
		}
		if err := service.Start(ctx, childLease); err != nil {
			t.Fatalf("start child job: %v", err)
		}
		if err := service.Finish(ctx, childLease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish child job: %v", err)
		}

		var attemptStatus string
		var attemptFence uint64
		if err := db.QueryRowContext(ctx, `
SELECT status, fencing_token
FROM task_attempts
WHERE id = ? AND task_id = ?`, job.attemptID, job.taskID).Scan(
			&attemptStatus, &attemptFence,
		); err != nil {
			t.Fatalf("read parent attempt after child: %v", err)
		}
		if attemptStatus != "running" || attemptFence != scanLease.FencingToken {
			t.Fatalf(
				"parent attempt after child = status %s fence %d, want running/%d",
				attemptStatus, attemptFence, scanLease.FencingToken,
			)
		}
		if err := service.Finish(ctx, scanLease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish parent scan after child: %v", err)
		}
		assertIntegrationState(
			t, ctx, db, job,
			"succeeded", "SUCCEEDED", "succeeded", 1, scanLease.FencingToken,
		)
	})

	t.Run("Trivy handoff is ordered and upstream partial reaches terminal task", func(t *testing.T) {
		job, scanLease, trivyJobID := prepareIntegrationTrivyHandoff(
			t, ctx, db, service, userID, 80, true,
		)
		if premature, found, err := service.Claim(
			ctx, KindTrivy, "queue-trivy-premature",
		); err != nil || found {
			t.Fatalf(
				"premature Trivy Claim() = (%+v, %v, %v), want no work",
				premature, found, err,
			)
		}
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		if err := service.Finish(ctx, scanLease, FinishInput{
			Outcome: OutcomePartialSucceeded,
		}); err != nil {
			t.Fatalf("finish scan handoff: %v", err)
		}
		var scanStatus, taskStatus, attemptStatus, stage string
		var completedAt sql.NullTime
		if err := db.QueryRowContext(ctx, `
SELECT scan.status, task.status, attempt.status, task.stage, task.completed_at
FROM jobs scan
JOIN tasks task ON task.id = scan.task_id
JOIN task_attempts attempt ON attempt.id = scan.task_attempt_id
WHERE scan.id = ?`, scanLease.JobID).Scan(
			&scanStatus, &taskStatus, &attemptStatus, &stage, &completedAt,
		); err != nil {
			t.Fatalf("read scan-to-Trivy handoff: %v", err)
		}
		if scanStatus != "succeeded" || taskStatus != "SCANNING" ||
			attemptStatus != "running" || stage != "SCANNING" ||
			completedAt.Valid {
			t.Fatalf(
				"handoff state = scan=%s task=%s attempt=%s stage=%s completed=%v",
				scanStatus, taskStatus, attemptStatus, stage, completedAt.Valid,
			)
		}

		trivyLease, found, err := service.Claim(
			ctx, KindTrivy, "queue-trivy-worker",
		)
		if err != nil || !found || trivyLease.JobID != trivyJobID {
			t.Fatalf("Trivy Claim() = (%+v, %v, %v)", trivyLease, found, err)
		}
		if err := service.Start(ctx, trivyLease); err != nil {
			t.Fatalf("start Trivy handoff: %v", err)
		}
		if err := service.Finish(ctx, trivyLease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish Trivy handoff: %v", err)
		}
		var trivyStatus string
		var progress uint16
		var attemptFence uint64
		if err := db.QueryRowContext(ctx, `
SELECT trivy.status, task.status, attempt.status,
       task.progress_basis_points, attempt.fencing_token
FROM jobs trivy
JOIN tasks task ON task.id = trivy.task_id
JOIN task_attempts attempt ON attempt.id = trivy.task_attempt_id
WHERE trivy.id = ?`, trivyJobID).Scan(
			&trivyStatus, &taskStatus, &attemptStatus,
			&progress, &attemptFence,
		); err != nil {
			t.Fatalf("read terminal Trivy handoff: %v", err)
		}
		if trivyStatus != "succeeded" ||
			taskStatus != "PARTIAL_SUCCEEDED" ||
			attemptStatus != "succeeded" || progress != 10_000 ||
			attemptFence != trivyLease.FencingToken {
			t.Fatalf(
				"terminal Trivy state = job=%s task=%s attempt=%s progress=%d fence=%d",
				trivyStatus, taskStatus, attemptStatus, progress, attemptFence,
			)
		}
		assertIntegrationTerminalRetention(t, ctx, db, job.taskID)
	})

	for offset, state := range []string{"queued", "leased", "running"} {
		t.Run("Trivy cancellation "+state, func(t *testing.T) {
			index := 81 + offset
			job, scanLease, trivyJobID := prepareIntegrationTrivyHandoff(
				t, ctx, db, service, userID, index, false,
			)
			if err := service.Finish(ctx, scanLease, FinishInput{
				Outcome: OutcomeSucceeded,
			}); err != nil {
				t.Fatalf("finish cancellation scan handoff: %v", err)
			}
			var trivyLease Lease
			if state != "queued" {
				var found bool
				var err error
				trivyLease, found, err = service.Claim(
					ctx, KindTrivy, "queue-trivy-cancel-"+state,
				)
				if err != nil || !found || trivyLease.JobID != trivyJobID {
					t.Fatalf("claim cancellation Trivy = (%+v, %v, %v)", trivyLease, found, err)
				}
			}
			if state == "running" {
				if err := service.Start(ctx, trivyLease); err != nil {
					t.Fatalf("start cancellation Trivy: %v", err)
				}
			}
			taskRepository := taskdomain.NewMySQLRepository(db)
			cancelled, err := taskRepository.Cancel(
				ctx,
				taskdomain.MutationRecord{
					TaskID: job.taskID, UserID: userID,
					IdempotencyKey:  "trivy-cancel-" + state,
					SampleRetention: taskdomain.DefaultSampleRetention,
				},
			)
			if err != nil {
				t.Fatalf("cancel Trivy %s: %v", state, err)
			}
			wantTaskStatus := "CANCELLED"
			if state == "running" {
				wantTaskStatus = "CANCEL_REQUESTED"
			}
			if cancelled.Status != wantTaskStatus {
				t.Fatalf("cancelled task status = %s, want %s", cancelled.Status, wantTaskStatus)
			}
			if state == "running" {
				if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND)
WHERE id = ?`, trivyJobID); err != nil {
					t.Fatal(err)
				}
				recovered, err := service.RecoverExpired(ctx, 10)
				if err != nil || recovered != 1 {
					t.Fatalf("recover cancelled Trivy = (%d, %v)", recovered, err)
				}
			}
			var jobStatus, actualTaskStatus, actualAttemptStatus string
			if err := db.QueryRowContext(ctx, `
SELECT trivy.status, task.status, attempt.status
FROM jobs trivy
JOIN tasks task ON task.id = trivy.task_id
JOIN task_attempts attempt ON attempt.id = trivy.task_attempt_id
WHERE trivy.id = ?`, trivyJobID).Scan(
				&jobStatus, &actualTaskStatus, &actualAttemptStatus,
			); err != nil {
				t.Fatal(err)
			}
			if jobStatus != "cancelled" ||
				actualTaskStatus != "CANCELLED" ||
				actualAttemptStatus != "cancelled" {
				t.Fatalf(
					"cancelled Trivy state = job=%s task=%s attempt=%s",
					jobStatus, actualTaskStatus, actualAttemptStatus,
				)
			}
			replay, err := taskRepository.Cancel(
				ctx,
				taskdomain.MutationRecord{
					TaskID: job.taskID, UserID: userID,
					IdempotencyKey:  "trivy-cancel-" + state,
					SampleRetention: taskdomain.DefaultSampleRetention,
				},
			)
			if err != nil || replay.Status != "CANCELLED" {
				t.Fatalf("cancel Trivy replay = (%+v, %v)", replay, err)
			}
		})
	}

	t.Run("skip locked distributes distinct jobs", func(t *testing.T) {
		for round := 0; round < 4; round++ {
			assertSkipLockedClaimRound(
				t, ctx, db, service, userID, 20+round*2, round,
			)
		}
	})

	t.Run("maximum delivery attempt fails deterministically", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 4)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET status = 'running',
    attempt = 3,
    max_attempts = 3,
    fencing_token = 4,
    lease_owner = 'dead-worker',
    lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND),
    heartbeat_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 2 SECOND),
    started_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 3 SECOND)
WHERE id = ?`, job.jobID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'running', fencing_token = 4, started_at = UTC_TIMESTAMP(6)
WHERE id = ?`, job.attemptID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET status = 'VALIDATING', stage = 'VALIDATING'
WHERE id = ?`, job.taskID); err != nil {
			t.Fatal(err)
		}
		assignIntegrationResourceSlot(
			t,
			ctx,
			db,
			resourcePoolGlobal,
			job.jobID,
			4,
			"dead-worker",
		)
		recovered, err := service.RecoverExpired(ctx, 10)
		if err != nil || recovered != 1 {
			t.Fatalf("RecoverExpired() = (%d, %v), want final failure", recovered, err)
		}
		assertIntegrationState(t, ctx, db, job, "failed", "FAILED", "failed", 3, 4)
		assertIntegrationTerminalRetention(t, ctx, db, job.taskID)
	})

	t.Run("finish starts retention once and terminal replay cannot drift it", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 70)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		lease, ok, err := service.Claim(ctx, KindScan, "queue-worker-retention")
		if err != nil || !ok || lease.JobID != job.jobID {
			t.Fatalf("retention Claim() = (%+v, %v, %v)", lease, ok, err)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("start retention job: %v", err)
		}
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("finish retention job: %v", err)
		}
		firstExpiry := assertIntegrationTerminalRetention(
			t, ctx, db, job.taskID,
		)
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome: OutcomeSucceeded,
		}); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("terminal Finish() replay error = %v, want ErrLeaseLost", err)
		}
		assertIntegrationSampleExpiry(
			t, ctx, db, job.taskID, firstExpiry,
		)
	})

	t.Run("finish preserves an administrator extension", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 71)
		var extended time.Time
		if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_expires_at = DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 90 DAY)
WHERE id = ?`, job.taskID); err != nil {
			t.Fatalf("extend integration sample retention: %v", err)
		}
		if err := db.QueryRowContext(ctx, `
SELECT sample_expires_at FROM tasks WHERE id = ?`, job.taskID).Scan(&extended); err != nil {
			t.Fatalf("read extended integration retention: %v", err)
		}
		lease, ok, err := service.Claim(ctx, KindScan, "queue-worker-extension")
		if err != nil || !ok || lease.JobID != job.jobID {
			t.Fatalf("extension Claim() = (%+v, %v, %v)", lease, ok, err)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("start extension job: %v", err)
		}
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome: OutcomePartialSucceeded,
		}); err != nil {
			t.Fatalf("finish extension job: %v", err)
		}
		assertIntegrationState(
			t, ctx, db, job,
			"succeeded", "PARTIAL_SUCCEEDED", "succeeded", 1, lease.FencingToken,
		)
		assertIntegrationSampleExpiry(t, ctx, db, job.taskID, extended)
	})

	t.Run("final transient finish starts retention", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 72)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		if _, err := db.ExecContext(ctx, `
UPDATE jobs SET attempt = 2, max_attempts = 3 WHERE id = ?`, job.jobID); err != nil {
			t.Fatalf("prepare final transient attempt: %v", err)
		}
		lease, ok, err := service.Claim(ctx, KindScan, "queue-worker-final-transient")
		if err != nil || !ok || lease.JobID != job.jobID {
			t.Fatalf("final transient Claim() = (%+v, %v, %v)", lease, ok, err)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("start final transient job: %v", err)
		}
		if err := service.Finish(ctx, lease, FinishInput{
			Outcome:   OutcomeTransientFailure,
			ErrorCode: "engine_timeout", ErrorMessage: "The analyzer timed out.",
		}); err != nil {
			t.Fatalf("finish final transient job: %v", err)
		}
		assertIntegrationState(
			t, ctx, db, job,
			"failed", "FAILED", "failed", 3, lease.FencingToken,
		)
		assertIntegrationTerminalRetention(t, ctx, db, job.taskID)
	})

	t.Run("immediate cancellation starts retention once", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 73)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		repository := taskdomain.NewMySQLRepository(db)
		record := taskdomain.MutationRecord{
			TaskID: job.taskID, UserID: userID,
			IdempotencyKey:  "queue-integration-immediate-cancel",
			SampleRetention: taskdomain.DefaultSampleRetention,
		}
		value, err := repository.Cancel(ctx, record)
		if err != nil || value.Status != taskdomain.StatusCancelled {
			t.Fatalf("immediate Cancel() = (%+v, %v)", value, err)
		}
		firstExpiry := assertIntegrationTerminalRetention(
			t, ctx, db, job.taskID,
		)
		replayed, err := repository.Cancel(ctx, record)
		if err != nil || replayed.Status != taskdomain.StatusCancelled {
			t.Fatalf("immediate Cancel() replay = (%+v, %v)", replayed, err)
		}
		assertIntegrationSampleExpiry(t, ctx, db, job.taskID, firstExpiry)
	})

	t.Run("terminal transition does not revive a deleted sample", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 75)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		var originalExpiry time.Time
		if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_deleted_at = UTC_TIMESTAMP(6)
WHERE id = ?`, job.taskID); err != nil {
			t.Fatalf("mark integration sample deleted: %v", err)
		}
		if err := db.QueryRowContext(ctx, `
SELECT sample_expires_at FROM tasks WHERE id = ?`, job.taskID).Scan(
			&originalExpiry,
		); err != nil {
			t.Fatalf("read deleted sample expiry: %v", err)
		}
		value, err := taskdomain.NewMySQLRepository(db).Cancel(
			ctx,
			taskdomain.MutationRecord{
				TaskID: job.taskID, UserID: userID,
				IdempotencyKey:  "queue-integration-deleted-sample-cancel",
				SampleRetention: taskdomain.DefaultSampleRetention,
			},
		)
		if err != nil || value.Status != taskdomain.StatusCancelled {
			t.Fatalf("deleted-sample Cancel() = (%+v, %v)", value, err)
		}
		assertIntegrationSampleExpiry(
			t, ctx, db, job.taskID, originalExpiry,
		)
	})

	t.Run("cooperative cancellation starts retention when recovery completes", func(t *testing.T) {
		job := seedIntegrationJob(t, ctx, db, userID, 74)
		setIntegrationSampleExpiryInPast(t, ctx, db, job.taskID)
		lease, ok, err := service.Claim(ctx, KindScan, "queue-worker-cancellation")
		if err != nil || !ok || lease.JobID != job.jobID {
			t.Fatalf("cancellation Claim() = (%+v, %v, %v)", lease, ok, err)
		}
		if err := service.Start(ctx, lease); err != nil {
			t.Fatalf("start cancellation job: %v", err)
		}
		value, err := taskdomain.NewMySQLRepository(db).Cancel(
			ctx,
			taskdomain.MutationRecord{
				TaskID: job.taskID, UserID: userID,
				IdempotencyKey:  "queue-integration-cooperative-cancel",
				SampleRetention: taskdomain.DefaultSampleRetention,
			},
		)
		if err != nil || value.Status != taskdomain.StatusCancelRequested {
			t.Fatalf("cooperative Cancel() = (%+v, %v)", value, err)
		}
		if !value.SampleExpiresAt.Before(time.Now().UTC()) {
			t.Fatalf(
				"cancel request prematurely moved sample expiry to %s",
				value.SampleExpiresAt,
			)
		}
		if _, err := db.ExecContext(ctx, `
UPDATE jobs
SET lease_until = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND)
WHERE id = ?`, job.jobID); err != nil {
			t.Fatalf("expire cancellation lease: %v", err)
		}
		recovered, err := service.RecoverExpired(ctx, 10)
		if err != nil || recovered != 1 {
			t.Fatalf("recover cancellation = (%d, %v)", recovered, err)
		}
		assertIntegrationState(
			t, ctx, db, job,
			"cancelled", "CANCELLED", "cancelled", 1, lease.FencingToken,
		)
		assertIntegrationTerminalRetention(t, ctx, db, job.taskID)
	})
}

func assertSkipLockedClaimRound(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	service *Service,
	userID uint64,
	firstIndex int,
	round int,
) {
	t.Helper()
	first := seedIntegrationJob(t, ctx, db, userID, firstIndex)
	second := seedIntegrationJob(t, ctx, db, userID, firstIndex+1)

	blocker, err := beginClaimTransaction(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	lockedJobID, err := lockNextClaimCandidate(ctx, blocker)
	if err != nil {
		t.Fatalf("lock first claim candidate in round %d: %v", round, err)
	}
	if lockedJobID != first.jobID {
		t.Fatalf(
			"locked job in round %d = %s, want first candidate %s",
			round, lockedJobID, first.jobID,
		)
	}

	claimCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	secondLease, found, err := service.Claim(
		claimCtx, KindScan, fmt.Sprintf("queue-worker-skip-%d-b", round),
	)
	if err != nil || !found {
		t.Fatalf(
			"Claim() while first candidate is locked in round %d = (%+v, %v, %v)",
			round, secondLease, found, err,
		)
	}
	if secondLease.JobID != second.jobID {
		t.Fatalf(
			"skip-locked Claim() in round %d selected %s, want %s",
			round, secondLease.JobID, second.jobID,
		)
	}
	if err := blocker.Rollback(); err != nil {
		t.Fatalf("release first claim candidate in round %d: %v", round, err)
	}

	firstLease, found, err := service.Claim(
		ctx, KindScan, fmt.Sprintf("queue-worker-skip-%d-a", round),
	)
	if err != nil || !found {
		t.Fatalf(
			"Claim() after releasing first candidate in round %d = (%+v, %v, %v)",
			round, firstLease, found, err,
		)
	}
	if firstLease.JobID != first.jobID {
		t.Fatalf(
			"released candidate Claim() in round %d selected %s, want %s",
			round, firstLease.JobID, first.jobID,
		)
	}
	finishIntegrationLease(t, ctx, service, secondLease)
	finishIntegrationLease(t, ctx, service, firstLease)
}

func lockNextClaimCandidate(
	ctx context.Context,
	transaction *sql.Tx,
) (string, error) {
	var lease Lease
	var payload []byte
	var attemptID sql.NullInt64
	var attemptToken sql.NullInt64
	var attemptStatus sql.NullString
	err := transaction.QueryRowContext(ctx, claimCandidateSQL, KindScan).Scan(
		&lease.JobID, &lease.TaskID, &attemptID, &lease.Kind, &payload,
		&lease.Attempt, &lease.MaxAttempts, &lease.FencingToken,
		&attemptToken, &attemptStatus,
	)
	if err != nil {
		return "", err
	}
	return lease.JobID, nil
}

type integrationClaimResult struct {
	lease Lease
	found bool
	err   error
}

type integrationMixedClaimRequest struct {
	name       string
	kind       Kind
	workerKind Kind
}

type integrationMixedClaimResult struct {
	name string
	integrationClaimResult
}

func claimConcurrently(
	t *testing.T,
	ctx context.Context,
	service *Service,
	owners ...string,
) []integrationClaimResult {
	return claimKindConcurrently(t, ctx, service, KindScan, owners...)
}

func claimKindConcurrently(
	t *testing.T,
	ctx context.Context,
	service *Service,
	kind Kind,
	owners ...string,
) []integrationClaimResult {
	t.Helper()
	start := make(chan struct{})
	results := make(chan integrationClaimResult, len(owners))
	var workers sync.WaitGroup
	for _, owner := range owners {
		owner := owner
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			lease, found, err := service.Claim(ctx, kind, owner)
			results <- integrationClaimResult{lease: lease, found: found, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	collected := make([]integrationClaimResult, 0, len(owners))
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func claimNativeConcurrently(
	t *testing.T,
	ctx context.Context,
	service *Service,
	owners ...string,
) []integrationClaimResult {
	t.Helper()
	start := make(chan struct{})
	results := make(chan integrationClaimResult, len(owners))
	var workers sync.WaitGroup
	for _, owner := range owners {
		owner := owner
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			lease, found, err := service.ClaimDecompileWorker(
				ctx,
				KindNative,
				owner,
			)
			results <- integrationClaimResult{
				lease: lease,
				found: found,
				err:   err,
			}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	collected := make([]integrationClaimResult, 0, len(owners))
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func claimMixedConcurrently(
	t *testing.T,
	ctx context.Context,
	service *Service,
	ownerPrefix string,
	requests ...integrationMixedClaimRequest,
) []integrationMixedClaimResult {
	t.Helper()
	start := make(chan struct{})
	results := make(chan integrationMixedClaimResult, len(requests))
	var workers sync.WaitGroup
	for _, request := range requests {
		request := request
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			owner := ownerPrefix + "-" + request.name
			var lease Lease
			var found bool
			var err error
			if request.workerKind == "" {
				lease, found, err = service.Claim(
					ctx,
					request.kind,
					owner,
				)
			} else {
				lease, found, err = service.ClaimDecompileWorker(
					ctx,
					request.workerKind,
					owner,
				)
			}
			results <- integrationMixedClaimResult{
				name: request.name,
				integrationClaimResult: integrationClaimResult{
					lease: lease,
					found: found,
					err:   err,
				},
			}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	collected := make([]integrationMixedClaimResult, 0, len(requests))
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func collectIntegrationMixedClaims(
	t *testing.T,
	results []integrationMixedClaimResult,
	expectedJobs map[string]string,
	claimedJobs map[string]struct{},
) []integrationMixedClaimResult {
	t.Helper()
	active := make([]integrationMixedClaimResult, 0, len(results))
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("%s mixed claim: %v", result.name, result.err)
		}
		if !result.found {
			continue
		}
		wantName, seeded := expectedJobs[result.lease.JobID]
		if !seeded {
			t.Fatalf("%s claimed unexpected job %s", result.name, result.lease.JobID)
		}
		if result.name != wantName {
			t.Fatalf(
				"%s claimed %s job %s",
				result.name,
				wantName,
				result.lease.JobID,
			)
		}
		if _, duplicate := claimedJobs[result.lease.JobID]; duplicate {
			t.Fatalf("job %s was claimed more than once", result.lease.JobID)
		}
		claimedJobs[result.lease.JobID] = struct{}{}
		assertIntegrationMixedLeaseSlots(t, result)
		active = append(active, result)
	}
	return active
}

func assertIntegrationMixedClaimsBlocked(
	t *testing.T,
	results []integrationMixedClaimResult,
	reason string,
) {
	t.Helper()
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("blocked %s mixed claim: %v", result.name, result.err)
		}
		if result.found {
			t.Fatalf("%s claimed job %s %s", result.name, result.lease.JobID, reason)
		}
	}
}

func finishIntegrationMixedLeaseByName(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	service *Service,
	active []integrationMixedClaimResult,
	name string,
) []integrationMixedClaimResult {
	t.Helper()
	for index, result := range active {
		if result.name != name {
			continue
		}
		finishIntegrationLease(t, ctx, service, result.lease)
		active = append(active[:index], active[index+1:]...)
		assertIntegrationMixedSlotCounts(t, ctx, db, active)
		return active
	}
	t.Fatalf("active mixed leases did not include %s", name)
	return nil
}

func assertIntegrationMixedLeaseSlots(
	t *testing.T,
	result integrationMixedClaimResult,
) {
	t.Helper()
	wanted := []string{resourcePoolGlobal}
	wantedWorkerKind := ""
	wantedEngineTarget := ""
	switch result.name {
	case "native":
		wanted = append(wanted, resourcePoolNative)
		wantedWorkerKind = string(KindNative)
		wantedEngineTarget = "ghidra"
	case "trivy":
		wanted = append(wanted, resourcePoolTrivy)
	case "bytecode":
		wantedWorkerKind = string(KindBytecode)
		wantedEngineTarget = "vineflower"
	case "scan":
	default:
		t.Fatalf("unknown mixed worker %q", result.name)
	}
	if wantedWorkerKind != "" {
		var payload struct {
			Engine struct {
				Target     string `json:"target"`
				WorkerKind string `json:"worker_kind"`
			} `json:"engine"`
		}
		if err := json.Unmarshal(result.lease.Payload, &payload); err != nil {
			t.Fatalf("decode %s decompile payload: %v", result.name, err)
		}
		if payload.Engine.WorkerKind != wantedWorkerKind ||
			payload.Engine.Target != wantedEngineTarget {
			t.Fatalf(
				"%s engine = %s/%s, want %s/%s",
				result.name,
				payload.Engine.WorkerKind,
				payload.Engine.Target,
				wantedWorkerKind,
				wantedEngineTarget,
			)
		}
	}
	if len(result.lease.ResourceSlots) != len(wanted) {
		t.Fatalf(
			"%s resource slots = %+v, want pools %v",
			result.name,
			result.lease.ResourceSlots,
			wanted,
		)
	}
	actual := make(map[string]struct{}, len(result.lease.ResourceSlots))
	for _, slot := range result.lease.ResourceSlots {
		if slot.SlotNumber == 0 {
			t.Fatalf("%s received zero-numbered slot %+v", result.name, slot)
		}
		if _, duplicate := actual[slot.Pool]; duplicate {
			t.Fatalf("%s received duplicate %s slots", result.name, slot.Pool)
		}
		actual[slot.Pool] = struct{}{}
	}
	for _, pool := range wanted {
		if _, found := actual[pool]; !found {
			t.Fatalf("%s did not receive required %s slot", result.name, pool)
		}
	}
}

func assertIntegrationMixedSlotCounts(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	active []integrationMixedClaimResult,
) {
	t.Helper()
	native := 0
	trivy := 0
	for _, result := range active {
		switch result.name {
		case "native":
			native++
		case "trivy":
			trivy++
		}
	}
	assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolGlobal, len(active))
	assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolNative, native)
	assertIntegrationOccupiedSlots(t, ctx, db, resourcePoolTrivy, trivy)
}

func finishIntegrationLease(
	t *testing.T,
	ctx context.Context,
	service *Service,
	lease Lease,
) {
	t.Helper()
	if err := service.Start(ctx, lease); err != nil {
		t.Fatalf("start integration lease %s: %v", lease.JobID, err)
	}
	if err := service.Finish(ctx, lease, FinishInput{
		Outcome: OutcomeSucceeded,
	}); err != nil {
		t.Fatalf("finish integration lease %s: %v", lease.JobID, err)
	}
}

func assertIntegrationOccupiedSlots(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	pool string,
	want int,
) {
	t.Helper()
	var actual int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM job_resource_slots
WHERE pool = ? AND job_id IS NOT NULL`, pool).Scan(&actual); err != nil {
		t.Fatalf("count occupied %s slots: %v", pool, err)
	}
	if actual != want {
		t.Fatalf("occupied %s slots = %d, want %d", pool, actual, want)
	}
}

func setIntegrationResourceLimits(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	heavy int,
	trivy int,
	native int,
) {
	t.Helper()
	if err := updateIntegrationResourceLimits(
		ctx,
		db,
		heavy,
		trivy,
		native,
	); err != nil {
		t.Fatalf("set integration resource limits to %d/%d/%d: %v", heavy, trivy, native, err)
	}
}

func updateIntegrationResourceLimits(
	ctx context.Context,
	db *sql.DB,
	heavy int,
	trivy int,
	native int,
) error {
	// Production rejects capacity drift after the first job. The integration
	// fixture changes the authority row only while every resource slot is free.
	transaction, err := beginClaimTransaction(ctx, db)
	if err != nil {
		return fmt.Errorf("begin integration resource limit update: %w", err)
	}
	defer transaction.Rollback()
	var currentHeavy int
	var currentTrivy int
	var currentNative int
	if err := transaction.QueryRowContext(ctx, `
SELECT heavy_slots, trivy_slots, native_slots
FROM job_resource_limits
WHERE id = 1
FOR UPDATE`).Scan(&currentHeavy, &currentTrivy, &currentNative); err != nil {
		return fmt.Errorf("lock integration resource limits: %w", err)
	}
	var occupied int
	if err := transaction.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM job_resource_slots
WHERE job_id IS NOT NULL`).Scan(&occupied); err != nil {
		return fmt.Errorf("count occupied integration resource slots: %w", err)
	}
	if occupied != 0 {
		return fmt.Errorf("cannot change integration resource limits with %d occupied slots", occupied)
	}
	if currentHeavy != heavy || currentTrivy != trivy || currentNative != native {
		result, err := transaction.ExecContext(ctx, `
UPDATE job_resource_limits
SET heavy_slots = ?,
    trivy_slots = ?,
    native_slots = ?,
    generation = generation + 1
WHERE id = 1`, heavy, trivy, native)
		if err != nil {
			return fmt.Errorf("update integration resource limits: %w", err)
		}
		if err := requireOne(
			result,
			ErrInconsistentState,
			"inspect integration resource limit update",
		); err != nil {
			return err
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit integration resource limit update: %w", err)
	}
	return nil
}

func releaseIntegrationResourceSlotsForUser(
	ctx context.Context,
	db *sql.DB,
	userID uint64,
) error {
	_, err := db.ExecContext(ctx, `
UPDATE job_resource_slots slot
JOIN jobs job ON job.id = slot.job_id
JOIN tasks task ON task.id = job.task_id
SET slot.job_id = NULL,
    slot.job_fencing_token = NULL,
    slot.lease_owner = NULL,
    slot.acquired_at = NULL
WHERE task.created_by = ?`, userID)
	if err != nil {
		return fmt.Errorf("release integration resource slots: %w", err)
	}
	return nil
}

func assignIntegrationResourceSlot(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	pool string,
	jobID string,
	fencingToken uint64,
	owner string,
) {
	t.Helper()
	result, err := db.ExecContext(ctx, `
UPDATE job_resource_slots
SET job_id = ?,
    job_fencing_token = ?,
    lease_owner = ?,
    acquired_at = UTC_TIMESTAMP(6)
WHERE pool = ?
  AND slot_number = 1
  AND job_id IS NULL`,
		jobID,
		fencingToken,
		owner,
		pool,
	)
	if err != nil {
		t.Fatalf("assign integration %s slot: %v", pool, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("assigned integration %s slots = %d, %v", pool, affected, err)
	}
}

func prepareIntegrationTrivyHandoff(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	service *Service,
	userID uint64,
	index int,
	upstreamPartial bool,
) (integrationJob, Lease, string) {
	t.Helper()
	job := seedIntegrationJob(t, ctx, db, userID, index)
	scanLease, found, err := service.Claim(
		ctx, KindScan, fmt.Sprintf("queue-scan-handoff-%d", index),
	)
	if err != nil || !found || scanLease.JobID != job.jobID {
		t.Fatalf("scan handoff Claim() = (%+v, %v, %v)", scanLease, found, err)
	}
	if err := service.Start(ctx, scanLease); err != nil {
		t.Fatalf("start scan handoff: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET status = 'INDEXING',
    stage = 'INDEXING',
    progress_basis_points = 8000
WHERE id = ?`, job.taskID); err != nil {
		t.Fatalf("advance integration scan to indexing: %v", err)
	}
	hash := fmt.Sprintf("%064x", 10_000+index)
	trivyJobID := integrationUUID(index*10 + 4)
	if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key
) VALUES (
    ?, ?, ?, 'trivy', 'queued',
    JSON_OBJECT(
        'schema_version', 1,
        'format', 'docker-tar',
        'source_storage_key', ?,
        'source_sha256', ?,
        'source_size_bytes', 1,
        'image_logical_path', '/',
        'upstream_partial', CAST(? AS JSON)
    ),
    UTC_TIMESTAMP(6), 0, 3, ?, ?
)`,
		trivyJobID, job.taskID, job.attemptID,
		"blobs/sha256/"+hash[:2]+"/"+hash, hash,
		fmt.Sprintf("%t", upstreamPartial), scanLease.FencingToken,
		fmt.Sprintf("trivy:attempt:%d", job.attemptID),
	); err != nil {
		t.Fatalf("seed integration Trivy handoff: %v", err)
	}
	return job, scanLease, trivyJobID
}

func seedIntegrationUser(t *testing.T, ctx context.Context, db *sql.DB) uint64 {
	t.Helper()
	result, err := db.ExecContext(ctx, `
INSERT INTO users (
    public_id, username, display_name, password_hash, role, status,
    force_password_change
) VALUES (?, ?, 'Queue Integration', 'not-used', 'operator', 'active', FALSE)`,
		integrationUUID(90), "queue-integration-user",
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

func seedIntegrationJob(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	userID uint64,
	index int,
) integrationJob {
	t.Helper()
	value := integrationJob{
		jobID: integrationUUID(index*10 + 1), taskID: integrationUUID(index*10 + 2),
		uploadID: integrationUUID(index*10 + 3),
	}
	hash := fmt.Sprintf("%064x", 10_000+index)
	blobResult, err := db.ExecContext(ctx, `
INSERT INTO blobs (
    sha256, size_bytes, storage_key, reference_count, state, verified_at
) VALUES (?, 1, ?, 2, 'available', UTC_TIMESTAMP(6))`,
		hash, "blobs/sha256/"+hash[:2]+"/"+hash,
	)
	if err != nil {
		t.Fatalf("seed blob %d: %v", index, err)
	}
	blobID, err := blobResult.LastInsertId()
	if err != nil || blobID <= 0 {
		t.Fatalf("seed blob ID = %d, %v", blobID, err)
	}
	value.blobID = uint64(blobID)
	if _, err := db.ExecContext(ctx, `
INSERT INTO uploads (
    id, created_by, original_name, display_name, content_type,
    declared_size_bytes, part_size_bytes, actual_sha256, status, blob_id,
    expires_at, completed_at
) VALUES (?, ?, ?, ?, 'application/octet-stream', 1, 33554432, ?,
          'completed', ?, DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 1 DAY), UTC_TIMESTAMP(6))`,
		value.uploadID, userID, []byte(fmt.Sprintf("queue-%d.bin", index)),
		fmt.Sprintf("queue-%d.bin", index), hash, blobID,
	); err != nil {
		t.Fatalf("seed upload %d: %v", index, err)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO tasks (
    id, upload_id, blob_id, created_by, name, tags, status,
    progress_basis_points, risk_level, limits_snapshot, sample_expires_at
) VALUES (?, ?, ?, ?, ?, JSON_ARRAY(), 'QUEUED', 0, 'UNKNOWN',
          JSON_OBJECT('max_depth', 10), DATE_ADD(UTC_TIMESTAMP(6), INTERVAL 30 DAY))`,
		value.taskID, value.uploadID, blobID, userID,
		fmt.Sprintf("Queue integration %d", index),
	); err != nil {
		t.Fatalf("seed task %d: %v", index, err)
	}
	attemptResult, err := db.ExecContext(ctx, `
INSERT INTO task_attempts (
    task_id, attempt_number, fencing_token, status
) VALUES (?, 1, 1, 'queued')`, value.taskID)
	if err != nil {
		t.Fatalf("seed task attempt %d: %v", index, err)
	}
	attemptID, err := attemptResult.LastInsertId()
	if err != nil || attemptID <= 0 {
		t.Fatalf("seed attempt ID = %d, %v", attemptID, err)
	}
	value.attemptID = uint64(attemptID)
	if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key
) VALUES (?, ?, ?, 'scan', 'queued', JSON_OBJECT('task_id', ?),
          UTC_TIMESTAMP(6), 0, 3, 1, ?)`,
		value.jobID, value.taskID, attemptID, value.taskID,
		fmt.Sprintf("queue-integration-%d", index),
	); err != nil {
		t.Fatalf("seed job %d: %v", index, err)
	}
	return value
}

func seedIntegrationNativeDecompileJob(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	userID uint64,
	index int,
) integrationJob {
	t.Helper()
	return seedIntegrationDecompileJob(
		t,
		ctx,
		db,
		userID,
		index,
		KindNative,
	)
}

func seedIntegrationBytecodeDecompileJob(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	userID uint64,
	index int,
) integrationJob {
	t.Helper()
	return seedIntegrationDecompileJob(
		t,
		ctx,
		db,
		userID,
		index,
		KindBytecode,
	)
}

func seedIntegrationDecompileJob(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	userID uint64,
	index int,
	workerKind Kind,
) integrationJob {
	t.Helper()
	if workerKind != KindNative && workerKind != KindBytecode {
		t.Fatalf("unsupported integration decompile worker %q", workerKind)
	}
	engineTarget := "ghidra"
	if workerKind == KindBytecode {
		engineTarget = "vineflower"
	}
	job := seedIntegrationJob(t, ctx, db, userID, index)
	if _, err := db.ExecContext(ctx, `
DELETE FROM jobs
WHERE id = ? AND kind = 'scan' AND status = 'queued'`, job.jobID); err != nil {
		t.Fatalf("remove integration %s scan job %d: %v", workerKind, index, err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET status = 'SUCCEEDED',
    stage = NULL,
    progress_basis_points = 10000,
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ?`, job.taskID); err != nil {
		t.Fatalf("terminalize integration %s task %d: %v", workerKind, index, err)
	}
	if _, err := db.ExecContext(ctx, `
UPDATE task_attempts
SET status = 'succeeded',
    started_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 SECOND),
    completed_at = UTC_TIMESTAMP(6)
WHERE id = ? AND task_id = ?`, job.attemptID, job.taskID); err != nil {
		t.Fatalf(
			"terminalize integration %s task attempt %d: %v",
			workerKind,
			index,
			err,
		)
	}
	job.jobID = integrationUUID(index*10 + 4)
	if _, err := db.ExecContext(ctx, `
INSERT INTO jobs (
    id, task_id, task_attempt_id, kind, status, payload, available_at,
    attempt, max_attempts, fencing_token, idempotency_key
) VALUES (
	?, ?, ?, 'decompile', 'queued',
    JSON_OBJECT(
        'schema_version', 1,
        'engine', JSON_OBJECT(
			'target', ?,
			'worker_kind', ?
        )
    ),
    UTC_TIMESTAMP(6), 0, 3, 0, ?
)`,
		job.jobID,
		job.taskID,
		job.attemptID,
		engineTarget,
		workerKind,
		fmt.Sprintf("queue-%s-integration-%d", workerKind, index),
	); err != nil {
		t.Fatalf("seed integration %s decompile %d: %v", workerKind, index, err)
	}
	return job
}

func assertIntegrationState(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	job integrationJob,
	jobStatus string,
	taskStatus string,
	attemptStatus string,
	attempt uint32,
	fence uint64,
) {
	t.Helper()
	var actualJobStatus, actualTaskStatus, actualAttemptStatus string
	var actualAttempt uint32
	var jobFence, attemptFence uint64
	err := db.QueryRowContext(ctx, `
SELECT j.status, task.status, task_attempt.status,
       j.attempt, j.fencing_token, task_attempt.fencing_token
FROM jobs j
JOIN tasks task ON task.id = j.task_id
JOIN task_attempts task_attempt ON task_attempt.id = j.task_attempt_id
WHERE j.id = ?`, job.jobID).Scan(
		&actualJobStatus, &actualTaskStatus, &actualAttemptStatus,
		&actualAttempt, &jobFence, &attemptFence,
	)
	if err != nil {
		t.Fatal(err)
	}
	if actualJobStatus != jobStatus || actualTaskStatus != taskStatus ||
		actualAttemptStatus != attemptStatus || actualAttempt != attempt ||
		jobFence != fence || attemptFence != fence {
		t.Fatalf(
			"state = job=%s task=%s attempt_status=%s attempt=%d fences=%d/%d",
			actualJobStatus, actualTaskStatus, actualAttemptStatus,
			actualAttempt, jobFence, attemptFence,
		)
	}
}

func setIntegrationSampleExpiryInPast(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	taskID string,
) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
UPDATE tasks
SET sample_expires_at = DATE_SUB(UTC_TIMESTAMP(6), INTERVAL 1 DAY)
WHERE id = ?`, taskID); err != nil {
		t.Fatalf("set integration sample expiry in the past: %v", err)
	}
}

func assertIntegrationTerminalRetention(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	taskID string,
) time.Time {
	t.Helper()
	var completedAt time.Time
	var sampleExpiresAt time.Time
	if err := db.QueryRowContext(ctx, `
SELECT completed_at, sample_expires_at
FROM tasks
WHERE id = ?`, taskID).Scan(&completedAt, &sampleExpiresAt); err != nil {
		t.Fatalf("read integration terminal retention: %v", err)
	}
	want := completedAt.Add(taskdomain.DefaultSampleRetention)
	if !sampleExpiresAt.Equal(want) {
		t.Fatalf(
			"terminal sample expiry = %s, want completion %s + retention = %s",
			sampleExpiresAt, completedAt, want,
		)
	}
	return sampleExpiresAt
}

func assertIntegrationSampleExpiry(
	t *testing.T,
	ctx context.Context,
	db *sql.DB,
	taskID string,
	want time.Time,
) {
	t.Helper()
	var actual time.Time
	if err := db.QueryRowContext(ctx, `
SELECT sample_expires_at
FROM tasks
WHERE id = ?`, taskID).Scan(&actual); err != nil {
		t.Fatalf("read integration sample expiry: %v", err)
	}
	if !actual.Equal(want) {
		t.Fatalf("sample expiry = %s, want preserved %s", actual, want)
	}
}

func cleanupIntegrationUser(t *testing.T, db *sql.DB, userID uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT blob_id
FROM uploads
WHERE created_by = ? AND blob_id IS NOT NULL`, userID)
	if err != nil {
		t.Logf("integration cleanup list blobs: %v", err)
		return
	}
	var blobIDs []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			t.Logf("integration cleanup scan blob: %v", err)
			_ = rows.Close()
			return
		}
		blobIDs = append(blobIDs, id)
	}
	if err := rows.Close(); err != nil {
		t.Logf("integration cleanup close blob rows: %v", err)
	}
	for _, pool := range []string{
		resourcePoolGlobal,
		resourcePoolTrivy,
		resourcePoolNative,
	} {
		if _, err := db.ExecContext(ctx, `
UPDATE job_resource_slots slot
JOIN jobs job ON job.id = slot.job_id
JOIN tasks task ON task.id = job.task_id
SET slot.job_id = NULL,
    slot.job_fencing_token = NULL,
    slot.lease_owner = NULL,
    slot.acquired_at = NULL
WHERE slot.pool = ? AND task.created_by = ?`, pool, userID); err != nil {
			t.Logf("integration cleanup %s slots: %v", pool, err)
		}
	}
	for _, query := range []string{
		"DELETE FROM tasks WHERE created_by = ?",
		"DELETE FROM uploads WHERE created_by = ?",
	} {
		if _, err := db.ExecContext(ctx, query, userID); err != nil {
			t.Logf("integration cleanup %q: %v", query, err)
		}
	}
	for _, blobID := range blobIDs {
		if _, err := db.ExecContext(ctx, "DELETE FROM blobs WHERE id = ?", blobID); err != nil {
			t.Logf("integration cleanup blob %d: %v", blobID, err)
		}
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID); err != nil {
		t.Logf("integration cleanup user: %v", err)
	}
}

func integrationUUID(value int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", 0x70000000+value, value)
}
