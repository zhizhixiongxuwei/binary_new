package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

const (
	testJobID                 = "123e4567-e89b-42d3-a456-426614174000"
	testTaskID                = "123e4567-e89b-42d3-a456-426614174001"
	testOwner                 = "scan-worker-1"
	testSampleRetentionMicros = int64(30 * 24 * time.Hour / time.Microsecond)
)

type transactionBeginnerStub struct {
	options sql.TxOptions
	called  bool
	err     error
}

func (s *transactionBeginnerStub) BeginTx(
	_ context.Context,
	options *sql.TxOptions,
) (*sql.Tx, error) {
	s.called = true
	if options != nil {
		s.options = *options
	}
	return nil, s.err
}

func TestBeginClaimTransactionUsesReadCommitted(t *testing.T) {
	sentinel := errors.New("stop after inspecting transaction options")
	beginner := &transactionBeginnerStub{err: sentinel}

	_, err := beginClaimTransaction(context.Background(), beginner)

	if !errors.Is(err, sentinel) || !beginner.called {
		t.Fatalf("beginClaimTransaction() error = %v, called = %v", err, beginner.called)
	}
	if beginner.options.Isolation != sql.LevelReadCommitted ||
		beginner.options.ReadOnly {
		t.Fatalf("claim transaction options = %+v", beginner.options)
	}
}

func TestClaimResourceRequirementsSeparateNativeFamily(t *testing.T) {
	tests := []struct {
		name       string
		request    claimRequest
		payload    []byte
		wantedPool []string
	}{
		{
			name:       "scan uses global",
			request:    claimRequest{Kind: KindScan},
			wantedPool: []string{resourcePoolGlobal},
		},
		{
			name:       "Trivy uses global and Trivy",
			request:    claimRequest{Kind: KindTrivy},
			wantedPool: []string{resourcePoolGlobal, resourcePoolTrivy},
		},
		{
			name:       "manual image uses global and Trivy",
			request:    claimRequest{Kind: KindImage},
			wantedPool: []string{resourcePoolGlobal, resourcePoolTrivy},
		},
		{
			name:       "native job uses global and native",
			request:    claimRequest{Kind: KindNative},
			wantedPool: []string{resourcePoolGlobal, resourcePoolNative},
		},
		{
			name: "native decompile uses global and native",
			request: claimRequest{
				Kind: KindDecompile, PayloadWorkerKind: KindNative,
			},
			payload: []byte(`{"engine":{"worker_kind":"native"}}`),
			wantedPool: []string{
				resourcePoolGlobal,
				resourcePoolNative,
			},
		},
		{
			name: "bytecode decompile does not use native",
			request: claimRequest{
				Kind: KindDecompile, PayloadWorkerKind: KindBytecode,
			},
			payload:    []byte(`{"engine":{"worker_kind":"bytecode"}}`),
			wantedPool: []string{resourcePoolGlobal},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.request.HeavySlotLimit = 4
			test.request.TrivySlotLimit = 2
			test.request.NativeSlotLimit = 3
			requirements, err := claimResourceRequirements(
				test.request,
				test.payload,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(requirements) != len(test.wantedPool) {
				t.Fatalf("requirements = %+v", requirements)
			}
			for index, wanted := range test.wantedPool {
				if requirements[index].pool != wanted {
					t.Fatalf("requirements = %+v", requirements)
				}
			}
		})
	}

	_, err := claimResourceRequirements(claimRequest{
		Kind: KindDecompile, PayloadWorkerKind: KindNative,
		HeavySlotLimit: 2, TrivySlotLimit: 1, NativeSlotLimit: 1,
	}, []byte(`{"engine":{"worker_kind":"bytecode"}}`))
	if !errors.Is(err, ErrInconsistentState) {
		t.Fatalf("mismatched decompile family error = %v", err)
	}
}

func TestJavaAnalysisUsesTheSingleGlobalHeavySlot(t *testing.T) {
	requirements, err := claimResourceRequirements(claimRequest{
		Kind: KindJavaAnalysis, HeavySlotLimit: 2,
		TrivySlotLimit: 1, NativeSlotLimit: 1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 1 || requirements[0].pool != resourcePoolGlobal ||
		requirements[0].limit != 1 {
		t.Fatalf("Java analysis resource requirements = %#v", requirements)
	}
}

func TestConfigureResourceLimitsInitializesOnlyFreshDatabase(t *testing.T) {
	t.Run("accepts current single-slot baseline", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)

		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
			WillReturnRows(sqlmock.NewRows([]string{
				"heavy_slots", "trivy_slots", "native_slots", "generation",
			}).AddRow(1, 1, 1, 2))
		mock.ExpectCommit()

		if err := repository.ConfigureResourceLimits(
			context.Background(), 1, 1, 1,
		); err != nil {
			t.Fatal(err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fresh database", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)

		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
			WillReturnRows(sqlmock.NewRows([]string{
				"heavy_slots", "trivy_slots", "native_slots", "generation",
			}).AddRow(2, 1, 1, 1))
		mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs`).
			WillReturnRows(sqlmock.NewRows([]string{"jobs_exist"}).AddRow(false))
		mock.ExpectExec(`(?s)UPDATE job_resource_limits.*heavy_slots = \?.*trivy_slots = \?.*native_slots = \?.*generation = generation \+ 1`).
			WithArgs(4, 2, 3, 2, 1, 1, uint64(1)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		if err := repository.ConfigureResourceLimits(
			context.Background(),
			4,
			2,
			3,
		); err != nil {
			t.Fatal(err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("established database rejects worker drift", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)

		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
			WillReturnRows(sqlmock.NewRows([]string{
				"heavy_slots", "trivy_slots", "native_slots", "generation",
			}).AddRow(2, 1, 1, 1))
		mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs`).
			WillReturnRows(sqlmock.NewRows([]string{"jobs_exist"}).AddRow(true))
		mock.ExpectRollback()

		err = repository.ConfigureResourceLimits(
			context.Background(),
			4,
			2,
			3,
		)
		if !errors.Is(err, ErrResourceLimitMismatch) {
			t.Fatalf("ConfigureResourceLimits() error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("generation compare and swap fails closed", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)

		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
			WillReturnRows(sqlmock.NewRows([]string{
				"heavy_slots", "trivy_slots", "native_slots", "generation",
			}).AddRow(2, 1, 1, 7))
		mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs`).
			WillReturnRows(sqlmock.NewRows([]string{"jobs_exist"}).AddRow(false))
		mock.ExpectRollback()

		err = repository.ConfigureResourceLimits(
			context.Background(),
			4,
			2,
			3,
		)
		if !errors.Is(err, ErrResourceLimitMismatch) {
			t.Fatalf("ConfigureResourceLimits() error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestClaimUsesSkipLockedAndAdvancesBothFences(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	until := time.Now().UTC().Add(time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j\.id.*FROM jobs j FORCE INDEX \(idx_jobs_claim\).*STRAIGHT_JOIN tasks task.*task\.status NOT IN.*j\.kind <> 'scan'.*ORDER BY j\.priority DESC, j\.available_at ASC, j\.id ASC.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindScan).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind", "payload",
			"attempt", "max_attempts", "fencing_token",
			"attempt_fencing_token", "attempt_status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "scan", []byte(`{"task_id":"x"}`),
			0, 3, 1, 1, "queued",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'leased'.*attempt = attempt \+ 1.*fencing_token = fencing_token \+ 1.*UTC_TIMESTAMP`).
		WithArgs(testOwner, int64(time.Minute/time.Microsecond), testJobID, uint32(0), uint64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET fencing_token = \?.*fencing_token = \?`).
		WithArgs(uint64(2), int64(19), testTaskID, int64(1)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FROM job_resource_limits.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{
			"heavy_slots", "trivy_slots", "native_slots", "generation",
		}).AddRow(2, 1, 1, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM archive_imports.*status = 'running'`).
		WillReturnRows(sqlmock.NewRows([]string{"running"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT slot_number.*FROM job_resource_slots FORCE INDEX \(PRIMARY\).*pool = \?.*slot_number <= \?.*job_id IS NULL.*FOR UPDATE SKIP LOCKED`).
		WithArgs(resourcePoolGlobal, 2).
		WillReturnRows(sqlmock.NewRows([]string{"slot_number"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = \?.*job_fencing_token = \?.*acquired_at = UTC_TIMESTAMP.*pool = \?.*slot_number = \?.*job_id IS NULL`).
		WithArgs(
			testJobID, uint64(2), testOwner,
			resourcePoolGlobal, uint8(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT lease_until.*FROM jobs`).
		WithArgs(testJobID).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	lease, ok, err := repository.Claim(context.Background(), claimRequest{
		Kind: KindScan, Owner: testOwner,
		LeaseDurationMicros: int64(time.Minute / time.Microsecond),
		HeavySlotLimit:      2,
		TrivySlotLimit:      1,
		NativeSlotLimit:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || lease.Attempt != 1 || lease.FencingToken != 2 ||
		lease.TaskAttemptID == nil || *lease.TaskAttemptID != 19 ||
		!lease.LeaseUntil.Equal(until) ||
		len(lease.ResourceSlots) != 1 ||
		lease.ResourceSlots[0] != (ResourceSlotLease{
			Pool: resourcePoolGlobal, SlotNumber: 1,
		}) {
		t.Fatalf("Claim() = (%+v, %v)", lease, ok)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestClaimReturnsNoWorkWithoutMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j\.id.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindScan).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, ok, err := repository.Claim(context.Background(), claimRequest{
		Kind: KindScan, Owner: testOwner, LeaseDurationMicros: 1,
	})
	if err != nil || ok {
		t.Fatalf("Claim() = (_, %v, %v), want no work", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTrivyClaimRollsBackWhenDedicatedSlotIsUnavailable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j\.id.*FROM jobs j.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindTrivy).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind", "payload",
			"attempt", "max_attempts", "fencing_token",
			"attempt_fencing_token", "attempt_status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "trivy", []byte(`{}`),
			0, 3, 7, 7, "running",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'leased'.*fencing_token = fencing_token \+ 1`).
		WithArgs(testOwner, int64(60_000_000), testJobID, uint32(0), uint64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET fencing_token = \?.*status = 'running'`).
		WithArgs(uint64(8), int64(19), testTaskID, int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{
			"heavy_slots", "trivy_slots", "native_slots", "generation",
		}).AddRow(2, 1, 1, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM archive_imports.*status = 'running'`).
		WillReturnRows(sqlmock.NewRows([]string{"running"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT slot_number.*pool = \?.*job_id IS NULL.*FOR UPDATE SKIP LOCKED`).
		WithArgs(resourcePoolGlobal, 2).
		WillReturnRows(sqlmock.NewRows([]string{"slot_number"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = \?.*pool = \?.*slot_number = \?.*job_id IS NULL`).
		WithArgs(
			testJobID,
			uint64(8),
			testOwner,
			resourcePoolGlobal,
			uint8(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT slot_number.*pool = \?.*job_id IS NULL.*FOR UPDATE SKIP LOCKED`).
		WithArgs(resourcePoolTrivy, 1).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	lease, found, err := repository.Claim(context.Background(), claimRequest{
		Kind: KindTrivy, Owner: testOwner,
		LeaseDurationMicros: 60_000_000,
		HeavySlotLimit:      2,
		TrivySlotLimit:      1,
		NativeSlotLimit:     1,
	})
	if err != nil || found || lease.JobID != "" {
		t.Fatalf("Claim() = (%+v, %v, %v), want no committed lease", lease, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestClaimNonScanJobPreservesRunningTaskAttemptFence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	until := time.Now().UTC().Add(time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j\.id.*LEFT JOIN task_attempts attempt.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindNative).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind", "payload",
			"attempt", "max_attempts", "fencing_token",
			"attempt_fencing_token", "attempt_status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "native", []byte(`{"node_id":7}`),
			0, 3, 0, 41, "running",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'leased'.*fencing_token = fencing_token \+ 1`).
		WithArgs(testOwner, int64(time.Minute/time.Microsecond), testJobID, uint32(0), uint64(0)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT lease_until.*FROM jobs`).
		WithArgs(testJobID).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	lease, ok, err := repository.Claim(context.Background(), claimRequest{
		Kind: KindNative, Owner: testOwner,
		LeaseDurationMicros: int64(time.Minute / time.Microsecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || lease.Kind != KindNative || lease.FencingToken != 1 ||
		lease.TaskAttemptID == nil || *lease.TaskAttemptID != 19 {
		t.Fatalf("Claim() = (%+v, %v)", lease, ok)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestClaimNativeDecompileUsesGlobalAndNativeSlots(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	until := time.Now().UTC().Add(time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT j[.]id.*j[.]kind IN \('decompile', 'image'\).*task[.]status IN.*task[.]sample_deleted_at IS NULL.*JSON_UNQUOTE\(JSON_EXTRACT\(.*engine[.]worker_kind.*ORDER BY.*FOR UPDATE SKIP LOCKED`).
		WithArgs(KindDecompile, KindNative).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind", "payload",
			"attempt", "max_attempts", "fencing_token",
			"attempt_fencing_token", "attempt_status",
		}).AddRow(
			testJobID, testTaskID, nil, "decompile",
			[]byte(`{"schema_version":1,"engine":{"worker_kind":"native"}}`),
			0, 3, 0, nil, nil,
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'leased'.*fencing_token = fencing_token \+ 1`).
		WithArgs(
			testOwner,
			int64(time.Minute/time.Microsecond),
			testJobID,
			uint32(0),
			uint64(0),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT heavy_slots, trivy_slots, native_slots, generation.*FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{
			"heavy_slots", "trivy_slots", "native_slots", "generation",
		}).AddRow(2, 1, 1, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM archive_imports.*status = 'running'`).
		WillReturnRows(sqlmock.NewRows([]string{"running"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT slot_number.*pool = \?.*job_id IS NULL.*FOR UPDATE SKIP LOCKED`).
		WithArgs(resourcePoolGlobal, 2).
		WillReturnRows(sqlmock.NewRows([]string{"slot_number"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = \?.*pool = \?.*slot_number = \?.*job_id IS NULL`).
		WithArgs(
			testJobID,
			uint64(1),
			testOwner,
			resourcePoolGlobal,
			uint8(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT slot_number.*pool = \?.*job_id IS NULL.*FOR UPDATE SKIP LOCKED`).
		WithArgs(resourcePoolNative, 1).
		WillReturnRows(sqlmock.NewRows([]string{"slot_number"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = \?.*pool = \?.*slot_number = \?.*job_id IS NULL`).
		WithArgs(
			testJobID,
			uint64(1),
			testOwner,
			resourcePoolNative,
			uint8(1),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT lease_until.*FROM jobs`).
		WithArgs(testJobID).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	lease, found, err := repository.Claim(
		context.Background(),
		claimRequest{
			Kind:                KindDecompile,
			PayloadWorkerKind:   KindNative,
			Owner:               testOwner,
			LeaseDurationMicros: int64(time.Minute / time.Microsecond),
			HeavySlotLimit:      2,
			TrivySlotLimit:      1,
			NativeSlotLimit:     1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !found ||
		lease.Kind != KindDecompile ||
		lease.TaskAttemptID != nil ||
		lease.FencingToken != 1 ||
		len(lease.ResourceSlots) != 2 ||
		lease.ResourceSlots[0].Pool != resourcePoolGlobal ||
		lease.ResourceSlots[1].Pool != resourcePoolNative {
		t.Fatalf("Claim() = (%+v, %v)", lease, found)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStartDecompileRevalidatesRetentionBeforeJobMutation(t *testing.T) {
	t.Run("retained terminal task", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := Lease{
			JobID: testJobID, TaskID: testTaskID,
			Kind: KindDecompile, Attempt: 1, MaxAttempts: 3,
			FencingToken: 1, Owner: testOwner,
			Payload: json.RawMessage(
				`{"engine":{"worker_kind":"native"}}`,
			),
			ResourceSlots: []ResourceSlotLease{
				{Pool: resourcePoolGlobal, SlotNumber: 1},
				{Pool: resourcePoolNative, SlotNumber: 1},
			},
		}
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*status IN.*sample_deleted_at IS NULL.*deleted_at IS NULL.*FOR UPDATE`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
		mock.ExpectExec(`(?s)UPDATE jobs.*status = 'running'.*lease_until > UTC_TIMESTAMP`).
			WithArgs(testJobID, testTaskID, testOwner, uint64(1)).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(`(?s)SELECT 1.*FROM job_resource_slots.*pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
			WithArgs(
				resourcePoolGlobal,
				uint8(1),
				testJobID,
				uint64(1),
				testOwner,
			).
			WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
		mock.ExpectQuery(`(?s)SELECT 1.*FROM job_resource_slots.*pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
			WithArgs(
				resourcePoolNative,
				uint8(1),
				testJobID,
				uint64(1),
				testOwner,
			).
			WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
		mock.ExpectCommit()
		if err := repository.Start(context.Background(), lease); err != nil {
			t.Fatal(err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("expired or deleting task", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		repository := NewMySQLRepository(db)
		lease := Lease{
			JobID: testJobID, TaskID: testTaskID,
			Kind: KindDecompile, Attempt: 1, MaxAttempts: 3,
			FencingToken: 1, Owner: testOwner,
		}
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*FOR UPDATE`).
			WithArgs(testTaskID).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		err = repository.Start(context.Background(), lease)
		if !errors.Is(err, ErrInconsistentState) {
			t.Fatalf("Start() error = %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStartCAnalysisTreatsConcurrentCancellationAsLeaseLoss(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	lease.Kind = KindCAnalysis
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM jobs job.*job.kind = 'c_analysis'.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.Start(context.Background(), lease)
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Start() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestStartScanTransitionsJobAttemptAndTaskAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	lease.ResourceSlots = []ResourceSlotLease{{
		Pool: resourcePoolGlobal, SlotNumber: 1,
	}}

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'running'.*lease_until > UTC_TIMESTAMP`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM job_resource_slots.*pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
		WithArgs(
			resourcePoolGlobal, uint8(1), testJobID, uint64(2), testOwner,
		).
		WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'running'.*fencing_token = \?.*status = 'queued'`).
		WithArgs(uint64(19), testTaskID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'VALIDATING'.*status = 'QUEUED'`).
		WithArgs(testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(mock, "task.status_changed", "Task scan started.")
	mock.ExpectCommit()

	if err := repository.Start(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatRejectsLostLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*lease_until = DATE_ADD.*lease_until > UTC_TIMESTAMP`).
		WithArgs(int64(time.Minute/time.Microsecond), testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	_, err = repository.Heartbeat(
		context.Background(), lease, int64(time.Minute/time.Microsecond),
	)
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Heartbeat() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatUsesDatabaseTimeAndReturnsRenewedDeadline(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	lease.ResourceSlots = []ResourceSlotLease{{
		Pool: resourcePoolGlobal, SlotNumber: 1,
	}}
	until := time.Now().UTC().Add(time.Minute)
	duration := int64(time.Minute / time.Microsecond)
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*lease_until = DATE_ADD\(UTC_TIMESTAMP\(6\), INTERVAL \? MICROSECOND\).*lease_until > UTC_TIMESTAMP`).
		WithArgs(duration, testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM job_resource_slots.*pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
		WithArgs(
			resourcePoolGlobal, uint8(1), testJobID, uint64(2), testOwner,
		).
		WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT lease_until.*status IN \('leased', 'running'\).*lease_until > UTC_TIMESTAMP`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	renewed, err := repository.Heartbeat(context.Background(), lease, duration)
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.LeaseUntil.Equal(until) {
		t.Fatalf("LeaseUntil = %v, want %v", renewed.LeaseUntil, until)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatNativeDecompileValidatesBothFencedPools(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := nativeDecompileLease()
	until := time.Now().UTC().Add(time.Minute)
	duration := int64(time.Minute / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*lease_until = DATE_ADD.*lease_until > UTC_TIMESTAMP`).
		WithArgs(
			duration,
			testJobID,
			testTaskID,
			testOwner,
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectExactResourceSlotValidation(mock, lease)
	mock.ExpectQuery(`(?s)SELECT lease_until.*status IN \('leased', 'running'\).*lease_until > UTC_TIMESTAMP`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"lease_until"}).AddRow(until))
	mock.ExpectCommit()

	renewed, err := repository.Heartbeat(
		context.Background(),
		lease,
		duration,
	)
	if err != nil || !renewed.LeaseUntil.Equal(until) {
		t.Fatalf("Heartbeat() = (%+v, %v)", renewed, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceLeaseActiveUsesExactFenceWithoutUnsafeEarlyPredicates(t *testing.T) {
	tests := []struct {
		name   string
		active bool
	}{
		{name: "active", active: true},
		{name: "inactive", active: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			request := workspaceLeaseRequest{
				JobID: testJobID, TaskID: testTaskID, TaskAttemptID: 19,
				FencingToken: 2, Kind: KindScan,
			}
			// An exact fenced lease in an active state remains conservatively
			// active even when lease_until looks stale or cancellation was
			// requested. Neither event synchronously stops a running worker.
			mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs job.*JOIN task_attempts attempt.*job\.task_attempt_id = \?.*job\.kind = \?.*job\.fencing_token = \?.*status IN \('leased', 'running', 'cancel_requested'\).*job\.kind IN \('decompile', 'image', 'c_analysis', 'java_analysis'\)\s+OR attempt\.fencing_token = \?`).
				WithArgs(
					testJobID, testTaskID, uint64(19),
					KindScan, uint64(2), uint64(2),
				).
				WillReturnRows(sqlmock.NewRows([]string{"active"}).
					AddRow(test.active))

			active, err := repository.WorkspaceLeaseActive(
				context.Background(), request,
			)
			if err != nil || active != test.active {
				t.Fatalf(
					"WorkspaceLeaseActive() = (%v, %v), want %v",
					active, err, test.active,
				)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTaskActivityAppendsEventUnderExactRunningLease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	payload := json.RawMessage(
		`{"analyzer":"ghidra","phase":"running","current":3,"total":10}`,
	)

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE tasks AS task.*JOIN jobs AS job.*event_sequence = task\.event_sequence \+ 1.*job\.status = 'running'.*job\.lease_owner = \?.*job\.fencing_token = \?.*job\.lease_until > UTC_TIMESTAMP`).
		WithArgs(
			testJobID,
			testTaskID,
			KindScan,
			testOwner,
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)INSERT INTO task_events.*event_sequence.*SELECT.*stage.*progress_basis_points.*FROM tasks.*WHERE id = \?`).
		WithArgs(
			"decompile.progress",
			"info",
			"Ghidra decompilation is running.",
			[]byte(payload),
			testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repository.TaskActivity(context.Background(), activityRequest{
		Lease: testLease(),
		Input: ActivityInput{
			EventType: "decompile.progress",
			Severity:  "info",
			Message:   "Ghidra decompilation is running.",
			Payload:   payload,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskActivityRejectsStaleWorkerBeforeAppendingEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE tasks AS task.*JOIN jobs AS job.*job\.status = 'running'.*job\.lease_until > UTC_TIMESTAMP`).
		WithArgs(
			testJobID,
			testTaskID,
			KindScan,
			testOwner,
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = repository.TaskActivity(context.Background(), activityRequest{
		Lease: testLease(),
		Input: ActivityInput{
			EventType: "trivy.progress",
			Severity:  "info",
			Message:   "Trivy scan is running.",
			Payload:   json.RawMessage(`{"analyzer":"trivy","phase":"scanning"}`),
		},
	})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("TaskActivity() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskProgressRejectsStaleWorkerBeforeTaskMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'running'.*lease_until > UTC_TIMESTAMP`).
		WithArgs(
			int64(time.Minute/time.Microsecond),
			testJobID, testTaskID, testOwner, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	err = repository.TaskProgress(context.Background(), progressRequest{
		Lease: lease,
		Input: ProgressInput{
			TaskStatus: "SCANNING", Stage: "SCANNING",
		},
		ProgressBasisPoints: 5000,
		LeaseDurationMicros: int64(time.Minute / time.Microsecond),
	})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("TaskProgress() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestTaskProgressUpdatesTaskAndAppendsEventAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	duration := int64(time.Minute / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectExec(`(?s)UPDATE jobs.*heartbeat_at = UTC_TIMESTAMP.*lease_until > UTC_TIMESTAMP`).
		WithArgs(duration, testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = \?.*event_sequence = event_sequence \+ 1`).
		WithArgs("SCANNING", "SCANNING", uint16(5000), testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(mock, "task.progress", "Task progress changed.")
	mock.ExpectCommit()

	err = repository.TaskProgress(context.Background(), progressRequest{
		Lease: lease,
		Input: ProgressInput{
			TaskStatus: "SCANNING", Stage: "SCANNING",
		},
		ProgressBasisPoints: 5000,
		LeaseDurationMicros: duration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishTransientFailureRequeuesAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	input := FinishInput{
		Outcome: OutcomeTransientFailure, ErrorCode: "engine_timeout",
		ErrorMessage: "The analyzer timed out.",
	}
	retryMicros := int64(5 * time.Second / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*lease_until > UTC_TIMESTAMP.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
		}).AddRow(testTaskID, int64(19), "scan", 1, 3))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*available_at = DATE_ADD.*lease_until > UTC_TIMESTAMP`).
		WithArgs(
			retryMicros, input.ErrorCode, input.ErrorMessage,
			testJobID, testTaskID, testOwner, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'queued'.*fencing_token = \?.*status = 'running'`).
		WithArgs(
			input.ErrorCode, input.ErrorMessage,
			uint64(19), testTaskID, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'QUEUED'.*error_code = \?`).
		WithArgs(input.ErrorCode, input.ErrorMessage, testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed",
		"Task requeued after a transient failure.",
	)
	mock.ExpectCommit()

	err = repository.Finish(context.Background(), finishRequest{
		Lease: lease, Input: input, RetryDelayMicros: retryMicros,
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishNativeDecompileReleasesBothFencedPools(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := nativeDecompileLease()

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
		}).AddRow(testTaskID, nil, "decompile", 1, 3))
	expectExactResourceSlotValidation(mock, lease)
	mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WithArgs(
			"succeeded",
			"",
			"",
			testJobID,
			testTaskID,
			testOwner,
			uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectExactResourceSlotValidation(mock, lease)
	for _, slot := range lease.ResourceSlots {
		mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = NULL.*WHERE pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?`).
			WithArgs(
				slot.Pool,
				slot.SlotNumber,
				testJobID,
				uint64(2),
				testOwner,
			).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()

	err = repository.Finish(context.Background(), finishRequest{
		Lease:                 lease,
		Input:                 FinishInput{Outcome: OutcomeSucceeded},
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishDeterministicFailureDoesNotRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	input := FinishInput{
		Outcome: OutcomeDeterministicFailure, ErrorCode: "invalid_format",
		ErrorMessage: "The format is not supported.",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
		}).AddRow(testTaskID, int64(19), "scan", 1, 3))
	mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WithArgs(
			"failed", input.ErrorCode, input.ErrorMessage,
			testJobID, testTaskID, testOwner, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WithArgs(
			"failed", input.ErrorCode, input.ErrorMessage,
			uint64(19), testTaskID, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*completed_at = UTC_TIMESTAMP.*`+
		`sample_expires_at = CASE.*sample_deleted_at IS NULL.*deleted_at IS NULL.*`+
		`GREATEST.*DATE_ADD\(UTC_TIMESTAMP\(6\), INTERVAL \? MICROSECOND\).*`+
		`status NOT IN`).
		WithArgs(
			"FAILED", uint16(0), input.ErrorCode, input.ErrorMessage,
			testSampleRetentionMicros, testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(mock, "task.status_changed", "Task scan finished.")
	mock.ExpectCommit()

	err = repository.Finish(context.Background(), finishRequest{
		Lease: lease, Input: input,
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishSuccessfulOutcomesResetSampleRetention(t *testing.T) {
	tests := []struct {
		name       string
		outcome    Outcome
		taskStatus string
	}{
		{
			name: "succeeded", outcome: OutcomeSucceeded,
			taskStatus: "SUCCEEDED",
		},
		{
			name: "partially succeeded", outcome: OutcomePartialSucceeded,
			taskStatus: "PARTIAL_SUCCEEDED",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			lease := testLease()
			input := FinishInput{Outcome: test.outcome}

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
				WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
				WillReturnRows(sqlmock.NewRows([]string{
					"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
				}).AddRow(testTaskID, int64(19), "scan", 1, 3))
			mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
				WithArgs(
					"succeeded", "", "",
					testJobID, testTaskID, testOwner, uint64(2),
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery(`(?s)SELECT EXISTS.*kind = 'trivy'.*status = 'queued'`).
				WithArgs(testTaskID, uint64(19)).
				WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
			mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
				WithArgs(
					"succeeded", "", "",
					uint64(19), testTaskID, uint64(2),
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*`+
				`sample_expires_at = CASE.*GREATEST.*INTERVAL \? MICROSECOND.*`+
				`status NOT IN`).
				WithArgs(
					test.taskStatus, uint16(10_000), "", "",
					testSampleRetentionMicros, testTaskID,
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			expectTaskEvent(mock, "task.status_changed", "Task scan finished.")
			mock.ExpectCommit()

			err = repository.Finish(context.Background(), finishRequest{
				Lease: lease, Input: input,
				SampleRetentionMicros: testSampleRetentionMicros,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFinishExhaustedTransientFailureStartsRetention(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	lease.Attempt = lease.MaxAttempts
	input := FinishInput{
		Outcome: OutcomeTransientFailure, ErrorCode: "engine_timeout",
		ErrorMessage: "The analyzer timed out.",
	}

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "kind", "attempt", "max_attempts",
		}).AddRow(testTaskID, int64(19), "scan", 3, 3))
	mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WithArgs(
			"failed", input.ErrorCode, input.ErrorMessage,
			testJobID, testTaskID, testOwner, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*completed_at = UTC_TIMESTAMP`).
		WithArgs(
			"failed", input.ErrorCode, input.ErrorMessage,
			uint64(19), testTaskID, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*`+
		`sample_expires_at = CASE.*GREATEST.*INTERVAL \? MICROSECOND.*`+
		`status NOT IN`).
		WithArgs(
			"FAILED", uint16(0), input.ErrorCode, input.ErrorMessage,
			testSampleRetentionMicros, testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(mock, "task.status_changed", "Task scan finished.")
	mock.ExpectCommit()

	err = repository.Finish(context.Background(), finishRequest{
		Lease: lease, Input: input,
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishReturnsLeaseLostBeforeAnyStateMutation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	lease := testLease()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT task_id, task_attempt_id, kind, attempt, max_attempts.*FOR UPDATE`).
		WithArgs(testJobID, testTaskID, testOwner, uint64(2)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repository.Finish(context.Background(), finishRequest{
		Lease: lease,
		Input: FinishInput{
			Outcome:   OutcomeDeterministicFailure,
			ErrorCode: "invalid_format", ErrorMessage: "Unsupported input.",
		},
		SampleRetentionMicros: testSampleRetentionMicros,
	})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("Finish() error = %v, want ErrLeaseLost", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredRequeuesBeforeMaximumAttempt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	retryMicros := int64(time.Second / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*lease_until <= UTC_TIMESTAMP.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(testJobID, testTaskID, int64(19), "scan", 1, 3, 2, "running"))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs(retryMicros, testJobID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 2, 1)
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*fencing_token = \?`).
		WithArgs(
			"queued", "queued", "queued",
			"The worker lease expired; the job was requeued.",
			int64(19), testTaskID, uint64(2),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*completed_at.*`+
		`sample_expires_at = CASE.*WHEN \? = 'FAILED'.*sample_deleted_at IS NULL.*`+
		`deleted_at IS NULL.*INTERVAL \? MICROSECOND.*status NOT IN`).
		WithArgs(
			"QUEUED", "The worker lease expired; the job was requeued.",
			"QUEUED", "QUEUED", testSampleRetentionMicros, testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed",
		"Task recovered after a worker lease expired.",
	)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, retryMicros, testSampleRetentionMicros,
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("RecoverExpired() count = %d, want 1", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredQuarantinesPoisonAndContinuesPage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	poisonID := "223e4567-e89b-42d3-a456-426614174000"

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			poisonID, testTaskID, nil, "decompile", 1, 3, 2, "running",
		).AddRow(
			testJobID, testTaskID, nil, "image", 1, 3, 3, "running",
		))
	mock.ExpectExec(`SAVEPOINT recover_expired_job`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs(int64(0), poisonID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT payload.*FROM jobs.*FOR UPDATE`).
		WithArgs(poisonID, uint64(2)).
		WillReturnRows(sqlmock.NewRows([]string{"payload"}).AddRow([]byte(`{}`)))
	mock.ExpectExec(`ROLLBACK TO SAVEPOINT recover_expired_job`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs.*lease_recovery_inconsistent`).
		WithArgs(poisonID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE job_resource_slots.*WHERE job_id = \?`).
		WithArgs(poisonID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`RELEASE SAVEPOINT recover_expired_job`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SAVEPOINT recover_expired_job`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs(int64(0), testJobID, uint64(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 3, 2)
	mock.ExpectExec(`RELEASE SAVEPOINT recover_expired_job`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, 0, testSampleRetentionMicros,
	)
	if err != nil || count != 2 {
		t.Fatalf("RecoverExpired() = (%d, %v), want (2, nil)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredCompletesPublishedCAnalysisJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	retryMicros := int64(time.Second / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "c_analysis",
			1, 3, 2, "running",
		))
	mock.ExpectQuery(`(?s)SELECT analysis.status, analyzer.status,.*analysis.error_code.*FOR UPDATE`).
		WithArgs(testTaskID, testJobID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "analyzer_status", "error_code", "error_message",
		}).AddRow("partial", "partial", nil, nil))
	mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*kind = 'c_analysis'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs("succeeded", nil, nil, testJobID, testTaskID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 2, 1)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, retryMicros, testSampleRetentionMicros,
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("RecoverExpired() count = %d, want 1", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredCAnalysisHandlesLeaseLossBeforeProcessorBegin(t *testing.T) {
	tests := []struct {
		name          string
		attempt       uint32
		maxAttempts   uint32
		retry         bool
		initialStatus string
		affected      int64
		invalidates   bool
	}{
		{
			name: "requeues running run", attempt: 1, maxAttempts: 3,
			retry: true, initialStatus: "running", affected: 2, invalidates: true,
		},
		{
			name:    "requeues queued run without snapshot mutation",
			attempt: 1, maxAttempts: 3, retry: true,
			initialStatus: "queued", affected: 0, invalidates: false,
		},
		{
			name: "fails final attempt", attempt: 3, maxAttempts: 3,
			initialStatus: "running", affected: 2, invalidates: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			retryMicros := int64(time.Second / time.Microsecond)

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_id", "task_attempt_id", "kind",
					"attempt", "max_attempts", "fencing_token", "status",
				}).AddRow(
					testJobID, testTaskID, nil, "c_analysis",
					test.attempt, test.maxAttempts, 2, "running",
				))
			mock.ExpectQuery(`(?s)SELECT analysis.status, analyzer.status,.*analysis.error_code.*FOR UPDATE`).
				WithArgs(testTaskID, testJobID).
				WillReturnRows(sqlmock.NewRows([]string{
					"status", "analyzer_status", "error_code", "error_message",
				}).AddRow(test.initialStatus, test.initialStatus, nil, nil))
			if test.retry {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(retryMicros, testJobID, uint64(2)).
					WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'failed'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(testJobID, uint64(2)).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			expectResourceSlotRelease(mock, testJobID, 2, 1)
			status := "failed"
			if test.retry {
				status = "queued"
			}
			mock.ExpectExec(`(?s)UPDATE c_analysis_runs analysis.*SET analysis.status = '`+status+
				`'.*analysis.status = analyzer.status.*analysis.status IN \('queued', 'running'\)`).
				WithArgs(testTaskID, testJobID).
				WillReturnResult(sqlmock.NewResult(0, test.affected))
			if test.invalidates {
				expectSourceAnalysisReportInvalidation(mock, testTaskID)
			}
			mock.ExpectCommit()

			count, err := repository.RecoverExpired(
				context.Background(), 10, retryMicros, testSampleRetentionMicros,
			)
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("RecoverExpired() count = %d, want 1", count)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoverExpiredCompletesPublishedJavaAnalysisJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)
	retryMicros := int64(time.Second / time.Microsecond)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "java_analysis",
			1, 3, 2, "running",
		))
	mock.ExpectQuery(`(?s)SELECT analysis.status, analyzer.status,.*analysis.error_code.*FROM java_analysis_runs.*FOR UPDATE`).
		WithArgs(testTaskID, testJobID).
		WillReturnRows(sqlmock.NewRows([]string{
			"status", "analyzer_status", "error_code", "error_message",
		}).AddRow("partial", "partial", nil, nil))
	mock.ExpectExec(`(?s)UPDATE jobs.*SET status = \?.*kind = 'java_analysis'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs("succeeded", nil, nil, testJobID, testTaskID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 2, 1)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, retryMicros, testSampleRetentionMicros,
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("RecoverExpired() count = %d, want 1", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredJavaAnalysisResetsIdentityBeforeRetry(t *testing.T) {
	tests := []struct {
		name          string
		attempt       uint32
		maxAttempts   uint32
		retry         bool
		initialStatus string
		affected      int64
		invalidates   bool
	}{
		{
			name: "requeues running run", attempt: 1, maxAttempts: 3,
			retry: true, initialStatus: "running", affected: 2, invalidates: true,
		},
		{
			name:    "requeues queued run without snapshot mutation",
			attempt: 1, maxAttempts: 3, retry: true,
			initialStatus: "queued", affected: 0, invalidates: false,
		},
		{
			name: "fails final attempt", attempt: 3, maxAttempts: 3,
			initialStatus: "running", affected: 2, invalidates: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)
			retryMicros := int64(time.Second / time.Microsecond)

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_id", "task_attempt_id", "kind",
					"attempt", "max_attempts", "fencing_token", "status",
				}).AddRow(
					testJobID, testTaskID, nil, "java_analysis",
					test.attempt, test.maxAttempts, 2, "running",
				))
			mock.ExpectQuery(`(?s)SELECT analysis.status, analyzer.status,.*analysis.error_code.*FROM java_analysis_runs.*FOR UPDATE`).
				WithArgs(testTaskID, testJobID).
				WillReturnRows(sqlmock.NewRows([]string{
					"status", "analyzer_status", "error_code", "error_message",
				}).AddRow(test.initialStatus, test.initialStatus, nil, nil))
			if test.retry {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'queued'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(retryMicros, testJobID, uint64(2)).
					WillReturnResult(sqlmock.NewResult(0, 1))
			} else {
				mock.ExpectExec(`(?s)UPDATE jobs.*status = 'failed'.*lease_until <= UTC_TIMESTAMP`).
					WithArgs(testJobID, uint64(2)).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			expectResourceSlotRelease(mock, testJobID, 2, 1)
			status := "failed"
			if test.retry {
				status = "queued"
			}
			pattern := `(?s)UPDATE java_analysis_runs analysis.*SET analysis.status = '` + status
			if test.retry {
				pattern += `'.*analysis.bundle_sha256 = NULL.*analysis.analyzed_files = 0.*analysis.status = analyzer.status`
			} else {
				pattern += `'.*analysis.error_code = 'lease_expired'.*analysis.status = analyzer.status`
			}
			mock.ExpectExec(pattern).
				WithArgs(testTaskID, testJobID).
				WillReturnResult(sqlmock.NewResult(0, test.affected))
			if test.invalidates {
				expectSourceAnalysisReportInvalidation(mock, testTaskID)
			}
			mock.ExpectCommit()

			count, err := repository.RecoverExpired(
				context.Background(), 10, retryMicros, testSampleRetentionMicros,
			)
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("RecoverExpired() count = %d, want 1", count)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReleaseRecoveredNativeDecompileUsesPayloadFamily(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	transaction, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	job := expiredJob{
		ID: testJobID, TaskID: testTaskID, Kind: KindDecompile,
		FencingToken: 7,
	}
	mock.ExpectQuery(`(?s)SELECT payload.*FROM jobs.*id = \?.*fencing_token = \?.*FOR UPDATE`).
		WithArgs(testJobID, uint64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"payload"}).AddRow(
			[]byte(`{"engine":{"worker_kind":"native"}}`),
		))
	for _, pool := range []string{resourcePoolGlobal, resourcePoolNative} {
		mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = NULL.*WHERE pool = \?.*job_id = \?.*job_fencing_token = \?`).
			WithArgs(pool, testJobID, uint64(7)).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()

	if err := releaseRecoveredResourceSlots(
		context.Background(),
		transaction,
		job,
	); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredFailsAtMaximumAttempt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(testJobID, testTaskID, int64(19), "scan", 3, 3, 4, "running"))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'failed'.*lease_until <= UTC_TIMESTAMP`).
		WithArgs(testJobID, uint64(4)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 4, 1)
	mock.ExpectExec(`(?s)UPDATE task_attempts.*SET status = \?.*fencing_token = \?`).
		WithArgs(
			"failed", "failed", "failed",
			"The worker lease expired after the final attempt.",
			int64(19), testTaskID, uint64(4),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE tasks.*SET status = \?.*completed_at`).
		WithArgs(
			"FAILED", "The worker lease expired after the final attempt.",
			"FAILED", "FAILED", testSampleRetentionMicros, testTaskID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed",
		"Task recovered after a worker lease expired.",
	)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, 0, testSampleRetentionMicros,
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("RecoverExpired() count = %d, want 1", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredFinalizesRequestedCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*status.*cancel_requested.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "scan",
			1, 3, 2, "cancel_requested",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status = 'cancel_requested'`).
		WithArgs(testJobID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 2, 1)
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'cancelled'.*fencing_token = \?`).
		WithArgs(int64(19), testTaskID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs.*status = 'cancel_requested'`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"remaining"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).
			AddRow("CANCEL_REQUESTED"))
	mock.ExpectExec(`(?s)UPDATE tasks.*status = 'CANCELLED'.*sample_expires_at = CASE.*`+
		`sample_deleted_at IS NULL.*deleted_at IS NULL.*GREATEST.*`+
		`INTERVAL \? MICROSECOND.*status = 'CANCEL_REQUESTED'`).
		WithArgs(testSampleRetentionMicros, testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTaskEvent(
		mock, "task.status_changed", "Task cancellation completed.",
	)
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(), 10, 0, testSampleRetentionMicros,
	)
	if err != nil || count != 1 {
		t.Fatalf("RecoverExpired() cancellation = (%d, %v)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverExpiredFinalizesSourceAnalysisCancellation(t *testing.T) {
	tests := []struct {
		name        string
		kind        Kind
		table       string
		affected    int64
		invalidates bool
	}{
		{
			name: "C analysis mutation", kind: KindCAnalysis,
			table: "c_analysis_runs", affected: 2, invalidates: true,
		},
		{
			name: "Java analysis mutation", kind: KindJavaAnalysis,
			table: "java_analysis_runs", affected: 2, invalidates: true,
		},
		{
			name: "C analysis already terminal", kind: KindCAnalysis,
			table: "c_analysis_runs", affected: 0, invalidates: false,
		},
		{
			name: "Java analysis already terminal", kind: KindJavaAnalysis,
			table: "java_analysis_runs", affected: 0, invalidates: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			repository := NewMySQLRepository(db)

			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*cancel_requested.*FOR UPDATE SKIP LOCKED`).
				WithArgs(10).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "task_id", "task_attempt_id", "kind",
					"attempt", "max_attempts", "fencing_token", "status",
				}).AddRow(
					testJobID, testTaskID, int64(19), test.kind,
					1, 3, 2, "cancel_requested",
				))
			mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status = 'cancel_requested'`).
				WithArgs(testJobID, uint64(2)).
				WillReturnResult(sqlmock.NewResult(0, 1))
			expectResourceSlotRelease(mock, testJobID, 2, 1)
			mock.ExpectExec(`(?s)UPDATE `+test.table+` analysis.*analyzer.status = 'cancelled'.*analysis.status IN \('queued', 'running', 'cancel_requested'\)`).
				WithArgs(testTaskID, testJobID).
				WillReturnResult(sqlmock.NewResult(0, test.affected))
			if test.invalidates {
				expectSourceAnalysisReportInvalidation(mock, testTaskID)
			}
			mock.ExpectCommit()

			count, err := repository.RecoverExpired(
				t.Context(), 10, 0, testSampleRetentionMicros,
			)
			if err != nil || count != 1 {
				t.Fatalf("RecoverExpired() = (%d, %v)", count, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoverCancelledJobLeavesDeletingTaskOwnedByRetention(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repository := NewMySQLRepository(db)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id, task_id, task_attempt_id, kind, attempt, max_attempts, fencing_token.*cancel_requested.*FOR UPDATE SKIP LOCKED`).
		WithArgs(10).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "task_id", "task_attempt_id", "kind",
			"attempt", "max_attempts", "fencing_token", "status",
		}).AddRow(
			testJobID, testTaskID, int64(19), "scan",
			1, 3, 2, "cancel_requested",
		))
	mock.ExpectExec(`(?s)UPDATE jobs.*status = 'cancelled'.*status = 'cancel_requested'`).
		WithArgs(testJobID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectResourceSlotRelease(mock, testJobID, 2, 1)
	mock.ExpectExec(`(?s)UPDATE task_attempts.*status = 'cancelled'.*fencing_token = \?`).
		WithArgs(int64(19), testTaskID, uint64(2)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`(?s)SELECT EXISTS.*FROM jobs.*status = 'cancel_requested'`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"remaining"}).AddRow(false))
	mock.ExpectQuery(`(?s)SELECT status.*FROM tasks.*WHERE id = \?.*FOR UPDATE`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow("DELETING"))
	mock.ExpectCommit()

	count, err := repository.RecoverExpired(
		context.Background(),
		10,
		0,
		testSampleRetentionMicros,
	)
	if err != nil || count != 1 {
		t.Fatalf("RecoverExpired() deleting task = (%d, %v)", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func testLease() Lease {
	attemptID := uint64(19)
	return Lease{
		JobID: testJobID, TaskID: testTaskID, TaskAttemptID: &attemptID,
		Kind: KindScan, Attempt: 1, MaxAttempts: 3,
		FencingToken: 2, Owner: testOwner,
	}
}

func nativeDecompileLease() Lease {
	return Lease{
		JobID: testJobID, TaskID: testTaskID,
		Kind: KindDecompile, Attempt: 1, MaxAttempts: 3,
		FencingToken: 2, Owner: testOwner,
		Payload: json.RawMessage(
			`{"engine":{"worker_kind":"native"}}`,
		),
		ResourceSlots: []ResourceSlotLease{
			{Pool: resourcePoolGlobal, SlotNumber: 1},
			{Pool: resourcePoolNative, SlotNumber: 1},
		},
	}
}

func expectExactResourceSlotValidation(
	mock sqlmock.Sqlmock,
	lease Lease,
) {
	for _, slot := range lease.ResourceSlots {
		mock.ExpectQuery(`(?s)SELECT 1.*FROM job_resource_slots.*pool = \?.*slot_number = \?.*job_id = \?.*job_fencing_token = \?.*lease_owner = \?.*FOR UPDATE`).
			WithArgs(
				slot.Pool,
				slot.SlotNumber,
				lease.JobID,
				lease.FencingToken,
				lease.Owner,
			).
			WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
	}
}

func expectTaskEvent(
	mock sqlmock.Sqlmock,
	eventType string,
	message string,
) {
	mock.ExpectExec(`(?s)INSERT INTO task_events.*SELECT.*FROM tasks.*WHERE id = \?`).
		WithArgs(eventType, message, testTaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSourceAnalysisReportInvalidation(
	mock sqlmock.Sqlmock,
	taskID string,
) {
	mock.ExpectExec(`(?s)UPDATE reports.*snapshot_state = 'stale'.*WHERE task_id = \?`).
		WithArgs(taskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectResourceSlotRelease(
	mock sqlmock.Sqlmock,
	jobID string,
	fencingToken uint64,
	rows int64,
) {
	pools := []string{resourcePoolGlobal, resourcePoolTrivy}
	for index := int64(0); index < rows; index++ {
		mock.ExpectExec(`(?s)UPDATE job_resource_slots.*job_id = NULL.*acquired_at = NULL.*WHERE pool = \?.*job_id = \?.*job_fencing_token = \?`).
			WithArgs(pools[index], jobID, fencingToken).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
}
