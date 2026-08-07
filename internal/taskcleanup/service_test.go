package taskcleanup

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type cleanupRepositoryStub struct {
	ids            []string
	claims         []Claim
	claimIndex     int
	claimAvailable bool
	claimErr       error
	complete       bool
	completeErr    error
	renew          bool
	renewCalls     int
	failures       []Failure
	completed      []Claim
}

func (s *cleanupRepositoryStub) ListReady(
	context.Context,
	int,
) ([]string, error) {
	return append([]string(nil), s.ids...), nil
}

func (s *cleanupRepositoryStub) Claim(
	_ context.Context,
	_ string,
	_ string,
	_ time.Duration,
) (Claim, bool, error) {
	if s.claimErr != nil {
		return Claim{}, false, s.claimErr
	}
	if !s.claimAvailable || s.claimIndex >= len(s.claims) {
		return Claim{}, false, nil
	}
	claim := s.claims[s.claimIndex]
	s.claimIndex++
	return claim, true, nil
}

func (s *cleanupRepositoryStub) Renew(
	context.Context,
	Claim,
	time.Duration,
) (bool, error) {
	s.renewCalls++
	return s.renew, nil
}

func (s *cleanupRepositoryStub) Complete(
	_ context.Context,
	claim Claim,
) (bool, error) {
	s.completed = append(s.completed, claim)
	return s.complete, s.completeErr
}

func (s *cleanupRepositoryStub) Fail(
	_ context.Context,
	_ Claim,
	failure Failure,
) (bool, error) {
	s.failures = append(s.failures, failure)
	return true, nil
}

type cleanupDeleterStub struct {
	failures   []error
	files      []StoredFile
	scopes     []Scope
	removeFile bool
}

type blockingCleanupDeleter struct{}

func (blockingCleanupDeleter) DeleteFile(
	ctx context.Context,
	_ StoredFile,
) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

type cancellationRaceRepository struct {
	cleanupRepositoryStub
	renewStarted chan struct{}
}

func (r *cancellationRaceRepository) Renew(
	ctx context.Context,
	_ Claim,
	_ time.Duration,
) (bool, error) {
	close(r.renewStarted)
	<-ctx.Done()
	return false, ctx.Err()
}

type cancellationRaceDeleter struct {
	renewStarted <-chan struct{}
}

func (d cancellationRaceDeleter) DeleteFile(
	context.Context,
	StoredFile,
) (bool, error) {
	<-d.renewStarted
	return true, nil
}

func (cancellationRaceDeleter) DeleteScope(
	context.Context,
	Scope,
) error {
	return nil
}

func (blockingCleanupDeleter) DeleteScope(
	context.Context,
	Scope,
) error {
	return nil
}

func (s *cleanupDeleterStub) DeleteFile(
	_ context.Context,
	file StoredFile,
) (bool, error) {
	s.files = append(s.files, file)
	if len(s.failures) > 0 {
		err := s.failures[0]
		s.failures = s.failures[1:]
		if err != nil {
			return false, err
		}
	}
	return s.removeFile, nil
}

func (s *cleanupDeleterStub) DeleteScope(
	_ context.Context,
	scope Scope,
) error {
	s.scopes = append(s.scopes, scope)
	return nil
}

func TestSweeperRetriesFailedPhysicalCleanupBeforeFinalizing(t *testing.T) {
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "task-deletion/1/test",
		FencingToken: 1, Attempt: 1,
		Files:  []StoredFile{{StorageKey: "reports/task/report.json"}},
		Scopes: []Scope{{Kind: FileReport, TaskID: testTaskID}},
	}
	repository := &cleanupRepositoryStub{
		ids: []string{testTaskID}, claims: []Claim{claim, {
			TaskID: testTaskID, LeaseOwner: claim.LeaseOwner,
			FencingToken: 2, Attempt: 2, Files: claim.Files,
			Scopes: claim.Scopes,
		}},
		claimAvailable: true, complete: true,
	}
	deleter := &cleanupDeleterStub{
		failures:   []error{errors.New("disk unavailable"), nil},
		removeFile: true,
	}
	sweeper, err := NewSweeper(repository, deleter, Config{
		LeaseOwner: claim.LeaseOwner, LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := sweeper.Sweep(context.Background(), 1)
	if err == nil || first.Claimed != 1 || first.Failures != 1 ||
		first.Completed != 0 || len(repository.failures) != 1 ||
		repository.failures[0].Code != "task_deletion_file_cleanup_failed" {
		t.Fatalf(
			"first Sweep() = (%+v, %v), failures=%+v",
			first, err, repository.failures,
		)
	}
	second, err := sweeper.Sweep(context.Background(), 1)
	if err != nil || second.Claimed != 1 || second.Completed != 1 ||
		second.FilesDeleted != 1 || len(repository.completed) != 1 {
		t.Fatalf("second Sweep() = (%+v, %v)", second, err)
	}
	if len(deleter.scopes) != 1 {
		t.Fatalf("scope cleanup calls = %d, want 1", len(deleter.scopes))
	}
}

func TestSweeperReportsClaimConflictsWithoutDeleting(t *testing.T) {
	repository := &cleanupRepositoryStub{
		ids: []string{testTaskID}, claimAvailable: false,
	}
	deleter := &cleanupDeleterStub{}
	sweeper, err := NewSweeper(repository, deleter, Config{
		LeaseOwner: "task-deletion/1/test", LeaseDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), 1)
	if err != nil || report.Conflicts != 1 || report.Claimed != 0 ||
		len(deleter.files) != 0 {
		t.Fatalf("Sweep() = (%+v, %v)", report, err)
	}
}

func TestSweeperCancelsLongScopeWorkWhenLeaseIsLost(t *testing.T) {
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "task-deletion/1/test",
		FencingToken: 1, Attempt: 1,
		Files: []StoredFile{{StorageKey: "artifacts/task/result"}},
	}
	repository := &cleanupRepositoryStub{
		ids: []string{testTaskID}, claims: []Claim{claim},
		claimAvailable: true, renew: false,
	}
	sweeper, err := NewSweeper(
		repository,
		blockingCleanupDeleter{},
		Config{
			LeaseOwner: claim.LeaseOwner, LeaseDuration: 30 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report, err := sweeper.Sweep(context.Background(), 1)
	if err == nil || report.Failures != 1 || report.Completed != 0 ||
		repository.renewCalls != 1 || len(repository.failures) != 1 {
		t.Fatalf(
			"Sweep() = (%+v, %v), renew=%d failures=%+v",
			report, err, repository.renewCalls, repository.failures,
		)
	}
	if time.Since(started) > time.Second {
		t.Fatal("lease loss did not cancel long-running cleanup promptly")
	}
}

func TestSweeperDoesNotTurnSuccessfulCleanupIntoRenewalCancellation(
	t *testing.T,
) {
	claim := Claim{
		TaskID: testTaskID, LeaseOwner: "task-deletion/1/test",
		FencingToken: 1, Attempt: 1,
		Files: []StoredFile{{StorageKey: "artifacts/task/result"}},
	}
	repository := &cancellationRaceRepository{
		cleanupRepositoryStub: cleanupRepositoryStub{
			ids: []string{testTaskID}, claims: []Claim{claim},
			claimAvailable: true, complete: true,
		},
		renewStarted: make(chan struct{}),
	}
	sweeper, err := NewSweeper(
		repository,
		cancellationRaceDeleter{renewStarted: repository.renewStarted},
		Config{
			LeaseOwner: claim.LeaseOwner, LeaseDuration: 30 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := sweeper.Sweep(context.Background(), 1)
	if err != nil || report.Completed != 1 || report.Failures != 0 {
		t.Fatalf("Sweep() = (%+v, %v)", report, err)
	}
}

func TestNewLeaseOwnerIsBoundedAndRequiresEntropy(t *testing.T) {
	owner, err := NewLeaseOwner(
		42,
		strings.NewReader("abcdefghijkl"),
	)
	if err != nil || owner != "task-deletion/42/6162636465666768696a6b6c" {
		t.Fatalf("NewLeaseOwner() = (%q, %v)", owner, err)
	}
	if _, err := NewLeaseOwner(0, strings.NewReader("abcdefghijkl")); err == nil {
		t.Fatal("NewLeaseOwner() accepted pid zero")
	}
	if _, err := NewLeaseOwner(1, io.LimitReader(
		strings.NewReader("short"), 5,
	)); err == nil {
		t.Fatal("NewLeaseOwner() accepted short entropy")
	}
}
