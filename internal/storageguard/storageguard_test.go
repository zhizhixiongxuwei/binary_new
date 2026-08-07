package storageguard

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"binaryscan/internal/systemstatus"
)

type probeStub struct {
	mu    sync.Mutex
	usage map[string]systemstatus.DiskUsage
	err   map[string]error
	block <-chan struct{}
	calls int
}

func (s *probeStub) Probe(
	_ context.Context,
	root string,
) (systemstatus.DiskUsage, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.block != nil {
		<-s.block
	}
	if err := s.err[root]; err != nil {
		return systemstatus.DiskUsage{}, err
	}
	return s.usage[root], nil
}

func TestCheckCreateAccountsForAssemblyPeakByFilesystem(t *testing.T) {
	newProbe := func(repositoryDevice uint64, free uint64) *probeStub {
		return &probeStub{usage: map[string]systemstatus.DiskUsage{
			"/data/uploads": {
				FreeBytes: free, TotalBytes: 3000, Writable: true,
				DeviceID: 10, DeviceKnown: true,
			},
			"/data/repository": {
				FreeBytes: free, TotalBytes: 3000, Writable: true,
				DeviceID: repositoryDevice, DeviceKnown: true,
			},
		}}
	}

	if err := newTestChecker(t, newProbe(11, 1000), 100).CheckCreate(
		context.Background(),
		900,
	); err != nil {
		t.Fatalf("separate filesystems were combined: %v", err)
	}
	if err := newTestChecker(t, newProbe(10, 1000), 100).CheckCreate(
		context.Background(),
		450,
	); err != nil {
		t.Fatalf("same-filesystem exact peak was rejected: %v", err)
	}
	if err := newTestChecker(t, newProbe(10, 1000), 100).CheckCreate(
		context.Background(),
		451,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("same filesystem was overcommitted: %v", err)
	}
}

func TestCheckerFailsClosedForLowReadOnlyOrUnavailableRoot(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*probeStub)
	}{
		{
			name: "low water",
			mutate: func(probe *probeStub) {
				value := probe.usage["/data/repository"]
				value.FreeBytes = 99
				probe.usage["/data/repository"] = value
			},
		},
		{
			name: "read only",
			mutate: func(probe *probeStub) {
				value := probe.usage["/data/uploads"]
				value.Writable = false
				probe.usage["/data/uploads"] = value
			},
		},
		{
			name: "probe unavailable",
			mutate: func(probe *probeStub) {
				probe.err["/data/uploads"] = errors.New(
					"password=secret path=/private/data",
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := &probeStub{
				usage: map[string]systemstatus.DiskUsage{
					"/data/uploads": {
						FreeBytes: 1000, TotalBytes: 2000, Writable: true,
					},
					"/data/repository": {
						FreeBytes: 1000, TotalBytes: 2000, Writable: true,
					},
				},
				err: map[string]error{},
			}
			test.mutate(probe)
			err := newTestChecker(t, probe, 100).CheckCreate(
				context.Background(),
				0,
			)
			if !errors.Is(err, ErrInsufficientStorage) ||
				err.Error() != ErrInsufficientStorage.Error() {
				t.Fatalf("CheckCreate() error = %v", err)
			}
		})
	}
}

func TestCheckerAccountsForOutstandingReservations(t *testing.T) {
	probe := sameDeviceProbe(1000)
	checker := newTestChecker(t, probe, 100)
	releasePart, err := checker.ReservePart(context.Background(), 600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.ReserveAssembly(
		context.Background(),
		400,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("overcommitted reservation error = %v", err)
	}
	releasePart()
	releaseAssembly, err := checker.ReserveAssembly(
		context.Background(),
		400,
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseAssembly()
	releaseAssembly()
}

func TestCheckerKeepsDistinctFilesystemReservationsIndependent(t *testing.T) {
	probe := &probeStub{usage: map[string]systemstatus.DiskUsage{
		"/data/uploads": {
			FreeBytes: 1000, Writable: true,
			DeviceID: 10, DeviceKnown: true,
		},
		"/data/repository": {
			FreeBytes: 1000, Writable: true,
			DeviceID: 11, DeviceKnown: true,
		},
	}}
	checker := newTestChecker(t, probe, 100)
	releasePart, err := checker.ReservePart(context.Background(), 900)
	if err != nil {
		t.Fatal(err)
	}
	defer releasePart()
	releaseAssembly, err := checker.ReserveAssembly(
		context.Background(),
		900,
	)
	if err != nil {
		t.Fatal(err)
	}
	releaseAssembly()
}

func TestReservePlanAccountsForBothCapacityDomainsAtomically(t *testing.T) {
	probe := &probeStub{usage: map[string]systemstatus.DiskUsage{
		"/data/uploads": {
			FreeBytes: 1000, Writable: true,
			DeviceID: 10, DeviceKnown: true,
		},
		"/data/repository": {
			FreeBytes: 700, Writable: true,
			DeviceID: 11, DeviceKnown: true,
		},
	}}
	checker := newTestChecker(t, probe, 100)

	release, err := checker.ReservePlan(context.Background(), 900, 600)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := checker.ReservePlan(
		context.Background(),
		1,
		1,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("overcommitted plan error = %v", err)
	}
}

func TestReservePlanCombinesRootsOnOneFilesystem(t *testing.T) {
	checker := newTestChecker(t, sameDeviceProbe(1000), 100)
	if _, err := checker.ReservePlan(
		context.Background(),
		450,
		450,
	); err != nil {
		t.Fatalf("exact shared-filesystem plan failed: %v", err)
	}

	checker = newTestChecker(t, sameDeviceProbe(1000), 100)
	if _, err := checker.ReservePlan(
		context.Background(),
		451,
		450,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("shared-filesystem overcommit error = %v", err)
	}
}

func TestCheckerRejectsOverflowBeforeProbing(t *testing.T) {
	probe := &probeStub{}
	checker := newTestChecker(t, probe, 1)
	checker.minimumFreeBytes = math.MaxUint64

	err := checker.CheckCreate(context.Background(), 1)
	if !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("CheckCreate() error = %v", err)
	}
	probe.mu.Lock()
	calls := probe.calls
	probe.mu.Unlock()
	if calls != 0 {
		t.Fatalf("overflow probed storage %d times", calls)
	}
}

func TestCheckerBoundsUncancelableProbes(t *testing.T) {
	block := make(chan struct{})
	probe := &probeStub{block: block}
	checker, err := NewChecker(Config{
		UploadsRoot: "/data/uploads", RepositoryRoot: "/data/repository",
		MinimumFreeBytes: 100, ProbeTimeout: 15 * time.Millisecond,
		StorageProbe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer close(block)

	started := time.Now()
	for range 2 {
		err := checker.CheckCreate(context.Background(), 1)
		if !errors.Is(err, ErrInsufficientStorage) {
			t.Fatalf("CheckCreate() error = %v", err)
		}
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("bounded checks took %s", elapsed)
	}
	probe.mu.Lock()
	calls := probe.calls
	probe.mu.Unlock()
	if calls != 2 {
		t.Fatalf("uncancelable probe calls = %d, want bounded at 2", calls)
	}
}

func TestCheckerValidatesConfigurationAndContext(t *testing.T) {
	valid := Config{
		UploadsRoot: "/data/uploads", RepositoryRoot: "/data/repository",
		MinimumFreeBytes: 1, StorageProbe: sameDeviceProbe(100),
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "relative uploads", mutate: func(config *Config) {
			config.UploadsRoot = "uploads"
		}},
		{name: "root repository", mutate: func(config *Config) {
			config.RepositoryRoot = "/"
		}},
		{name: "non canonical", mutate: func(config *Config) {
			config.UploadsRoot = "/data/../uploads"
		}},
		{name: "minimum", mutate: func(config *Config) {
			config.MinimumFreeBytes = 0
		}},
		{name: "timeout", mutate: func(config *Config) {
			config.ProbeTimeout = -time.Second
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewChecker(config); err == nil {
				t.Fatal("NewChecker() error = nil")
			}
		})
	}

	checker, err := NewChecker(valid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checker.CheckCreate(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckCreate() error = %v", err)
	}
	if err := checker.CheckCreate(
		context.Background(),
		-1,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("CheckCreate(-1) error = %v", err)
	}
	if err := checker.CheckCreate(
		nil,
		0,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("CheckCreate(nil) error = %v", err)
	}
	if _, err := checker.ReservePart(
		context.Background(),
		-1,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("ReservePart(-1) error = %v", err)
	}
	if _, err := checker.ReserveAssembly(
		context.Background(),
		-1,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("ReserveAssembly(-1) error = %v", err)
	}
	if _, err := checker.ReservePlan(
		context.Background(),
		-1,
		0,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("ReservePlan(-1, 0) error = %v", err)
	}
	if _, err := checker.ReservePlan(
		context.Background(),
		0,
		-1,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("ReservePlan(0, -1) error = %v", err)
	}
	if _, err := checker.ReservePlan(
		nil,
		0,
		0,
	); !errors.Is(err, ErrInsufficientStorage) {
		t.Fatalf("ReservePlan(nil) error = %v", err)
	}
}

func sameDeviceProbe(free uint64) *probeStub {
	return &probeStub{usage: map[string]systemstatus.DiskUsage{
		"/data/uploads": {
			FreeBytes: free, TotalBytes: free * 2, Writable: true,
			DeviceID: 10, DeviceKnown: true,
		},
		"/data/repository": {
			FreeBytes: free, TotalBytes: free * 2, Writable: true,
			DeviceID: 10, DeviceKnown: true,
		},
	}}
}

func newTestChecker(
	t *testing.T,
	probe systemstatus.StorageProbe,
	minimum int64,
) *Checker {
	t.Helper()
	checker, err := NewChecker(Config{
		UploadsRoot: "/data/uploads", RepositoryRoot: "/data/repository",
		MinimumFreeBytes: minimum, StorageProbe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	return checker
}
