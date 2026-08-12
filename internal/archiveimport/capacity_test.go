package archiveimport

import (
	"context"
	"testing"

	"binaryscan/internal/systemstatus"
)

type capacityProbe map[string]systemstatus.DiskUsage

func (probe capacityProbe) Probe(_ context.Context, root string) (systemstatus.DiskUsage, error) {
	return probe[root], nil
}

func TestCapacityGuardAccountsForEveryActualFilesystemDomain(t *testing.T) {
	probe := capacityProbe{
		"/sandbox/input":  {FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 1},
		"/sandbox/output": {FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 2},
		"/sandbox/run":    {FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 3},
		"/task-work":      {FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 4},
		"/repository":     {FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 5},
	}
	guard, err := NewCapacityGuard(CapacityGuardConfig{
		SandboxRoots: []string{
			"/sandbox/input", "/sandbox/output", "/sandbox/run", "/task-work",
		},
		RepositoryRoot: "/repository", MinimumFree: 100, Probe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := guard.ReservePlan(context.Background(), StoragePlan{SourceBytes: 400, ExpandedBytes: 400})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := guard.ReservePlan(context.Background(), StoragePlan{SourceBytes: 101, ExpandedBytes: 101}); err == nil {
		t.Fatal("ReservePlan() ignored a distinct sandbox capacity domain")
	}
}

func TestCapacityGuardCombinesSharedSandboxAndRepositoryDevice(t *testing.T) {
	usage := systemstatus.DiskUsage{
		FreeBytes: 1000, Writable: true, DeviceKnown: true, DeviceID: 7,
	}
	probe := capacityProbe{
		"/sandbox/input": usage, "/sandbox/output": usage,
		"/sandbox/run": usage, "/task-work": usage, "/repository": usage,
	}
	guard, err := NewCapacityGuard(CapacityGuardConfig{
		SandboxRoots: []string{
			"/sandbox/input", "/sandbox/output", "/sandbox/run", "/task-work",
		},
		RepositoryRoot: "/repository", MinimumFree: 100, Probe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.ReservePlan(context.Background(), StoragePlan{SourceBytes: 200, ExpandedBytes: 200}); err == nil {
		t.Fatal("ReservePlan() did not combine shared capacity-domain demand")
	}
}

func TestCapacityGuardSharedDeviceUsesThreeSourcePlusThreeExpandedBytes(t *testing.T) {
	usage := systemstatus.DiskUsage{
		FreeBytes: 701, Writable: true, DeviceKnown: true, DeviceID: 7,
	}
	probe := capacityProbe{
		"/sandbox/input": usage, "/sandbox/output": usage,
		"/sandbox/run": usage, "/task-work": usage, "/repository": usage,
	}
	guard, err := NewCapacityGuard(CapacityGuardConfig{
		SandboxRoots: []string{
			"/sandbox/input", "/sandbox/output", "/sandbox/run", "/task-work",
		},
		RepositoryRoot: "/repository", MinimumFree: 100, Probe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	// S=100 and E=100 require exactly 3S+3E=600 bytes on one device. A
	// duplicated per-root total would reject this otherwise valid reservation.
	release, err := guard.ReservePlan(
		context.Background(), StoragePlan{SourceBytes: 100, ExpandedBytes: 100},
	)
	if err != nil {
		t.Fatalf("ReservePlan() overcounted a shared device: %v", err)
	}
	release()
	usage.FreeBytes = 699
	probe = capacityProbe{
		"/sandbox/input": usage, "/sandbox/output": usage,
		"/sandbox/run": usage, "/task-work": usage, "/repository": usage,
	}
	guard, err = NewCapacityGuard(CapacityGuardConfig{
		SandboxRoots: []string{
			"/sandbox/input", "/sandbox/output", "/sandbox/run", "/task-work",
		},
		RepositoryRoot: "/repository", MinimumFree: 100, Probe: probe,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guard.ReservePlan(
		context.Background(), StoragePlan{SourceBytes: 100, ExpandedBytes: 100},
	); err == nil {
		t.Fatal("ReservePlan() admitted a reservation at the low-water boundary")
	}
}
