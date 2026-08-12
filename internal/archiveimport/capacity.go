package archiveimport

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"binaryscan/internal/systemstatus"
)

type CapacityGuardConfig struct {
	SandboxRoots   []string
	RepositoryRoot string
	MinimumFree    int64
	Probe          systemstatus.StorageProbe
	ProbeTimeout   time.Duration
}

type capacityGuard struct {
	roots       []string
	repository  string
	minimumFree uint64
	probe       systemstatus.StorageProbe
	timeout     time.Duration
	mu          sync.Mutex
	reserved    map[uint64]uint64
}

func NewCapacityGuard(config CapacityGuardConfig) (StorageGuard, error) {
	if len(config.SandboxRoots) == 0 || config.RepositoryRoot == "" || config.MinimumFree <= 0 {
		return nil, errors.New("archive capacity guard configuration is invalid")
	}
	if config.Probe == nil {
		config.Probe = systemstatus.SecureStorageProbe{}
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = 500 * time.Millisecond
	}
	return &capacityGuard{
		roots: append([]string(nil), config.SandboxRoots...), repository: config.RepositoryRoot,
		minimumFree: uint64(config.MinimumFree), probe: config.Probe,
		timeout: config.ProbeTimeout, reserved: make(map[uint64]uint64),
	}, nil
}

func (guard *capacityGuard) ReservePlan(
	ctx context.Context,
	plan StoragePlan,
) (func(), error) {
	if ctx == nil || plan.SourceBytes < 0 || plan.ExpandedBytes < 0 || guard.timeout <= 0 {
		return nil, errors.New("archive capacity reservation is invalid")
	}
	guard.mu.Lock()
	defer guard.mu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, guard.timeout)
	defer cancel()
	type domain struct {
		usage systemstatus.DiskUsage
		bytes uint64
	}
	domains := make(map[uint64]domain)
	add := func(root string, required uint64) error {
		usage, err := guard.probe.Probe(probeCtx, root)
		if err != nil || !usage.Writable || !usage.DeviceKnown {
			return errors.New("archive capacity domain is unavailable")
		}
		value := domains[usage.DeviceID]
		if value.bytes > math.MaxUint64-required {
			return errors.New("archive capacity reservation overflows")
		}
		value.usage = usage
		value.bytes += required
		domains[usage.DeviceID] = value
		return nil
	}
	if len(guard.roots) != 4 {
		return nil, errors.New("archive capacity roots are incomplete")
	}
	// Per-root peaks: input staging S, private run snapshot S, sandbox output E,
	// materialized task workspace E, repository verified source snapshot plus
	// published eligible members S+E. Domains are merged only when devices match.
	for index, bytes := range []uint64{
		uint64(plan.SourceBytes), uint64(plan.ExpandedBytes),
		uint64(plan.SourceBytes), uint64(plan.ExpandedBytes),
	} {
		if err := add(guard.roots[index], bytes); err != nil {
			return nil, err
		}
	}
	repositoryBytes := uint64(plan.SourceBytes)
	if repositoryBytes > math.MaxUint64-uint64(plan.ExpandedBytes) {
		return nil, errors.New("archive repository capacity overflows")
	}
	if err := add(guard.repository, repositoryBytes+uint64(plan.ExpandedBytes)); err != nil {
		return nil, err
	}
	reservedNow := make(map[uint64]uint64, len(domains))
	for id, value := range domains {
		existing := guard.reserved[id]
		if existing > math.MaxUint64-value.bytes ||
			existing+value.bytes > math.MaxUint64-guard.minimumFree ||
			value.usage.FreeBytes < guard.minimumFree+existing+value.bytes {
			return nil, errors.New("archive capacity is below the low-water mark")
		}
		reservedNow[id] = value.bytes
	}
	for id, bytes := range reservedNow {
		guard.reserved[id] += bytes
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			guard.mu.Lock()
			defer guard.mu.Unlock()
			for id, bytes := range reservedNow {
				guard.reserved[id] -= bytes
			}
		})
	}, nil
}
