package storageguard

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"sync"
	"time"

	"binaryscan/internal/systemstatus"
)

const defaultProbeTimeout = 500 * time.Millisecond

var ErrInsufficientStorage = errors.New("insufficient storage capacity")

type Config struct {
	UploadsRoot      string
	RepositoryRoot   string
	MinimumFreeBytes int64
	ProbeTimeout     time.Duration
	StorageProbe     systemstatus.StorageProbe
}

type Checker struct {
	roots            [2]string
	minimumFreeBytes uint64
	probeTimeout     time.Duration
	probe            systemstatus.StorageProbe
	probeSlots       chan struct{}
	capacityMu       sync.Mutex
	reservedBytes    [2]uint64
}

type probeResult struct {
	index int
	usage systemstatus.DiskUsage
	err   error
}

func NewChecker(config Config) (*Checker, error) {
	for _, root := range []string{config.UploadsRoot, config.RepositoryRoot} {
		if !filepath.IsAbs(root) || root == "/" || filepath.Clean(root) != root {
			return nil, errors.New("storage guard roots must be canonical absolute paths below /")
		}
	}
	if config.MinimumFreeBytes <= 0 {
		return nil, errors.New("storage guard minimum free bytes must be positive")
	}
	if config.ProbeTimeout == 0 {
		config.ProbeTimeout = defaultProbeTimeout
	}
	if config.ProbeTimeout < 0 {
		return nil, errors.New("storage guard probe timeout must be positive")
	}
	if config.StorageProbe == nil {
		config.StorageProbe = systemstatus.SecureStorageProbe{}
	}
	return &Checker{
		roots: [2]string{
			config.UploadsRoot,
			config.RepositoryRoot,
		},
		minimumFreeBytes: uint64(config.MinimumFreeBytes),
		probeTimeout:     config.ProbeTimeout,
		probe:            config.StorageProbe,
		probeSlots:       make(chan struct{}, 2),
	}, nil
}

func (c *Checker) CheckCreate(ctx context.Context, size int64) error {
	if ctx == nil {
		return ErrInsufficientStorage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return ErrInsufficientStorage
	}
	requestBytes := uint64(size)
	if requestBytes > math.MaxUint64/2 {
		return ErrInsufficientStorage
	}
	c.capacityMu.Lock()
	defer c.capacityMu.Unlock()
	return c.checkLocked(ctx, [2]uint64{requestBytes, requestBytes})
}

func (c *Checker) checkLocked(ctx context.Context, additions [2]uint64) error {
	if ctx == nil {
		return ErrInsufficientStorage
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for index, addition := range additions {
		required, ok := checkedCapacitySum(c.reservedBytes[index], addition)
		if !ok || required > math.MaxUint64-c.minimumFreeBytes {
			return ErrInsufficientStorage
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, c.probeTimeout)
	defer cancel()
	var resultsByIndex [2]systemstatus.DiskUsage
	results := make(chan probeResult, len(c.roots))
	for index, root := range c.roots {
		index, root := index, root
		go func() {
			result := c.probeRoot(probeCtx, root)
			result.index = index
			results <- result
		}()
	}
	for range c.roots {
		result := <-results
		if result.err != nil || !result.usage.Writable {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrInsufficientStorage
		}
		resultsByIndex[result.index] = result.usage
	}
	for index, usage := range resultsByIndex {
		requiredAdditional, ok := c.requiredForRoot(
			index,
			additions,
			resultsByIndex,
		)
		if !ok || requiredAdditional > math.MaxUint64-c.minimumFreeBytes ||
			usage.FreeBytes < c.minimumFreeBytes+requiredAdditional {
			return ErrInsufficientStorage
		}
	}
	return nil
}

func (c *Checker) requiredForRoot(
	index int,
	additions [2]uint64,
	usage [2]systemstatus.DiskUsage,
) (uint64, bool) {
	values := []uint64{
		c.reservedBytes[index],
		additions[index],
	}
	other := 1 - index
	sameCapacityDomain := !usage[index].DeviceKnown ||
		!usage[other].DeviceKnown ||
		usage[index].DeviceID == usage[other].DeviceID
	if sameCapacityDomain {
		values = append(
			values,
			c.reservedBytes[other],
			additions[other],
		)
	}
	return checkedCapacitySum(values...)
}

func (c *Checker) reserve(
	ctx context.Context,
	additions [2]uint64,
) (func(), error) {
	c.capacityMu.Lock()
	defer c.capacityMu.Unlock()
	if err := c.checkLocked(ctx, additions); err != nil {
		return nil, err
	}
	for index, value := range additions {
		if value > math.MaxUint64-c.reservedBytes[index] {
			return nil, ErrInsufficientStorage
		}
		c.reservedBytes[index] += value
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.capacityMu.Lock()
			for index, value := range additions {
				c.reservedBytes[index] -= value
			}
			c.capacityMu.Unlock()
		})
	}, nil
}

func (c *Checker) probeRoot(ctx context.Context, root string) probeResult {
	select {
	case c.probeSlots <- struct{}{}:
	case <-ctx.Done():
		return probeResult{err: ctx.Err()}
	}
	result := make(chan probeResult, 1)
	go func() {
		usage, err := c.probe.Probe(ctx, root)
		<-c.probeSlots
		result <- probeResult{usage: usage, err: err}
	}()
	select {
	case value := <-result:
		return value
	case <-ctx.Done():
		return probeResult{err: ctx.Err()}
	}
}

func (c *Checker) ReservePart(
	ctx context.Context,
	size int64,
) (func(), error) {
	if size < 0 {
		return nil, ErrInsufficientStorage
	}
	return c.reserve(ctx, [2]uint64{uint64(size), 0})
}

func (c *Checker) ReserveAssembly(
	ctx context.Context,
	size int64,
) (func(), error) {
	if size < 0 {
		return nil, ErrInsufficientStorage
	}
	return c.reserve(ctx, [2]uint64{0, uint64(size)})
}

// ReservePlan atomically reserves different byte budgets on the uploads/work
// root and repository root. This is used by multi-stage jobs whose temporary
// and durable outputs peak independently.
func (c *Checker) ReservePlan(
	ctx context.Context,
	workBytes int64,
	repositoryBytes int64,
) (func(), error) {
	if workBytes < 0 || repositoryBytes < 0 {
		return nil, ErrInsufficientStorage
	}
	return c.reserve(ctx, [2]uint64{
		uint64(workBytes),
		uint64(repositoryBytes),
	})
}

func checkedCapacitySum(values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, false
		}
		total += value
	}
	return total, true
}
