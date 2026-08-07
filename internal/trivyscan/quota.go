package trivyscan

import (
	"context"
	"errors"
	"math"

	"binaryscan/internal/containerarchive"
)

const (
	maxSupportedExpandedBytes = int64(50 * 1024 * 1024 * 1024)
	maxSupportedReportBytes   = int64(1024 * 1024 * 1024)
	quotaAllocationUnitBytes  = int64(4 << 10)
	trivyRuntimeReserveBytes  = int64(64 << 20)
	trivyInputMetadataBytes   = int64(512 << 20)
)

type quotaPlan struct {
	InputBytes       int64
	ExpandedBytes    int64
	ReportBytes      int64
	AdapterWorkBytes int64
	WorkBytes        int64
	RepositoryBytes  int64
	ScanTargets      int
}

type quotaLimitError struct {
	code    string
	message string
}

func (e *quotaLimitError) Error() string {
	return e.code + ": " + e.message
}

func buildQuotaPlan(
	ctx context.Context,
	plans []sourcePlan,
	maxExpandedBytes int64,
	maxReportBytes int64,
) (quotaPlan, error) {
	if ctx == nil || len(plans) == 0 ||
		maxExpandedBytes <= 0 ||
		maxExpandedBytes > maxSupportedExpandedBytes ||
		maxReportBytes <= 0 ||
		maxReportBytes > maxSupportedReportBytes {
		return quotaPlan{}, errors.New("invalid Trivy quota plan")
	}
	maxInputBytes, ok := quotaAdd(
		maxExpandedBytes,
		trivyInputMetadataBytes,
	)
	if !ok {
		return quotaPlan{}, quotaOverflow()
	}
	remainingInput := maxInputBytes
	remainingExpanded := maxExpandedBytes
	var result quotaPlan
	totalTargets := 0
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return quotaPlan{}, err
		}
		if plan.source == nil || plan.source.size <= 0 ||
			len(plan.inspection.Targets) == 0 {
			return quotaPlan{}, errors.New("incomplete Trivy quota source plan")
		}
		if len(plan.inspection.Targets) >
			math.MaxInt-totalTargets {
			return quotaPlan{}, quotaOverflow()
		}
		totalTargets += len(plan.inspection.Targets)

		switch plan.handoff.Format {
		case containerarchive.FormatDocker:
			inputBytes, ok := allocatedFileBytes(plan.source.size)
			if !ok {
				return quotaPlan{}, quotaOverflow()
			}
			inputBytes, ok = quotaAdd(
				inputBytes,
				quotaAllocationUnitBytes,
			)
			if !ok {
				return quotaPlan{}, quotaOverflow()
			}
			if inputBytes > remainingInput {
				return quotaPlan{}, &quotaLimitError{
					code: "trivy_materialized_size_limit",
					message: "Container image inputs exceed the configured " +
						"temporary-space limit.",
				}
			}
			if plan.source.size > remainingExpanded {
				return quotaPlan{}, &quotaLimitError{
					code: "trivy_expanded_size_limit",
					message: "Container image data exceeds the configured " +
						"expanded-data limit.",
				}
			}
			result.InputBytes += inputBytes
			result.ExpandedBytes += plan.source.size
			remainingInput -= inputBytes
			remainingExpanded -= plan.source.size
		case containerarchive.FormatOCI:
			if plan.ociPlan == nil {
				return quotaPlan{}, errors.New(
					"incomplete OCI quota source plan",
				)
			}
			usage, err := plan.ociPlan.EstimateUsageWithin(
				ctx,
				remainingInput,
				remainingExpanded,
			)
			if err != nil {
				return quotaPlan{}, err
			}
			result.InputBytes += usage.MaterializedBudgetBytes
			result.ExpandedBytes += usage.ExpandedLayerBytes
			remainingInput -= usage.MaterializedBudgetBytes
			remainingExpanded -= usage.ExpandedLayerBytes
		default:
			return quotaPlan{}, errors.New(
				"unsupported Trivy quota source format",
			)
		}
	}

	result.ScanTargets = totalTargets
	if result.ScanTargets > maxAutomaticImageTargets {
		result.ScanTargets = maxAutomaticImageTargets
	}
	reportBytes, ok := quotaMultiply(
		int64(result.ScanTargets),
		maxReportBytes,
	)
	if !ok {
		return quotaPlan{}, quotaOverflow()
	}
	result.ReportBytes = reportBytes
	result.RepositoryBytes = reportBytes
	result.AdapterWorkBytes, ok = quotaAdd(
		maxExpandedBytes,
		reportBytes,
		trivyRuntimeReserveBytes,
	)
	if !ok {
		return quotaPlan{}, quotaOverflow()
	}
	result.WorkBytes, ok = quotaAdd(
		result.InputBytes,
		result.AdapterWorkBytes,
	)
	if !ok {
		return quotaPlan{}, quotaOverflow()
	}
	return result, nil
}

func allocatedFileBytes(size int64) (int64, bool) {
	if size < 0 || size > math.MaxInt64-(quotaAllocationUnitBytes-1) {
		return 0, false
	}
	value := (size + quotaAllocationUnitBytes - 1) &
		^(quotaAllocationUnitBytes - 1)
	if value == 0 {
		value = quotaAllocationUnitBytes
	}
	return value, true
}

func quotaAdd(values ...int64) (int64, bool) {
	var total int64
	for _, value := range values {
		if value < 0 || value > math.MaxInt64-total {
			return 0, false
		}
		total += value
	}
	return total, true
}

func quotaMultiply(left int64, right int64) (int64, bool) {
	if left < 0 || right < 0 ||
		(left != 0 && right > math.MaxInt64/left) {
		return 0, false
	}
	return left * right, true
}

func quotaOverflow() error {
	return &quotaLimitError{
		code:    "trivy_quota_overflow",
		message: "Container image temporary-space accounting overflowed.",
	}
}
