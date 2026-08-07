package trivyscan

import (
	"context"
	"errors"
	"math"
	"testing"

	"binaryscan/internal/containerarchive"
)

func TestBuildQuotaPlanReservesAggregateInputOutputAndReports(t *testing.T) {
	plans := []sourcePlan{
		dockerQuotaSourcePlan(1 << 20),
		dockerQuotaSourcePlan(2 << 20),
	}
	quota, err := buildQuotaPlan(
		context.Background(),
		plans,
		8<<20,
		2<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if quota.InputBytes != 3<<20+2*quotaAllocationUnitBytes ||
		quota.ExpandedBytes != 3<<20 ||
		quota.ReportBytes != 4<<20 ||
		quota.RepositoryBytes != quota.ReportBytes ||
		quota.AdapterWorkBytes !=
			8<<20+4<<20+trivyRuntimeReserveBytes ||
		quota.WorkBytes != quota.InputBytes+quota.AdapterWorkBytes ||
		quota.ScanTargets != 2 {
		t.Fatalf("quota = %+v", quota)
	}
}

func TestBuildQuotaPlanCapsReportReservationAtAutomaticTargetLimit(t *testing.T) {
	plan := dockerQuotaSourcePlan(1 << 20)
	plan.inspection.Targets = make(
		[]containerarchive.Target,
		maxAutomaticImageTargets+100,
	)
	quota, err := buildQuotaPlan(
		context.Background(),
		[]sourcePlan{plan},
		8<<20,
		1<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if quota.ScanTargets != maxAutomaticImageTargets ||
		quota.ReportBytes != maxAutomaticImageTargets*(1<<20) {
		t.Fatalf("target-capped quota = %+v", quota)
	}
}

func TestBuildQuotaPlanRejectsAggregateExpandedData(t *testing.T) {
	_, err := buildQuotaPlan(
		context.Background(),
		[]sourcePlan{
			dockerQuotaSourcePlan(2 << 20),
			dockerQuotaSourcePlan(2 << 20),
		},
		3<<20,
		1<<20,
	)
	var limit *quotaLimitError
	if !errors.As(err, &limit) ||
		limit.code != "trivy_expanded_size_limit" {
		t.Fatalf("buildQuotaPlan() error = %v", err)
	}
}

func TestBuildQuotaPlanHonorsCancellationAndArithmeticBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildQuotaPlan(
		ctx,
		[]sourcePlan{dockerQuotaSourcePlan(1)},
		1<<20,
		1,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled buildQuotaPlan() error = %v", err)
	}
	if _, ok := allocatedFileBytes(math.MaxInt64); ok {
		t.Fatal("allocatedFileBytes accepted overflow")
	}
	if _, ok := quotaAdd(math.MaxInt64, 1); ok {
		t.Fatal("quotaAdd accepted overflow")
	}
	if _, ok := quotaMultiply(math.MaxInt64, 2); ok {
		t.Fatal("quotaMultiply accepted overflow")
	}
}

func dockerQuotaSourcePlan(size int64) sourcePlan {
	return sourcePlan{
		handoff: HandoffSource{Format: containerarchive.FormatDocker},
		source:  &sourceFile{size: size},
		inspection: containerarchive.Inspection{
			Format: containerarchive.FormatDocker,
			Targets: []containerarchive.Target{{
				Platform: containerarchive.Platform{
					OS: "linux", Architecture: "amd64",
				},
			}},
		},
	}
}
