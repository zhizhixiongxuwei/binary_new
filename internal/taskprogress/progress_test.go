package taskprogress

import (
	"errors"
	"testing"
)

func TestCalculateAppliesPipelineStageWeights(t *testing.T) {
	half := uint16(5_000)
	complete := uint16(10_000)
	tests := []struct {
		stage         string
		local         *uint16
		progress      uint16
		indeterminate bool
	}{
		{stage: "VALIDATING", progress: 0, indeterminate: true},
		{stage: "IDENTIFYING", progress: 500, indeterminate: true},
		{stage: "EXTRACTING", local: &half, progress: 3_500},
		{stage: "INDEXING", local: &complete, progress: 7_000},
		{stage: "SCANNING", local: &half, progress: 8_250},
		{stage: " reporting ", progress: 9_500},
	}
	for _, test := range tests {
		t.Run(test.stage, func(t *testing.T) {
			progress, indeterminate, err := Calculate(test.stage, test.local)
			if err != nil || progress != test.progress ||
				indeterminate != test.indeterminate {
				t.Fatalf(
					"Calculate() = (%d, %v, %v), want (%d, %v, nil)",
					progress, indeterminate, err,
					test.progress, test.indeterminate,
				)
			}
		})
	}
}

func TestCalculateRejectsUnknownStageAndOutOfRangeFraction(t *testing.T) {
	overflow := uint16(10_001)
	for _, test := range []struct {
		stage string
		local *uint16
	}{
		{stage: "UNKNOWN"},
		{stage: "SCANNING", local: &overflow},
	} {
		if _, _, err := Calculate(test.stage, test.local); !errors.Is(
			err,
			ErrInvalidProgress,
		) {
			t.Fatalf("Calculate(%q) error = %v", test.stage, err)
		}
	}
}

func TestIsIndeterminateMatchesPersistedWeightedBoundary(t *testing.T) {
	if !IsIndeterminate("SCANNING", 7_000) {
		t.Fatal("SCANNING at its boundary must be indeterminate")
	}
	if IsIndeterminate("SCANNING", 7_001) {
		t.Fatal("SCANNING after measured progress must be determinate")
	}
	if IsIndeterminate("REPORTING", 9_500) || IsIndeterminate("", 0) {
		t.Fatal("fixed reporting and absent stages must be determinate")
	}
}
