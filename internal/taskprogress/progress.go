// Package taskprogress owns the task pipeline's weighted progress contract.
package taskprogress

import (
	"errors"
	"strings"
)

const TotalBasisPoints uint16 = 10_000

const (
	ValidatingStartBasisPoints  uint16 = 0
	IdentifyingStartBasisPoints uint16 = 500
	ExtractingStartBasisPoints  uint16 = 1_500
	IndexingStartBasisPoints    uint16 = 5_500
	ScanningStartBasisPoints    uint16 = 7_000
	ReportingStartBasisPoints   uint16 = 9_500
)

type stageRange struct {
	start uint16
	end   uint16
}

// Stage weights intentionally describe work rather than elapsed time. A task
// reports the completed fraction inside its current stage when that total is
// known; otherwise it remains at the stage boundary with indeterminate=true.
var stageRanges = map[string]stageRange{
	"VALIDATING":  {start: ValidatingStartBasisPoints, end: IdentifyingStartBasisPoints},
	"IDENTIFYING": {start: IdentifyingStartBasisPoints, end: ExtractingStartBasisPoints},
	"EXTRACTING":  {start: ExtractingStartBasisPoints, end: IndexingStartBasisPoints},
	"INDEXING":    {start: IndexingStartBasisPoints, end: ScanningStartBasisPoints},
	"SCANNING":    {start: ScanningStartBasisPoints, end: ReportingStartBasisPoints},
	"REPORTING":   {start: ReportingStartBasisPoints, end: TotalBasisPoints},
}

var ErrInvalidProgress = errors.New("invalid weighted task progress")

// Calculate converts optional stage-local basis points into overall progress.
// A nil local value means the stage total is not known yet.
func Calculate(stage string, localBasisPoints *uint16) (uint16, bool, error) {
	stage = strings.ToUpper(strings.TrimSpace(stage))
	stageProgress, ok := stageRanges[stage]
	if !ok {
		return 0, false, ErrInvalidProgress
	}
	if localBasisPoints == nil {
		return stageProgress.start, stage != "REPORTING", nil
	}
	if *localBasisPoints > TotalBasisPoints {
		return 0, false, ErrInvalidProgress
	}
	weight := uint32(stageProgress.end - stageProgress.start)
	overall := uint32(stageProgress.start) +
		weight*uint32(*localBasisPoints)/uint32(TotalBasisPoints)
	return uint16(overall), false, nil
}

// IsIndeterminate reconstructs the progress mode from persisted task state.
// Reporting has a fixed finalization unit; other stages at their lower boundary
// have not established a measurable total yet.
func IsIndeterminate(stage string, overallBasisPoints uint16) bool {
	stage = strings.ToUpper(strings.TrimSpace(stage))
	stageProgress, ok := stageRanges[stage]
	return ok && stage != "REPORTING" && overallBasisPoints == stageProgress.start
}

func Start(stage string) (uint16, error) {
	progress, _, err := Calculate(stage, nil)
	return progress, err
}
