package queue

import (
	"encoding/json"
	"time"
)

type Kind string

const (
	KindScan         Kind = "scan"
	KindImage        Kind = "image"
	KindNative       Kind = "native"
	KindBytecode     Kind = "bytecode"
	KindTrivy        Kind = "trivy"
	KindReport       Kind = "report"
	KindDecompile    Kind = "decompile"
	KindCAnalysis    Kind = "c_analysis"
	KindJavaAnalysis Kind = "java_analysis"
	KindPythonAnalysis Kind = "python_analysis"
)

type Outcome string

const (
	OutcomeSucceeded            Outcome = "succeeded"
	OutcomePartialSucceeded     Outcome = "partial_succeeded"
	OutcomeDeterministicFailure Outcome = "deterministic_failure"
	OutcomeTransientFailure     Outcome = "transient_failure"
)

type Lease struct {
	JobID         string
	TaskID        string
	TaskAttemptID *uint64
	Kind          Kind
	Payload       json.RawMessage
	Attempt       uint32
	MaxAttempts   uint32
	FencingToken  uint64
	Owner         string
	LeaseUntil    time.Time
	ResourceSlots []ResourceSlotLease
}

// ResourceSlotLease identifies the exact database slot fenced to a job lease.
// The job's lease_until remains the only lease clock; slots carry identity only.
type ResourceSlotLease struct {
	Pool       string
	SlotNumber uint8
}

type ProgressInput struct {
	TaskStatus string
	Stage      string
	// StageProgressBasisPoints is the measured fraction of the current stage.
	// Nil means that the stage's total work is not known yet.
	StageProgressBasisPoints *uint16
}

// ActivityInput is a safe, user-visible analyzer milestone. Payload must be a
// bounded JSON object containing counters and public analyzer metadata only.
type ActivityInput struct {
	EventType string
	Severity  string
	Message   string
	Payload   json.RawMessage
}

type FinishInput struct {
	Outcome      Outcome
	ErrorCode    string
	ErrorMessage string
}

type Config struct {
	LeaseDuration   time.Duration
	RetryDelay      time.Duration
	SampleRetention time.Duration
	HeavySlotLimit  int
	TrivySlotLimit  int
	NativeSlotLimit int
}

type claimRequest struct {
	Kind                Kind
	PayloadWorkerKind   Kind
	Owner               string
	LeaseDurationMicros int64
	HeavySlotLimit      int
	TrivySlotLimit      int
	NativeSlotLimit     int
}

type progressRequest struct {
	Lease               Lease
	Input               ProgressInput
	ProgressBasisPoints uint16
	LeaseDurationMicros int64
}

type activityRequest struct {
	Lease Lease
	Input ActivityInput
}

type finishRequest struct {
	Lease                 Lease
	Input                 FinishInput
	RetryDelayMicros      int64
	SampleRetentionMicros int64
}

type workspaceLeaseRequest struct {
	JobID         string
	TaskID        string
	TaskAttemptID uint64
	FencingToken  uint64
	Kind          Kind
}
