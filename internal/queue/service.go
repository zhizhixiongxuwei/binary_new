package queue

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/task"
	"binaryscan/internal/taskprogress"
	"binaryscan/internal/workspace"
)

var (
	queueUUIDPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	stagePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
	codePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	eventPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	validKinds   = map[Kind]struct{}{
		KindScan: {}, KindImage: {}, KindNative: {}, KindBytecode: {},
		KindTrivy: {}, KindReport: {}, KindDecompile: {},
		KindCAnalysis:    {},
		KindJavaAnalysis: {},
	}
	activeTaskStatuses = map[string]struct{}{
		"VALIDATING": {}, "IDENTIFYING": {}, "EXTRACTING": {},
		"INDEXING": {}, "SCANNING": {}, "REPORTING": {},
	}
)

type Repository interface {
	ConfigureResourceLimits(context.Context, int, int, int) error
	Claim(context.Context, claimRequest) (Lease, bool, error)
	Start(context.Context, Lease) error
	Heartbeat(context.Context, Lease, int64) (Lease, error)
	TaskProgress(context.Context, progressRequest) error
	TaskActivity(context.Context, activityRequest) error
	Finish(context.Context, finishRequest) error
	RecoverExpired(context.Context, int, int64, int64) (int, error)
	WorkspaceLeaseActive(context.Context, workspaceLeaseRequest) (bool, error)
}

// ConfigureResourceLimits initializes the database authority on a brand-new
// installation, or verifies that this worker matches the established limits.
func (s *Service) ConfigureResourceLimits(ctx context.Context) error {
	return s.repository.ConfigureResourceLimits(
		ctx,
		s.config.HeavySlotLimit,
		s.config.TrivySlotLimit,
		s.config.NativeSlotLimit,
	)
}

type Service struct {
	repository Repository
	config     Config
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("queue repository is required")
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration > 24*time.Hour {
		return nil, errors.New("queue lease duration must be between zero and 24 hours")
	}
	if config.RetryDelay < 0 || config.RetryDelay > 24*time.Hour {
		return nil, errors.New("queue retry delay must be between zero and 24 hours")
	}
	if config.SampleRetention == 0 {
		config.SampleRetention = task.DefaultSampleRetention
	}
	if config.SampleRetention < time.Microsecond {
		return nil, errors.New("queue sample retention must be at least one microsecond")
	}
	if config.HeavySlotLimit == 0 {
		config.HeavySlotLimit = 2
	}
	if config.TrivySlotLimit == 0 {
		config.TrivySlotLimit = 1
	}
	if config.NativeSlotLimit == 0 {
		config.NativeSlotLimit = 1
	}
	if config.HeavySlotLimit < 1 || config.HeavySlotLimit > 4 {
		return nil, errors.New("queue heavy slot limit must be between 1 and 4")
	}
	if config.TrivySlotLimit < 1 ||
		config.TrivySlotLimit > config.HeavySlotLimit {
		return nil, errors.New(
			"queue Trivy slot limit must be between 1 and the heavy slot limit",
		)
	}
	if config.NativeSlotLimit < 1 ||
		config.NativeSlotLimit > config.HeavySlotLimit {
		return nil, errors.New(
			"queue native slot limit must be between 1 and the heavy slot limit",
		)
	}
	return &Service{repository: repository, config: config}, nil
}

func (s *Service) Claim(ctx context.Context, kind Kind, owner string) (Lease, bool, error) {
	if _, ok := validKinds[kind]; !ok || !validOwner(owner) {
		return Lease{}, false, ErrInvalidInput
	}
	return s.repository.Claim(ctx, claimRequest{
		Kind: kind, Owner: owner,
		LeaseDurationMicros: s.config.LeaseDuration.Microseconds(),
		HeavySlotLimit:      s.config.HeavySlotLimit,
		TrivySlotLimit:      s.config.TrivySlotLimit,
		NativeSlotLimit:     s.config.NativeSlotLimit,
	})
}

// ClaimDecompileWorker preserves jobs.kind='decompile' while atomically
// selecting only the worker family named by the immutable payload.
func (s *Service) ClaimDecompileWorker(
	ctx context.Context,
	workerKind Kind,
	owner string,
) (Lease, bool, error) {
	if (workerKind != KindNative && workerKind != KindBytecode) ||
		!validOwner(owner) {
		return Lease{}, false, ErrInvalidInput
	}
	return s.repository.Claim(ctx, claimRequest{
		Kind: KindDecompile, PayloadWorkerKind: workerKind, Owner: owner,
		LeaseDurationMicros: s.config.LeaseDuration.Microseconds(),
		HeavySlotLimit:      s.config.HeavySlotLimit,
		TrivySlotLimit:      s.config.TrivySlotLimit,
		NativeSlotLimit:     s.config.NativeSlotLimit,
	})
}

func (s *Service) Start(ctx context.Context, lease Lease) error {
	if !validLease(lease, s.config) {
		return ErrInvalidInput
	}
	return s.repository.Start(ctx, lease)
}

func (s *Service) Heartbeat(ctx context.Context, lease Lease) (Lease, error) {
	if !validLease(lease, s.config) {
		return Lease{}, ErrInvalidInput
	}
	return s.repository.Heartbeat(ctx, lease, s.config.LeaseDuration.Microseconds())
}

func (s *Service) TaskProgress(
	ctx context.Context,
	lease Lease,
	input ProgressInput,
) error {
	input.TaskStatus = strings.ToUpper(strings.TrimSpace(input.TaskStatus))
	input.Stage = strings.ToUpper(strings.TrimSpace(input.Stage))
	if !validLease(lease, s.config) ||
		(lease.Kind != KindScan && lease.Kind != KindTrivy) ||
		!stagePattern.MatchString(input.Stage) {
		return ErrInvalidInput
	}
	if _, ok := activeTaskStatuses[input.TaskStatus]; !ok {
		return ErrInvalidInput
	}
	if input.TaskStatus != input.Stage {
		return ErrInvalidInput
	}
	progress, _, err := taskprogress.Calculate(
		input.Stage,
		input.StageProgressBasisPoints,
	)
	if err != nil {
		return ErrInvalidInput
	}
	return s.repository.TaskProgress(ctx, progressRequest{
		Lease: lease, Input: input,
		ProgressBasisPoints: progress,
		LeaseDurationMicros: s.config.LeaseDuration.Microseconds(),
	})
}

// TaskActivity appends an analyzer milestone only while the exact fenced job
// lease is still running. It deliberately does not mutate task status or the
// task's weighted progress value.
func (s *Service) TaskActivity(
	ctx context.Context,
	lease Lease,
	input ActivityInput,
) error {
	input.EventType = strings.TrimSpace(input.EventType)
	input.Severity = strings.ToLower(strings.TrimSpace(input.Severity))
	input.Message = strings.TrimSpace(input.Message)
	if !validLease(lease, s.config) ||
		!eventPattern.MatchString(input.EventType) ||
		!validActivitySeverity(input.Severity) ||
		!validActivityMessage(input.Message) ||
		!validActivityPayload(input.Payload) {
		return ErrInvalidInput
	}
	input.Payload = append(json.RawMessage(nil), input.Payload...)
	return s.repository.TaskActivity(ctx, activityRequest{
		Lease: lease,
		Input: input,
	})
}

func (s *Service) Finish(ctx context.Context, lease Lease, input FinishInput) error {
	if !validLease(lease, s.config) || !validFinishInput(input) {
		return ErrInvalidInput
	}
	return s.repository.Finish(ctx, finishRequest{
		Lease: lease, Input: input,
		RetryDelayMicros:      s.config.RetryDelay.Microseconds(),
		SampleRetentionMicros: s.config.SampleRetention.Microseconds(),
	})
}

func (s *Service) RecoverExpired(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 1_000 {
		return 0, ErrInvalidInput
	}
	return s.repository.RecoverExpired(
		ctx,
		limit,
		s.config.RetryDelay.Microseconds(),
		s.config.SampleRetention.Microseconds(),
	)
}

// WorkspaceLeaseActive reports whether the exact fenced lease recorded in a
// workspace marker may still be using that directory. Lease time alone is not
// enough to declare it inactive: a concurrent heartbeat can hold the row lock
// while a non-locking query still observes the older, apparently expired row.
// A cancellation request is likewise not terminal until status or fencing
// changes, because workers do not stop synchronously with that write.
func (s *Service) WorkspaceLeaseActive(
	ctx context.Context,
	identity workspace.Identity,
) (bool, error) {
	if err := identity.Validate(); err != nil {
		return false, ErrInvalidInput
	}
	return s.repository.WorkspaceLeaseActive(ctx, workspaceLeaseRequest{
		JobID: identity.JobID, TaskID: identity.TaskID,
		TaskAttemptID: identity.TaskAttemptID,
		FencingToken:  identity.FencingToken,
		Kind:          Kind(identity.Kind),
	})
}

func validLease(lease Lease, config Config) bool {
	if !queueUUIDPattern.MatchString(lease.JobID) ||
		!queueUUIDPattern.MatchString(lease.TaskID) ||
		!validOwner(lease.Owner) ||
		lease.Attempt == 0 ||
		lease.MaxAttempts == 0 ||
		lease.Attempt > lease.MaxAttempts ||
		lease.FencingToken == 0 {
		return false
	}
	if _, ok := validKinds[lease.Kind]; !ok {
		return false
	}
	if lease.TaskAttemptID != nil && *lease.TaskAttemptID == 0 {
		return false
	}
	if (lease.Kind == KindScan || lease.Kind == KindTrivy) &&
		lease.TaskAttemptID == nil {
		return false
	}
	expectedPools, err := resourcePoolsForLease(lease)
	if err != nil {
		return false
	}
	if len(lease.ResourceSlots) != len(expectedPools) {
		return false
	}
	for index, expectedPool := range expectedPools {
		slot := lease.ResourceSlots[index]
		limit := config.HeavySlotLimit
		if expectedPool == resourcePoolTrivy {
			limit = config.TrivySlotLimit
		} else if expectedPool == resourcePoolNative {
			limit = config.NativeSlotLimit
		} else if (lease.Kind == KindCAnalysis || lease.Kind == KindJavaAnalysis) &&
			expectedPool == resourcePoolGlobal {
			limit = 1
		}
		if slot.Pool != expectedPool ||
			slot.SlotNumber == 0 ||
			int(slot.SlotNumber) > limit {
			return false
		}
	}
	return true
}

func validOwner(owner string) bool {
	if len(owner) == 0 || len(owner) > 255 || strings.TrimSpace(owner) != owner {
		return false
	}
	for _, character := range owner {
		if character > unicode.MaxASCII || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFinishInput(input FinishInput) bool {
	switch input.Outcome {
	case OutcomeSucceeded, OutcomePartialSucceeded:
		return input.ErrorCode == "" && input.ErrorMessage == ""
	case OutcomeDeterministicFailure, OutcomeTransientFailure:
		return codePattern.MatchString(input.ErrorCode) &&
			validErrorMessage(input.ErrorMessage)
	default:
		return false
	}
}

func validErrorMessage(message string) bool {
	if !utf8.ValidString(message) || len(message) > 2048 {
		return false
	}
	for _, character := range message {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validActivitySeverity(value string) bool {
	switch value {
	case "debug", "info", "warning", "error":
		return true
	default:
		return false
	}
}

func validActivityMessage(message string) bool {
	if message == "" || !utf8.ValidString(message) || len(message) > 512 {
		return false
	}
	for _, character := range message {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validActivityPayload(payload json.RawMessage) bool {
	if len(payload) < 2 || len(payload) > 8<<10 || !json.Valid(payload) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(payload, &object) == nil && object != nil
}
