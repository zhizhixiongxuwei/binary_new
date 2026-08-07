package imageextract

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxLogicalPathBytes = 4096
	maxTextBytes        = 2048
	maxIdentifierBytes  = 128
)

type Engine struct {
	extractors map[string]Extractor
	formats    []string
	limits     Limits
}

func NewEngine(registry *Registry, limits Limits) (*Engine, error) {
	if registry == nil {
		return nil, invalidRequest("registry is required")
	}
	extractors := registry.snapshot()
	formats := make([]string, 0, len(extractors))
	for format := range extractors {
		formats = append(formats, format)
	}
	slices.Sort(formats)
	return &Engine{
		extractors: extractors,
		formats:    formats,
		limits:     normalizedLimits(limits),
	}, nil
}

func (engine *Engine) Limits() Limits {
	if engine == nil {
		return Limits{}
	}
	return engine.limits
}

// Formats returns the immutable, sorted routing table captured when the
// Engine was constructed. Later Registry changes do not alter a live Engine.
func (engine *Engine) Formats() []string {
	if engine == nil {
		return []string{}
	}
	return append([]string(nil), engine.formats...)
}

// Extract routes a request by canonical format and returns every validated
// result retained before completion, cancellation, or a configured limit.
func (engine *Engine) Extract(
	ctx context.Context,
	request Request,
) (Result, error) {
	result := Result{Entries: []Entry{}, Partitions: []Partition{}}
	if engine == nil || engine.extractors == nil {
		return result, invalidRequest("engine is nil")
	}
	if ctx == nil {
		return result, invalidRequest("context is nil")
	}
	format, err := canonicalFormat(request.Format)
	if err != nil {
		return result, err
	}
	result.Format = format
	if request.Source == nil || request.SizeBytes < 0 || request.Depth < 0 {
		return result, invalidRequest("source, size, or depth is invalid")
	}
	if err := ctx.Err(); err != nil {
		result.Partial = true
		result.LimitCode = LimitContextCancelled
		result.ErrorCode = string(LimitContextCancelled)
		result.ErrorMessage = "image extraction was cancelled"
		return result, err
	}
	if request.SizeBytes > engine.limits.MaxInputBytes {
		setResultLimit(&result, LimitMaxInputBytes)
		return result, nil
	}
	if request.Depth >= engine.limits.MaxDepth {
		setResultLimit(&result, LimitMaxDepth)
		return result, nil
	}
	extractor, found := engine.extractors[format]
	if !found {
		return result, fmt.Errorf("%w: %s", ErrUnsupported, format)
	}

	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	collector := newCollector(
		operationCtx,
		cancel,
		format,
		request.SizeBytes,
		request.Depth,
		engine.limits,
	)
	request.Format = format
	readBudget := newByteBudget(engine.limits.MaxReadBytes, cancel)
	request.Source = &readOnlySource{
		ctx: operationCtx, source: request.Source, size: request.SizeBytes,
		budget: readBudget,
	}
	extractErr := invokeExtractor(extractor, operationCtx, request, collector)
	collector.close()
	result = collector.result()
	result.ReadBytes = readBudget.usedBytes()

	if collector.limit != nil {
		setResultLimit(&result, collector.limit.Code)
		return result, nil
	}
	if collector.terminalErr != nil {
		result.Partial = true
		result.ErrorCode = "invalid_extractor_result"
		result.ErrorMessage = boundedMessage(collector.terminalErr.Error())
		return result, collector.terminalErr
	}
	if readBudget.limitReached() {
		setResultLimit(&result, LimitMaxReadBytes)
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		result.Partial = true
		result.LimitCode = LimitContextCancelled
		result.ErrorCode = string(LimitContextCancelled)
		result.ErrorMessage = "image extraction was cancelled"
		return result, err
	}
	if extractErr == nil {
		return result, nil
	}
	var limit *LimitError
	if errors.As(extractErr, &limit) && knownLimitCode(limit.Code) {
		setResultLimit(&result, limit.Code)
		return result, nil
	}
	result.Partial = true
	switch {
	case errors.Is(extractErr, context.Canceled),
		errors.Is(extractErr, context.DeadlineExceeded):
		result.LimitCode = LimitContextCancelled
		result.ErrorCode = string(LimitContextCancelled)
	case errors.Is(extractErr, ErrCorruptImage):
		result.ErrorCode = "image_corrupt"
	case errors.Is(extractErr, ErrExtractorPanic):
		result.ErrorCode = "extractor_panic"
	case errors.Is(extractErr, ErrInvalidResult):
		result.ErrorCode = "invalid_extractor_result"
	default:
		result.ErrorCode = "extractor_failed"
	}
	result.ErrorMessage = boundedMessage(extractErr.Error())
	return result, extractErr
}

func invokeExtractor(
	extractor Extractor,
	ctx context.Context,
	request Request,
	sink Sink,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrExtractorPanic
		}
	}()
	return extractor.Extract(ctx, request, sink)
}

func setResultLimit(result *Result, code LimitCode) {
	result.Partial = true
	result.LimitCode = code
	result.ErrorCode = string(code)
	result.ErrorMessage = "image extraction stopped at the configured limit"
}

func normalizedLimits(limits Limits) Limits {
	limits.MaxInputBytes = boundedInt64(
		limits.MaxInputBytes,
		DefaultMaxInputBytes,
	)
	limits.MaxReadBytes = boundedInt64(
		limits.MaxReadBytes,
		DefaultMaxReadBytes,
	)
	limits.MaxExpandedBytes = boundedInt64(
		limits.MaxExpandedBytes,
		DefaultMaxExpandedBytes,
	)
	limits.MaxEntryBytes = boundedInt64(
		limits.MaxEntryBytes,
		DefaultMaxEntryBytes,
	)
	if limits.MaxEntryBytes > limits.MaxExpandedBytes {
		limits.MaxEntryBytes = limits.MaxExpandedBytes
	}
	limits.MaxEntries = boundedInt(limits.MaxEntries, DefaultMaxEntries)
	limits.MaxExtents = boundedInt(limits.MaxExtents, DefaultMaxExtents)
	limits.MaxPartitions = boundedInt(
		limits.MaxPartitions,
		DefaultMaxPartitions,
	)
	limits.MaxDepth = boundedInt(limits.MaxDepth, DefaultMaxDepth)
	return limits
}

func boundedInt64(value, maximum int64) int64 {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

func boundedInt(value, maximum int) int {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}

type collector struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	format           string
	sourceSize       int64
	requestDepth     int
	limits           Limits
	entries          []Entry
	partitions       []Partition
	entryPaths       map[string]struct{}
	partitionIDs     map[string]Partition
	partitionIndexes map[string]struct{}
	expandedBytes    int64
	extentCount      int
	limit            *LimitError
	terminalErr      error
	closed           bool
	partial          bool
}

func newCollector(
	ctx context.Context,
	cancel context.CancelFunc,
	format string,
	sourceSize int64,
	requestDepth int,
	limits Limits,
) *collector {
	return &collector{
		ctx: ctx, cancel: cancel, format: format, sourceSize: sourceSize,
		requestDepth: requestDepth, limits: limits,
		entries: []Entry{}, partitions: []Partition{},
		entryPaths:       make(map[string]struct{}),
		partitionIDs:     make(map[string]Partition),
		partitionIndexes: make(map[string]struct{}),
	}
}

func (collector *collector) AddEntry(entry Entry) error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if err := collector.ready(); err != nil {
		return err
	}
	if len(collector.entries) >= collector.limits.MaxEntries {
		return collector.stopAtLimit(LimitMaxEntries)
	}
	if entry.ID != uint64(len(collector.entries)+1) {
		return collector.stopInvalid("entry IDs must be contiguous")
	}
	if err := validateLogicalPath(entry.LogicalPath); err != nil {
		return collector.stopInvalid("entry logical path is invalid")
	}
	if _, duplicate := collector.entryPaths[entry.LogicalPath]; duplicate {
		return collector.stopInvalid("entry logical path is duplicated")
	}
	wantDepth := collector.requestDepth + 1
	if entry.ParentID == 0 {
		if path.Dir(entry.LogicalPath) != "/" {
			return collector.stopInvalid("entry root relation is invalid")
		}
	} else {
		if entry.ParentID >= entry.ID || entry.ParentID > uint64(len(collector.entries)) {
			return collector.stopInvalid("entry parent is unavailable")
		}
		parent := collector.entries[entry.ParentID-1]
		wantDepth = parent.Depth + 1
		if parent.Kind != EntryDirectory ||
			path.Dir(entry.LogicalPath) != parent.LogicalPath {
			return collector.stopInvalid("entry parent relation is invalid")
		}
	}
	if entry.Depth != wantDepth {
		return collector.stopInvalid("entry depth is invalid")
	}
	if entry.Depth > collector.limits.MaxDepth {
		return collector.stopAtLimit(LimitMaxDepth)
	}
	if !validEntryKind(entry.Kind) || entry.SizeBytes < 0 {
		return collector.stopInvalid("entry kind or size is invalid")
	}
	if !validLinkTarget(entry.Kind, entry.LinkTarget) {
		return collector.stopInvalid("entry link target is invalid")
	}
	if err := collector.validateExtents(entry); err != nil {
		return err
	}
	if entry.Status == "" {
		entry.Status = defaultEntryStatus(entry.Kind)
	}
	if !validPublishedStatus(entry.Status) ||
		!validStatusError(entry.Status, entry.ErrorCode, entry.ErrorMessage) {
		return collector.stopInvalid("entry status is invalid")
	}
	if entry.PartitionID != "" {
		partition, found := collector.partitionIDs[entry.PartitionID]
		if !found {
			return collector.stopInvalid("entry partition is unavailable")
		}
		for _, extent := range entry.Extents {
			if extent.OffsetBytes < partition.StartOffsetBytes ||
				extent.SizeBytes > partition.StartOffsetBytes+
					partition.SizeBytes-extent.OffsetBytes {
				return collector.stopInvalid(
					"file extent is outside its partition",
				)
			}
		}
	}
	if entry.Format != "" {
		canonical, err := canonicalFormat(entry.Format)
		if err != nil {
			return collector.stopInvalid("entry format is invalid")
		}
		entry.Format = canonical
	}

	if entry.Kind == EntryFile {
		if entry.SizeBytes > collector.limits.MaxEntryBytes {
			return collector.stopAtLimit(LimitMaxEntryBytes)
		}
		remaining := collector.limits.MaxExpandedBytes - collector.expandedBytes
		if entry.SizeBytes > remaining {
			return collector.stopAtLimit(LimitMaxExpandedBytes)
		}
		collector.expandedBytes += entry.SizeBytes
	}
	entry.Extents = append([]Extent(nil), entry.Extents...)
	collector.extentCount += len(entry.Extents)
	if entry.Status == StatusUnsupported || entry.Status == StatusCorrupt {
		collector.partial = true
	}
	collector.appendEntry(entry)
	return nil
}

func (collector *collector) validateExtents(entry Entry) error {
	if entry.Kind != EntryFile {
		if len(entry.Extents) != 0 {
			return collector.stopInvalid("non-file entry carries content extents")
		}
		return nil
	}
	if entry.SizeBytes == 0 {
		if len(entry.Extents) != 0 {
			return collector.stopInvalid("empty file carries content extents")
		}
		return nil
	}
	if len(entry.Extents) == 0 {
		return collector.stopInvalid("file content extents are missing")
	}
	if len(entry.Extents) > collector.limits.MaxExtents-collector.extentCount {
		return collector.stopAtLimit(LimitMaxExtents)
	}
	var total int64
	ordered := append([]Extent(nil), entry.Extents...)
	for _, extent := range ordered {
		if extent.OffsetBytes < 0 || extent.SizeBytes <= 0 ||
			extent.OffsetBytes > collector.sourceSize ||
			extent.SizeBytes > collector.sourceSize-extent.OffsetBytes {
			return collector.stopInvalid("file extent is outside the source")
		}
		if extent.SizeBytes > entry.SizeBytes-total {
			return collector.stopInvalid("file extent sizes do not match entry size")
		}
		total += extent.SizeBytes
	}
	if total != entry.SizeBytes {
		return collector.stopInvalid("file extent sizes do not match entry size")
	}
	slices.SortFunc(ordered, func(left, right Extent) int {
		switch {
		case left.OffsetBytes < right.OffsetBytes:
			return -1
		case left.OffsetBytes > right.OffsetBytes:
			return 1
		default:
			return 0
		}
	})
	for index := 1; index < len(ordered); index++ {
		previous := ordered[index-1]
		if ordered[index].OffsetBytes < previous.OffsetBytes+previous.SizeBytes {
			return collector.stopInvalid("file extents overlap")
		}
	}
	return nil
}

func (collector *collector) AddPartition(partition Partition) error {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if err := collector.ready(); err != nil {
		return err
	}
	if len(collector.partitions) >= collector.limits.MaxPartitions {
		return collector.stopAtLimit(LimitMaxPartitions)
	}
	if !validIdentifier(partition.ID, 64) {
		return collector.stopInvalid("partition ID is invalid")
	}
	if _, duplicate := collector.partitionIDs[partition.ID]; duplicate {
		return collector.stopInvalid("partition ID is duplicated")
	}
	if partition.Index == 0 || partition.StartOffsetBytes < 0 ||
		partition.SizeBytes <= 0 ||
		partition.StartOffsetBytes > collector.sourceSize ||
		partition.SizeBytes > collector.sourceSize-partition.StartOffsetBytes {
		return collector.stopInvalid("partition range is outside the source")
	}
	if partition.ParentID != "" {
		parent, found := collector.partitionIDs[partition.ParentID]
		if !found ||
			partition.StartOffsetBytes < parent.StartOffsetBytes ||
			partition.SizeBytes >
				parent.StartOffsetBytes+parent.SizeBytes-partition.StartOffsetBytes {
			return collector.stopInvalid("partition parent relation is invalid")
		}
	}
	indexKey := fmt.Sprintf("%s:%d", partition.ParentID, partition.Index)
	if _, duplicate := collector.partitionIndexes[indexKey]; duplicate {
		return collector.stopInvalid("partition index is duplicated")
	}
	for _, existing := range collector.partitions {
		if existing.ParentID == partition.ParentID &&
			partition.StartOffsetBytes <
				existing.StartOffsetBytes+existing.SizeBytes &&
			existing.StartOffsetBytes <
				partition.StartOffsetBytes+partition.SizeBytes {
			return collector.stopInvalid("sibling partition ranges overlap")
		}
	}
	if partition.Status == "" {
		partition.Status = StatusIndexed
	}
	if !validPublishedStatus(partition.Status) ||
		!validStatusError(
			partition.Status,
			partition.ErrorCode,
			partition.ErrorMessage,
		) ||
		!validOptionalText(partition.Scheme, maxIdentifierBytes) ||
		!validOptionalText(partition.Type, maxIdentifierBytes) ||
		!validOptionalText(partition.Filesystem, maxIdentifierBytes) {
		return collector.stopInvalid("partition metadata is invalid")
	}
	collector.partitions = append(collector.partitions, partition)
	if partition.Status == StatusUnsupported || partition.Status == StatusCorrupt {
		collector.partial = true
	}
	collector.partitionIDs[partition.ID] = partition
	collector.partitionIndexes[indexKey] = struct{}{}
	return nil
}

func (collector *collector) ready() error {
	if collector.closed {
		return invalidResult("sink is closed")
	}
	if collector.terminalErr != nil {
		return collector.terminalErr
	}
	if collector.limit != nil {
		return collector.limit
	}
	if err := collector.ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (collector *collector) close() {
	collector.mu.Lock()
	collector.closed = true
	collector.cancel()
	collector.mu.Unlock()
}

func (collector *collector) appendEntry(entry Entry) {
	collector.entries = append(collector.entries, entry)
	collector.entryPaths[entry.LogicalPath] = struct{}{}
}

func (collector *collector) stopAtLimit(code LimitCode) error {
	if collector.limit == nil {
		collector.limit = &LimitError{Code: code}
		collector.cancel()
	}
	return collector.limit
}

func (collector *collector) stopInvalid(message string) error {
	if collector.terminalErr == nil {
		collector.terminalErr = invalidResult(message)
		collector.cancel()
	}
	return collector.terminalErr
}

func (collector *collector) result() Result {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	entries := make([]Entry, len(collector.entries))
	copy(entries, collector.entries)
	for index := range entries {
		entries[index].Extents = append(
			[]Extent(nil), collector.entries[index].Extents...,
		)
	}
	return Result{
		Format: collector.format, Entries: entries,
		Partitions:    append([]Partition(nil), collector.partitions...),
		ExpandedBytes: collector.expandedBytes,
		ExtentCount:   collector.extentCount,
		Partial:       collector.partial,
	}
}

func validateLogicalPath(value string) error {
	if len(value) < 2 || len(value) > maxLogicalPathBytes ||
		!utf8.ValidString(value) || !norm.NFC.IsNormalString(value) ||
		value[0] != '/' ||
		strings.Contains(value, "\\") || path.Clean(value) != value {
		return ErrInvalidResult
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return ErrInvalidResult
		}
	}
	for _, part := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return ErrInvalidResult
		}
	}
	return nil
}

func validEntryKind(value EntryKind) bool {
	switch value {
	case EntryFile, EntryDirectory, EntrySymlink, EntryHardlink, EntrySpecial:
		return true
	default:
		return false
	}
}

func validLinkTarget(kind EntryKind, target string) bool {
	if kind != EntrySymlink && kind != EntryHardlink {
		return target == ""
	}
	return target != "" && validOptionalText(target, maxLogicalPathBytes)
}

func defaultEntryStatus(kind EntryKind) Status {
	if kind == EntryFile || kind == EntryDirectory {
		return StatusIndexed
	}
	return StatusRecorded
}

func validPublishedStatus(value Status) bool {
	switch value {
	case StatusIndexed, StatusRecorded, StatusUnsupported, StatusCorrupt:
		return true
	default:
		return false
	}
}

func validStatusError(status Status, code, message string) bool {
	hasError := code != "" || message != ""
	needsError := status == StatusUnsupported || status == StatusCorrupt
	return hasError == needsError &&
		(!hasError || validIdentifier(code, maxIdentifierBytes)) &&
		validOptionalText(message, maxTextBytes)
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func validOptionalText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character == 0 || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func boundedMessage(value string) string {
	value = strings.ToValidUTF8(value, "")
	var builder strings.Builder
	builder.Grow(min(len(value), maxTextBytes))
	for _, character := range value {
		if unicode.IsControl(character) {
			character = ' '
		}
		width := utf8.RuneLen(character)
		if builder.Len()+width > maxTextBytes {
			break
		}
		builder.WriteRune(character)
	}
	return builder.String()
}

func knownLimitCode(code LimitCode) bool {
	switch code {
	case LimitMaxInputBytes, LimitMaxReadBytes, LimitMaxExpandedBytes,
		LimitMaxEntryBytes, LimitMaxEntries, LimitMaxExtents,
		LimitMaxPartitions, LimitMaxDepth,
		LimitContextCancelled:
		return true
	default:
		return false
	}
}

type readOnlySource struct {
	ctx    context.Context
	source io.ReaderAt
	size   int64
	budget *byteBudget
}

func (source *readOnlySource) ReadAt(buffer []byte, offset int64) (int, error) {
	if err := source.ctx.Err(); err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, invalidRequest("source offset is negative")
	}
	if len(buffer) == 0 {
		return 0, nil
	}
	if offset >= source.size {
		return 0, io.EOF
	}
	available := source.size - offset
	requested := int64(len(buffer))
	truncated := requested > available
	if truncated {
		buffer = buffer[:int(available)]
	}
	if source.budget != nil && !source.budget.consume(int64(len(buffer))) {
		return 0, &LimitError{Code: LimitMaxReadBytes}
	}
	count, err := source.source.ReadAt(buffer, offset)
	if count < 0 || count > len(buffer) {
		return 0, invalidRequest("source reader returned an invalid count")
	}
	if contextErr := source.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	if truncated && err == nil && count == len(buffer) {
		err = io.EOF
	}
	if count != len(buffer) && err == nil {
		err = io.ErrUnexpectedEOF
	}
	return count, err
}

type byteBudget struct {
	mu       sync.Mutex
	maximum  int64
	used     int64
	exceeded bool
	cancel   context.CancelFunc
}

func newByteBudget(maximum int64, cancel context.CancelFunc) *byteBudget {
	return &byteBudget{maximum: maximum, cancel: cancel}
}

func (budget *byteBudget) consume(amount int64) bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if amount < 0 || amount > budget.maximum-budget.used {
		budget.exceeded = true
		budget.cancel()
		return false
	}
	budget.used += amount
	return true
}

func (budget *byteBudget) usedBytes() int64 {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.used
}

func (budget *byteBudget) limitReached() bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	return budget.exceeded
}
