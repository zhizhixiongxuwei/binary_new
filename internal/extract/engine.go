// Package extract provides bounded, recursive, content-addressed archive
// extraction. Archive paths are logical identifiers only and are never used as
// filesystem destinations.
package extract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"runtime"

	"binaryscan/internal/filetype"
	"binaryscan/internal/imageextract"
	"binaryscan/internal/imageformats"
)

const (
	defaultMaxExpandedBytes = int64(50 << 30)
	defaultMaxEntryBytes    = int64(10 << 30)
	defaultMaxNodes         = 100_000
	defaultMaxDepth         = 10
	defaultMaxRatio         = int64(100)

	// This is an active, per-Extract ceiling rather than a per archive or
	// per recursion-level allowance. With four workers, the configured
	// decoder/parser memory therefore remains bounded to 1.5 GiB in total.
	// RAR reserves 320 MiB before decoding because legacy PPM can retain a
	// 256 MiB model independently from its decode window and filter buffers.
	maxTaskParserDecoderMemoryBytes = int64(384 << 20)
)

// Detector is the content detector required by Engine.
type Detector interface {
	Detect(io.ReaderAt, int64) (filetype.Result, error)
}

type contextDetector interface {
	DetectContext(context.Context, io.ReaderAt, int64) (filetype.Result, error)
}

func detectContent(
	ctx context.Context,
	detector Detector,
	source io.ReaderAt,
	size int64,
) (filetype.Result, error) {
	if contextual, ok := detector.(contextDetector); ok {
		return contextual.DetectContext(ctx, source, size)
	}
	return detector.Detect(source, size)
}

// Engine performs one bounded recursive extraction operation at a time.
type Engine struct {
	detector                 Detector
	imageEngine              *imageextract.Engine
	trustedSevenZip          *trustedSevenZipAdapter
	externalArchive          ExternalArchiveAdapter
	limits                   Limits
	parserDecoderMemoryLimit int64
}

// NewEngine constructs an extraction engine. Non-positive fields use project
// defaults; values above the project security ceilings are clamped.
func NewEngine(detector Detector, limits Limits) *Engine {
	return newEngine(detector, limits)
}

// NewEngineWithTrustedSevenZip opts into a trusted external 7zz helper for 7Z
// and CAB expansion. This adapter validates the helper's output after it runs;
// it is not an OS sandbox. NewEngine never discovers or enables a helper.
func NewEngineWithTrustedSevenZip(
	detector Detector,
	limits Limits,
	config TrustedSevenZipConfig,
) (*Engine, error) {
	adapter, err := newTrustedSevenZipAdapter(config)
	if err != nil {
		return nil, err
	}
	engine := newEngine(detector, limits)
	engine.trustedSevenZip = adapter
	return engine, nil
}

func newEngine(detector Detector, limits Limits) *Engine {
	if limits.MaxExpandedBytes <= 0 ||
		limits.MaxExpandedBytes > defaultMaxExpandedBytes {
		limits.MaxExpandedBytes = defaultMaxExpandedBytes
	}
	if limits.MaxEntryBytes <= 0 ||
		limits.MaxEntryBytes > defaultMaxEntryBytes {
		limits.MaxEntryBytes = defaultMaxEntryBytes
	}
	if limits.MaxEntryBytes > limits.MaxExpandedBytes {
		limits.MaxEntryBytes = limits.MaxExpandedBytes
	}
	if limits.MaxNodes <= 0 || limits.MaxNodes > defaultMaxNodes {
		limits.MaxNodes = defaultMaxNodes
	}
	if limits.MaxDepth <= 0 || limits.MaxDepth > defaultMaxDepth {
		limits.MaxDepth = defaultMaxDepth
	}
	if limits.MaxRatio <= 0 || limits.MaxRatio > defaultMaxRatio {
		limits.MaxRatio = defaultMaxRatio
	}
	imageLimits := imageextract.Limits{
		MaxInputBytes:    imageextract.DefaultMaxInputBytes,
		MaxExpandedBytes: limits.MaxExpandedBytes,
		MaxEntryBytes:    limits.MaxEntryBytes,
		MaxEntries:       limits.MaxNodes,
		MaxExtents:       imageextract.DefaultMaxExtents,
		MaxPartitions:    imageextract.DefaultMaxPartitions,
		MaxDepth:         limits.MaxDepth,
	}
	imageRegistry := imageextract.NewRegistry()
	var imageEngine *imageextract.Engine
	if err := imageformats.RegisterBuiltins(imageRegistry, imageLimits); err == nil {
		imageEngine, _ = imageextract.NewEngine(imageRegistry, imageLimits)
	}
	return &Engine{
		detector:                 detector,
		imageEngine:              imageEngine,
		limits:                   limits,
		parserDecoderMemoryLimit: maxTaskParserDecoderMemoryBytes,
	}
}

// WithLimits returns an independent engine with the requested non-zero limit
// overrides while preserving the detector and explicitly configured external
// archive adapters. It lets durable jobs execute their persisted limit
// snapshot rather than silently adopting newer process configuration.
func (engine *Engine) WithLimits(overrides Limits) *Engine {
	if engine == nil {
		return nil
	}
	limits := engine.limits
	if overrides.MaxExpandedBytes > 0 {
		limits.MaxExpandedBytes = overrides.MaxExpandedBytes
	}
	if overrides.MaxEntryBytes > 0 {
		limits.MaxEntryBytes = overrides.MaxEntryBytes
	}
	if overrides.MaxNodes > 0 {
		limits.MaxNodes = overrides.MaxNodes
	}
	if overrides.MaxDepth > 0 {
		limits.MaxDepth = overrides.MaxDepth
	}
	if overrides.MaxRatio > 0 {
		limits.MaxRatio = overrides.MaxRatio
	}
	clone := newEngine(engine.detector, limits)
	clone.trustedSevenZip = engine.trustedSevenZip
	clone.externalArchive = engine.externalArchive
	return clone
}

// Supports reports whether Engine can expand the supplied detector format.
func (engine *Engine) Supports(format string) bool {
	switch format {
	case "7z", "cab":
		return engine != nil &&
			(engine.externalArchive != nil || engine.trustedSevenZip != nil)
	case "zip", "jar", "war", "ear", "apk",
		"tar", "docker-tar", "oci-tar",
		"gzip", "bzip2", "xz", "zstd", "lzma",
		"ar", "deb", "rpm", "cpio", "rar",
		"raw-img", "mbr-img", "gpt-img", "iso9660":
		return true
	default:
		return false
	}
}

// SupportsLogicalPackageRoot reports the exact v1 archive-import allowlist.
// Executable ZIP derivatives and container TARs are intentionally excluded:
// they are task inputs, not outer archive packages.
func (engine *Engine) SupportsLogicalPackageRoot(format string) bool {
	switch format {
	case "zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd",
		"cab", "cpio", "ar", "deb", "rpm":
		return engine.Supports(format)
	default:
		return false
	}
}

// Extract expands source beneath the caller-owned root. Result.Nodes never
// contains the root itself; first-level entries use ParentLocalID zero.
func (engine *Engine) Extract(
	ctx context.Context,
	source *os.File,
	rootFormat string,
	workDir string,
) (Result, error) {
	return engine.extract(ctx, source, rootFormat, workDir, false)
}

// ExtractLogicalPackage expands an outer upload archive while only traversing
// format-inherent wrappers (for example gzip -> tar and DEB/RPM payloads).
// Ordinary member archives are detected and retained but never recursively
// expanded. Every regular member has a matching Result.MaterializedFiles item.
func (engine *Engine) ExtractLogicalPackage(
	ctx context.Context,
	source *os.File,
	rootFormat string,
	workDir string,
) (Result, error) {
	if engine == nil || !engine.SupportsLogicalPackageRoot(rootFormat) {
		return Result{}, fmt.Errorf(
			"extract: unsupported logical-package root format %q",
			rootFormat,
		)
	}
	return engine.extract(ctx, source, rootFormat, workDir, true)
}

// ExtractLogicalPackageInDirectory is the descriptor-bound variant used when
// a shared-UID process could rename or replace the workspace pathname. All
// extractor-created files resolve through the already-open directory handle.
func (engine *Engine) ExtractLogicalPackageInDirectory(
	ctx context.Context,
	source *os.File,
	rootFormat string,
	directory *os.File,
) (Result, error) {
	if directory == nil {
		return Result{}, errors.New("extract: nil work directory descriptor")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return Result{}, errors.New("extract: invalid work directory descriptor")
	}
	var workDir string
	switch runtime.GOOS {
	case "linux":
		workDir = fmt.Sprintf("/proc/self/fd/%d", directory.Fd())
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		workDir = fmt.Sprintf("/dev/fd/%d", directory.Fd())
	default:
		return Result{}, errors.New("extract: descriptor-bound work directories are unsupported")
	}
	opened, err := os.Stat(workDir)
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		return Result{}, errors.New("extract: work directory descriptor identity changed")
	}
	return engine.extractAt(ctx, source, rootFormat, workDir, true, false)
}

func (engine *Engine) extract(
	ctx context.Context,
	source *os.File,
	rootFormat string,
	workDir string,
	logicalPackage bool,
) (Result, error) {
	return engine.extractAt(ctx, source, rootFormat, workDir, logicalPackage, true)
}

func (engine *Engine) extractAt(
	ctx context.Context,
	source *os.File,
	rootFormat string,
	workDir string,
	logicalPackage bool,
	validateWorkPath bool,
) (Result, error) {
	if engine == nil || engine.detector == nil {
		return Result{}, errors.New("extract: nil engine or detector")
	}
	if ctx == nil {
		return Result{}, errors.New("extract: nil context")
	}
	if source == nil {
		return Result{}, errors.New("extract: nil source")
	}
	if !engine.Supports(rootFormat) {
		return Result{}, fmt.Errorf("extract: unsupported root format %q", rootFormat)
	}
	info, err := source.Stat()
	if err != nil {
		return Result{}, fmt.Errorf("extract: stat source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, errors.New("extract: source is not a regular file")
	}
	if validateWorkPath {
		if err := ensureWorkDirectory(workDir); err != nil {
			return Result{}, err
		}
	}
	state := operationState{
		engine:         engine,
		ctx:            ctx,
		workDir:        workDir,
		rootSize:       info.Size(),
		nextID:         1,
		paths:          make(map[string]struct{}),
		nodeIndex:      make(map[int]int),
		directories:    make(map[string]int),
		reservedPaths:  make(map[string]struct{}),
		archiveNames:   make(map[string]string),
		logicalPackage: logicalPackage,
		rootFormat:     rootFormat,
		memory: parserDecoderMemory{
			limit: engine.parserDecoderMemoryLimit,
		},
	}
	container := containerBudget{sourceSize: info.Size()}
	err = state.extractContainer(
		source, info.Size(), rootFormat, 0, "", 0, &container,
	)
	if err != nil {
		var limit *limitError
		if errors.As(err, &limit) {
			state.markLimit(limit.code)
		} else if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			state.markLimit(LimitContextCancelled)
			return state.result(), err
		} else {
			return state.result(), err
		}
	}
	return state.result(), nil
}

type operationState struct {
	engine            *Engine
	ctx               context.Context
	workDir           string
	rootSize          int64
	nextID            int
	nodes             []Node
	containerImages   []ContainerImage
	paths             map[string]struct{}
	nodeIndex         map[int]int
	directories       map[string]int
	reservedPaths     map[string]struct{}
	archiveNames      map[string]string
	logicalPackage    bool
	rootFormat        string
	materializedFiles []MaterializedFile
	expandedBytes     int64
	partial           bool
	limitCode         string
	stopped           bool
	memory            parserDecoderMemory

	// Shared by every CPIO reached during one recursive extraction. Keeping
	// this on the operation prevents sibling or nested archives from each
	// receiving a fresh retained-symlink-metadata allowance.
	retainedCPIOSymlinkMetadataBytes int64
}

type parserDecoderMemory struct {
	limit int64
	used  int64
	peak  int64
}

func (memory *parserDecoderMemory) acquire(
	requested int64,
	limitCode string,
) (func(), *limitError) {
	if requested < 0 ||
		requested > memory.limit ||
		memory.used > memory.limit-requested {
		return nil, &limitError{code: limitCode}
	}
	memory.used += requested
	if memory.used > memory.peak {
		memory.peak = memory.used
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		memory.used -= requested
		if memory.used < 0 {
			panic("extract: parser/decoder memory budget released twice")
		}
	}, nil
}

type containerBudget struct {
	sourceSize int64
	expanded   int64
	scanDepth  int
}

type limitError struct {
	code   string
	global bool
}

func (err *limitError) Error() string {
	return "extract: limit reached: " + err.code
}

func (state *operationState) result() Result {
	for index := range state.nodes {
		state.nodes[index].ErrorMessage = boundedText(
			state.nodes[index].ErrorMessage, 2048,
		)
	}
	return Result{
		Nodes:                   state.nodes,
		ContainerImages:         state.containerImages,
		MaterializedFiles:       state.materializedFiles,
		ExpandedBytes:           state.expandedBytes,
		Partial:                 state.partial,
		LimitCode:               state.limitCode,
		parserDecoderMemoryPeak: state.memory.peak,
		parserDecoderMemoryUsed: state.memory.used,
	}
}

func (state *operationState) markLimit(code string) {
	state.partial = true
	if state.limitCode == "" {
		state.limitCode = code
	}
}

func (state *operationState) appendNode(node Node) (int, error) {
	if len(state.nodes) >= state.engine.limits.MaxNodes {
		state.stopped = true
		state.markLimit(LimitMaxNodes)
		return -1, &limitError{code: LimitMaxNodes, global: true}
	}
	if _, duplicate := state.paths[node.LogicalPath]; duplicate {
		original := node.LogicalPath
		location, err := state.uniqueQuarantineLocation(
			node.ParentLocalID,
			"duplicate",
		)
		if err != nil {
			return -1, err
		}
		node.LogicalPath = location.logical
		node.ParentLocalID = location.parentID
		node.Depth = location.depth
		state.reserveLogicalPath(node.LogicalPath)
		node.MetadataJSON, err = addMetadataField(
			node.MetadataJSON,
			"duplicate_logical_path",
			original,
		)
		if err != nil {
			return -1, fmt.Errorf(
				"extract: merge duplicate path metadata: %w",
				err,
			)
		}
		if node.ErrorCode == "" {
			node.ExtractionStatus = StatusInvalidPath
			node.ErrorCode = "duplicate_logical_path"
			node.ErrorMessage = "duplicate archive entry path was safely remapped"
		}
		state.partial = true
	}
	node.DisplayName = path.Base(node.LogicalPath)
	node.LocalID = state.nextID
	state.nextID++
	node.ErrorMessage = boundedText(node.ErrorMessage, 2048)
	if node.MetadataJSON == nil {
		node.MetadataJSON = json.RawMessage("{}")
	}
	state.nodes = append(state.nodes, node)
	state.paths[node.LogicalPath] = struct{}{}
	if node.ArchiveNameID != "" {
		if state.archiveNames == nil {
			state.archiveNames = make(map[string]string)
		}
		state.archiveNames[node.LogicalPath] = node.ArchiveNameID
	}
	state.nodeIndex[node.LocalID] = len(state.nodes) - 1
	if node.NodeType == NodeTypeDirectory {
		state.directories[node.LogicalPath] = node.LocalID
	}
	return len(state.nodes) - 1, nil
}

func addMetadataField(
	raw json.RawMessage,
	key string,
	value any,
) (json.RawMessage, error) {
	metadata := make(map[string]json.RawMessage)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, err
		}
	}
	encodedValue, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	metadata[key] = encodedValue
	return json.Marshal(metadata)
}

func (state *operationState) nodeByLocalID(localID int) *Node {
	index, found := state.nodeIndex[localID]
	if !found || index < 0 || index >= len(state.nodes) {
		return nil
	}
	return &state.nodes[index]
}

func (state *operationState) reserve(
	requested int64,
	container *containerBudget,
) (int64, *limitError) {
	if requested <= 0 {
		return 0, nil
	}
	allowed := requested
	code := ""
	global := false
	apply := func(remaining int64, candidate string, isGlobal bool) {
		if remaining < 0 {
			remaining = 0
		}
		if remaining < allowed {
			allowed = remaining
			code = candidate
			global = isGlobal
		}
	}
	apply(state.engine.limits.MaxExpandedBytes-state.expandedBytes,
		LimitMaxExpandedBytes, true)
	apply(ratioCapacity(state.rootSize, state.engine.limits.MaxRatio)-state.expandedBytes,
		LimitMaxRatio, true)
	apply(ratioCapacity(container.sourceSize, state.engine.limits.MaxRatio)-container.expanded,
		LimitMaxRatio, false)
	state.expandedBytes += allowed
	container.expanded += allowed
	if allowed < requested {
		state.markLimit(code)
		if global {
			state.stopped = true
		}
		return allowed, &limitError{code: code, global: global}
	}
	return allowed, nil
}

func ratioCapacity(size, ratio int64) int64 {
	if size <= 0 {
		return 0
	}
	if ratio <= 0 || size > math.MaxInt64/ratio {
		return math.MaxInt64
	}
	return size * ratio
}

func (state *operationState) reservationCapacity(
	container *containerBudget,
) int64 {
	capacity := state.engine.limits.MaxExpandedBytes - state.expandedBytes
	rootRatioRemaining := ratioCapacity(
		state.rootSize,
		state.engine.limits.MaxRatio,
	) - state.expandedBytes
	if rootRatioRemaining < capacity {
		capacity = rootRatioRemaining
	}
	containerRatioRemaining := ratioCapacity(
		container.sourceSize,
		state.engine.limits.MaxRatio,
	) - container.expanded
	if containerRatioRemaining < capacity {
		capacity = containerRatioRemaining
	}
	if capacity < 0 {
		return 0
	}
	return capacity
}

func metadataJSON(value map[string]any) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage("{}")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

func (state *operationState) extractContainer(
	source *os.File,
	sourceSize int64,
	format string,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	if err := state.ctx.Err(); err != nil {
		return err
	}
	switch format {
	case "zip", "jar", "war", "ear", "apk":
		return state.extractZIP(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "tar", "docker-tar", "oci-tar":
		return state.extractTAR(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "gzip":
		return state.extractGZIP(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "bzip2":
		return state.extractBZIP2(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "xz":
		return state.extractXZ(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "zstd":
		return state.extractZSTD(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "lzma":
		return state.extractLZMA(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "ar":
		return state.extractAR(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "deb":
		return state.extractDEB(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "rpm":
		return state.extractRPM(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "cpio":
		return state.extractCPIO(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "rar":
		return state.extractRAR(source, sourceSize, parentID, prefix, parentDepth, budget)
	case "7z", "cab":
		if state.engine.externalArchive != nil {
			return state.extractWithArchiveSandbox(
				source, sourceSize, format, parentID, prefix, parentDepth, budget,
			)
		}
		if state.engine.trustedSevenZip == nil {
			return fmt.Errorf("extract: trusted 7zz helper is not configured for %q", format)
		}
		return state.extractWithTrustedSevenZip(
			source, sourceSize, format, parentID, prefix, parentDepth, budget,
		)
	case "raw-img", "mbr-img", "gpt-img", "iso9660":
		return state.extractImage(
			source, sourceSize, format, parentID, prefix, parentDepth, budget,
		)
	default:
		return fmt.Errorf("extract: unsupported format %q", format)
	}
}
