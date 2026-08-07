package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	JVMFallbackEngineName               = "go-jvm-bytecode"
	DefaultJVMTargetJavaRelease         = 21
	DefaultJVMMaxArchiveEntries         = 20_000
	DefaultJVMMaxExpandedBytes    int64 = 50 << 30
	DefaultJVMMaxClassBytes       int64 = 64 << 20
	DefaultJVMMaxCompressionRatio       = 100
	DefaultJVMMaxArchiveDepth           = 10

	maximumJVMTargetJavaRelease       = 99
	maximumJVMClassBytes        int64 = 256 << 20
	jvmIndexMediaType                 = "application/vnd.binaryscan.jvm-bytecode-index+json"
)

var (
	ErrNoJVMClasses  = errors.New("bytecode: no JVM classes")
	errJVMIndexLimit = errors.New("JVM bytecode index exceeds its byte limit")
)

// JVMEngineConfig is immutable after NewJVMFallbackEngine returns. The target
// release is encoded into Descriptor.Version, and therefore into CacheKey.
type JVMEngineConfig struct {
	TargetJavaRelease   int
	MaxArchiveEntries   int
	MaxExpandedBytes    int64
	MaxClassBytes       int64
	MaxCompressionRatio int
	MaxArchiveDepth     int
}

// JVMFallbackEngine provides a pure-Go bytecode-only fallback. It deliberately
// has a distinct descriptor from source decompilers such as Vineflower.
type JVMFallbackEngine struct {
	config      JVMEngineConfig
	descriptor  Descriptor
	fingerprint string
}

func NewJVMFallbackEngine(config JVMEngineConfig) (*JVMFallbackEngine, error) {
	normalized, err := normalizeJVMEngineConfig(config)
	if err != nil {
		return nil, err
	}
	fingerprint := jvmConfigFingerprint(normalized)
	return &JVMFallbackEngine{
		config: normalized,
		descriptor: Descriptor{
			Name: JVMFallbackEngineName,
			Version: "1.1.0-java" + strconv.Itoa(normalized.TargetJavaRelease) +
				"-cfg" + fingerprint,
		},
		fingerprint: fingerprint,
	}, nil
}

func (engine *JVMFallbackEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *JVMFallbackEngine) Config() JVMEngineConfig {
	if engine == nil {
		return JVMEngineConfig{}
	}
	return engine.config
}

// ConfigFingerprint is a stable SHA-256 identity for every normalized engine
// parameter. Descriptor.Version embeds the same value so Execute's CacheKey
// cannot alias runs made with different fallback limits or target releases.
func (engine *JVMFallbackEngine) ConfigFingerprint() string {
	if engine == nil {
		return ""
	}
	return engine.fingerprint
}

func (engine *JVMFallbackEngine) Supports(format Format) bool {
	if engine == nil {
		return false
	}
	switch format {
	case FormatClass, FormatJAR, FormatWAR, FormatEAR:
		return true
	default:
		return false
	}
}

func (engine *JVMFallbackEngine) Decompile(
	ctx context.Context,
	request Request,
) (Output, error) {
	if engine == nil {
		return Output{}, fmt.Errorf("%w: JVM fallback engine is nil", ErrInvalidConfiguration)
	}
	if ctx == nil {
		return Output{}, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	verified, err := request.Input.VerifiedReader()
	if err != nil {
		return Output{}, fmt.Errorf("%w: verified JVM input is unavailable", ErrInvalidRequest)
	}
	candidateSet, singlePayload, err := engine.candidates(ctx, request, verified)
	if err != nil {
		return Output{}, err
	}
	if candidateSet.cleanup != nil {
		defer candidateSet.cleanup()
	}
	if len(candidateSet.candidates) == 0 && len(candidateSet.failures) == 0 {
		return Output{}, ErrNoJVMClasses
	}
	if request.Limits.MaxClasses > 0 &&
		len(candidateSet.candidates)+len(candidateSet.failures) > request.Limits.MaxClasses {
		return Output{}, fmt.Errorf("%w: selected class count limit", ErrJVMArchiveLimit)
	}
	output := Output{
		Classes: []ClassIndex{}, Artifacts: []Artifact{},
		ClassErrors: []ClassError{}, Warnings: []string{},
	}
	for _, failure := range candidateSet.failures {
		engine.appendArchiveFailure(&output, request, failure)
		if limitErr := checkJVMErrorLimit(output, request); limitErr != nil {
			return Output{}, limitErr
		}
	}
	var indexWriter *jvmArtifactWriter
	abortWriter := func() {
		if indexWriter != nil {
			indexWriter.abort()
		}
	}
	methodCount := 0
	for index, candidate := range candidateSet.candidates {
		if err := ctx.Err(); err != nil {
			abortWriter()
			return Output{}, err
		}
		payload := singlePayload
		readCode := "invalid_class"
		if candidate.readFailureCode != "" {
			err = errJVMZIPEntryRead
			readCode = candidate.readFailureCode
		} else if candidate.file != nil {
			payload, err = readJVMZIPEntry(
				ctx, candidate.file, uint64(engine.config.MaxClassBytes),
			)
			readCode = "class_read_failed"
		} else if candidate.spool != nil {
			payload, err = readJVMSpoolClass(ctx, candidate, engine.config.MaxClassBytes)
			readCode = "class_read_failed"
		}
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				abortWriter()
				return Output{}, contextErr
			}
			reason := candidate.readFailureReason
			if reason == "" {
				reason = "class bytes could not be read"
			}
			engine.appendClassFailure(&output, request, candidate, readCode, reason)
			if limitErr := checkJVMErrorLimit(output, request); limitErr != nil {
				abortWriter()
				return Output{}, limitErr
			}
			continue
		}
		parsed, parseErr := parseJVMClass(payload)
		if parseErr != nil {
			engine.appendClassFailure(&output, request, candidate, "invalid_class",
				parseErr.Error())
			if limitErr := checkJVMErrorLimit(output, request); limitErr != nil {
				abortWriter()
				return Output{}, limitErr
			}
			continue
		}
		if request.Limits.MaxMethods > 0 &&
			len(parsed.Methods) > request.Limits.MaxMethods-methodCount {
			abortWriter()
			return Output{}, fmt.Errorf("%w: JVM method count limit", ErrJVMArchiveLimit)
		}
		methodCount += len(parsed.Methods)
		classIndex, record := buildJVMClassIndex(request, candidate, parsed)
		maximumArtifacts := request.Limits.MaxArtifacts
		if maximumArtifacts == 0 {
			maximumArtifacts = DefaultMaxArtifacts
		}
		if len(output.Artifacts) >= maximumArtifacts {
			abortWriter()
			return Output{}, fmt.Errorf("%w: JVM artifact count limit", ErrJVMArchiveLimit)
		}
		if indexWriter == nil {
			maximum := request.Limits.MaxArtifactBytes
			if maximum == 0 {
				maximum = DefaultMaxArtifactBytes
			}
			indexWriter, err = newJVMArtifactWriter(
				request.Workspace, maximum, engine.config.TargetJavaRelease,
			)
			if err != nil {
				return Output{}, err
			}
		}
		artifact, artifactErr := indexWriter.add(ctx, record)
		if artifactErr != nil {
			abortWriter()
			return Output{}, artifactErr
		}
		classIndex.ArtifactIDs = []string{artifact.ID}
		artifact.ClassKeys = []string{classIndex.Key}
		output.Classes = append(output.Classes, classIndex)
		output.Artifacts = append(output.Artifacts, artifact)
		if request.Input.Format == FormatClass &&
			index+1 != len(candidateSet.candidates) {
			abortWriter()
			return Output{}, errors.New("bytecode: invalid single-class candidate set")
		}
	}
	if err := ctx.Err(); err != nil {
		abortWriter()
		return Output{}, err
	}
	if len(output.ClassErrors) > 0 {
		output.Status = StatusPartial
	} else {
		output.Status = StatusBytecodeOnly
	}
	return output, nil
}

func (engine *JVMFallbackEngine) candidates(
	ctx context.Context,
	request Request,
	verified io.ReaderAt,
) (jvmArchiveCandidateSet, []byte, error) {
	switch request.Input.Format {
	case FormatClass:
		payload, err := readJVMVerifiedClass(
			ctx, verified, request.Input.SizeBytes, engine.config.MaxClassBytes,
		)
		if err != nil {
			return jvmArchiveCandidateSet{}, nil, err
		}
		return jvmArchiveCandidateSet{candidates: []jvmArchiveCandidate{{
			entryPath: "input.class", logicalPath: "input.class",
			identityPath: encodeJVMArchiveIdentity("input.class"),
		}}}, payload, nil
	case FormatJAR:
		candidates, err := enumerateJVMArchive(
			ctx, verified, request.Input.SizeBytes, engine.config,
		)
		return jvmArchiveCandidateSet{candidates: candidates}, nil, err
	case FormatWAR, FormatEAR:
		set, err := enumerateNestedJVMArchives(
			ctx, verified, request.Input.SizeBytes, engine.config, request.Workspace,
		)
		return set, nil, err
	default:
		return jvmArchiveCandidateSet{}, nil, fmt.Errorf(
			"%w: JVM input format is unsupported", ErrInvalidRequest,
		)
	}
}

func readJVMSpoolClass(
	ctx context.Context,
	candidate jvmArchiveCandidate,
	maximum int64,
) ([]byte, error) {
	if candidate.spool == nil || candidate.spoolOffset < 0 || candidate.spoolSize < 0 ||
		candidate.spoolSize > maximum || candidate.spoolSize > int64(math.MaxInt) {
		return nil, ErrJVMArchiveLimit
	}
	reader := io.NewSectionReader(
		candidate.spool, candidate.spoolOffset, candidate.spoolSize,
	)
	payload := make([]byte, int(candidate.spoolSize))
	if _, err := io.ReadFull(&contextReader{ctx: ctx, reader: reader}, payload); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, err
	}
	return payload, nil
}

func readJVMVerifiedClass(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	maximum int64,
) ([]byte, error) {
	if size < 0 || size > maximum || size > int64(math.MaxInt) {
		return nil, fmt.Errorf("%w: class byte limit", ErrJVMArchiveLimit)
	}
	section := io.NewSectionReader(reader, 0, size)
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(&contextReader{ctx: ctx, reader: section}, payload); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: verified class is truncated", ErrInvalidRequest)
	}
	var extra [1]byte
	count, err := (&contextReader{ctx: ctx, reader: section}).Read(extra[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: verified class size differs", ErrInvalidRequest)
	}
	return payload, nil
}

func (engine *JVMFallbackEngine) appendClassFailure(
	output *Output,
	request Request,
	candidate jvmArchiveCandidate,
	code string,
	message string,
) {
	key := jvmStableKey(
		"class", string(request.Input.Format), candidate.identityPath,
		request.Input.SHA256,
	)
	binaryName := fallbackJVMBinaryName(candidate.logicalPath, key)
	output.Classes = append(output.Classes, ClassIndex{
		Key: key, Kind: KindClass, BinaryName: binaryName,
		DisplayName: binaryName, Language: "java-bytecode",
		Status: ClassFailed, ArtifactIDs: []string{}, Methods: []MethodIndex{},
	})
	output.ClassErrors = append(output.ClassErrors, ClassError{
		ClassKey: key, Code: code, Message: sanitizeJVMErrorMessage(message),
	})
}

func (engine *JVMFallbackEngine) appendArchiveFailure(
	output *Output,
	request Request,
	failure jvmArchiveFailure,
) {
	key := jvmStableKey(
		"module", string(request.Input.Format), failure.identityPath,
		request.Input.SHA256,
	)
	displayName := failure.entryPath
	if !validJVMText(displayName, 2048) {
		displayName = "nested archive " + strings.TrimPrefix(key, "module:")[:16]
	}
	output.Classes = append(output.Classes, ClassIndex{
		Key: key, Kind: KindModule, BinaryName: displayName,
		DisplayName: displayName, Language: "java-bytecode",
		Status: ClassFailed, ArtifactIDs: []string{}, Methods: []MethodIndex{},
	})
	output.ClassErrors = append(output.ClassErrors, ClassError{
		ClassKey: key, Code: failure.code,
		Message: sanitizeJVMErrorMessage(failure.message),
	})
}

func checkJVMErrorLimit(output Output, request Request) error {
	if request.Limits.MaxClassErrors > 0 &&
		len(output.ClassErrors) > request.Limits.MaxClassErrors {
		return fmt.Errorf("%w: JVM class error count limit", ErrJVMArchiveLimit)
	}
	return nil
}

func buildJVMClassIndex(
	request Request,
	candidate jvmArchiveCandidate,
	parsed jvmParsedClass,
) (ClassIndex, jvmIndexClassRecord) {
	classKey := jvmStableKey(
		"class", string(request.Input.Format), candidate.identityPath,
		parsed.BinaryName,
	)
	classIndex := ClassIndex{
		Key: classKey, Kind: KindClass, BinaryName: parsed.BinaryName,
		DisplayName: parsed.BinaryName, SourceFile: parsed.SourceFile,
		Language: "java-bytecode", Status: ClassBytecodeOnly,
		ArtifactIDs: []string{}, Methods: make([]MethodIndex, 0, len(parsed.Methods)),
	}
	record := jvmIndexClassRecord{
		ClassKey: classKey, EntryPath: candidate.entryPath,
		SelectedRelease: candidate.release, BinaryName: parsed.BinaryName,
		MinorVersion: parsed.MinorVersion, MajorVersion: parsed.MajorVersion,
		AccessFlags: parsed.AccessFlags, SHA256: parsed.SHA256,
		Methods: make([]jvmIndexMethodRecord, 0, len(parsed.Methods)),
	}
	for _, method := range parsed.Methods {
		methodKey := jvmStableKey(
			"method", classKey, method.Name, method.Descriptor,
		)
		methodIndex := MethodIndex{
			Key: methodKey, Name: method.Name,
			QualifiedName: parsed.BinaryName + "." + method.Name,
			Descriptor:    method.Descriptor,
		}
		methodRecord := jvmIndexMethodRecord{
			MethodKey: methodKey, Name: method.Name,
			Descriptor: method.Descriptor, AccessFlags: method.AccessFlags,
		}
		if method.Code != nil {
			methodIndex.Bytecode = &BytecodeRange{
				OffsetBytes: method.Code.OffsetBytes,
				SizeBytes:   method.Code.SizeBytes,
			}
			methodRecord.Code = &jvmIndexCodeRecord{
				OffsetBytes: method.Code.OffsetBytes,
				SizeBytes:   method.Code.SizeBytes,
				SHA256:      method.Code.SHA256,
				BytecodeHex: method.Code.Hex,
			}
		}
		classIndex.Methods = append(classIndex.Methods, methodIndex)
		record.Methods = append(record.Methods, methodRecord)
	}
	return classIndex, record
}

func jvmStableKey(prefix string, components ...string) string {
	hasher := sha256.New()
	for _, component := range components {
		_, _ = io.WriteString(hasher, strconv.Itoa(len(component)))
		_, _ = io.WriteString(hasher, ":")
		_, _ = io.WriteString(hasher, component)
	}
	return prefix + ":" + hex.EncodeToString(hasher.Sum(nil))
}

func fallbackJVMBinaryName(logicalPath string, key string) string {
	name := strings.TrimSuffix(logicalPath, ".class")
	for _, prefix := range []string{"WEB-INF/classes/", "BOOT-INF/classes/"} {
		name = strings.TrimPrefix(name, prefix)
	}
	name = strings.ReplaceAll(name, "/", ".")
	if validJVMText(name, 2048) {
		return name
	}
	digest := strings.TrimPrefix(key, "class:")
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return "unresolved." + digest
}

func sanitizeJVMErrorMessage(message string) string {
	message = strings.TrimSpace(strings.ReplaceAll(message, "\x00", ""))
	if !validText(message, 4096) {
		return "class processing failed"
	}
	return message
}

func normalizeJVMEngineConfig(config JVMEngineConfig) (JVMEngineConfig, error) {
	if config.TargetJavaRelease < 0 || config.MaxArchiveEntries < 0 ||
		config.MaxExpandedBytes < 0 || config.MaxClassBytes < 0 ||
		config.MaxCompressionRatio < 0 || config.MaxArchiveDepth < 0 {
		return JVMEngineConfig{}, fmt.Errorf("%w: JVM engine limits are negative", ErrInvalidConfiguration)
	}
	if config.TargetJavaRelease == 0 {
		config.TargetJavaRelease = DefaultJVMTargetJavaRelease
	}
	if config.MaxArchiveEntries == 0 {
		config.MaxArchiveEntries = DefaultJVMMaxArchiveEntries
	}
	if config.MaxExpandedBytes == 0 {
		config.MaxExpandedBytes = DefaultJVMMaxExpandedBytes
	}
	if config.MaxClassBytes == 0 {
		config.MaxClassBytes = DefaultJVMMaxClassBytes
	}
	if config.MaxCompressionRatio == 0 {
		config.MaxCompressionRatio = DefaultJVMMaxCompressionRatio
	}
	if config.MaxArchiveDepth == 0 {
		config.MaxArchiveDepth = DefaultJVMMaxArchiveDepth
	}
	if config.TargetJavaRelease < 8 ||
		config.TargetJavaRelease > maximumJVMTargetJavaRelease ||
		config.MaxArchiveEntries > DefaultJVMMaxArchiveEntries ||
		config.MaxExpandedBytes > DefaultJVMMaxExpandedBytes ||
		config.MaxClassBytes > maximumJVMClassBytes ||
		config.MaxClassBytes > config.MaxExpandedBytes ||
		config.MaxCompressionRatio > DefaultJVMMaxCompressionRatio ||
		config.MaxArchiveDepth > DefaultJVMMaxArchiveDepth {
		return JVMEngineConfig{}, fmt.Errorf("%w: JVM engine limits exceed ceilings", ErrInvalidConfiguration)
	}
	return config, nil
}

func jvmConfigFingerprint(config JVMEngineConfig) string {
	canonical := fmt.Sprintf(
		"target_java_release=%d\nmax_archive_entries=%d\nmax_expanded_bytes=%d\nmax_class_bytes=%d\nmax_compression_ratio=%d\nmax_archive_depth=%d\n",
		config.TargetJavaRelease,
		config.MaxArchiveEntries,
		config.MaxExpandedBytes,
		config.MaxClassBytes,
		config.MaxCompressionRatio,
		config.MaxArchiveDepth,
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

type jvmIndexClassRecord struct {
	ClassKey        string                 `json:"class_key"`
	EntryPath       string                 `json:"entry_path"`
	SelectedRelease int                    `json:"selected_release"`
	BinaryName      string                 `json:"binary_name"`
	MinorVersion    uint16                 `json:"minor_version"`
	MajorVersion    uint16                 `json:"major_version"`
	AccessFlags     uint16                 `json:"access_flags"`
	SHA256          string                 `json:"sha256"`
	Methods         []jvmIndexMethodRecord `json:"methods"`
}

type jvmIndexMethodRecord struct {
	MethodKey   string              `json:"method_key"`
	Name        string              `json:"name"`
	Descriptor  string              `json:"descriptor"`
	AccessFlags uint16              `json:"access_flags"`
	Code        *jvmIndexCodeRecord `json:"code,omitempty"`
}

type jvmIndexCodeRecord struct {
	OffsetBytes uint64 `json:"offset_bytes"`
	SizeBytes   uint64 `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	BytecodeHex string `json:"bytecode_hex"`
}

type jvmArtifactWriter struct {
	workspace     string
	directory     string
	maximum       int64
	written       int64
	targetRelease int
	paths         []string
}

func newJVMArtifactWriter(
	workspace string,
	maximum int64,
	targetRelease int,
) (*jvmArtifactWriter, error) {
	if maximum <= 0 {
		return nil, errJVMIndexLimit
	}
	directory, err := os.MkdirTemp(workspace, ".jvm-bytecode-")
	if err != nil {
		return nil, fmt.Errorf("create JVM index directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return nil, fmt.Errorf("protect JVM index directory: %w", err)
	}
	return &jvmArtifactWriter{
		workspace: workspace, directory: directory, maximum: maximum,
		targetRelease: targetRelease, paths: []string{},
	}, nil
}

func (writer *jvmArtifactWriter) add(
	ctx context.Context,
	record jvmIndexClassRecord,
) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	payload, err := json.Marshal(struct {
		SchemaVersion     string              `json:"schema_version"`
		Kind              string              `json:"kind"`
		TargetJavaRelease int                 `json:"target_java_release"`
		Class             jvmIndexClassRecord `json:"class"`
	}{
		SchemaVersion: "1.0", Kind: "jvm_bytecode_index",
		TargetJavaRelease: writer.targetRelease, Class: record,
	})
	if err != nil {
		return Artifact{}, fmt.Errorf("encode JVM index record: %w", err)
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > writer.maximum-writer.written {
		return Artifact{}, errJVMIndexLimit
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	name := fmt.Sprintf(
		"class-%06d-%s.json", len(writer.paths)+1, digest[:16],
	)
	indexPath := filepath.Join(writer.directory, name)
	file, err := os.OpenFile(indexPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Artifact{}, fmt.Errorf("create JVM class index: %w", err)
	}
	removeIncomplete := true
	defer func() {
		_ = file.Close()
		if removeIncomplete {
			_ = os.Remove(indexPath)
		}
	}()
	for position := 0; position < len(payload); {
		if err := ctx.Err(); err != nil {
			return Artifact{}, err
		}
		end := position + 64<<10
		if end > len(payload) {
			end = len(payload)
		}
		count, writeErr := file.Write(payload[position:end])
		position += count
		if writeErr != nil {
			return Artifact{}, fmt.Errorf("write JVM class index: %w", writeErr)
		}
		if count == 0 {
			return Artifact{}, io.ErrShortWrite
		}
	}
	if err := file.Sync(); err != nil {
		return Artifact{}, fmt.Errorf("sync JVM class index: %w", err)
	}
	if err := file.Close(); err != nil {
		return Artifact{}, fmt.Errorf("close JVM class index: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	removeIncomplete = false
	writer.paths = append(writer.paths, indexPath)
	writer.written += int64(len(payload))
	relativePath, err := filepath.Rel(writer.workspace, indexPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("locate JVM index: %w", err)
	}
	relativePath = filepath.ToSlash(relativePath)
	id := "jvm-index-" + digest
	return Artifact{
		ID: id, Kind: ArtifactIndex, MediaType: jvmIndexMediaType,
		RelativePath: relativePath, SHA256: digest, SizeBytes: int64(len(payload)),
		Chunk:     ArtifactChunk{SetID: id, Index: 0, Count: 1},
		ClassKeys: []string{},
	}, nil
}

func (writer *jvmArtifactWriter) abort() {
	if writer == nil {
		return
	}
	for _, path := range writer.paths {
		_ = os.Remove(path)
	}
	_ = os.Remove(writer.directory)
}
