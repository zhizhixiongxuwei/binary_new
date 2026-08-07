package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	PYCFallbackEngineName             = "go-python-bytecode"
	DefaultPYCMaxInputBytes     int64 = 64 << 20
	DefaultPYCMaxObjects              = 20_000
	DefaultPYCMaxObjectDepth          = 100
	DefaultPYCMaxContainerItems       = 20_000
	DefaultPYCMaxStringBytes    int64 = 64 << 20
	DefaultPYCMaxBytecodeBytes  int64 = 32 << 20
	DefaultPYCMaxCodeObjects          = 20_000
	DefaultPYCMaxIndexBytes     int64 = 64 << 20
	pycIndexMediaType                 = "application/vnd.binaryscan.python-bytecode-index+json"
)

var (
	ErrMalformedPYC     = errors.New("bytecode: malformed PYC")
	ErrPYCResourceLimit = errors.New("bytecode: PYC resource limit exceeded")
)

type PYCConfig struct {
	MaxInputBytes     int64
	MaxObjects        int
	MaxObjectDepth    int
	MaxContainerItems int
	MaxStringBytes    int64
	MaxBytecodeBytes  int64
	MaxCodeObjects    int
	MaxIndexBytes     int64
}

type PYCFallbackEngine struct {
	config      PYCConfig
	descriptor  Descriptor
	fingerprint string
}

func NewPYCFallbackEngine(config PYCConfig) (*PYCFallbackEngine, error) {
	normalized, err := normalizePYCConfig(config)
	if err != nil {
		return nil, err
	}
	fingerprint := pycConfigFingerprint(normalized)
	return &PYCFallbackEngine{
		config: normalized,
		descriptor: Descriptor{
			Name:    PYCFallbackEngineName,
			Version: "1.0.0-cpython38-310-cfg" + fingerprint,
		},
		fingerprint: fingerprint,
	}, nil
}

func (engine *PYCFallbackEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *PYCFallbackEngine) Config() PYCConfig {
	if engine == nil {
		return PYCConfig{}
	}
	return engine.config
}

func (engine *PYCFallbackEngine) ConfigFingerprint() string {
	if engine == nil {
		return ""
	}
	return engine.fingerprint
}

func (engine *PYCFallbackEngine) Supports(format Format) bool {
	return engine != nil && format == FormatPYC
}

func (engine *PYCFallbackEngine) Decompile(
	ctx context.Context,
	request Request,
) (Output, error) {
	if engine == nil {
		return Output{}, fmt.Errorf("%w: PYC fallback engine is nil", ErrInvalidConfiguration)
	}
	if ctx == nil {
		return Output{}, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	if request.Input.Format != FormatPYC {
		return Output{}, fmt.Errorf("%w: PYC input format is required", ErrInvalidRequest)
	}
	payload, err := readVerifiedPYC(ctx, request.Input, engine.config.MaxInputBytes)
	if err != nil {
		return Output{}, err
	}
	header, err := inspectPYCHeader(payload)
	if err != nil {
		if errors.Is(err, ErrMalformedPYC) {
			return failedPYCOutput(request, "invalid_pyc", err.Error()), nil
		}
		return Output{}, err
	}
	if !header.known {
		return Output{
			Status: StatusUnsupported, Classes: []ClassIndex{}, Artifacts: []Artifact{},
			ClassErrors: []ClassError{},
			Warnings:    []string{"The PYC magic number is not recognized by the offline fallback."},
		}, nil
	}
	if !header.supported {
		return Output{
			Status: StatusUnsupported, Classes: []ClassIndex{}, Artifacts: []Artifact{},
			ClassErrors: []ClassError{},
			Warnings: []string{fmt.Sprintf(
				"CPython %s PYC bytecode fallback is not implemented.", header.pythonVersion,
			)},
		}, nil
	}
	root, err := parsePYCMarshal(ctx, payload, header.headerSize, engine.config)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Output{}, contextErr
		}
		if errors.Is(err, ErrPYCResourceLimit) {
			return Output{}, err
		}
		return failedPYCOutput(request, "invalid_pyc", err.Error()), nil
	}
	return engine.buildOutput(ctx, request, payload, header, root)
}

type pycVersionInfo struct {
	pythonVersion string
	headerSize    int
	supported     bool
}

var pycVersions = map[uint16]pycVersionInfo{
	62211: {pythonVersion: "2.7", headerSize: 8},
	3230:  {pythonVersion: "3.3", headerSize: 12},
	3310:  {pythonVersion: "3.4", headerSize: 12},
	3350:  {pythonVersion: "3.5", headerSize: 12},
	3351:  {pythonVersion: "3.5", headerSize: 12},
	3379:  {pythonVersion: "3.6", headerSize: 12},
	3394:  {pythonVersion: "3.7", headerSize: 16},
	3413:  {pythonVersion: "3.8", headerSize: 16, supported: true},
	3425:  {pythonVersion: "3.9", headerSize: 16, supported: true},
	3439:  {pythonVersion: "3.10", headerSize: 16, supported: true},
	3495:  {pythonVersion: "3.11", headerSize: 16},
	3531:  {pythonVersion: "3.12", headerSize: 16},
	3571:  {pythonVersion: "3.13", headerSize: 16},
	3619:  {pythonVersion: "3.14", headerSize: 16},
	3627:  {pythonVersion: "3.14", headerSize: 16},
}

type pycHeader struct {
	known         bool
	supported     bool
	magic         uint16
	pythonVersion string
	headerSize    int
	flags         uint32
	hashBased     bool
	checkSource   bool
	sourceHash    string
	timestamp     uint32
	sourceSize    uint32
}

func inspectPYCHeader(payload []byte) (pycHeader, error) {
	if len(payload) < 4 || payload[2] != '\r' || payload[3] != '\n' {
		return pycHeader{}, malformedPYC("magic trailer is invalid")
	}
	magic := binary.LittleEndian.Uint16(payload[:2])
	version, known := pycVersions[magic]
	header := pycHeader{known: known, magic: magic}
	if !known {
		return header, nil
	}
	header.supported = version.supported
	header.pythonVersion = version.pythonVersion
	header.headerSize = version.headerSize
	if len(payload) <= version.headerSize {
		return pycHeader{}, malformedPYC("version-specific header is truncated")
	}
	if payload[version.headerSize]&^pycMarshalReferenceFlag != pycTypeCode {
		return pycHeader{}, malformedPYC("marshal root marker is not a code object")
	}
	if version.headerSize == 16 {
		header.flags = binary.LittleEndian.Uint32(payload[4:8])
		if header.flags&^uint32(3) != 0 ||
			header.flags&2 != 0 && header.flags&1 == 0 {
			return pycHeader{}, malformedPYC("PEP 552 flags are invalid")
		}
		header.hashBased = header.flags&1 != 0
		header.checkSource = header.flags&2 != 0
		if header.hashBased {
			header.sourceHash = hex.EncodeToString(payload[8:16])
		} else {
			header.timestamp = binary.LittleEndian.Uint32(payload[8:12])
			header.sourceSize = binary.LittleEndian.Uint32(payload[12:16])
		}
	}
	return header, nil
}

func readVerifiedPYC(
	ctx context.Context,
	input Input,
	maximum int64,
) ([]byte, error) {
	if input.SizeBytes < 0 || input.SizeBytes > maximum ||
		input.SizeBytes > int64(math.MaxInt) {
		return nil, pycLimit("input bytes")
	}
	reader, err := input.VerifiedReader()
	if err != nil {
		return nil, fmt.Errorf("%w: verified PYC input is unavailable", ErrInvalidRequest)
	}
	payload := make([]byte, int(input.SizeBytes))
	if _, err := io.ReadFull(&contextReader{ctx: ctx, reader: reader}, payload); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: verified PYC input is truncated", ErrInvalidRequest)
	}
	return payload, nil
}

type pycIndexedCode struct {
	object        *pycMarshalObject
	qualifiedName string
	path          string
}

func (engine *PYCFallbackEngine) buildOutput(
	ctx context.Context,
	request Request,
	payload []byte,
	header pycHeader,
	root *pycMarshalObject,
) (Output, error) {
	moduleName := pycModuleName(root.code.filename.bytes, request.Input.SHA256)
	codes, err := collectPYCCodeObjects(ctx, root, moduleName, engine.config.MaxCodeObjects)
	if err != nil {
		return Output{}, err
	}
	if len(codes) == 0 {
		return Output{}, malformedPYC("PYC contains no code object")
	}
	if len(codes) > request.Limits.MaxMethods {
		return Output{}, pycLimit("result method count")
	}
	if request.Limits.MaxClasses < 1 || request.Limits.MaxArtifacts < 1 {
		return Output{}, pycLimit("result object count")
	}
	moduleKey := pycStableKey("module", request.Input.SHA256, moduleName)
	classIndex := ClassIndex{
		Key: moduleKey, Kind: KindModule, BinaryName: moduleName,
		DisplayName: moduleName, Language: "python-bytecode",
		Status: ClassBytecodeOnly, ArtifactIDs: []string{},
		Methods: make([]MethodIndex, 0, len(codes)),
	}
	filename := string(root.code.filename.bytes)
	if sourceFile := pycSourceFile(filename); sourceFile != "" {
		classIndex.SourceFile = sourceFile
	}
	records := make([]pycIndexMethodRecord, 0, len(codes))
	for _, indexed := range codes {
		if err := ctx.Err(); err != nil {
			return Output{}, err
		}
		code := indexed.object.code
		name := string(code.name.bytes)
		digestBytes := sha256.Sum256(code.bytecode.bytes)
		digest := hex.EncodeToString(digestBytes[:])
		methodKey := pycStableKey(
			"method", moduleKey, indexed.path, indexed.qualifiedName, digest,
		)
		descriptor := fmt.Sprintf(
			"argcount=%d;posonly=%d;kwonly=%d;locals=%d;stack=%d;flags=0x%x",
			code.argCount, code.posOnlyCount, code.kwOnlyCount,
			code.nlocals, code.stackSize, code.flags,
		)
		method := MethodIndex{
			Key: methodKey, Name: name, QualifiedName: indexed.qualifiedName,
			Descriptor: descriptor, Signature: pycSignature(code),
		}
		if code.firstLine > 0 {
			method.Source = &SourceRange{
				StartLine: uint32(code.firstLine), EndLine: uint32(code.firstLine),
			}
		}
		if len(code.bytecode.bytes) > 0 {
			method.Bytecode = &BytecodeRange{
				OffsetBytes: code.bytecode.byteOffset,
				SizeBytes:   uint64(len(code.bytecode.bytes)),
			}
		}
		classIndex.Methods = append(classIndex.Methods, method)
		records = append(records, pycIndexMethodRecord{
			MethodKey: methodKey, Name: name, QualifiedName: indexed.qualifiedName,
			Descriptor: descriptor, Signature: method.Signature,
			FirstLine: code.firstLine, Code: pycIndexCodeRecord{
				OffsetBytes: code.bytecode.byteOffset,
				SizeBytes:   uint64(len(code.bytecode.bytes)), SHA256: digest,
				Representation: "raw_cpython_co_code_bytes",
				RawBytecodeHex: hex.EncodeToString(code.bytecode.bytes),
			},
		})
	}
	document := pycIndexDocument{
		SchemaVersion: "1.0", Kind: "python_bytecode_index",
		PythonVersion: header.pythonVersion, MagicNumber: header.magic,
		Header: pycIndexHeader{
			SizeBytes: header.headerSize, Flags: header.flags,
			HashBased: header.hashBased, CheckSource: header.checkSource,
			SourceHash: header.sourceHash, Timestamp: header.timestamp,
			SourceSize: header.sourceSize,
		},
		Representation: pycIndexRepresentation{
			Encoding:             "raw_cpython_co_code_bytes",
			InstructionDecoding:  "not_performed",
			SourceReconstruction: "not_performed",
		},
		Module: pycIndexModule{
			ModuleKey: moduleKey, Name: moduleName, Filename: filename,
			SHA256: request.Input.SHA256, Methods: records,
		},
	}
	maximum := min(engine.config.MaxIndexBytes, request.Limits.MaxArtifactBytes)
	artifact, err := writePYCIndex(ctx, request.Workspace, maximum, document)
	if err != nil {
		return Output{}, err
	}
	classIndex.ArtifactIDs = []string{artifact.ID}
	artifact.ClassKeys = []string{moduleKey}
	return Output{
		Status:  StatusBytecodeOnly,
		Classes: []ClassIndex{classIndex}, Artifacts: []Artifact{artifact},
		ClassErrors: []ClassError{},
		Warnings: []string{
			"Raw CPython co_code bytes are indexed without opcode disassembly or source reconstruction.",
		},
		Execution: &Execution{
			ExitCode: 0, OutputBytes: artifact.SizeBytes, OutputFiles: 1,
		},
	}, nil
}

func collectPYCCodeObjects(
	ctx context.Context,
	root *pycMarshalObject,
	moduleName string,
	maximum int,
) ([]pycIndexedCode, error) {
	result := make([]pycIndexedCode, 0)
	seen := make(map[*pycMarshalObject]struct{})
	var visit func(*pycMarshalObject, string, string) error
	visit = func(object *pycMarshalObject, scope string, objectPath string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if object == nil {
			return malformedPYC("marshal graph contains a nil object")
		}
		if _, exists := seen[object]; exists {
			return nil
		}
		seen[object] = struct{}{}
		if object.code != nil {
			if len(result) >= maximum {
				return pycLimit("code object index count")
			}
			name := string(object.code.name.bytes)
			qualified := scope + "." + name
			if len(result) == 0 {
				qualified = moduleName + ".<module>"
			}
			result = append(result, pycIndexedCode{
				object: object, qualifiedName: qualified, path: objectPath,
			})
			for index, constant := range object.code.constants.items {
				if err := visit(
					constant, qualifiedScope(moduleName, qualified, len(result) == 1),
					objectPath+"/const/"+strconv.Itoa(index),
				); err != nil {
					return err
				}
			}
			return nil
		}
		for index, item := range object.items {
			if err := visit(
				item, scope, objectPath+"/item/"+strconv.Itoa(index),
			); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(root, moduleName, "root"); err != nil {
		return nil, err
	}
	return result, nil
}

func qualifiedScope(moduleName string, qualified string, root bool) string {
	if root {
		return moduleName
	}
	return qualified
}

func pycSignature(code *pycCodeObject) string {
	name := string(code.name.bytes)
	variableNames := make([]string, len(code.variableNames.items))
	for index, item := range code.variableNames.items {
		variableNames[index] = string(item.bytes)
	}
	parts := make([]string, 0, code.argCount+code.kwOnlyCount+3)
	for index := 0; index < code.argCount; index++ {
		parts = append(parts, variableNames[index])
		if code.posOnlyCount > 0 && index+1 == code.posOnlyCount {
			parts = append(parts, "/")
		}
	}
	next := code.argCount + code.kwOnlyCount
	if code.flags&pycCodeFlagVarArgs != 0 {
		parts = append(parts, "*"+variableNames[next])
		next++
	} else if code.kwOnlyCount > 0 {
		parts = append(parts, "*")
	}
	for index := 0; index < code.kwOnlyCount; index++ {
		parts = append(parts, variableNames[code.argCount+index])
	}
	if code.flags&pycCodeFlagVarKeywords != 0 {
		parts = append(parts, "**"+variableNames[next])
	}
	return name + "(" + strings.Join(parts, ", ") + ")"
}

func pycModuleName(filename []byte, inputSHA256 string) string {
	name := path.Base(strings.ReplaceAll(string(filename), "\\", "/"))
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".py"), ".pyw")
	if !validText(name, 1024) || strings.ContainsAny(name, "/\\") ||
		strings.HasPrefix(name, "<") {
		return "python_module_" + inputSHA256[:16]
	}
	return name
}

func pycSourceFile(filename string) string {
	name := path.Base(strings.ReplaceAll(filename, "\\", "/"))
	if validRelativePath(name) {
		return name
	}
	return ""
}

func failedPYCOutput(request Request, code string, message string) Output {
	key := pycStableKey("module", request.Input.SHA256, "invalid")
	display := "python_module_" + request.Input.SHA256[:16]
	return Output{
		Status: StatusPartial,
		Classes: []ClassIndex{{
			Key: key, Kind: KindModule, BinaryName: display, DisplayName: display,
			Language: "python-bytecode", Status: ClassFailed,
			ArtifactIDs: []string{}, Methods: []MethodIndex{},
		}},
		Artifacts: []Artifact{},
		ClassErrors: []ClassError{{
			ClassKey: key, Code: code, Message: sanitizePYCError(message),
		}},
		Warnings: []string{},
	}
}

func sanitizePYCError(message string) string {
	message = strings.TrimSpace(strings.ReplaceAll(message, "\x00", ""))
	if !validText(message, 4096) {
		return "PYC processing failed"
	}
	return message
}

func pycStableKey(prefix string, components ...string) string {
	hasher := sha256.New()
	for _, component := range components {
		_, _ = io.WriteString(hasher, strconv.Itoa(len(component)))
		_, _ = io.WriteString(hasher, ":")
		_, _ = io.WriteString(hasher, component)
	}
	return prefix + ":" + hex.EncodeToString(hasher.Sum(nil))
}

func normalizePYCConfig(config PYCConfig) (PYCConfig, error) {
	if config.MaxInputBytes < 0 || config.MaxObjects < 0 ||
		config.MaxObjectDepth < 0 || config.MaxContainerItems < 0 ||
		config.MaxStringBytes < 0 || config.MaxBytecodeBytes < 0 ||
		config.MaxCodeObjects < 0 || config.MaxIndexBytes < 0 {
		return PYCConfig{}, fmt.Errorf("%w: PYC limits are negative", ErrInvalidConfiguration)
	}
	if config.MaxInputBytes == 0 {
		config.MaxInputBytes = DefaultPYCMaxInputBytes
	}
	if config.MaxObjects == 0 {
		config.MaxObjects = DefaultPYCMaxObjects
	}
	if config.MaxObjectDepth == 0 {
		config.MaxObjectDepth = DefaultPYCMaxObjectDepth
	}
	if config.MaxContainerItems == 0 {
		config.MaxContainerItems = DefaultPYCMaxContainerItems
	}
	if config.MaxStringBytes == 0 {
		config.MaxStringBytes = DefaultPYCMaxStringBytes
	}
	if config.MaxBytecodeBytes == 0 {
		config.MaxBytecodeBytes = DefaultPYCMaxBytecodeBytes
	}
	if config.MaxCodeObjects == 0 {
		config.MaxCodeObjects = DefaultPYCMaxCodeObjects
	}
	if config.MaxIndexBytes == 0 {
		config.MaxIndexBytes = DefaultPYCMaxIndexBytes
	}
	if config.MaxInputBytes > DefaultPYCMaxInputBytes ||
		config.MaxObjects > DefaultPYCMaxObjects ||
		config.MaxObjectDepth > DefaultPYCMaxObjectDepth ||
		config.MaxContainerItems > DefaultPYCMaxContainerItems ||
		config.MaxStringBytes > DefaultPYCMaxStringBytes ||
		config.MaxBytecodeBytes > DefaultPYCMaxBytecodeBytes ||
		config.MaxCodeObjects > DefaultPYCMaxCodeObjects ||
		config.MaxIndexBytes > DefaultPYCMaxIndexBytes ||
		config.MaxContainerItems > config.MaxObjects ||
		config.MaxCodeObjects > config.MaxObjects ||
		config.MaxBytecodeBytes > config.MaxStringBytes {
		return PYCConfig{}, fmt.Errorf("%w: PYC limits exceed ceilings", ErrInvalidConfiguration)
	}
	return config, nil
}

func pycConfigFingerprint(config PYCConfig) string {
	canonical := fmt.Sprintf(
		"supported=cpython3.8:3413,cpython3.9:3425,cpython3.10:3439\nmax_input_bytes=%d\nmax_objects=%d\nmax_object_depth=%d\nmax_container_items=%d\nmax_string_bytes=%d\nmax_bytecode_bytes=%d\nmax_code_objects=%d\nmax_index_bytes=%d\n",
		config.MaxInputBytes, config.MaxObjects, config.MaxObjectDepth,
		config.MaxContainerItems, config.MaxStringBytes, config.MaxBytecodeBytes,
		config.MaxCodeObjects, config.MaxIndexBytes,
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func malformedPYC(message string) error {
	return fmt.Errorf("%w: %s", ErrMalformedPYC, message)
}

func pycLimit(resource string) error {
	return fmt.Errorf("%w: %s", ErrPYCResourceLimit, resource)
}

type pycIndexDocument struct {
	SchemaVersion  string                 `json:"schema_version"`
	Kind           string                 `json:"kind"`
	PythonVersion  string                 `json:"python_version"`
	MagicNumber    uint16                 `json:"magic_number"`
	Header         pycIndexHeader         `json:"header"`
	Representation pycIndexRepresentation `json:"representation"`
	Module         pycIndexModule         `json:"module"`
}

type pycIndexHeader struct {
	SizeBytes   int    `json:"size_bytes"`
	Flags       uint32 `json:"flags"`
	HashBased   bool   `json:"hash_based"`
	CheckSource bool   `json:"check_source"`
	SourceHash  string `json:"source_hash,omitempty"`
	Timestamp   uint32 `json:"timestamp,omitempty"`
	SourceSize  uint32 `json:"source_size,omitempty"`
}

type pycIndexRepresentation struct {
	Encoding             string `json:"encoding"`
	InstructionDecoding  string `json:"instruction_decoding"`
	SourceReconstruction string `json:"source_reconstruction"`
}

type pycIndexModule struct {
	ModuleKey string                 `json:"module_key"`
	Name      string                 `json:"name"`
	Filename  string                 `json:"filename"`
	SHA256    string                 `json:"sha256"`
	Methods   []pycIndexMethodRecord `json:"methods"`
}

type pycIndexMethodRecord struct {
	MethodKey     string             `json:"method_key"`
	Name          string             `json:"name"`
	QualifiedName string             `json:"qualified_name"`
	Descriptor    string             `json:"descriptor"`
	Signature     string             `json:"signature"`
	FirstLine     int                `json:"first_line"`
	Code          pycIndexCodeRecord `json:"code"`
}

type pycIndexCodeRecord struct {
	OffsetBytes    uint64 `json:"offset_bytes"`
	SizeBytes      uint64 `json:"size_bytes"`
	SHA256         string `json:"sha256"`
	Representation string `json:"representation"`
	RawBytecodeHex string `json:"raw_bytecode_hex"`
}

func writePYCIndex(
	ctx context.Context,
	workspace string,
	maximum int64,
	document pycIndexDocument,
) (Artifact, error) {
	if maximum <= 0 {
		return Artifact{}, pycLimit("index bytes")
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return Artifact{}, fmt.Errorf("encode PYC index: %w", err)
	}
	payload = append(payload, '\n')
	if int64(len(payload)) > maximum {
		return Artifact{}, pycLimit("index bytes")
	}
	directory, err := os.MkdirTemp(workspace, ".pyc-bytecode-")
	if err != nil {
		return Artifact{}, fmt.Errorf("create PYC index directory: %w", err)
	}
	removeDirectory := true
	defer func() {
		if removeDirectory {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return Artifact{}, fmt.Errorf("protect PYC index directory: %w", err)
	}
	digestBytes := sha256.Sum256(payload)
	digest := hex.EncodeToString(digestBytes[:])
	filename := "module-" + digest[:16] + ".json"
	indexPath := filepath.Join(directory, filename)
	file, err := os.OpenFile(indexPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Artifact{}, fmt.Errorf("create PYC index: %w", err)
	}
	removeFile := true
	defer func() {
		_ = file.Close()
		if removeFile {
			_ = os.Remove(indexPath)
		}
	}()
	for position := 0; position < len(payload); {
		if err := ctx.Err(); err != nil {
			return Artifact{}, err
		}
		end := min(position+64<<10, len(payload))
		count, writeErr := file.Write(payload[position:end])
		position += count
		if writeErr != nil {
			return Artifact{}, fmt.Errorf("write PYC index: %w", writeErr)
		}
		if count == 0 {
			return Artifact{}, io.ErrShortWrite
		}
	}
	if err := file.Sync(); err != nil {
		return Artifact{}, fmt.Errorf("sync PYC index: %w", err)
	}
	if err := file.Close(); err != nil {
		return Artifact{}, fmt.Errorf("close PYC index: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	removeFile = false
	removeDirectory = false
	relativePath, err := filepath.Rel(workspace, indexPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("locate PYC index: %w", err)
	}
	id := "pyc-index-" + digest
	return Artifact{
		ID: id, Kind: ArtifactIndex, MediaType: pycIndexMediaType,
		RelativePath: filepath.ToSlash(relativePath), SHA256: digest,
		SizeBytes: int64(len(payload)),
		Chunk:     ArtifactChunk{SetID: id, Index: 0, Count: 1},
		ClassKeys: []string{},
	}, nil
}
