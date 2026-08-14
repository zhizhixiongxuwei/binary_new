package bytecode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPYCFallbackEngineGoldenCPython38(t *testing.T) {
	payload := goldenPYCFixture(3413, false)
	result, workspace, err := executePYCFixture(t, payload, PYCConfig{}, Limits{})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || len(result.Classes) != 1 ||
		len(result.Artifacts) != 1 || len(result.ClassErrors) != 0 {
		t.Fatalf("PYC result = %#v", result)
	}
	module := result.Classes[0]
	if module.Kind != KindModule || module.BinaryName != "module" ||
		module.SourceFile != "module.py" || module.Language != "python-bytecode" ||
		module.Status != ClassBytecodeOnly || len(module.Methods) != 2 {
		t.Fatalf("PYC module = %#v", module)
	}
	methods := make(map[string]MethodIndex, len(module.Methods))
	for _, method := range module.Methods {
		methods[method.Name] = method
	}
	if methods["<module>"].QualifiedName != "module.<module>" ||
		methods["greet"].QualifiedName != "module.greet" ||
		methods["greet"].Signature != "greet(name)" ||
		methods["greet"].Bytecode == nil ||
		methods["greet"].Bytecode.SizeBytes != 4 {
		t.Fatalf("PYC methods = %#v", module.Methods)
	}
	document, raw := readPYCIndexFixture(t, workspace, result.Artifacts[0])
	if document.SchemaVersion != "1.0" ||
		document.Kind != "python_bytecode_index" ||
		document.PythonVersion != "3.8" || document.MagicNumber != 3413 ||
		document.Representation.Encoding != "raw_cpython_co_code_bytes" ||
		document.Representation.InstructionDecoding != "not_performed" ||
		document.Representation.SourceReconstruction != "not_performed" ||
		len(document.Module.Methods) != 2 ||
		document.Module.Methods[1].Code.RawBytecodeHex != "7c005300" ||
		document.Module.Methods[1].Code.Representation !=
			"raw_cpython_co_code_bytes" {
		t.Fatalf("PYC index = %#v; raw = %q", document, raw)
	}
	offset := int(document.Module.Methods[1].Code.OffsetBytes)
	if offset+4 > len(payload) ||
		hex.EncodeToString(payload[offset:offset+4]) != "7c005300" {
		t.Fatalf("PYC bytecode range does not address the original input")
	}
	if len(result.Warnings) != 1 ||
		!strings.Contains(result.Warnings[0], "without opcode disassembly") {
		t.Fatalf("PYC warning = %#v", result.Warnings)
	}

	second, secondWorkspace, err := executePYCFixture(
		t, payload, PYCConfig{}, Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	secondDocument, secondRaw := readPYCIndexFixture(
		t, secondWorkspace, second.Artifacts[0],
	)
	if result.CacheKey != second.CacheKey ||
		result.Artifacts[0].SHA256 != second.Artifacts[0].SHA256 ||
		!bytes.Equal(raw, secondRaw) || !reflect.DeepEqual(document, secondDocument) {
		t.Fatal("PYC output is not deterministic")
	}
}

func TestPYCFallbackEngineSupportedVersionBoundary(t *testing.T) {
	for _, test := range []struct {
		magic   uint16
		version string
	}{
		{magic: 3413, version: "3.8"},
		{magic: 3425, version: "3.9"},
		{magic: 3439, version: "3.10"},
	} {
		t.Run(test.version, func(t *testing.T) {
			result, workspace, err := executePYCFixture(
				t, goldenPYCFixture(test.magic, true), PYCConfig{}, Limits{},
			)
			if err != nil || result.Status != StatusBytecodeOnly {
				t.Fatalf("Execute() = %#v, %v", result, err)
			}
			document, _ := readPYCIndexFixture(t, workspace, result.Artifacts[0])
			if document.PythonVersion != test.version || !document.Header.HashBased ||
				!document.Header.CheckSource || document.Header.SourceHash !=
				"0011223344556677" {
				t.Fatalf("version/header = %#v", document)
			}
		})
	}
}

func TestPYCFallbackEngineReturnsUnsupportedHonestly(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		warning string
	}{
		{
			name:    "known newer version",
			payload: goldenPYCFixture(3495, false),
			warning: "CPython 3.11",
		},
		{
			name:    "unknown magic",
			payload: append([]byte{0x34, 0x12, '\r', '\n'}, []byte("unknown")...),
			warning: "not recognized",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := executePYCFixture(
				t, test.payload, PYCConfig{}, Limits{},
			)
			if err != nil || result.Status != StatusUnsupported ||
				len(result.Classes) != 0 || len(result.Artifacts) != 0 ||
				len(result.Warnings) != 1 ||
				!strings.Contains(result.Warnings[0], test.warning) {
				t.Fatalf("unsupported result = %#v, error = %v", result, err)
			}
		})
	}
}

func TestPYCFallbackEngineIsolatesMalformedInput(t *testing.T) {
	fixtures := map[string][]byte{
		"truncated marshal": goldenPYCFixture(3413, false)[:35],
		"invalid flags": func() []byte {
			payload := goldenPYCFixture(3413, false)
			binary.LittleEndian.PutUint32(payload[4:8], 0x80)
			return payload
		}(),
		"non-code root": func() []byte {
			payload := goldenPYCFixture(3413, false)
			payload[16] = pycTypeNone
			return payload
		}(),
	}
	for name, payload := range fixtures {
		t.Run(name, func(t *testing.T) {
			result, _, err := executePYCFixture(t, payload, PYCConfig{}, Limits{})
			if err != nil || result.Status != StatusPartial ||
				len(result.Classes) != 1 || result.Classes[0].Status != ClassFailed ||
				len(result.ClassErrors) != 1 ||
				result.ClassErrors[0].Code != "invalid_pyc" ||
				len(result.Artifacts) != 0 {
				t.Fatalf("malformed result = %#v, error = %v", result, err)
			}
		})
	}
}

func TestPYCFallbackEngineRejectsMaliciousLengthsAndLimits(t *testing.T) {
	maliciousLength := pycFixtureHeader(3413, false)
	maliciousLength = append(maliciousLength, pycTypeCode)
	for range 6 {
		maliciousLength = appendInt32(maliciousLength, 0)
	}
	maliciousLength = append(maliciousLength, pycTypeBytes)
	maliciousLength = appendInt32(maliciousLength, 0x7fffffff)
	if _, _, err := executePYCFixture(
		t, maliciousLength, PYCConfig{}, Limits{},
	); !errors.Is(err, ErrPYCResourceLimit) {
		t.Fatalf("malicious length error = %v", err)
	}

	deep := goldenPYCFixtureWithConstant(3413, func(writer *pycFixtureWriter) {
		writeNestedPYCList(writer, 8)
	})
	if _, _, err := executePYCFixture(
		t, deep, PYCConfig{MaxObjectDepth: 5}, Limits{},
	); !errors.Is(err, ErrPYCResourceLimit) {
		t.Fatalf("object depth error = %v", err)
	}

	if _, _, err := executePYCFixture(
		t, goldenPYCFixture(3413, false),
		PYCConfig{MaxBytecodeBytes: 3, MaxStringBytes: 1024}, Limits{},
	); !errors.Is(err, ErrPYCResourceLimit) {
		t.Fatalf("bytecode limit error = %v", err)
	}
	if _, _, err := executePYCFixture(
		t, goldenPYCFixture(3413, false),
		PYCConfig{MaxIndexBytes: 128}, Limits{},
	); !errors.Is(err, ErrPYCResourceLimit) {
		t.Fatalf("index limit error = %v", err)
	}
	if _, _, err := executePYCFixture(
		t, goldenPYCFixture(3413, false), PYCConfig{}, Limits{MaxMethods: 1},
	); !errors.Is(err, ErrPYCResourceLimit) {
		t.Fatalf("method limit error = %v", err)
	}
}

func TestPYCFallbackEngineHandlesRecursiveMarshalReferences(t *testing.T) {
	payload := goldenPYCFixtureWithConstant(3413, func(writer *pycFixtureWriter) {
		reference := writer.referenceTag(pycTypeList)
		writer.int32(1)
		writer.tag(pycTypeReference)
		writer.int32(int32(reference))
	})
	result, _, err := executePYCFixture(t, payload, PYCConfig{}, Limits{})
	if err != nil || result.Status != StatusBytecodeOnly ||
		len(result.Classes) != 1 || len(result.Classes[0].Methods) != 2 {
		t.Fatalf("recursive reference result = %#v, error = %v", result, err)
	}

	broken := append([]byte(nil), payload...)
	position := bytes.LastIndexByte(broken, pycTypeReference)
	if position < 0 {
		t.Fatal("reference fixture marker not found")
	}
	binary.LittleEndian.PutUint32(broken[position+1:position+5], 0x7fffffff)
	malformed, _, err := executePYCFixture(t, broken, PYCConfig{}, Limits{})
	if err != nil || malformed.Status != StatusPartial ||
		len(malformed.ClassErrors) != 1 {
		t.Fatalf("broken reference = %#v, %v", malformed, err)
	}
}

func TestPYCFallbackEngineCancellationAndConfiguration(t *testing.T) {
	engine, err := NewPYCFallbackEngine(PYCConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if engine.Descriptor().Name != PYCFallbackEngineName ||
		!strings.Contains(engine.Descriptor().Version, "cpython38-310-cfg") ||
		len(engine.ConfigFingerprint()) != 64 || !engine.Supports(FormatPYC) ||
		engine.Supports(FormatClass) {
		t.Fatalf("engine identity = %#v / %q", engine.Descriptor(), engine.ConfigFingerprint())
	}
	if _, err := NewPYCFallbackEngine(PYCConfig{MaxObjectDepth: 101}); err == nil {
		t.Fatal("NewPYCFallbackEngine() accepted excessive object depth")
	}

	payload := goldenPYCFixture(3413, false)
	workspace := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "cancel.pyc")
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Execute(ctx, engine, Request{
		Input: Input{
			Path: inputPath, SHA256: hex.EncodeToString(digest[:]),
			Format: FormatPYC, SizeBytes: int64(len(payload)),
		},
		Workspace: workspace, ArtifactValidator: mustPYCValidator(t),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Execute() error = %v", err)
	}
}

func FuzzPYCMarshalParserNeverPanics(f *testing.F) {
	f.Add(goldenPYCFixture(3413, false))
	f.Add([]byte{0x55, 0x0d, '\r', '\n'})
	f.Add([]byte("not-pyc"))
	config, err := normalizePYCConfig(PYCConfig{
		MaxInputBytes: 1 << 20, MaxObjects: 1024, MaxObjectDepth: 16,
		MaxContainerItems: 1024, MaxStringBytes: 1 << 20,
		MaxBytecodeBytes: 1 << 20, MaxCodeObjects: 1024,
		MaxIndexBytes: 1 << 20,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}
		header, headerErr := inspectPYCHeader(payload)
		if headerErr == nil && header.known && header.supported {
			_, _ = parsePYCMarshal(context.Background(), payload, header.headerSize, config)
		}
	})
}

type pycFixtureWriter struct {
	buffer     bytes.Buffer
	references int
}

func goldenPYCFixture(magic uint16, hashBased bool) []byte {
	return goldenPYCFixtureWithConstant(magic, nil, hashBased)
}

func goldenPYCFixtureWithConstant(
	magic uint16,
	extra func(*pycFixtureWriter),
	hashBased ...bool,
) []byte {
	header := pycFixtureHeader(magic, len(hashBased) > 0 && hashBased[0])
	writer := &pycFixtureWriter{}
	writer.referenceTag(pycTypeCode)
	for _, value := range []int32{0, 0, 0, 0, 2, 0} {
		writer.int32(value)
	}
	writer.byteString([]byte{0x64, 0x00, 0x53, 0x00})
	constantCount := 2
	if extra != nil {
		constantCount++
	}
	writer.referenceTag(pycTypeSmallTuple)
	writer.tag(byte(constantCount))
	writer.tag(pycTypeNone)
	writer.code("greet", "module.py", 1, []byte{0x7c, 0x00, 0x53, 0x00})
	if extra != nil {
		extra(writer)
	}
	writer.emptyTuple()
	writer.emptyTuple()
	writer.emptyTuple()
	writer.emptyTuple()
	writer.shortASCII("module.py")
	writer.shortASCII("<module>")
	writer.int32(1)
	writer.byteString(nil)
	return append(header, writer.buffer.Bytes()...)
}

func (writer *pycFixtureWriter) code(
	name string,
	filename string,
	argCount int32,
	code []byte,
) {
	writer.referenceTag(pycTypeCode)
	for _, value := range []int32{argCount, 0, 0, argCount, 2, 0x43} {
		writer.int32(value)
	}
	writer.byteString(code)
	writer.referenceTag(pycTypeSmallTuple)
	writer.tag(1)
	writer.tag(pycTypeNone)
	writer.emptyTuple()
	writer.referenceTag(pycTypeSmallTuple)
	writer.tag(byte(argCount))
	if argCount > 0 {
		writer.shortASCII("name")
	}
	writer.emptyTuple()
	writer.emptyTuple()
	writer.shortASCII(filename)
	writer.shortASCII(name)
	writer.int32(2)
	writer.byteString([]byte{0x02, 0x01})
}

func (writer *pycFixtureWriter) emptyTuple() {
	writer.referenceTag(pycTypeSmallTuple)
	writer.tag(0)
}

func (writer *pycFixtureWriter) byteString(payload []byte) {
	writer.referenceTag(pycTypeBytes)
	writer.int32(int32(len(payload)))
	_, _ = writer.buffer.Write(payload)
}

func (writer *pycFixtureWriter) shortASCII(value string) {
	writer.referenceTag(pycTypeShortASCII)
	writer.tag(byte(len(value)))
	_, _ = writer.buffer.WriteString(value)
}

func (writer *pycFixtureWriter) referenceTag(kind byte) int {
	index := writer.references
	writer.references++
	writer.tag(kind | pycMarshalReferenceFlag)
	return index
}

func (writer *pycFixtureWriter) tag(value byte) {
	_ = writer.buffer.WriteByte(value)
}

func (writer *pycFixtureWriter) int32(value int32) {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], uint32(value))
	_, _ = writer.buffer.Write(encoded[:])
}

func writeNestedPYCList(writer *pycFixtureWriter, depth int) {
	if depth == 0 {
		writer.tag(pycTypeNone)
		return
	}
	writer.referenceTag(pycTypeList)
	writer.int32(1)
	writeNestedPYCList(writer, depth-1)
}

func pycFixtureHeader(magic uint16, hashBased bool) []byte {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint16(header[:2], magic)
	copy(header[2:4], "\r\n")
	if hashBased {
		binary.LittleEndian.PutUint32(header[4:8], 3)
		copy(header[8:16], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	} else {
		binary.LittleEndian.PutUint32(header[8:12], 1_700_000_000)
		binary.LittleEndian.PutUint32(header[12:16], 42)
	}
	return header
}

func appendInt32(payload []byte, value int32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], uint32(value))
	return append(payload, encoded[:]...)
}

func executePYCFixture(
	t *testing.T,
	payload []byte,
	config PYCConfig,
	limits Limits,
) (Result, string, error) {
	t.Helper()
	inputDirectory := t.TempDir()
	workspace := t.TempDir()
	inputPath := filepath.Join(inputDirectory, "fixture.pyc")
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	engine, err := NewPYCFallbackEngine(config)
	if err != nil {
		return Result{}, workspace, err
	}
	result, err := Execute(context.Background(), engine, Request{
		Input: Input{
			Path: inputPath, SHA256: hex.EncodeToString(digest[:]),
			Format: FormatPYC, SizeBytes: int64(len(payload)),
		},
		Workspace: workspace, Limits: limits,
		ArtifactValidator: mustPYCValidator(t),
	})
	return result, workspace, err
}

func mustPYCValidator(t *testing.T) ArtifactValidator {
	t.Helper()
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-python": SourceInspectorFunc(InspectUTF8Source),
	})
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func readPYCIndexFixture(
	t *testing.T,
	workspace string,
	artifact Artifact,
) (pycIndexDocument, []byte) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(
		workspace, filepath.FromSlash(artifact.RelativePath),
	))
	if err != nil {
		t.Fatal(err)
	}
	var document pycIndexDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document, payload
}
