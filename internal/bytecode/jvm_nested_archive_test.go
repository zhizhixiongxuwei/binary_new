package bytecode

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestJVMFallbackEngineEnumeratesWARLibraryClasses(t *testing.T) {
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Library.class", payload: generatedJVMClass(t, "pkg/Library", "call", 61)},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{
			name:    "WEB-INF/classes/web/Controller.class",
			payload: generatedJVMClass(t, "web/Controller", "serve", 61),
		},
		{name: "WEB-INF/lib/library.jar", payload: library, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || len(result.Classes) != 2 ||
		len(result.Artifacts) != 2 || len(result.ClassErrors) != 0 {
		t.Fatalf("WAR result = %#v", result)
	}
	wantPaths := map[string]string{
		"web.Controller": "WEB-INF/classes/web/Controller.class",
		"pkg.Library":    "WEB-INF/lib/library.jar!/pkg/Library.class",
	}
	for _, class := range result.Classes {
		if len(class.ArtifactIDs) != 1 {
			t.Fatalf("class artifacts = %#v", class)
		}
		var artifact Artifact
		for _, candidate := range result.Artifacts {
			if candidate.ID == class.ArtifactIDs[0] {
				artifact = candidate
			}
		}
		document, _ := readJVMIndexFixture(t, workspace, artifact)
		if document.Class.EntryPath != wantPaths[class.BinaryName] {
			t.Fatalf("entry path for %q = %q", class.BinaryName, document.Class.EntryPath)
		}
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineEnumeratesRecursiveEARModules(t *testing.T) {
	domain := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "domain/Entity.class", payload: generatedJVMClass(t, "domain/Entity", "id", 61)},
	})
	service := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "private/modules/domain.jar", payload: domain, store: true},
	})
	ear := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "arbitrary/location/service.jar", payload: service, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, ear, FormatEAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusBytecodeOnly || len(result.Classes) != 1 ||
		result.Classes[0].BinaryName != "domain.Entity" {
		t.Fatalf("EAR result = %#v", result)
	}
	document, _ := readJVMIndexFixture(t, workspace, result.Artifacts[0])
	if document.Class.EntryPath !=
		"arbitrary/location/service.jar!/private/modules/domain.jar!/domain/Entity.class" {
		t.Fatalf("recursive EAR entry path = %q", document.Class.EntryPath)
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineKeepsSameNamedNestedClassesDistinct(t *testing.T) {
	class := generatedJVMClass(t, "pkg/Same", "run", 61)
	first := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Same.class", payload: class},
	})
	second := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Same.class", payload: class},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/first.jar", payload: first, store: true},
		{name: "WEB-INF/lib/second.jar", payload: second, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(result.Classes) != 2 || len(result.Artifacts) != 2 ||
		result.Classes[0].Key == result.Classes[1].Key ||
		result.Artifacts[0].ID == result.Artifacts[1].ID {
		t.Fatalf("same-named nested classes collided: %#v", result)
	}
	paths := make(map[string]struct{})
	for _, artifact := range result.Artifacts {
		document, _ := readJVMIndexFixture(t, workspace, artifact)
		paths[document.Class.EntryPath] = struct{}{}
	}
	for _, want := range []string{
		"WEB-INF/lib/first.jar!/pkg/Same.class",
		"WEB-INF/lib/second.jar!/pkg/Same.class",
	} {
		if _, exists := paths[want]; !exists {
			t.Fatalf("nested paths = %#v, missing %q", paths, want)
		}
	}
}

func TestJVMFallbackEngineEscapesCompositePathSeparators(t *testing.T) {
	class := generatedJVMClass(t, "pkg/Same", "run", 61)
	nested := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Same.class", payload: class},
	})
	ear := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "a.jar", payload: nested, store: true},
		{name: "a.jar!/pkg/Same.class", payload: class},
	})
	result, workspace, err := executeJVMFixture(
		t, ear, FormatEAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(result.Classes) != 2 || result.Classes[0].Key == result.Classes[1].Key {
		t.Fatalf("composite-path identities collided: %#v", result.Classes)
	}
	paths := make(map[string]struct{})
	for _, artifact := range result.Artifacts {
		document, _ := readJVMIndexFixture(t, workspace, artifact)
		paths[document.Class.EntryPath] = struct{}{}
	}
	for _, want := range []string{
		"a.jar!/pkg/Same.class",
		"a.jar!!/pkg/Same.class",
	} {
		if _, exists := paths[want]; !exists {
			t.Fatalf("escaped paths = %#v, missing %q", paths, want)
		}
	}
}

func TestJVMFallbackEngineSelectsMultiReleaseClassInsideWAR(t *testing.T) {
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "META-INF/MANIFEST.MF", payload: []byte(
			"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
		)},
		{name: "pkg/Choice.class", payload: generatedJVMClass(t, "pkg/Choice", "base", 52)},
		{
			name:    "META-INF/versions/17/pkg/Choice.class",
			payload: generatedJVMClass(t, "pkg/Choice", "java17", 61),
		},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/choice.jar", payload: library, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{TargetJavaRelease: 21}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(result.Classes) != 1 || len(result.Classes[0].Methods) != 1 ||
		result.Classes[0].Methods[0].Name != "java17" {
		t.Fatalf("nested multi-release class = %#v", result.Classes)
	}
	document, _ := readJVMIndexFixture(t, workspace, result.Artifacts[0])
	if document.Class.SelectedRelease != 17 || document.Class.EntryPath !=
		"WEB-INF/lib/choice.jar!/META-INF/versions/17/pkg/Choice.class" {
		t.Fatalf("nested multi-release index = %#v", document.Class)
	}
}

func TestJVMFallbackEngineIsolatesNestedArchiveSecurityFailures(t *testing.T) {
	validClass := generatedJVMClass(t, "web/Good", "run", 61)
	badClass := generatedJVMClass(t, "bad/Bad", "run", 61)
	tests := []struct {
		name   string
		nested []byte
	}{
		{
			name: "traversal",
			nested: generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "../Bad.class", payload: badClass},
			}),
		},
		{
			name: "duplicate",
			nested: generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "bad/Bad.class", payload: badClass},
				{name: "bad/Bad.class", payload: badClass},
			}),
		},
		{
			name:   "special",
			nested: generatedJVMSpecialArchive(t),
		},
		{
			name: "encrypted",
			nested: markJVMZIPEncrypted(t, generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "bad/Bad.class", payload: badClass, store: true},
			})),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
				{name: "WEB-INF/classes/web/Good.class", payload: validClass},
				{name: "WEB-INF/lib/bad.jar", payload: test.nested, store: true},
			})
			result, workspace, err := executeJVMFixture(
				t, war, FormatWAR, JVMEngineConfig{}, Limits{},
			)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if result.Status != StatusPartial || len(result.Classes) != 2 ||
				len(result.Artifacts) != 1 || len(result.ClassErrors) != 1 ||
				result.ClassErrors[0].Code != "nested_archive_invalid" {
				t.Fatalf("nested security result = %#v", result)
			}
			failures := 0
			for _, class := range result.Classes {
				if class.Kind == KindModule && class.Status == ClassFailed {
					failures++
				}
			}
			if failures != 1 {
				t.Fatalf("nested module failures = %#v", result.Classes)
			}
			assertNoJVMArchiveScratch(t, workspace)
		})
	}
}

func TestJVMFallbackEnginePublishesAllFailedNestedArchivePartial(t *testing.T) {
	bad := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "../Bad.class", payload: []byte("bad")},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/bad.jar", payload: bad, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.Classes) != 1 ||
		result.Classes[0].Kind != KindModule ||
		result.Classes[0].Status != ClassFailed || len(result.Artifacts) != 0 ||
		len(result.ClassErrors) != 1 {
		t.Fatalf("all-failed nested result = %#v", result)
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineReportsUnreadableNestedArchive(t *testing.T) {
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Hidden.class", payload: generatedJVMClass(t, "pkg/Hidden", "run", 61)},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/corrupt.jar", payload: library, store: true},
	})
	war = corruptFirstJVMZIPEntryPayload(t, war)
	result, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.Classes) != 1 ||
		result.Classes[0].Kind != KindModule || len(result.ClassErrors) != 1 ||
		result.ClassErrors[0].Code != "nested_archive_read_failed" {
		t.Fatalf("unreadable nested result = %#v", result)
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineIsolatesMalformedClassesInsideNestedJAR(t *testing.T) {
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Bad.class", payload: []byte("not a class"), store: true},
		{name: "pkg/Good.class", payload: generatedJVMClass(t, "pkg/Good", "run", 61)},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/library.jar", payload: library, store: true},
	})
	result, _, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.Classes) != 2 ||
		len(result.Artifacts) != 1 || len(result.ClassErrors) != 1 ||
		result.ClassErrors[0].Code != "invalid_class" {
		t.Fatalf("nested malformed class result = %#v", result)
	}
}

func TestJVMFallbackEngineEnforcesSharedNestedArchiveLimits(t *testing.T) {
	class := generatedJVMClass(t, "pkg/Only", "run", 61)
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Only.class", payload: class, store: true},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/library.jar", payload: library, store: true},
	})
	tests := []struct {
		name   string
		config JVMEngineConfig
	}{
		{
			name:   "entry count across layers",
			config: JVMEngineConfig{MaxArchiveEntries: 1},
		},
		{
			name: "expanded bytes across layers",
			config: JVMEngineConfig{
				MaxExpandedBytes: int64(len(library) + len(class) - 1),
				MaxClassBytes:    int64(len(class)),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, workspace, err := executeJVMFixture(
				t, war, FormatWAR, test.config, Limits{},
			)
			if !errors.Is(err, ErrJVMArchiveLimit) {
				t.Fatalf("Execute() error = %v, want %v", err, ErrJVMArchiveLimit)
			}
			assertNoJVMArchiveScratch(t, workspace)
		})
	}
}

func TestJVMFallbackEngineEnforcesCumulativeNestedCompressionRatio(t *testing.T) {
	library := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "large.bin", payload: bytes.Repeat([]byte("x"), 16<<10), store: true},
	})
	war := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "WEB-INF/lib/library.jar", payload: library, store: true},
	})
	_, workspace, err := executeJVMFixture(
		t, war, FormatWAR, JVMEngineConfig{MaxCompressionRatio: 1}, Limits{},
	)
	if !errors.Is(err, ErrJVMArchiveLimit) ||
		!strings.Contains(err.Error(), "cumulative compression ratio") {
		t.Fatalf("Execute() error = %v, want cumulative ratio limit", err)
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineReportsNestedDepthAsPartial(t *testing.T) {
	deepest := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "pkg/Hidden.class", payload: generatedJVMClass(t, "pkg/Hidden", "run", 61)},
	})
	middle := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "lib/deep.jar", payload: deepest, store: true},
	})
	ear := generatedJVMArchive(t, []jvmZIPFixtureEntry{
		{name: "modules/middle.jar", payload: middle, store: true},
	})
	result, workspace, err := executeJVMFixture(
		t, ear, FormatEAR, JVMEngineConfig{MaxArchiveDepth: 2}, Limits{},
	)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Status != StatusPartial || len(result.Classes) != 1 ||
		result.Classes[0].Kind != KindModule || len(result.ClassErrors) != 1 ||
		result.ClassErrors[0].Code != "nested_archive_depth_exceeded" ||
		result.Classes[0].DisplayName != "modules/middle.jar!/lib/deep.jar" {
		t.Fatalf("depth-limited result = %#v", result)
	}
	assertNoJVMArchiveScratch(t, workspace)
}

func TestJVMFallbackEngineDepthIsPartOfIdentity(t *testing.T) {
	defaults, err := NewJVMFallbackEngine(JVMEngineConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if defaults.Config().MaxArchiveDepth != DefaultJVMMaxArchiveDepth ||
		DefaultJVMMaxArchiveDepth != 10 {
		t.Fatalf("default archive depth = %d", defaults.Config().MaxArchiveDepth)
	}
	shallow, err := NewJVMFallbackEngine(JVMEngineConfig{MaxArchiveDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	deep, err := NewJVMFallbackEngine(JVMEngineConfig{MaxArchiveDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if shallow.ConfigFingerprint() == deep.ConfigFingerprint() ||
		shallow.Descriptor() == deep.Descriptor() {
		t.Fatal("archive depth is missing from engine identity")
	}
	if _, err := NewJVMFallbackEngine(JVMEngineConfig{
		MaxArchiveDepth: DefaultJVMMaxArchiveDepth + 1,
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("depth ceiling error = %v", err)
	}
}

func generatedJVMSpecialArchive(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	header := &zip.FileHeader{Name: "bad/link.jar", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("target")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func markJVMZIPEncrypted(t *testing.T, archive []byte) []byte {
	t.Helper()
	mutated := append([]byte(nil), archive...)
	foundLocal, foundDirectory := false, false
	for offset := 0; offset+10 <= len(mutated); offset++ {
		signature := binary.LittleEndian.Uint32(mutated[offset : offset+4])
		switch signature {
		case 0x04034b50:
			flags := binary.LittleEndian.Uint16(mutated[offset+6 : offset+8])
			binary.LittleEndian.PutUint16(mutated[offset+6:offset+8], flags|1)
			foundLocal = true
		case jvmZIPDirectoryHeaderSignature:
			flags := binary.LittleEndian.Uint16(mutated[offset+8 : offset+10])
			binary.LittleEndian.PutUint16(mutated[offset+8:offset+10], flags|1)
			foundDirectory = true
		}
	}
	if !foundLocal || !foundDirectory {
		t.Fatal("generated ZIP headers were not found")
	}
	return mutated
}

func corruptFirstJVMZIPEntryPayload(t *testing.T, archive []byte) []byte {
	t.Helper()
	mutated := append([]byte(nil), archive...)
	if len(mutated) < 30 || binary.LittleEndian.Uint32(mutated[:4]) != 0x04034b50 {
		t.Fatal("generated ZIP local header is missing")
	}
	nameLength := int(binary.LittleEndian.Uint16(mutated[26:28]))
	extraLength := int(binary.LittleEndian.Uint16(mutated[28:30]))
	payloadOffset := 30 + nameLength + extraLength
	if payloadOffset >= len(mutated) {
		t.Fatal("generated ZIP payload is missing")
	}
	mutated[payloadOffset] ^= 0xff
	return mutated
}

func assertNoJVMArchiveScratch(t *testing.T, workspace string) {
	t.Helper()
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".jvm-archive-") {
			t.Fatalf("JVM archive scratch leaked: %q", entry.Name())
		}
	}
}
