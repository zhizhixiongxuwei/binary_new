package imageextract

import (
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestPackageHasNoHostMountLoopOrShellExecutionCapability(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate package source")
	}
	directory := filepath.Dir(currentFile)
	files, err := filepath.Glob(filepath.Join(directory, "*.go"))
	if err != nil {
		t.Fatalf("glob package: %v", err)
	}
	forbiddenImports := map[string]struct{}{
		"os":                    {},
		"os/exec":               {},
		"syscall":               {},
		"unsafe":                {},
		"golang.org/x/sys/unix": {},
	}
	set := token.NewFileSet()
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(set, filename, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", filename, err)
			}
			if _, forbidden := forbiddenImports[path]; forbidden {
				t.Errorf("%s imports forbidden host capability %q", filename, path)
			}
		}
	}
}

func TestPublicRequestsExposeNoExecutableDeviceOrHostDestination(t *testing.T) {
	readerAt := reflect.TypeOf((*io.ReaderAt)(nil)).Elem()
	requestType := reflect.TypeOf(Request{})
	source, found := requestType.FieldByName("Source")
	if !found || source.Type != readerAt {
		t.Fatalf("Request.Source type = %v, want io.ReaderAt", source.Type)
	}
	for _, value := range []any{Request{}, ToolInvocation{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := strings.ToLower(typeOf.Field(index).Name)
			for _, forbidden := range []string{
				"executable", "command", "environment", "device", "destination",
			} {
				if strings.Contains(name, forbidden) {
					t.Errorf("%s exposes forbidden field %s", typeOf, name)
				}
			}
		}
	}

	backendType := reflect.TypeOf((*ToolBackend)(nil)).Elem()
	methods := make([]string, backendType.NumMethod())
	for index := range methods {
		methods[index] = backendType.Method(index).Name
	}
	if !reflect.DeepEqual(methods, []string{"RunFLS", "RunMMLS"}) {
		t.Fatalf("ToolBackend methods = %v", methods)
	}
}
