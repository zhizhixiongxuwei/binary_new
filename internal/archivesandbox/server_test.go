package archivesandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"binaryscan/internal/extract"
)

func TestClientServerIdentifyAndExtract(t *testing.T) {
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(temporaryRoot, "binaryscan-as-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socketDirectory := filepath.Join(root, "socket")
	inputRoot := filepath.Join(root, "input")
	outputRoot := filepath.Join(root, "output")
	runRoot := filepath.Join(root, "run")
	for _, directory := range []string{
		socketDirectory, inputRoot, outputRoot, runRoot,
	} {
		if err := os.Mkdir(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	fileTool := writeTestTool(t, root, "file-tool", `#!/bin/sh
printf '%s\n' 'application/x-test-archive'
`)
	sevenZipTool := writeTestTool(t, root, "7zz-tool", `#!/bin/sh
output=''
for argument do
  case "$argument" in
    -o*) output=${argument#-o} ;;
  esac
done
test -n "$output" || exit 2
/bin/mkdir -p "$output/nested"
printf '%s' 'seven-zip-payload' > "$output/nested/payload.txt"
`)
	libarchiveTool := writeTestTool(t, root, "bsdtar-tool", `#!/bin/sh
output=''
previous=''
for argument do
  if test "$previous" = '--directory'; then output=$argument; fi
  previous=$argument
done
test -n "$output" || exit 2
/bin/mkdir -p "$output/cabinet"
printf '%s' 'cab-payload' > "$output/cabinet/payload.txt"
`)
	socketPath := filepath.Join(socketDirectory, "archive.sock")
	server, err := NewServer(ServerConfig{
		SocketPath:           socketPath,
		SocketMode:           0o600,
		InputRoot:            inputRoot,
		OutputRoot:           outputRoot,
		RunRoot:              runRoot,
		LibmagicExecutable:   fileTool,
		LibmagicVersion:      "test-magic-1",
		LibarchiveExecutable: libarchiveTool,
		LibarchiveVersion:    "test-archive-1",
		SevenZipExecutable:   sevenZipTool,
		SevenZipVersion:      "test-7zz-1",
		MaxConcurrent:        1,
		TerminationGrace:     100 * time.Millisecond,
		ReleaseTimeout:       time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	waitForServerPath(t, socketPath, serveResult)

	client, err := NewClient(ClientConfig{
		SocketPath: socketPath,
		InputRoot:  inputRoot,
		OutputRoot: outputRoot,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := []byte("untrusted input")
	classified, err := client.Classify(
		context.Background(),
		bytes.NewReader(payload),
		int64(len(payload)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if classified.MIMEType != "application/x-test-archive" ||
		classified.Version != "test-magic-1" {
		t.Fatalf("Classify() = %#v", classified)
	}

	sourcePath := filepath.Join(root, "source.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, test := range []struct {
		name     string
		engine   string
		format   string
		relative string
		want     string
	}{
		{
			name: "7z", engine: extract.ExternalEngineSevenZip,
			format: "7z", relative: "nested/payload.txt",
			want: "seven-zip-payload",
		},
		{
			name: "cab", engine: extract.ExternalEngineLibarchive,
			format: "cab", relative: "cabinet/payload.txt",
			want: "cab-payload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := source.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			session, err := client.Extract(
				context.Background(),
				source,
				int64(len(payload)),
				extract.ExternalArchiveRequest{
					Engine:             test.engine,
					Format:             test.format,
					MaxEntries:         10,
					MaxEntryBytes:      1024,
					MaxExpandedBytes:   4096,
					MaxDurationSeconds: 5,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			outputPath := session.OutputPath()
			contents, err := os.ReadFile(filepath.Join(outputPath, test.relative))
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != test.want {
				t.Fatalf("extracted payload = %q", contents)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			waitForPath(t, outputPath, false)
		})
	}

	cancel()
	if err := <-serveResult; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestLibarchiveCommandUsesSecureExtractionFlags(t *testing.T) {
	server := &Server{
		libarchive: executableIdentity{path: "/usr/bin/bsdtar"},
	}
	_, arguments, err := server.command(Request{
		Engine: EngineLibarchive,
	}, "/sandbox/output/request")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"--safe-writes",
		"--no-same-owner",
		"--no-same-permissions",
		"--no-acls",
		"--no-fflags",
		"--no-xattrs",
		"--no-mac-metadata",
	} {
		if !slices.Contains(arguments, required) {
			t.Errorf("libarchive arguments %q omit %q", arguments, required)
		}
	}
	if strings.Join(arguments, " ") != strings.Join([]string{
		"--extract", "--file", "/proc/self/fd/3",
		"--directory", "/sandbox/output/request",
		"--safe-writes", "--no-same-owner", "--no-same-permissions",
		"--no-acls", "--no-fflags", "--no-xattrs", "--no-mac-metadata",
	}, " ") {
		t.Fatalf("libarchive arguments changed: %q", arguments)
	}
}

func TestRequestRejectsEngineFormatConfusion(t *testing.T) {
	request := Request{
		SchemaVersion:      SchemaVersion,
		RequestID:          strings.Repeat("a", 32),
		Operation:          OperationExtract,
		Engine:             EngineSevenZip,
		Format:             "cab",
		InputName:          strings.Repeat("a", 32) + ".bin",
		InputSHA256:        strings.Repeat("b", 64),
		InputSizeBytes:     1,
		OutputName:         strings.Repeat("a", 32),
		MaxEntries:         1,
		MaxEntryBytes:      1,
		MaxExpandedBytes:   1,
		MaxDurationSeconds: 1,
	}
	if err := request.validate(); err == nil {
		t.Fatalf("validate() error = %v, want engine/format rejection", err)
	}
}

func writeTestTool(t *testing.T, root, name, contents string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForPath(t *testing.T, path string, present bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := os.Lstat(path)
		if present && err == nil || !present && errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("path %q present=%t, last error=%v", path, present, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForServerPath(t *testing.T, path string, result <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case err := <-result:
			t.Fatalf("archive sandbox exited before socket publication: %v", err)
		default:
		}
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect archive sandbox socket %q: %v", path, err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("archive sandbox socket %q was not published", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
