package archivesandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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
	server.rawToolExecutionForTests = true
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
			if runtime.GOOS == "linux" && test.name == "7z" {
				entries, err := os.ReadDir(outputRoot)
				if err != nil || len(entries) != 1 {
					t.Fatalf("output root entries = %v/%v", entries, err)
				}
				name := entries[0].Name()
				held := filepath.Join(outputRoot, name+".held")
				if err := os.Rename(filepath.Join(outputRoot, name), held); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(outputRoot, name), 0o700); err != nil {
					t.Fatal(err)
				}
				sentinel := filepath.Join(outputRoot, name, "replacement")
				if err := os.WriteFile(sentinel, []byte("attacker"), 0o600); err != nil {
					t.Fatal(err)
				}
				contents, err = os.ReadFile(filepath.Join(outputPath, test.relative))
				if err != nil || string(contents) != test.want {
					t.Fatalf("descriptor output changed after replacement: %q/%v", contents, err)
				}
				if err := session.Close(); err == nil {
					t.Fatal("session accepted a replaced output name")
				}
				contents, err = os.ReadFile(sentinel)
				if err != nil || string(contents) != "attacker" {
					t.Fatalf("replacement was removed or changed: %q/%v", contents, err)
				}
				_ = os.RemoveAll(filepath.Join(outputRoot, name))
				_ = os.RemoveAll(held)
				waitForPath(t, outputPath, false)
				return
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

func TestOutputLeaseIsHeldUntilClientAcknowledges(t *testing.T) {
	server, client, source := newServingExtractionFixture(t, `#!/bin/sh
output=''
for argument do case "$argument" in -o*) output=${argument#-o} ;; esac; done
printf '%s' 'leased' > "$output/payload.txt"
`)
	server.config.ReleaseTimeout = 25 * time.Millisecond
	session, err := client.Extract(
		context.Background(), source, 1,
		extract.ExternalArchiveRequest{
			Engine: extract.ExternalEngineSevenZip, Format: "7z",
			MaxEntries: 2, MaxEntryBytes: 1024,
			MaxExpandedBytes: 1024, MaxDurationSeconds: 5,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	outputPath := session.OutputPath()
	time.Sleep(4 * server.config.ReleaseTimeout)
	contents, err := os.ReadFile(filepath.Join(outputPath, "payload.txt"))
	if err != nil || string(contents) != "leased" {
		t.Fatalf("unacknowledged output was released early: %q/%v", contents, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	waitForPath(t, outputPath, false)
}

func TestOutputCapacityViolationKillsToolImmediately(t *testing.T) {
	server, client, source := newServingExtractionFixture(t, `#!/bin/sh
output=''
for argument do case "$argument" in -o*) output=${argument#-o} ;; esac; done
trap '' TERM
while :; do printf '%01024d' 0 >> "$output/bomb"; done
`)
	server.config.TerminationGrace = 2 * time.Second
	server.config.MonitorInterval = 5 * time.Millisecond
	started := time.Now()
	_, err := client.Extract(
		context.Background(), source, 1,
		extract.ExternalArchiveRequest{
			Engine: extract.ExternalEngineSevenZip, Format: "7z",
			MaxEntries: 2, MaxEntryBytes: 1024,
			MaxExpandedBytes: 1024, MaxDurationSeconds: 10,
		},
	)
	if err == nil {
		t.Fatal("capacity-violating tool unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed >= server.config.TerminationGrace-250*time.Millisecond {
		t.Fatalf("capacity violation waited for graceful termination: %s", elapsed)
	}
}

func TestFilesystemLowWaterViolationKillsToolImmediately(t *testing.T) {
	server, client, source := newServingExtractionFixture(t, `#!/bin/sh
output=''
for argument do case "$argument" in -o*) output=${argument#-o} ;; esac; done
trap '' TERM
while :; do /bin/sleep 1; done
`)
	server.config.TerminationGrace = 2 * time.Second
	server.config.MonitorInterval = 5 * time.Millisecond
	server.freeSpaceCheck = func(*os.File, int64) error {
		return errors.New("simulated low-water breach")
	}
	started := time.Now()
	_, err := client.Extract(
		context.Background(), source, 1,
		extract.ExternalArchiveRequest{
			Engine: extract.ExternalEngineSevenZip, Format: "7z",
			MaxEntries: 2, MaxEntryBytes: 1024,
			MaxExpandedBytes: 1024, MaxDurationSeconds: 10,
		},
	)
	if err == nil {
		t.Fatal("low-water violating tool unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("low-water breach waited for graceful termination: %s", elapsed)
	}
}

func TestClientCancellationKillsToolImmediately(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	script := fmt.Sprintf(`#!/bin/sh
output=''
for argument do case "$argument" in -o*) output=${argument#-o} ;; esac; done
: > %q
trap '' TERM
while :; do /bin/sleep 1; done
`, marker)
	server, client, source := newServingExtractionFixture(t, script)
	server.config.TerminationGrace = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := client.Extract(ctx, source, 1, extract.ExternalArchiveRequest{
			Engine: extract.ExternalEngineSevenZip, Format: "7z",
			MaxEntries: 2, MaxEntryBytes: 1024,
			MaxExpandedBytes: 1024, MaxDurationSeconds: 10,
		})
		result <- err
	}()
	waitForPath(t, marker, true)
	started := time.Now()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Extract() error = %v, want context cancellation", err)
		}
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("cancelled client waited for graceful tool shutdown: %s", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled client left archive tool running")
	}
}

func newServingExtractionFixture(
	t *testing.T,
	toolScript string,
) (*Server, *Client, *os.File) {
	t.Helper()
	server, roots := newUnitServer(t, toolScript)
	server.config.SocketPath = filepath.Join(roots.root, "socket", "archive.sock")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	waitForServerPath(t, server.config.SocketPath, result)
	t.Cleanup(func() {
		cancel()
		if err := <-result; err != nil {
			t.Errorf("Serve() cleanup error = %v", err)
		}
		_ = server.Close()
	})
	client, err := NewClient(ClientConfig{
		SocketPath: server.config.SocketPath,
		InputRoot:  roots.input,
		OutputRoot: filepath.Join(roots.root, "output"),
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	sourcePath := filepath.Join(roots.root, "source")
	if err := os.WriteFile(sourcePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	return server, client, source
}

func TestPrivateInputSnapshotCannotBeMutatedThroughStagedName(t *testing.T) {
	server, roots := newUnitServer(t, `#!/bin/sh
exit 0
`)
	defer server.Close()
	run, err := server.createRunDirectory(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	original := []byte("verified-original")
	mutated := []byte("mutated-original!")
	if len(original) != len(mutated) {
		t.Fatal("test mutation must preserve size")
	}
	inputName := strings.Repeat("b", 32) + ".bin"
	inputPath := filepath.Join(roots.input, inputName)
	if err := os.WriteFile(inputPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	snapshot, err := server.openVerifiedInput(context.Background(), Request{
		InputName: inputName, InputSizeBytes: int64(len(original)),
		InputSHA256: hex.EncodeToString(digest[:]),
	}, run)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	snapshotInfo, err := run.root.Lstat("input.snapshot")
	if err != nil || !snapshotInfo.Mode().IsRegular() || snapshotInfo.Mode().Perm() != 0o400 {
		t.Fatalf("private snapshot was not sealed: %#v, %v", snapshotInfo, err)
	}
	if err := os.WriteFile(inputPath, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("private snapshot changed to %q", got)
	}
}

func TestServerStartupClearsStaleRootsWithoutFollowingSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	root, err = os.MkdirTemp(root, "binaryscan-as-stale-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input")
	output := filepath.Join(root, "output")
	run := filepath.Join(root, "run")
	socket := filepath.Join(root, "socket")
	for _, directory := range []string{input, output, run, socket} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "stale"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(input, "outside-link")); err != nil {
		t.Fatal(err)
	}
	tool := writeTestTool(t, root, "noop", "#!/bin/sh\nexit 0\n")
	server, err := NewServer(ServerConfig{
		SocketPath: filepath.Join(socket, "archive.sock"), SocketMode: 0o600,
		InputRoot: input, OutputRoot: output, RunRoot: run,
		LibmagicExecutable: tool, LibmagicVersion: "test",
		LibarchiveExecutable: tool, LibarchiveVersion: "test",
		SevenZipExecutable: tool, SevenZipVersion: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, directory := range []string{input, output, run} {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("stale root %s was not empty: %v/%v", directory, entries, err)
		}
	}
	contents, err := os.ReadFile(sentinel)
	if err != nil || string(contents) != "preserve" {
		t.Fatalf("outside sentinel changed: %q/%v", contents, err)
	}
}

func TestToolTimeoutDoesNotKillUnrelatedPeerOrPoisonServer(t *testing.T) {
	markerRoot := t.TempDir()
	marker := filepath.Join(markerRoot, "first")
	script := fmt.Sprintf(`#!/bin/sh
if test ! -f %q; then
	: > %q
  /bin/sleep 5
fi
exit 0
`, marker, marker)
	server, roots := newUnitServer(t, script)
	defer server.Close()
	unrelated := exec.Command("/bin/sh", "-c", "sleep 10")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = unrelated.Process.Kill()
		_, _ = unrelated.Process.Wait()
	}()
	inputPath := filepath.Join(roots.root, "input-file")
	if err := os.WriteFile(inputPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Engine: EngineSevenZip, MaxDurationSeconds: 2}
	run, err := server.createRunDirectory(strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	result := server.runTool(context.Background(), request, input, run, "", nil, nil, nil)
	_ = input.Close()
	_ = run.Close()
	if result.err == nil || !result.forced {
		t.Fatalf("timed out tool result = %+v", result)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("timed out tool did not publish its marker: %v", err)
	}
	if err := unrelated.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		t.Fatalf("unrelated peer was killed: %v", err)
	}
	input, err = os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	run, err = server.createRunDirectory(strings.Repeat("d", 32))
	if err != nil {
		t.Fatal(err)
	}
	request.MaxDurationSeconds = 3
	result = server.runTool(context.Background(), request, input, run, "", nil, nil, nil)
	_ = input.Close()
	_ = run.Close()
	if result.err != nil {
		t.Fatalf("server did not accept a request after timeout: %v", result.err)
	}
}

type unitServerRoots struct {
	root  string
	input string
}

func newUnitServer(t *testing.T, toolScript string) (*Server, unitServerRoots) {
	t.Helper()
	temporaryRoot, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(temporaryRoot, "binaryscan-as-unit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	input := filepath.Join(root, "input")
	output := filepath.Join(root, "output")
	run := filepath.Join(root, "run")
	socket := filepath.Join(root, "socket")
	for _, directory := range []string{input, output, run, socket} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tool := writeTestTool(t, root, "tool", toolScript)
	server, err := NewServer(ServerConfig{
		SocketPath: filepath.Join(socket, "archive.sock"), SocketMode: 0o600,
		InputRoot: input, OutputRoot: output, RunRoot: run,
		LibmagicExecutable: tool, LibmagicVersion: "test",
		LibarchiveExecutable: tool, LibarchiveVersion: "test",
		SevenZipExecutable: tool, SevenZipVersion: "test",
		TerminationGrace: 100 * time.Millisecond,
		MonitorInterval:  10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.rawToolExecutionForTests = true
	return server, unitServerRoots{root: root, input: input}
}

func TestLibarchiveCommandUsesSecureExtractionFlags(t *testing.T) {
	server := &Server{
		config:     ServerConfig{RunRoot: "/sandbox/run"},
		libarchive: executableIdentity{path: "/usr/bin/bsdtar"},
	}
	_, arguments, err := server.command(Request{
		Engine: EngineLibarchive, RequestID: strings.Repeat("a", 32),
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
		"--extract", "--file", "/sandbox/run/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/input.snapshot",
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
		MinimumFreeBytes:   1,
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
