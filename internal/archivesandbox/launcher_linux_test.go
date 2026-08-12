//go:build linux

package archivesandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"binaryscan/internal/extract"
	"golang.org/x/sys/unix"
)

const (
	launcherProbeMode = "__binaryscan_archive_launcher_probe_v1"
	launcherTestEnv   = "BINARYSCAN_LINUX_SANDBOX_INTEGRATION"
)

func TestMain(m *testing.M) {
	if handled, err := MaybeRunToolLauncher(os.Args); handled {
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		os.Exit(0)
	}
	if len(os.Args) >= 2 && os.Args[1] == launcherProbeMode {
		os.Exit(runLauncherProbe(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func TestLinuxLauncherRejectsMalformedInvocation(t *testing.T) {
	for _, arguments := range [][]string{
		{toolLauncherMode},
		{"5", "3", "4", "5", "1", "536870912", "1", "--", "x"},
		{"6", "3", "4", "5", "0", "536870912", "1", "--", "x"},
		{"6", "3", "4", "5", "1", "1", "1", "--", "x"},
	} {
		if _, err := parseLinuxLauncherRequest(arguments); err == nil {
			t.Fatalf("parseLinuxLauncherRequest(%q) succeeded", arguments)
		}
	}
}

func TestLauncherOutputPath(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		want      string
	}{
		{[]string{"x", "-o/output", "--", "/input"}, "/output"},
		{[]string{"--extract", "--directory", "/output"}, "/output"},
		{[]string{"l", "--", "/input"}, ""},
	} {
		if got := launcherOutputPath(test.arguments); got != test.want {
			t.Fatalf("launcherOutputPath(%q) = %q, want %q", test.arguments, got, test.want)
		}
	}
}

func TestLauncherInputPath(t *testing.T) {
	for _, test := range []struct {
		arguments []string
		want      string
	}{
		{[]string{"x", "-o/output", "--", "/input"}, "/input"},
		{[]string{"--extract", "--file", "/input", "--directory", "/output"}, "/input"},
		{[]string{"--brief", "--", "/input"}, "/input"},
	} {
		if got := launcherInputPath(test.arguments); got != test.want {
			t.Fatalf("launcherInputPath(%q) = %q, want %q", test.arguments, got, test.want)
		}
	}
}

func TestParseLinuxLauncherRequestCapturesCanonicalPaths(t *testing.T) {
	request, err := parseLinuxLauncherRequest([]string{
		"6", "3", "4", "5", "1024", "536870912", "5", "--",
		"x", "-o/var/lib/binaryscan-archive/output/request", "--",
		"/var/lib/binaryscan-archive/run/request/input.snapshot",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.inputPath != "/var/lib/binaryscan-archive/run/request/input.snapshot" ||
		request.outputPath != "/var/lib/binaryscan-archive/output/request" {
		t.Fatalf("launcher paths = %q/%q", request.inputPath, request.outputPath)
	}
}

func TestCanonicalSandboxPath(t *testing.T) {
	if !canonicalSandboxPath("/var/lib/binaryscan-archive/run/request/input.snapshot", "run") ||
		!canonicalSandboxPath("/var/lib/binaryscan-archive/output/request", "output") {
		t.Fatal("canonical sandbox paths were rejected")
	}
	for _, path := range []string{
		"/var/lib/binaryscan-archive/run/../secrets", "/var/lib/binaryscan-archive/runaway/x", "/tmp/x",
	} {
		if canonicalSandboxPath(path, "run") {
			t.Fatalf("unsafe sandbox path %q was accepted", path)
		}
	}
}

func TestVirtualFilesystemMountRejectsOrdinaryTemporaryFilesystem(t *testing.T) {
	if virtualFilesystemMount(t.TempDir()) {
		t.Fatal("ordinary temporary filesystem was treated as a Docker Desktop bind mount")
	}
}

func TestLinuxLauncherInheritedDescriptorsRemainOpenAcrossExec(t *testing.T) {
	if os.Getenv(launcherTestEnv) != "1" {
		t.Skip("run inside the scanner tools image")
	}
	for _, path := range []string{"/usr/bin/7zz"} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("frozen archive tool %q is unavailable: %v", path, err)
		}
	}
	root := t.TempDir()
	inputPath := filepath.Join(root, "fixture.7z")
	payloadPath := filepath.Join(root, "payload.txt")
	if err := os.WriteFile(payloadPath, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/7zz", "a", "-bd", "-bb0", inputPath, payloadPath).CombinedOutput(); err != nil {
		t.Fatalf("create 7z fixture: %v: %s", err, output)
	}
	if err := os.Chmod(inputPath, 0o400); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	outputDirectory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer outputDirectory.Close()
	runDirectory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer runDirectory.Close()
	identity, err := validateExecutable("/usr/bin/7zz", "verified")
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{}
	command, cleanup, err := server.buildToolCommand(
		identity,
		[]string{"l", "-slt", "-ba", "--", "/proc/self/fd/3"},
		Request{Operation: OperationExtract, MaxEntryBytes: 1024, MaxDurationSeconds: 5},
		input, outputDirectory, runDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "Path = payload.txt") {
		t.Fatalf("launcher listing failed: %v: %s", err, output)
	}
}

func TestLinuxLauncherExtractsToCanonicalOutputPath(t *testing.T) {
	if os.Getenv(launcherTestEnv) != "1" {
		t.Skip("run inside the scanner tools image")
	}
	if _, err := os.Stat("/usr/bin/7zz"); err != nil {
		t.Skipf("frozen archive tool is unavailable: %v", err)
	}
	root := t.TempDir()
	inputPath := filepath.Join(root, "fixture.7z")
	payloadPath := filepath.Join(root, "payload.txt")
	outputPath := filepath.Join(root, "output")
	runPath := filepath.Join(root, "run")
	if err := os.WriteFile(payloadPath, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/7zz", "a", "-bd", "-bb0", inputPath, payloadPath).CombinedOutput(); err != nil {
		t.Fatalf("create 7z fixture: %v: %s", err, output)
	}
	if err := os.Chmod(inputPath, 0o400); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{outputPath, runPath} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	outputDirectory, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outputDirectory.Close()
	runDirectory, err := os.Open(runPath)
	if err != nil {
		t.Fatal(err)
	}
	defer runDirectory.Close()
	identity, err := validateExecutable("/usr/bin/7zz", "verified")
	if err != nil {
		t.Fatal(err)
	}
	command, cleanup, err := (&Server{}).buildToolCommand(
		identity,
		[]string{"x", "-y", "-aoa", "-bd", "-bb0", "-bso0", "-bsp0", "-o" + outputPath, "--", inputPath},
		Request{Operation: OperationExtract, MaxEntryBytes: 1024, MaxDurationSeconds: 5},
		input, outputDirectory, runDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("launcher extraction failed: %v: %s", err, output)
	}
	contents, err := os.ReadFile(filepath.Join(outputPath, "payload.txt"))
	if err != nil || string(contents) != "ok" {
		t.Fatalf("extracted payload = %q/%v", contents, err)
	}
}

func TestLinuxSeccompFilterRejectsAMD64X32ABI(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 exists only under the amd64 audit architecture")
	}
	filters, err := linuxSeccompFilters()
	if err != nil {
		t.Fatal(err)
	}
	for _, syscallNumber := range []uint32{
		uint32(1 << 30),
		uint32(1<<30) | uint32(unix.SYS_SOCKET),
		uint32(1<<30) | uint32(unix.SYS_CLONE),
	} {
		if result, err := evaluateSeccompFilter(
			filters, unix.AUDIT_ARCH_X86_64, syscallNumber, 0,
		); err != nil || result != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("x32 syscall %#x result = %#x/%v", syscallNumber, result, err)
		}
	}
	if result, err := evaluateSeccompFilter(
		filters, unix.AUDIT_ARCH_X86_64, uint32(unix.SYS_READ), 0,
	); err != nil || result != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("native read result = %#x/%v", result, err)
	}
}

func TestLinuxLauncherKillsRawAMD64X32Syscall(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 exists only under the amd64 audit architecture")
	}
	requireLinuxLauncherIntegration(t)
	command, _, _ := newLauncherProbeCommand(t, "x32")
	err := command.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("raw x32 syscall was not killed: %v", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGSYS {
		t.Fatalf("raw x32 syscall status = %v", exitErr.Sys())
	}
}

func evaluateSeccompFilter(
	filters []unix.SockFilter,
	architecture, syscallNumber uint32,
	argument0 uint64,
) (uint32, error) {
	loadWord := func(offset uint32) (uint32, error) {
		switch offset {
		case 0:
			return syscallNumber, nil
		case 4:
			return architecture, nil
		case 16:
			return uint32(argument0), nil
		default:
			return 0, fmt.Errorf("unsupported seccomp_data offset %d", offset)
		}
	}
	var accumulator uint32
	for pc := 0; pc >= 0 && pc < len(filters); {
		instruction := filters[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			value, err := loadWord(instruction.K)
			if err != nil {
				return 0, err
			}
			accumulator = value
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if accumulator == instruction.K {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if accumulator&instruction.K != 0 {
				pc += int(instruction.Jt) + 1
			} else {
				pc += int(instruction.Jf) + 1
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K, nil
		default:
			return 0, fmt.Errorf("unsupported BPF instruction %#x", instruction.Code)
		}
	}
	return 0, errors.New("seccomp filter exited without a verdict")
}

func TestLinuxLauncherConfinement(t *testing.T) {
	requireLinuxLauncherIntegration(t)
	for _, path := range []string{"/run/secrets/archive-test-secret", "/data/archive-test-secret"} {
		if contents, err := os.ReadFile(path); err != nil || string(contents) != "host-secret" {
			t.Fatalf("integration secret %q is not readable before confinement: %q/%v", path, contents, err)
		}
	}
	command, outputRoot, runRoot := newLauncherProbeCommand(t,
		"confine", "/run/secrets/archive-test-secret", "/data/archive-test-secret",
	)
	socketFD, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	socketInput := os.NewFile(uintptr(socketFD), "unconnected-socket")
	if socketInput == nil {
		_ = unix.Close(socketFD)
		t.Fatal("socket descriptor could not be wrapped")
	}
	defer socketInput.Close()
	command.Stdin = socketInput
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("confined probe failed: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if stdout.String() != "confined\n" {
		t.Fatalf("confined probe output = %q", stdout.String())
	}
	for _, path := range []string{
		filepath.Join(outputRoot, "allowed-output"),
		filepath.Join(runRoot, "allowed-run"),
	} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != "ok" {
			t.Fatalf("allowed launcher path %q = %q/%v", path, contents, err)
		}
	}
}

func TestLinuxLauncherPreservesProcessGroupCancellation(t *testing.T) {
	requireLinuxLauncherIntegration(t)
	command, _, _ := newLauncherProbeCommand(t, "hang")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("confined hanging process exited successfully after SIGKILL")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("confined process group survived cancellation; stderr=%q", stderr.String())
	}
}

func TestLinuxLauncherExtractsFrozenSevenZipAndCAB(t *testing.T) {
	requireLinuxLauncherIntegration(t)
	for _, path := range []string{"/usr/bin/file", "/usr/bin/bsdtar", "/usr/bin/7zz"} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("frozen archive tool %q is unavailable: %v", path, err)
		}
	}
	root := t.TempDir()
	socketRoot := filepath.Join(root, "socket")
	inputRoot := filepath.Join(root, "input")
	outputRoot := filepath.Join(root, "output")
	runRoot := filepath.Join(root, "run")
	fixtureRoot := filepath.Join(root, "fixtures")
	for _, directory := range []string{socketRoot, inputRoot, outputRoot, runRoot, fixtureRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	payloadPath := filepath.Join(fixtureRoot, "payload.txt")
	if err := os.WriteFile(payloadPath, []byte("launcher-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	sevenZipPath := filepath.Join(fixtureRoot, "fixture.7z")
	create7z := exec.Command("/usr/bin/7zz", "a", "-bd", "-bb0", sevenZipPath, payloadPath)
	if output, err := create7z.CombinedOutput(); err != nil {
		t.Fatalf("create 7z fixture: %v: %s", err, output)
	}
	cabPath := filepath.Join(fixtureRoot, "fixture.cab")
	if err := os.WriteFile(cabPath, uncompressedCAB("payload.txt", []byte("launcher-payload")), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		SocketPath: filepath.Join(socketRoot, "archive.sock"), SocketMode: 0o600,
		InputRoot: inputRoot, OutputRoot: outputRoot, RunRoot: runRoot,
		LibmagicExecutable: "/usr/bin/file", LibmagicVersion: "5.46",
		LibarchiveExecutable: "/usr/bin/bsdtar", LibarchiveVersion: "3.8.3",
		SevenZipExecutable: "/usr/bin/7zz", SevenZipVersion: "24.09",
		TerminationGrace: 250 * time.Millisecond, ReleaseTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	waitForServerPath(t, server.config.SocketPath, serveResult)
	client, err := NewClient(ClientConfig{
		SocketPath: server.config.SocketPath,
		InputRoot:  inputRoot, OutputRoot: outputRoot,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SelfTest(context.Background()); err != nil {
		t.Fatalf("frozen archive sandbox self-test: %v", err)
	}
	for _, fixture := range []struct {
		name, path, engine, format string
	}{
		{"7z", sevenZipPath, extract.ExternalEngineSevenZip, "7z"},
		{"cab", cabPath, extract.ExternalEngineLibarchive, "cab"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source, err := os.Open(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			info, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			classified, err := client.Classify(context.Background(), source, info.Size())
			if err != nil || classified.MIMEType == "" {
				t.Fatalf("classify frozen %s fixture: %#v/%v", fixture.name, classified, err)
			}
			if _, err := source.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			session, err := client.Extract(context.Background(), source, info.Size(), extract.ExternalArchiveRequest{
				Engine: fixture.engine, Format: fixture.format,
				MaxEntries: 10, MaxEntryBytes: 1 << 20,
				MaxExpandedBytes: 2 << 20, MaxDurationSeconds: 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			contents, err := os.ReadFile(filepath.Join(session.OutputPath(), "payload.txt"))
			if err != nil || string(contents) != "launcher-payload" {
				t.Fatalf("extracted payload = %q/%v", contents, err)
			}
		})
	}
	cancel()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}

func requireLinuxLauncherIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(launcherTestEnv) != "1" {
		t.Skip("set BINARYSCAN_LINUX_SANDBOX_INTEGRATION=1 inside the scanner tools image")
	}
}

func newLauncherProbeCommand(t *testing.T, arguments ...string) (*exec.Cmd, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	toolPath := filepath.Join(root, "launcher-probe")
	toolBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolPath, toolBytes, 0o555); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(toolPath)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input")
	if err := os.WriteFile(inputPath, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	outputRoot := filepath.Join(root, "output")
	runRoot := filepath.Join(root, "run")
	for _, path := range []string{outputRoot, runRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.Open(outputRoot)
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.Open(runRoot)
	if err != nil {
		t.Fatal(err)
	}
	probeArguments := append([]string{launcherProbeMode}, arguments...)
	command, cleanup, err := (&Server{}).buildToolCommand(
		executableIdentity{path: toolPath, info: info}, probeArguments,
		Request{Operation: OperationExtract, MaxEntryBytes: 4096, MaxDurationSeconds: 5},
		input, output, run,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup()
		_ = input.Close()
		_ = output.Close()
		_ = run.Close()
	})
	command.Env = append(os.Environ(), "BINARYSCAN_DB_PASSWORD=must-not-leak")
	command.Stdin = strings.NewReader("")
	return command, outputRoot, runRoot
}

func runLauncherProbe(arguments []string) int {
	if len(arguments) == 1 && arguments[0] == "hang" {
		for {
			time.Sleep(time.Second)
		}
	}
	if len(arguments) == 1 && arguments[0] == "x32" {
		_, _, _ = unix.RawSyscall(uintptr(unix.SYS_GETPID)|(1<<30), 0, 0, 0)
		return 91
	}
	if len(arguments) != 3 || arguments[0] != "confine" {
		return 2
	}
	if os.Getenv("BINARYSCAN_DB_PASSWORD") != "" || os.Getenv("PATH") != "/nonexistent" {
		return 3
	}
	input := os.NewFile(3, "launcher-input")
	if input == nil {
		return 4
	}
	contents := make([]byte, 5)
	if _, err := input.Read(contents); err != nil || string(contents) != "input" {
		return 5
	}
	for _, path := range arguments[1:] {
		if contents, err := os.ReadFile(path); err == nil {
			_, _ = fmt.Fprintf(os.Stderr, "read forbidden %s: %q\n", path, contents)
			return 6
		}
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err == nil {
		_ = unix.Close(fd)
		return 7
	}
	if !errors.Is(err, unix.EPERM) {
		return 8
	}
	if err := unix.Connect(0, &unix.SockaddrInet4{Port: 9}); !errors.Is(err, unix.EPERM) {
		return 9
	}
	pid, _, errno := unix.RawSyscall(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0)
	if errno == 0 {
		if pid == 0 {
			unix.Exit(99)
		}
		return 10
	}
	if !errors.Is(errno, unix.EPERM) {
		return 11
	}
	if err := unix.Exec("/bin/sh", []string{"sh", "-c", "exit 0"}, []string{"PATH=/nonexistent"}); !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		return 12
	}
	for _, limit := range []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_NOFILE, launcherNoFileLimit},
		{unix.RLIMIT_NPROC, launcherProcessLimit},
		{unix.RLIMIT_FSIZE, 4096},
		{unix.RLIMIT_AS, launcherAddressSpace},
		{unix.RLIMIT_CPU, 5},
		{unix.RLIMIT_CORE, 0},
	} {
		var current unix.Rlimit
		if err := unix.Getrlimit(limit.resource, &current); err != nil ||
			current.Cur != limit.value || current.Max != limit.value {
			return 13
		}
	}
	for _, path := range []string{"/proc/self/fd/4/allowed-output", "/proc/self/fd/5/allowed-run"} {
		if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
			return 14
		}
	}
	_, _ = fmt.Fprintln(os.Stdout, "confined")
	return 0
}

func uncompressedCAB(name string, payload []byte) []byte {
	nameBytes := append([]byte(name), 0)
	fileOffset := uint32(36 + 8)
	dataOffset := fileOffset + uint32(16+len(nameBytes))
	totalSize := dataOffset + 8 + uint32(len(payload))
	buffer := bytes.NewBuffer(make([]byte, 0, totalSize))
	buffer.WriteString("MSCF")
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	_ = binary.Write(buffer, binary.LittleEndian, totalSize)
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	_ = binary.Write(buffer, binary.LittleEndian, fileOffset)
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	buffer.WriteByte(3)
	buffer.WriteByte(1)
	_ = binary.Write(buffer, binary.LittleEndian, uint16(1)) // folders
	_ = binary.Write(buffer, binary.LittleEndian, uint16(1)) // files
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0)) // flags
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0)) // set ID
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0)) // cabinet index
	_ = binary.Write(buffer, binary.LittleEndian, dataOffset)
	_ = binary.Write(buffer, binary.LittleEndian, uint16(1)) // data blocks
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0)) // no compression
	_ = binary.Write(buffer, binary.LittleEndian, uint32(len(payload)))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0))    // folder index
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0x21)) // 1980-01-01
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0))    // midnight
	_ = binary.Write(buffer, binary.LittleEndian, uint16(0x20))
	buffer.Write(nameBytes)
	_ = binary.Write(buffer, binary.LittleEndian, uint32(0))
	_ = binary.Write(buffer, binary.LittleEndian, uint16(len(payload)))
	_ = binary.Write(buffer, binary.LittleEndian, uint16(len(payload)))
	buffer.Write(payload)
	return buffer.Bytes()
}
