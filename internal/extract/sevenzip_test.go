package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"binaryscan/internal/filetype"
)

func TestConfiguredSevenZipEngineDispatches7ZAndCAB(t *testing.T) {
	for _, test := range []struct {
		format string
		input  []byte
	}{
		{format: "7z", input: sevenZipExtractFixture()},
		{format: "cab", input: cabExtractFixture()},
	} {
		t.Run(test.format, func(t *testing.T) {
			result, extractErr, invocation := runFakeSevenZipExtract(
				t,
				context.Background(),
				test.input,
				test.format,
				generousLimits(),
				"normal",
				func(*TrustedSevenZipConfig) {},
			)
			if extractErr != nil {
				t.Fatalf("Extract() error = %v", extractErr)
			}
			assertNodeGraph(t, result.Nodes)
			if result.Partial || result.LimitCode != "" || len(result.Nodes) != 2 {
				t.Fatalf("result = %+v", result)
			}
			directory := findNode(t, result.Nodes, "/docs")
			payload := findNode(t, result.Nodes, "/docs/payload.txt")
			if directory.NodeType != NodeTypeDirectory ||
				directory.ExtractionStatus != StatusRecorded {
				t.Fatalf("directory = %+v", directory)
			}
			if payload.NodeType != NodeTypeFile ||
				payload.ExtractionStatus != StatusExtracted ||
				payload.SizeBytes != int64(len("payload")) {
				t.Fatalf("payload = %+v", payload)
			}
			var metadata map[string]any
			if err := json.Unmarshal(payload.MetadataJSON, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["archive"] != test.format ||
				metadata["trusted_helper"] != "7zz" {
				t.Fatalf("metadata = %#v", metadata)
			}
			assertTrustedSevenZipInvocation(t, invocation)
		})
	}
}

func TestSevenZipEngineIsExplicitlyOptIn(t *testing.T) {
	engine := NewEngine(filetype.Detector{}, Limits{})
	for _, format := range []string{"7z", "cab"} {
		if engine.Supports(format) {
			t.Fatalf("default Engine unexpectedly supports %q", format)
		}
	}
	executable, _ := newFakeSevenZipExecutable(t, "normal")
	configured, err := NewEngineWithTrustedSevenZip(
		filetype.Detector{},
		Limits{},
		TrustedSevenZipConfig{Executable: executable},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"7z", "cab"} {
		if !configured.Supports(format) {
			t.Fatalf("configured Engine does not support %q", format)
		}
	}
}

func TestSevenZipRecursesAcrossConfiguredExternalFormats(t *testing.T) {
	result, extractErr, _ := runFakeSevenZipExtract(
		t,
		context.Background(),
		sevenZipExtractFixture(),
		"7z",
		generousLimits(),
		"nested",
		func(*TrustedSevenZipConfig) {},
	)
	if extractErr != nil {
		t.Fatal(extractErr)
	}
	inner := findNode(t, result.Nodes, "/inner.cab")
	payload := findNode(t, result.Nodes, "/inner.cab/payload.txt")
	if result.Partial || inner.Format != "cab" ||
		inner.ExtractionStatus != StatusExtracted ||
		payload.ExtractionStatus != StatusExtracted ||
		payload.SizeBytes != int64(len("nested")) {
		t.Fatalf("result=%+v inner=%+v payload=%+v", result, inner, payload)
	}
}

func TestSevenZipRejectsUnsafeExecutableConfiguration(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "fake-7zz")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngineWithTrustedSevenZip(
		filetype.Detector{}, Limits{}, TrustedSevenZipConfig{Executable: executable},
	); err == nil {
		t.Fatal("non-executable file was accepted")
	}
	if err := os.Chmod(executable, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked-7zz")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngineWithTrustedSevenZip(
		filetype.Detector{}, Limits{}, TrustedSevenZipConfig{Executable: link},
	); err == nil {
		t.Fatal("symbolic-link executable was accepted")
	}
	if _, err := NewEngineWithTrustedSevenZip(
		filetype.Detector{},
		Limits{},
		TrustedSevenZipConfig{
			Executable:     executable,
			MaxDuration:    25 * time.Hour,
			MaxStdoutBytes: 1,
			MaxStderrBytes: 1,
		},
	); err == nil {
		t.Fatal("invalid duration was accepted")
	}
}

func TestSevenZipRejectsUnsafeMaterializedTrees(t *testing.T) {
	for _, mode := range []string{
		"symlink",
		"hardlink",
		"fifo",
		"replace_output",
	} {
		t.Run(mode, func(t *testing.T) {
			result, extractErr, invocation := runFakeSevenZipExtract(
				t,
				context.Background(),
				sevenZipExtractFixture(),
				"7z",
				generousLimits(),
				mode,
				func(*TrustedSevenZipConfig) {},
			)
			if extractErr != nil {
				t.Fatalf("Extract() error = %v", extractErr)
			}
			assertNodeGraph(t, result.Nodes)
			if !result.Partial || len(result.Nodes) != 1 {
				t.Fatalf("result = %+v", result)
			}
			node := result.Nodes[0]
			if node.ExtractionStatus != StatusCorrupt ||
				node.ErrorCode != "7z_trusted_helper_output_unsafe" {
				t.Fatalf("node = %+v", node)
			}
			stagePath := filepath.Dir(invocation.OutputPath)
			if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("private stage was not removed: %v", err)
			}
		})
	}
}

func TestSevenZipClassifiesExtractorFailureAndOutputOverflow(t *testing.T) {
	for _, test := range []struct {
		mode string
		code string
	}{
		{mode: "corrupt", code: "7z_trusted_helper_failed"},
		{mode: "output_limit", code: "7z_trusted_helper_diagnostic_limit"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			result, extractErr, _ := runFakeSevenZipExtract(
				t,
				context.Background(),
				sevenZipExtractFixture(),
				"7z",
				generousLimits(),
				test.mode,
				func(config *TrustedSevenZipConfig) {
					config.MaxStdoutBytes = 64
					config.MaxStderrBytes = 64
				},
			)
			if extractErr != nil {
				t.Fatalf("Extract() error = %v", extractErr)
			}
			if !result.Partial || len(result.Nodes) != 1 ||
				result.Nodes[0].ErrorCode != test.code ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestSevenZipTimeoutTerminatesTheProcessGroup(t *testing.T) {
	started := time.Now()
	result, extractErr, invocation := runFakeSevenZipExtract(
		t,
		context.Background(),
		sevenZipExtractFixture(),
		"7z",
		generousLimits(),
		"timeout",
		func(config *TrustedSevenZipConfig) {
			config.MaxDuration = time.Second
			config.TerminationGrace = 40 * time.Millisecond
		},
	)
	if extractErr != nil {
		t.Fatalf("Extract() error = %v", extractErr)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("timed out process group took %s to terminate", elapsed)
	}
	if !result.Partial || len(result.Nodes) != 1 ||
		result.Nodes[0].ErrorCode != "7z_trusted_helper_timeout" {
		t.Fatalf("result = %+v", result)
	}
	if invocation.ChildPID <= 0 {
		t.Fatalf("fake 7zz did not report its child PID: %+v", invocation)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := syscall.Kill(invocation.ChildPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("process-group child %d is still alive: %v", invocation.ChildPID, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSevenZipPropagatesCallerCancellation(t *testing.T) {
	_, extractErr, invocation := runFakeSevenZipExtractAfterReadyCancel(
		t,
		sevenZipExtractFixture(),
		"7z",
		generousLimits(),
	)
	if !errors.Is(extractErr, context.Canceled) {
		t.Fatalf("Extract() error = %v, want context cancellation", extractErr)
	}
	if invocation.ChildPID <= 0 {
		t.Fatalf("cancellation occurred before helper readiness: %+v", invocation)
	}
}

func TestSevenZipFeedsExistingExtractionLimits(t *testing.T) {
	t.Run("entry bytes", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxEntryBytes = 1024
		input := append(sevenZipExtractFixture(), make([]byte, 4096)...)
		result, extractErr, _ := runFakeSevenZipExtract(
			t,
			context.Background(),
			input,
			"7z",
			limits,
			"large_entry",
			func(*TrustedSevenZipConfig) {},
		)
		if extractErr != nil {
			t.Fatal(extractErr)
		}
		if !result.Partial || result.LimitCode != LimitMaxEntryBytes {
			t.Fatalf("result=%+v", result)
		}
		if len(result.Nodes) > 0 {
			node := findNode(t, result.Nodes, "/large.bin")
			if node.ExtractionStatus != StatusLimitExceeded ||
				node.SizeBytes != limits.MaxEntryBytes {
				t.Fatalf("result=%+v node=%+v", result, node)
			}
		}
	})

	t.Run("ratio", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxRatio = 2
		result, extractErr, _ := runFakeSevenZipExtract(
			t,
			context.Background(),
			sevenZipExtractFixture(),
			"7z",
			limits,
			"ratio",
			func(*TrustedSevenZipConfig) {},
		)
		if extractErr != nil {
			t.Fatal(extractErr)
		}
		capacity := int64(len(sevenZipExtractFixture())) * 2
		if !result.Partial || result.LimitCode != LimitMaxRatio ||
			(result.ExpandedBytes != 0 && result.ExpandedBytes != capacity) {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("nodes", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxNodes = 2
		result, extractErr, _ := runFakeSevenZipExtract(
			t,
			context.Background(),
			sevenZipExtractFixture(),
			"7z",
			limits,
			"nodes",
			func(*TrustedSevenZipConfig) {},
		)
		if extractErr != nil {
			t.Fatal(extractErr)
		}
		if !result.Partial || result.LimitCode != LimitMaxNodes ||
			len(result.Nodes) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("depth", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxDepth = 3
		result, extractErr, _ := runFakeSevenZipExtract(
			t,
			context.Background(),
			sevenZipExtractFixture(),
			"7z",
			limits,
			"depth",
			func(*TrustedSevenZipConfig) {},
		)
		if extractErr != nil {
			t.Fatal(extractErr)
		}
		if !result.Partial || result.LimitCode != LimitMaxDepth {
			t.Fatalf("result = %+v", result)
		}
		for _, node := range result.Nodes {
			if node.Depth > limits.MaxDepth {
				t.Fatalf("node exceeds depth limit: %+v", node)
			}
		}
	})
}

type fakeSevenZipInvocation struct {
	Arguments        []string `json:"arguments"`
	WorkingDirectory string   `json:"working_directory"`
	WorkingEntries   int      `json:"working_entries"`
	OutputPath       string   `json:"output_path"`
	OutputEntries    int      `json:"output_entries"`
	IsolatedSiblings bool     `json:"isolated_siblings"`
	EnvironmentPath  string   `json:"environment_path"`
	ChildPID         int      `json:"child_pid,omitempty"`
}

func runFakeSevenZipExtract(
	t *testing.T,
	ctx context.Context,
	input []byte,
	format string,
	limits Limits,
	mode string,
	configure func(*TrustedSevenZipConfig),
) (Result, error, fakeSevenZipInvocation) {
	t.Helper()
	executable, logPath := newFakeSevenZipExecutable(t, mode)
	config := TrustedSevenZipConfig{Executable: executable}
	configure(&config)
	engine, err := NewEngineWithTrustedSevenZip(filetype.Detector{}, limits, config)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.Supports(format) {
		t.Fatalf("Engine does not support %q", format)
	}
	sourcePath := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(sourcePath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	result, extractErr := engine.Extract(ctx, source, format, t.TempDir())
	if !errors.Is(extractErr, context.Canceled) &&
		!errors.Is(extractErr, context.DeadlineExceeded) {
		assertNodeGraph(t, result.Nodes)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		if errors.Is(extractErr, context.Canceled) ||
			errors.Is(extractErr, context.DeadlineExceeded) {
			return result, extractErr, fakeSevenZipInvocation{}
		}
		t.Fatalf("read fake 7zz invocation: %v", err)
	}
	var invocation fakeSevenZipInvocation
	if err := json.Unmarshal(logData, &invocation); err != nil {
		t.Fatalf("decode fake 7zz invocation: %v; data=%q", err, logData)
	}
	return result, extractErr, invocation
}

type fakeSevenZipOutcome struct {
	result Result
	err    error
}

func runFakeSevenZipExtractAfterReadyCancel(
	t *testing.T,
	input []byte,
	format string,
	limits Limits,
) (Result, error, fakeSevenZipInvocation) {
	t.Helper()
	executable, logPath := newFakeSevenZipExecutable(t, "timeout")
	engine, err := NewEngineWithTrustedSevenZip(
		filetype.Detector{},
		limits,
		TrustedSevenZipConfig{
			Executable:       executable,
			MaxDuration:      10 * time.Second,
			TerminationGrace: 20 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(sourcePath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outcome := make(chan fakeSevenZipOutcome, 1)
	workDir := t.TempDir()
	go func() {
		result, extractErr := engine.Extract(ctx, source, format, workDir)
		outcome <- fakeSevenZipOutcome{result: result, err: extractErr}
	}()

	waitForFakeSevenZipReady(t, logPath+".ready", outcome)
	cancel()
	operation := waitForFakeSevenZipOutcome(t, outcome)
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read ready fake 7zz invocation: %v", err)
	}
	var invocation fakeSevenZipInvocation
	if err := json.Unmarshal(logData, &invocation); err != nil {
		t.Fatalf("decode ready fake 7zz invocation: %v", err)
	}
	return operation.result, operation.err, invocation
}

func waitForFakeSevenZipReady(
	t *testing.T,
	readyPath string,
	outcome <-chan fakeSevenZipOutcome,
) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case operation := <-outcome:
			t.Fatalf("fake 7zz completed before ready handshake: %v", operation.err)
		case <-ticker.C:
			body, err := os.ReadFile(readyPath)
			if err == nil && string(body) == "ready" {
				return
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read fake 7zz ready file: %v", err)
			}
		case <-timeout.C:
			t.Fatal("timed out waiting for fake 7zz ready handshake")
		}
	}
}

func waitForFakeSevenZipOutcome(
	t *testing.T,
	outcome <-chan fakeSevenZipOutcome,
) fakeSevenZipOutcome {
	t.Helper()
	select {
	case operation := <-outcome:
		return operation
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for cancelled fake 7zz")
		return fakeSevenZipOutcome{}
	}
}

func newFakeSevenZipExecutable(t *testing.T, mode string) (string, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err = filepath.EvalSymlinks(testBinary)
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "invocation.json")
	readyPath := logPath + ".ready"
	executable := filepath.Join(directory, "fake-7zz")
	script := fmt.Sprintf(
		"#!/bin/sh\nBINARYSCAN_FAKE_7ZZ=1\nBINARYSCAN_FAKE_7ZZ_MODE=%s\nBINARYSCAN_FAKE_7ZZ_LOG=%s\nBINARYSCAN_FAKE_7ZZ_READY=%s\nexport BINARYSCAN_FAKE_7ZZ BINARYSCAN_FAKE_7ZZ_MODE BINARYSCAN_FAKE_7ZZ_LOG BINARYSCAN_FAKE_7ZZ_READY\nexec %s -test.run='^TestSevenZipHelperProcess$' -- \"$@\"\n",
		shellQuote(mode),
		shellQuote(logPath),
		shellQuote(readyPath),
		shellQuote(testBinary),
	)
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	return executable, logPath
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func assertTrustedSevenZipInvocation(
	t *testing.T,
	invocation fakeSevenZipInvocation,
) {
	t.Helper()
	if invocation.WorkingEntries != 0 || invocation.OutputEntries != 0 {
		t.Fatalf("7zz directories were not empty before execution: %+v", invocation)
	}
	if invocation.EnvironmentPath != "/nonexistent" {
		t.Fatalf("7zz PATH was not sanitized: %+v", invocation)
	}
	if filepath.Base(invocation.WorkingDirectory) != "run" ||
		filepath.Base(invocation.OutputPath) != "output" ||
		!invocation.IsolatedSiblings {
		t.Fatalf("7zz directories are not isolated siblings: %+v", invocation)
	}
	wantPrefix := []string{
		"x", "-y", "-aoa", "-bd", "-bb0", "-bso0", "-bsp0", "-spf-",
		"-o" + invocation.OutputPath,
		"--",
	}
	if len(invocation.Arguments) != len(wantPrefix)+1 ||
		!reflect.DeepEqual(invocation.Arguments[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("7zz arguments = %#v, want prefix %#v", invocation.Arguments, wantPrefix)
	}
	source := invocation.Arguments[len(invocation.Arguments)-1]
	if !filepath.IsAbs(source) || filepath.Base(source) != sevenZipStagedArchiveFilename ||
		filepath.Base(filepath.Dir(source)) != "input" {
		t.Fatalf("staged source argument = %q", source)
	}
	for _, argument := range invocation.Arguments {
		if strings.ContainsAny(argument, "\n\r\x00") {
			t.Fatalf("unsafe argument = %q", argument)
		}
	}
}

func sevenZipExtractFixture() []byte {
	data := make([]byte, 32)
	copy(data, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4})
	binary.LittleEndian.PutUint32(
		data[8:12],
		crc32.ChecksumIEEE(data[12:32]),
	)
	return data
}

func cabExtractFixture() []byte {
	data := make([]byte, 100)
	copy(data, "MSCF")
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[16:20], 36)
	data[24], data[25] = 3, 1
	binary.LittleEndian.PutUint16(data[26:28], 1)
	binary.LittleEndian.PutUint16(data[28:30], 1)
	return data
}

func TestSevenZipHelperProcess(t *testing.T) {
	if os.Getenv("BINARYSCAN_FAKE_7ZZ") != "1" {
		return
	}
	arguments := argumentsAfterSeparator(os.Args)
	outputPath := ""
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-o") && len(argument) > 2 {
			outputPath = argument[2:]
			break
		}
	}
	if outputPath == "" {
		fmt.Fprintln(os.Stderr, "missing output argument")
		os.Exit(91)
	}
	workingDirectory, _ := os.Getwd()
	workingEntries, _ := os.ReadDir(workingDirectory)
	outputEntries, _ := os.ReadDir(outputPath)
	invocation := fakeSevenZipInvocation{
		Arguments:        arguments,
		WorkingDirectory: workingDirectory,
		WorkingEntries:   len(workingEntries),
		OutputPath:       outputPath,
		OutputEntries:    len(outputEntries),
		EnvironmentPath:  os.Getenv("PATH"),
		IsolatedSiblings: sameDirectoryIdentity(
			filepath.Dir(workingDirectory),
			filepath.Dir(outputPath),
		),
	}
	logPath := os.Getenv("BINARYSCAN_FAKE_7ZZ_LOG")
	writeFakeSevenZipLog(logPath, invocation)

	switch os.Getenv("BINARYSCAN_FAKE_7ZZ_MODE") {
	case "normal":
		mustFakeMkdir(filepath.Join(outputPath, "docs"))
		mustFakeWrite(filepath.Join(outputPath, "docs", "payload.txt"), []byte("payload"))
	case "nested":
		sourcePath := arguments[len(arguments)-1]
		source, err := os.ReadFile(sourcePath)
		if err != nil {
			panic(err)
		}
		if bytes.HasPrefix(source, []byte("MSCF")) {
			mustFakeWrite(filepath.Join(outputPath, "payload.txt"), []byte("nested"))
		} else {
			mustFakeWrite(filepath.Join(outputPath, "inner.cab"), cabExtractFixture())
		}
	case "corrupt":
		fmt.Fprintln(os.Stderr, "fixture archive is corrupt")
		os.Exit(7)
	case "output_limit":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 4096))
	case "symlink":
		if err := os.Symlink("/etc/passwd", filepath.Join(outputPath, "link")); err != nil {
			panic(err)
		}
	case "hardlink":
		first := filepath.Join(outputPath, "first")
		mustFakeWrite(first, []byte("hardlink"))
		if err := os.Link(first, filepath.Join(outputPath, "second")); err != nil {
			panic(err)
		}
	case "fifo":
		if err := syscall.Mkfifo(filepath.Join(outputPath, "pipe"), 0o600); err != nil {
			panic(err)
		}
	case "replace_output":
		if err := os.Remove(outputPath); err != nil {
			panic(err)
		}
		if err := os.Mkdir(outputPath, 0o700); err != nil {
			panic(err)
		}
		mustFakeWrite(filepath.Join(outputPath, "payload"), []byte("replacement"))
	case "large_entry":
		mustFakeWrite(filepath.Join(outputPath, "large.bin"), bytes.Repeat([]byte("L"), 64<<10))
	case "ratio":
		mustFakeWrite(filepath.Join(outputPath, "ratio.bin"), bytes.Repeat([]byte("R"), 8<<10))
	case "nodes":
		for _, name := range []string{"a", "b", "c"} {
			mustFakeWrite(filepath.Join(outputPath, name), []byte(name))
		}
	case "depth":
		deep := outputPath
		for _, name := range []string{"a", "b", "c", "d", "e"} {
			deep = filepath.Join(deep, name)
			mustFakeMkdir(deep)
		}
		mustFakeWrite(filepath.Join(deep, "payload"), []byte("deep"))
	case "timeout":
		signal.Ignore(syscall.SIGTERM)
		readyReader, readyWriter, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		child := exec.Command(
			os.Args[0],
			"-test.run=^TestSevenZipSleeperProcess$",
		)
		child.Env = append(os.Environ(), "BINARYSCAN_SEVENZIP_SLEEPER=1")
		child.ExtraFiles = []*os.File{readyWriter}
		if err := child.Start(); err != nil {
			panic(err)
		}
		if err := readyWriter.Close(); err != nil {
			panic(err)
		}
		var readyByte [1]byte
		if _, err := io.ReadFull(readyReader, readyByte[:]); err != nil {
			panic(err)
		}
		if err := readyReader.Close(); err != nil {
			panic(err)
		}
		invocation.ChildPID = child.Process.Pid
		writeFakeSevenZipLog(logPath, invocation)
		writeFakeSevenZipReady(os.Getenv("BINARYSCAN_FAKE_7ZZ_READY"))
		time.Sleep(30 * time.Second)
	default:
		fmt.Fprintln(os.Stderr, "unknown fake mode")
		os.Exit(92)
	}
}

func TestSevenZipSleeperProcess(t *testing.T) {
	if os.Getenv("BINARYSCAN_SEVENZIP_SLEEPER") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	ready := os.NewFile(3, "fake-7zz-sleeper-ready")
	if ready == nil {
		panic("missing fake 7zz sleeper ready descriptor")
	}
	if _, err := ready.Write([]byte{1}); err != nil {
		panic(err)
	}
	if err := ready.Close(); err != nil {
		panic(err)
	}
	time.Sleep(30 * time.Second)
}

func argumentsAfterSeparator(arguments []string) []string {
	for index, argument := range arguments {
		if argument == "--" {
			return append([]string(nil), arguments[index+1:]...)
		}
	}
	return nil
}

func writeFakeSevenZipLog(path string, invocation fakeSevenZipInvocation) {
	encoded, err := json.Marshal(invocation)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		panic(err)
	}
}

func writeFakeSevenZipReady(path string) {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte("ready"), 0o600); err != nil {
		panic(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		panic(err)
	}
}

func sameDirectoryIdentity(left string, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

func mustFakeMkdir(path string) {
	if err := os.Mkdir(path, 0o700); err != nil {
		panic(err)
	}
}

func mustFakeWrite(path string, body []byte) {
	if err := os.WriteFile(path, body, 0o600); err != nil {
		panic(err)
	}
}
