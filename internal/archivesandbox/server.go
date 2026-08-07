package archivesandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultServerGrace       = 10 * time.Second
	defaultMonitorInterval   = 25 * time.Millisecond
	defaultReleaseTimeout    = 30 * time.Second
	defaultDiagnosticBytes   = int64(1 << 20)
	maxServerDiagnosticBytes = int64(16 << 20)
	containmentExitCode      = 75
)

type ServerConfig struct {
	SocketPath string
	SocketMode fs.FileMode
	InputRoot  string
	OutputRoot string
	RunRoot    string

	LibmagicExecutable   string
	LibmagicVersion      string
	LibarchiveExecutable string
	LibarchiveVersion    string
	SevenZipExecutable   string
	SevenZipVersion      string

	MaxConcurrent             int
	TerminationGrace          time.Duration
	MonitorInterval           time.Duration
	ReleaseTimeout            time.Duration
	MaxDiagnosticBytes        int64
	ResetOnContainmentFailure bool
	Exit                      func(int)
}

type executableIdentity struct {
	path string
	info os.FileInfo
}

type Server struct {
	config     ServerConfig
	inputRoot  *os.Root
	inputInfo  os.FileInfo
	outputRoot *os.Root
	outputInfo os.FileInfo
	runRoot    *os.Root
	runInfo    os.FileInfo
	libmagic   executableIdentity
	libarchive executableIdentity
	sevenZip   executableIdentity
	semaphore  chan struct{}
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.SocketMode == 0 {
		config.SocketMode = 0o660
	}
	if config.SocketMode.Perm()&0o007 != 0 ||
		config.SocketMode.Perm()&0o600 == 0 {
		return nil, errors.New("archive sandbox socket mode is unsafe")
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 1
	}
	if config.TerminationGrace == 0 {
		config.TerminationGrace = defaultServerGrace
	}
	if config.MonitorInterval == 0 {
		config.MonitorInterval = defaultMonitorInterval
	}
	if config.ReleaseTimeout == 0 {
		config.ReleaseTimeout = defaultReleaseTimeout
	}
	if config.MaxDiagnosticBytes == 0 {
		config.MaxDiagnosticBytes = defaultDiagnosticBytes
	}
	if config.Exit == nil {
		config.Exit = os.Exit
	}
	if config.MaxConcurrent < 1 || config.MaxConcurrent > 4 ||
		config.TerminationGrace <= 0 || config.TerminationGrace > time.Minute ||
		config.MonitorInterval < time.Millisecond ||
		config.MonitorInterval > time.Second ||
		config.ReleaseTimeout <= 0 || config.ReleaseTimeout > 5*time.Minute ||
		config.MaxDiagnosticBytes <= 0 ||
		config.MaxDiagnosticBytes > maxServerDiagnosticBytes {
		return nil, errors.New("archive sandbox server limits are invalid")
	}
	for name, value := range map[string]string{
		"socket": config.SocketPath,
		"input":  config.InputRoot,
		"output": config.OutputRoot,
		"run":    config.RunRoot,
	} {
		if value == "" || !filepath.IsAbs(value) ||
			filepath.Clean(value) != value || value == string(filepath.Separator) {
			return nil, fmt.Errorf("archive sandbox %s path is invalid", name)
		}
	}
	if rootsOverlap(config.InputRoot, config.OutputRoot) ||
		rootsOverlap(config.InputRoot, config.RunRoot) ||
		rootsOverlap(config.OutputRoot, config.RunRoot) {
		return nil, errors.New("archive sandbox data roots overlap")
	}
	inputRoot, inputInfo, err := openDirectoryRoot(config.InputRoot)
	if err != nil {
		return nil, fmt.Errorf("open sandbox input root: %w", err)
	}
	outputRoot, outputInfo, err := openDirectoryRoot(config.OutputRoot)
	if err != nil {
		_ = inputRoot.Close()
		return nil, fmt.Errorf("open sandbox output root: %w", err)
	}
	runRoot, runInfo, err := openDirectoryRoot(config.RunRoot)
	if err != nil {
		_ = inputRoot.Close()
		_ = outputRoot.Close()
		return nil, fmt.Errorf("open sandbox run root: %w", err)
	}
	cleanup := func() {
		_ = inputRoot.Close()
		_ = outputRoot.Close()
		_ = runRoot.Close()
	}
	libmagic, err := validateExecutable(
		config.LibmagicExecutable,
		config.LibmagicVersion,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("validate libmagic frontend: %w", err)
	}
	libarchive, err := validateExecutable(
		config.LibarchiveExecutable,
		config.LibarchiveVersion,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("validate libarchive frontend: %w", err)
	}
	sevenZip, err := validateExecutable(
		config.SevenZipExecutable,
		config.SevenZipVersion,
	)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("validate 7zz: %w", err)
	}
	return &Server{
		config:    config,
		inputRoot: inputRoot, inputInfo: inputInfo,
		outputRoot: outputRoot, outputInfo: outputInfo,
		runRoot: runRoot, runInfo: runInfo,
		libmagic: libmagic, libarchive: libarchive, sevenZip: sevenZip,
		semaphore: make(chan struct{}, config.MaxConcurrent),
	}, nil
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	return errors.Join(
		server.inputRoot.Close(),
		server.outputRoot.Close(),
		server.runRoot.Close(),
	)
}

func (server *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("archive sandbox server context is nil")
	}
	if err := server.validateRoots(); err != nil {
		return err
	}
	if err := prepareSocketPath(server.config.SocketPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: server.config.SocketPath, Net: "unix"},
	)
	if err != nil {
		return fmt.Errorf("listen on archive sandbox socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(server.config.SocketPath)
	}()
	if err := os.Chmod(server.config.SocketPath, server.config.SocketMode); err != nil {
		return fmt.Errorf("chmod archive sandbox socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept archive sandbox connection: %w", err)
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer connection.Close()
			server.handle(ctx, connection)
		}()
	}
}

func (server *Server) handle(parent context.Context, connection *net.UnixConn) {
	var request Request
	if err := readFrame(connection, &request); err != nil || request.validate() != nil {
		return
	}
	requestContext, cancel := context.WithCancel(parent)
	defer cancel()
	acknowledged := make(chan error, 1)
	go func() {
		var value [1]byte
		_, err := io.ReadFull(connection, value[:])
		if err == nil && value[0] != ackByte {
			err = errors.New("archive sandbox acknowledgement is invalid")
		}
		acknowledged <- err
		cancel()
	}()

	response := Response{
		SchemaVersion: SchemaVersion,
		RequestID:     request.RequestID,
		Status:        "succeeded",
		EngineVersion: "archive-sandbox-v1",
	}
	var outputName string
	forced := false
	switch request.Operation {
	case OperationPing:
	case OperationIdentify:
		mime, operationForced, err := server.identify(requestContext, request)
		forced = operationForced
		if err != nil {
			response = failedResponse(request, "libmagic_failed", err)
		} else {
			response.MIMEType = mime
			response.EngineVersion = server.config.LibmagicVersion
		}
	case OperationExtract:
		outputName = request.OutputName
		operationForced, err := server.extract(requestContext, request)
		forced = operationForced
		if err != nil {
			response = failedResponse(request, "archive_extraction_failed", err)
			outputName = ""
		} else {
			response.OutputName = request.OutputName
			if request.Engine == EngineSevenZip {
				response.EngineVersion = server.config.SevenZipVersion
			} else {
				response.EngineVersion = server.config.LibarchiveVersion
			}
		}
	}
	if outputName != "" {
		defer server.removeOutput(outputName)
	}
	_ = writeFrame(connection, response)
	_ = connection.SetReadDeadline(time.Now().Add(server.config.ReleaseTimeout))
	select {
	case <-acknowledged:
	case <-time.After(server.config.ReleaseTimeout):
	}
	if forced && server.config.ResetOnContainmentFailure {
		go func() {
			time.Sleep(25 * time.Millisecond)
			server.config.Exit(containmentExitCode)
		}()
	}
}

func (server *Server) identify(
	ctx context.Context,
	request Request,
) (string, bool, error) {
	input, err := server.openVerifiedInput(ctx, request)
	if err != nil {
		return "", false, err
	}
	defer input.Close()
	if err := server.acquire(ctx); err != nil {
		return "", false, err
	}
	defer server.release()
	runPath, cleanup, err := server.createRunDirectory(request.RequestID)
	if err != nil {
		return "", false, err
	}
	defer cleanup()
	result := server.runTool(ctx, request, input, runPath, "")
	if result.err != nil {
		return "", result.forced, result.err
	}
	mime := strings.TrimSpace(result.stdout)
	if !validMIME(mime) {
		return "", false, errors.New("libmagic returned an invalid MIME type")
	}
	return mime, result.forced, nil
}

func (server *Server) extract(
	ctx context.Context,
	request Request,
) (bool, error) {
	input, err := server.openVerifiedInput(ctx, request)
	if err != nil {
		return false, err
	}
	defer input.Close()
	if err := server.acquire(ctx); err != nil {
		return false, err
	}
	defer server.release()
	if err := server.validateRoots(); err != nil {
		return false, err
	}
	if err := server.outputRoot.Mkdir(request.OutputName, 0o750); err != nil {
		return false, fmt.Errorf("create archive sandbox output: %w", err)
	}
	defer func() {
		if ctx.Err() != nil {
			server.removeOutput(request.OutputName)
		}
	}()
	outputPath := filepath.Join(server.config.OutputRoot, request.OutputName)
	runPath, cleanup, err := server.createRunDirectory(request.RequestID)
	if err != nil {
		return false, err
	}
	defer cleanup()
	result := server.runTool(ctx, request, input, runPath, outputPath)
	if result.err != nil {
		server.removeOutput(request.OutputName)
		return result.forced, result.err
	}
	if err := inspectOutput(outputPath, request, true); err != nil {
		server.removeOutput(request.OutputName)
		return false, err
	}
	return result.forced, nil
}

type toolResult struct {
	stdout string
	forced bool
	err    error
}

func (server *Server) runTool(
	ctx context.Context,
	request Request,
	input *os.File,
	runPath string,
	outputPath string,
) toolResult {
	identity, arguments, err := server.command(request, outputPath)
	if err != nil {
		return toolResult{err: err}
	}
	if _, err := validateExecutable(identity.path, "verified"); err != nil {
		return toolResult{err: err}
	}
	current, err := os.Lstat(identity.path)
	if err != nil || !os.SameFile(identity.info, current) {
		return toolResult{err: errors.New("archive sandbox executable was replaced")}
	}
	duration := time.Duration(request.MaxDurationSeconds) * time.Second
	runContext, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	stdout := newBoundedCapture(server.config.MaxDiagnosticBytes)
	stderr := newBoundedCapture(server.config.MaxDiagnosticBytes)
	overflow := make(chan struct{}, 1)
	stdout.overflow = overflow
	stderr.overflow = overflow
	command := exec.Command(identity.path, arguments...)
	command.Dir = runPath
	command.Env = []string{
		"HOME=" + runPath,
		"TMPDIR=" + runPath,
		"LANG=C",
		"LC_ALL=C",
		"PATH=/nonexistent",
	}
	command.Stdin = strings.NewReader("")
	command.Stdout = stdout
	command.Stderr = stderr
	command.ExtraFiles = []*os.File{input}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	baseline := cgroupPeerSnapshot()
	if err := command.Start(); err != nil {
		return toolResult{err: fmt.Errorf("start archive sandbox tool: %w", err)}
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	monitor := time.NewTicker(server.config.MonitorInterval)
	defer monitor.Stop()
	for {
		select {
		case waitErr := <-done:
			escaped := killNewCgroupPeers(baseline)
			if escaped {
				return toolResult{
					forced: true,
					err:    errors.New("archive sandbox detected an escaped descendant"),
				}
			}
			if stdout.Exceeded() || stderr.Exceeded() {
				return toolResult{
					forced: true,
					err: errors.New(
						"archive sandbox diagnostic output limit reached",
					),
				}
			}
			if waitErr != nil {
				return toolResult{err: fmt.Errorf(
					"archive sandbox tool failed: %v: %s",
					waitErr,
					boundedDiagnostic(stderr.String()),
				)}
			}
			return toolResult{stdout: stdout.String()}
		case <-runContext.Done():
			server.terminate(command.Process, done)
			_ = killNewCgroupPeers(baseline)
			return toolResult{forced: true, err: runContext.Err()}
		case <-overflow:
			server.terminate(command.Process, done)
			_ = killNewCgroupPeers(baseline)
			return toolResult{
				forced: true,
				err:    errors.New("archive sandbox diagnostic output limit reached"),
			}
		case <-monitor.C:
			if outputPath == "" {
				continue
			}
			if err := inspectOutput(outputPath, request, false); err != nil {
				server.terminate(command.Process, done)
				_ = killNewCgroupPeers(baseline)
				return toolResult{forced: true, err: err}
			}
		}
	}
}

func (server *Server) command(
	request Request,
	outputPath string,
) (executableIdentity, []string, error) {
	inputPath := "/proc/self/fd/3"
	switch request.Engine {
	case EngineLibmagic:
		return server.libmagic, []string{
			"--brief", "--mime-type", "--", inputPath,
		}, nil
	case EngineSevenZip:
		return server.sevenZip, []string{
			"x", "-y", "-aoa", "-bd", "-bb0", "-bso0", "-bsp0",
			"-spf-", "-o" + outputPath, "--", inputPath,
		}, nil
	case EngineLibarchive:
		return server.libarchive, []string{
			"--extract",
			"--file", inputPath,
			"--directory", outputPath,
			"--safe-writes",
			"--no-same-owner",
			"--no-same-permissions",
			"--no-acls",
			"--no-fflags",
			"--no-xattrs",
			"--no-mac-metadata",
		}, nil
	default:
		return executableIdentity{}, nil, errors.New(
			"archive sandbox engine is unsupported",
		)
	}
}

func (server *Server) terminate(process *os.Process, done <-chan error) {
	if process == nil {
		return
	}
	_ = syscall.Kill(-process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(server.config.TerminationGrace)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
	}
	_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
	select {
	case <-done:
	case <-time.After(server.config.TerminationGrace):
	}
}

func (server *Server) openVerifiedInput(
	ctx context.Context,
	request Request,
) (*os.File, error) {
	if err := validateDirectoryIdentity(
		server.config.InputRoot,
		server.inputRoot,
		server.inputInfo,
	); err != nil {
		return nil, err
	}
	info, err := server.inputRoot.Lstat(request.InputName)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() != request.InputSizeBytes {
		return nil, errors.New("archive sandbox input identity is invalid")
	}
	opened, err := server.inputRoot.Open(request.InputName)
	if err != nil {
		return nil, fmt.Errorf("open archive sandbox input: %w", err)
	}
	openedInfo, err := opened.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = opened.Close()
		return nil, errors.New("archive sandbox input changed while opening")
	}
	hash := sha256.New()
	written, err := copyContext(
		ctx,
		hash,
		io.NewSectionReader(opened, 0, request.InputSizeBytes),
		request.InputSizeBytes,
	)
	if err != nil || written != request.InputSizeBytes ||
		hex.EncodeToString(hash.Sum(nil)) != request.InputSHA256 {
		_ = opened.Close()
		return nil, errors.New("archive sandbox input hash does not match")
	}
	current, err := server.inputRoot.Lstat(request.InputName)
	after, statErr := opened.Stat()
	if err != nil || statErr != nil || !os.SameFile(info, current) ||
		!os.SameFile(info, after) || after.Size() != request.InputSizeBytes {
		_ = opened.Close()
		return nil, errors.New("archive sandbox input changed during verification")
	}
	return opened, nil
}

func (server *Server) createRunDirectory(
	requestID string,
) (string, func(), error) {
	if err := validateDirectoryIdentity(
		server.config.RunRoot,
		server.runRoot,
		server.runInfo,
	); err != nil {
		return "", nil, err
	}
	if err := server.runRoot.Mkdir(requestID, 0o700); err != nil {
		return "", nil, fmt.Errorf("create archive sandbox run directory: %w", err)
	}
	path := filepath.Join(server.config.RunRoot, requestID)
	return path, func() { _ = server.runRoot.RemoveAll(requestID) }, nil
}

func (server *Server) removeOutput(name string) {
	if requestIDPattern.MatchString(name) {
		_ = server.outputRoot.RemoveAll(name)
	}
}

func (server *Server) acquire(ctx context.Context) error {
	select {
	case server.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) release() {
	<-server.semaphore
}

func (server *Server) validateRoots() error {
	for _, item := range []struct {
		path string
		root *os.Root
		info os.FileInfo
	}{
		{server.config.InputRoot, server.inputRoot, server.inputInfo},
		{server.config.OutputRoot, server.outputRoot, server.outputInfo},
		{server.config.RunRoot, server.runRoot, server.runInfo},
	} {
		if err := validateDirectoryIdentity(item.path, item.root, item.info); err != nil {
			return fmt.Errorf("archive sandbox root changed: %w", err)
		}
	}
	return nil
}

func prepareSocketPath(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox socket parent is invalid")
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || current.Mode()&os.ModeSocket == 0 ||
		current.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox socket path is occupied")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale archive sandbox socket: %w", err)
	}
	return nil
}

func validateExecutable(path string, version string) (executableIdentity, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) ||
		(version != "verified" && !validBoundedText(version, 256)) {
		return executableIdentity{}, errors.New("tool path or version is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return executableIdentity{}, errors.New("tool path contains a symbolic link")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return executableIdentity{}, errors.New("tool is not a regular executable")
	}
	return executableIdentity{path: path, info: info}, nil
}

func failedResponse(request Request, code string, err error) Response {
	message := "archive sandbox operation failed"
	if err != nil {
		message = boundedDiagnostic(err.Error())
	}
	return Response{
		SchemaVersion: SchemaVersion,
		RequestID:     request.RequestID,
		Status:        "failed",
		EngineVersion: "archive-sandbox-v1",
		ErrorCode:     code,
		ErrorMessage:  message,
	}
}

func inspectOutput(path string, request Request, harden bool) error {
	rootInfo, err := os.Lstat(path)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox output root is invalid")
	}
	rootDevice := fileDevice(rootInfo)
	entries := 0
	var total int64
	var paths []string
	err = filepath.WalkDir(path, func(
		current string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path {
			return nil
		}
		relative, err := filepath.Rel(path, current)
		if err != nil || !validRelativeOutputPath(relative) {
			return errors.New("archive sandbox output path is invalid")
		}
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("archive sandbox output contains a link or special file")
		}
		if rootDevice != 0 && fileDevice(info) != rootDevice {
			return errors.New("archive sandbox output crossed a filesystem boundary")
		}
		entries++
		if entries > request.MaxEntries {
			return errors.New("archive sandbox output entry limit reached")
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || info.Size() > request.MaxEntryBytes ||
				fileLinkCount(info) != 1 ||
				info.Size() > request.MaxExpandedBytes-total {
				return errors.New("archive sandbox output byte limit reached")
			}
			total += info.Size()
		}
		paths = append(paths, current)
		return nil
	})
	if err != nil {
		return err
	}
	if !harden {
		return nil
	}
	sort.Slice(paths, func(left, right int) bool {
		return len(paths[left]) > len(paths[right])
	})
	for _, current := range paths {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		mode := fs.FileMode(0o640)
		if info.IsDir() {
			mode = 0o750
		}
		if err := os.Chmod(current, mode); err != nil {
			return fmt.Errorf("harden archive sandbox output: %w", err)
		}
	}
	return os.Chmod(path, 0o750)
}

func validRelativeOutputPath(value string) bool {
	if value == "" || value == "." || filepath.IsAbs(value) ||
		len(value) > 2048 || !utf8.ValidString(value) ||
		strings.Contains(value, `\`) || filepath.Clean(value) != value {
		return false
	}
	parts := strings.Split(filepath.ToSlash(value), "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
		if index == 0 && len(part) >= 2 && part[1] == ':' &&
			((part[0] >= 'a' && part[0] <= 'z') ||
				(part[0] >= 'A' && part[0] <= 'Z')) {
			return false
		}
		for _, character := range part {
			if character == 0 || unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func fileDevice(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Dev)
}

func fileLinkCount(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

func boundedDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, character := range value {
		if character >= 0x20 && character != 0x7f {
			builder.WriteRune(character)
		}
		if builder.Len() >= 2048 {
			break
		}
	}
	if builder.Len() == 0 {
		return "archive sandbox operation failed"
	}
	return builder.String()
}

type boundedCapture struct {
	mu       sync.Mutex
	maximum  int64
	written  int64
	buffer   strings.Builder
	overflow chan struct{}
	once     sync.Once
	exceeded bool
}

func newBoundedCapture(maximum int64) *boundedCapture {
	return &boundedCapture{maximum: maximum}
}

func (capture *boundedCapture) Write(value []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	remaining := capture.maximum - capture.written
	if remaining < 0 {
		remaining = 0
	}
	accepted := len(value)
	if int64(accepted) > remaining {
		accepted = int(remaining)
	}
	if accepted > 0 {
		capture.buffer.Write(value[:accepted])
		capture.written += int64(accepted)
	}
	if accepted != len(value) {
		capture.exceeded = true
		capture.once.Do(func() {
			if capture.overflow != nil {
				capture.overflow <- struct{}{}
			}
		})
	}
	return len(value), nil
}

func (capture *boundedCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.buffer.String()
}

func (capture *boundedCapture) Exceeded() bool {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.exceeded
}

func parseMode(value string) (fs.FileMode, error) {
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed > 0o777 {
		return 0, errors.New("invalid file mode")
	}
	return fs.FileMode(parsed), nil
}
