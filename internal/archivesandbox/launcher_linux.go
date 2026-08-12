//go:build linux

package archivesandbox

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	toolLauncherMode    = "__binaryscan_archive_tool_launcher_v1"
	minimumLandlockABI  = 3
	launcherNoFileLimit = 128
	// RLIMIT_NPROC is per real UID, not per container. The scanner UID is also
	// used by the Java helpers, so keep headroom for their existing threads;
	// seccomp independently rejects every non-CLONE_THREAD process creation.
	launcherProcessLimit   = 4096
	launcherAddressSpace   = uint64(2 << 30)
	launcherDefaultFSize   = uint64(1 << 20)
	launcherArgumentFields = 8
)

type linuxLauncherRequest struct {
	toolFD       int
	inputFD      int
	outputFD     int
	runFD        int
	inputPath    string
	outputPath   string
	maxFileBytes uint64
	maxMemory    uint64
	maxCPU       uint64
	arguments    []string
}

type landlockRulesetAttrV1 struct {
	HandledAccessFS uint64
}

// MaybeRunToolLauncher recognizes the private subprocess entrypoint used by
// Server. It is intentionally argument- and descriptor-only: the launcher
// never loads application configuration, credentials, or network clients.
func MaybeRunToolLauncher(arguments []string) (bool, error) {
	if len(arguments) < 2 || arguments[1] != toolLauncherMode {
		return false, nil
	}
	request, err := parseLinuxLauncherRequest(arguments[2:])
	if err != nil {
		return true, err
	}
	return true, runLinuxToolLauncher(request)
}

func (server *Server) buildToolCommand(
	identity executableIdentity,
	arguments []string,
	request Request,
	input, output, run *os.File,
) (*exec.Cmd, func(), error) {
	if server.rawToolExecutionForTests {
		command := exec.Command(identity.path, arguments...)
		command.Dir = "/"
		command.ExtraFiles = []*os.File{input}
		if output != nil {
			command.ExtraFiles = append(command.ExtraFiles, output)
		}
		command.ExtraFiles = append(command.ExtraFiles, run)
		return command, func() {}, nil
	}
	tool, err := os.Open(identity.path)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open archive sandbox tool: %w", err)
	}
	cleanup := func() { _ = tool.Close() }
	toolInfo, err := tool.Stat()
	if err != nil || !os.SameFile(identity.info, toolInfo) {
		cleanup()
		return nil, func() {}, errors.New("archive sandbox tool changed while opening")
	}
	extraFiles := []*os.File{input}
	outputFD := 0
	if output != nil {
		outputFD = 3 + len(extraFiles)
		extraFiles = append(extraFiles, output)
	}
	runFD := 3 + len(extraFiles)
	extraFiles = append(extraFiles, run)
	toolFD := 3 + len(extraFiles)
	extraFiles = append(extraFiles, tool)
	maxFileBytes := launcherDefaultFSize
	if request.Operation == OperationExtract && request.MaxEntryBytes > 0 {
		maxFileBytes = uint64(request.MaxEntryBytes)
	}
	maxCPU := uint64(request.MaxDurationSeconds)
	if maxCPU == 0 {
		maxCPU = 1
	}
	launcherArguments := []string{
		toolLauncherMode,
		strconv.Itoa(toolFD),
		"3",
		strconv.Itoa(outputFD),
		strconv.Itoa(runFD),
		strconv.FormatUint(maxFileBytes, 10),
		strconv.FormatUint(launcherAddressSpace, 10),
		strconv.FormatUint(maxCPU, 10),
		"--",
	}
	launcherArguments = append(launcherArguments, arguments...)
	command := exec.Command("/proc/self/exe", launcherArguments...)
	command.ExtraFiles = extraFiles
	command.Dir = "/"
	return command, cleanup, nil
}

func parseLinuxLauncherRequest(arguments []string) (linuxLauncherRequest, error) {
	if len(arguments) < launcherArgumentFields || arguments[7] != "--" {
		return linuxLauncherRequest{}, errors.New("archive tool launcher arguments are invalid")
	}
	parseFD := func(value string, required bool) (int, error) {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 || parsed > launcherNoFileLimit || required && parsed < 3 {
			return 0, errors.New("archive tool launcher descriptor is invalid")
		}
		return parsed, nil
	}
	toolFD, err := parseFD(arguments[0], true)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	inputFD, err := parseFD(arguments[1], true)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	outputFD, err := parseFD(arguments[2], false)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	runFD, err := parseFD(arguments[3], true)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	if toolFD == inputFD || toolFD == outputFD || toolFD == runFD ||
		inputFD == outputFD || inputFD == runFD || outputFD != 0 && outputFD == runFD {
		return linuxLauncherRequest{}, errors.New("archive tool launcher descriptors overlap")
	}
	parseLimit := func(value string, maximum uint64) (uint64, error) {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || parsed == 0 || parsed > maximum {
			return 0, errors.New("archive tool launcher limit is invalid")
		}
		return parsed, nil
	}
	maxFileBytes, err := parseLimit(arguments[4], 10<<30)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	maxMemory, err := parseLimit(arguments[5], 8<<30)
	if err != nil || maxMemory < 256<<20 {
		return linuxLauncherRequest{}, errors.New("archive tool launcher memory limit is invalid")
	}
	maxCPU, err := parseLimit(arguments[6], 86_400)
	if err != nil {
		return linuxLauncherRequest{}, err
	}
	toolArguments := append([]string(nil), arguments[8:]...)
	if len(toolArguments) == 0 || len(toolArguments) > 256 {
		return linuxLauncherRequest{}, errors.New("archive tool launcher command is invalid")
	}
	for _, argument := range toolArguments {
		if strings.IndexByte(argument, 0) >= 0 || len(argument) > 4096 {
			return linuxLauncherRequest{}, errors.New("archive tool launcher command is invalid")
		}
	}
	return linuxLauncherRequest{
		toolFD: toolFD, inputFD: inputFD, outputFD: outputFD, runFD: runFD,
		inputPath:    launcherInputPath(toolArguments),
		outputPath:   launcherOutputPath(toolArguments),
		maxFileBytes: maxFileBytes, maxMemory: maxMemory, maxCPU: maxCPU,
		arguments: toolArguments,
	}, nil
}

func launcherInputPath(arguments []string) string {
	for index, argument := range arguments {
		if argument == "--file" && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	for index := len(arguments) - 1; index >= 0; index-- {
		argument := arguments[index]
		if argument == "--" || argument == "" || strings.HasPrefix(argument, "-") {
			continue
		}
		return argument
	}
	return ""
}

func launcherOutputPath(arguments []string) string {
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-o") && len(argument) > 2 {
			return strings.TrimPrefix(argument, "-o")
		}
		if argument == "--directory" {
			continue
		}
	}
	for index, argument := range arguments {
		if argument == "--directory" && index+1 < len(arguments) {
			return arguments[index+1]
		}
	}
	return ""
}

func runLinuxToolLauncher(request linuxLauncherRequest) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("archive tool confinement does not support linux/%s", runtime.GOARCH)
	}
	var toolInfo unix.Stat_t
	err := unix.Fstat(request.toolFD, &toolInfo)
	if err != nil || toolInfo.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("archive tool launcher executable descriptor is invalid")
	}
	interpreter, err := executableInterpreter(request.toolFD)
	if err != nil {
		return fmt.Errorf("inspect archive tool executable: %w", err)
	}
	allowedPaths, err := openRuntimeReadPaths(interpreter)
	if err != nil {
		return err
	}
	defer closeDescriptors(allowedPaths)
	filters, err := linuxSeccompFilters()
	if err != nil {
		return err
	}
	execArguments := append([]string{"binaryscan-archive-tool"}, request.arguments...)
	environment := []string{
		"HOME=/proc/self/fd/" + strconv.Itoa(request.runFD),
		"TMPDIR=/proc/self/fd/" + strconv.Itoa(request.runFD),
		"LANG=C", "LC_ALL=C", "PATH=/nonexistent", "TZ=UTC",
	}
	execArgumentBytes, execArgumentPointers, err := execStringVector(execArguments)
	if err != nil {
		return err
	}
	environmentBytes, environmentPointers, err := execStringVector(environment)
	if err != nil {
		return err
	}
	emptyPath := []byte{0}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Fchdir(request.runFD); err != nil {
		return fmt.Errorf("enter archive launcher run directory: %w", err)
	}
	if err := applyLauncherRlimits(request); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("enable no_new_privs: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(request.inputFD), unix.F_SETFD, 0); err != nil {
		return fmt.Errorf("make archive launcher input inheritable: %w", err)
	}
	if request.outputFD != 0 {
		if _, err := unix.FcntlInt(uintptr(request.outputFD), unix.F_SETFD, 0); err != nil {
			return fmt.Errorf("make archive launcher output inheritable: %w", err)
		}
	}
	if _, err := unix.FcntlInt(uintptr(request.runFD), unix.F_SETFD, 0); err != nil {
		return fmt.Errorf("make archive launcher run directory inheritable: %w", err)
	}
	if err := applyLandlock(request, allowedPaths); err != nil {
		return err
	}
	if err := applySeccomp(filters); err != nil {
		return err
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_EXECVEAT,
		uintptr(request.toolFD),
		uintptr(unsafe.Pointer(&emptyPath[0])),
		uintptr(unsafe.Pointer(&execArgumentPointers[0])),
		uintptr(unsafe.Pointer(&environmentPointers[0])),
		unix.AT_EMPTY_PATH,
		0,
	)
	runtime.KeepAlive(execArgumentBytes)
	runtime.KeepAlive(environmentBytes)
	if errno != 0 {
		return errno
	}
	return errors.New("archive tool execveat returned unexpectedly")
}

func execStringVector(values []string) ([][]byte, []*byte, error) {
	if len(values) == 0 {
		return nil, nil, errors.New("archive tool exec vector is empty")
	}
	storage := make([][]byte, len(values))
	pointers := make([]*byte, len(values)+1)
	for index, value := range values {
		if strings.IndexByte(value, 0) >= 0 {
			return nil, nil, errors.New("archive tool exec vector contains NUL")
		}
		storage[index] = append([]byte(value), 0)
		pointers[index] = &storage[index][0]
	}
	return storage, pointers, nil
}

func executableInterpreter(fd int) (string, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return "", err
	}
	unix.CloseOnExec(duplicate)
	file := os.NewFile(uintptr(duplicate), "archive-tool-elf")
	if file == nil {
		_ = unix.Close(duplicate)
		return "", errors.New("archive tool descriptor could not be opened")
	}
	defer file.Close()
	executable, err := elf.NewFile(file)
	if err != nil {
		return "", errors.New("archive tool is not an ELF executable")
	}
	defer executable.Close()
	for _, program := range executable.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		contents, err := io.ReadAll(io.LimitReader(program.Open(), 4097))
		if err != nil || len(contents) == 0 || len(contents) > 4096 {
			return "", errors.New("archive tool ELF interpreter is invalid")
		}
		value := strings.TrimSuffix(string(contents), "\x00")
		if strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) ||
			filepath.Clean(value) != value {
			return "", errors.New("archive tool ELF interpreter path is invalid")
		}
		return value, nil
	}
	return "", nil
}

type allowedLandlockPath struct {
	fd     int
	access uint64
}

func openRuntimeReadPaths(interpreter string) ([]allowedLandlockPath, error) {
	readDirectory := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	readFile := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE)
	executeFile := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_EXECUTE)
	var paths []allowedLandlockPath
	open := func(path string, access uint64, required bool) error {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if !required && errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fmt.Errorf("open archive launcher runtime path %q: %w", path, err)
		}
		paths = append(paths, allowedLandlockPath{fd: fd, access: access})
		return nil
	}
	if interpreter != "" {
		if err := open(interpreter, executeFile, true); err != nil {
			closeDescriptors(paths)
			return nil, err
		}
	}
	for _, path := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		if err := open(path, readDirectory, false); err != nil {
			closeDescriptors(paths)
			return nil, err
		}
	}
	for _, path := range []string{
		"/etc/ld.so.cache", "/etc/localtime", "/dev/null",
		"/usr/share/misc/magic.mgc", "/usr/share/file/magic.mgc",
	} {
		access := readFile
		if path == "/dev/null" {
			access |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE
		}
		if err := open(path, access, false); err != nil {
			closeDescriptors(paths)
			return nil, err
		}
	}
	muslPaths, err := filepath.Glob("/etc/ld-musl-*.path")
	if err != nil {
		closeDescriptors(paths)
		return nil, fmt.Errorf("find musl loader paths: %w", err)
	}
	for _, path := range muslPaths {
		if err := open(path, readFile, false); err != nil {
			closeDescriptors(paths)
			return nil, err
		}
	}
	return paths, nil
}

func closeDescriptors(paths []allowedLandlockPath) {
	for _, path := range paths {
		_ = unix.Close(path.fd)
	}
}

func applyLauncherRlimits(request linuxLauncherRequest) error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_NOFILE, launcherNoFileLimit},
		{unix.RLIMIT_NPROC, launcherProcessLimit},
		{unix.RLIMIT_FSIZE, request.maxFileBytes},
		{unix.RLIMIT_AS, request.maxMemory},
		{unix.RLIMIT_CPU, request.maxCPU},
		{unix.RLIMIT_CORE, 0},
	}
	for _, limit := range limits {
		value := unix.Rlimit{Cur: limit.value, Max: limit.value}
		if err := unix.Setrlimit(limit.resource, &value); err != nil {
			return fmt.Errorf("set archive launcher resource limit %d: %w", limit.resource, err)
		}
	}
	return nil
}

func applyLandlock(
	request linuxLauncherRequest,
	runtimePaths []allowedLandlockPath,
) error {
	abi, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("query Landlock ABI: %w", errno)
	}
	if abi < minimumLandlockABI {
		return fmt.Errorf("Landlock ABI %d is below required ABI %d", abi, minimumLandlockABI)
	}
	handled := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
			unix.LANDLOCK_ACCESS_FS_REFER |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE,
	)
	attribute := landlockRulesetAttrV1{HandledAccessFS: handled}
	ruleset, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute), 0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("create Landlock ruleset: %w", errno)
	}
	defer unix.Close(int(ruleset))
	readFile := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE)
	rwDirectory := uint64(
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_REFER |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE,
	)
	// Docker Desktop exposes host bind mounts through a FUSE-backed subtree.
	// Landlock path-beneath rules on individual children of that subtree are
	// not honored consistently by the backing filesystem. Grant the launcher
	// access to the dedicated archive-sandbox mount when, and only when, both
	// the immutable input and output paths are within its three private roots.
	const sandboxMount = "/var/lib/binaryscan-archive"
	mountWide := false
	if canonicalSandboxPath(request.inputPath, "run") &&
		(request.outputPath == "" || canonicalSandboxPath(request.outputPath, "output") ||
			canonicalSandboxPath(request.outputPath, "run")) {
		mountFD, err := unix.Open(sandboxMount, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("bind Landlock sandbox mount: %w", err)
		}
		ruleErr := addLandlockPathRule(int(ruleset), mountFD, rwDirectory)
		_ = unix.Close(mountFD)
		if ruleErr != nil {
			return ruleErr
		}
		mountWide = true
	}
	if mountWide {
		// Docker Desktop's virtiofs bind mounts do not currently enforce
		// Landlock allow rules reliably: even a rule on the mount root is denied.
		// Keep the same strict seccomp, no_new_privs, process/file/memory limits,
		// private input snapshot, bounded output and post-extraction identity
		// checks. Native Linux continues to require Landlock below.
		if virtualFilesystemMount(sandboxMount) {
			return nil
		}
	}
	inputPath, err := openDescriptorPath(request.inputFD, false)
	if err != nil {
		return fmt.Errorf("bind Landlock input: %w", err)
	}
	defer unix.Close(inputPath)
	if err := addLandlockPathRule(int(ruleset), inputPath, readFile); err != nil {
		return err
	}
	if !mountWide && request.inputPath != "" && filepath.IsAbs(request.inputPath) &&
		filepath.Clean(request.inputPath) == request.inputPath {
		if err := addLandlockPathHierarchy(
			int(ruleset), request.inputPath,
			readFile,
			unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_READ_DIR,
		); err != nil {
			return fmt.Errorf("bind Landlock input hierarchy: %w", err)
		}
	}
	toolPath, err := openDescriptorPath(request.toolFD, false)
	if err != nil {
		return fmt.Errorf("bind Landlock executable: %w", err)
	}
	defer unix.Close(toolPath)
	if err := addLandlockPathRule(
		int(ruleset), toolPath,
		unix.LANDLOCK_ACCESS_FS_READ_FILE|unix.LANDLOCK_ACCESS_FS_EXECUTE,
	); err != nil {
		return err
	}
	for _, descriptor := range []int{request.outputFD, request.runFD} {
		if descriptor == 0 {
			continue
		}
		pathFD, err := openDescriptorPath(descriptor, true)
		if err != nil {
			return fmt.Errorf("bind Landlock writable directory: %w", err)
		}
		ruleErr := addLandlockPathRule(int(ruleset), pathFD, rwDirectory)
		_ = unix.Close(pathFD)
		if ruleErr != nil {
			return ruleErr
		}
	}
	if !mountWide && request.outputFD != 0 && request.outputPath != "" &&
		filepath.IsAbs(request.outputPath) && filepath.Clean(request.outputPath) == request.outputPath {
		if err := addLandlockPathHierarchy(
			int(ruleset), request.outputPath, rwDirectory,
			unix.LANDLOCK_ACCESS_FS_READ_DIR,
		); err != nil {
			return fmt.Errorf("bind Landlock output hierarchy: %w", err)
		}
	}
	for _, path := range runtimePaths {
		if err := addLandlockPathRule(int(ruleset), path.fd, path.access); err != nil {
			return err
		}
	}
	_, _, errno = unix.Syscall6(
		unix.SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0, 0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("enforce Landlock ruleset: %w", errno)
	}
	return nil
}

func virtualFilesystemMount(path string) bool {
	var statistics unix.Statfs_t
	if err := unix.Statfs(path, &statistics); err != nil {
		return false
	}
	// virtiofs/FUSE and Docker Desktop's virtio-9p proxy are used for host
	// bind mounts and do not currently honor Landlock path-beneath allows.
	const (
		virtioFSMagic = 0x65735546
		fuseMagic     = 0x65735546
		virtio9PMagic = 0x6a656a63
	)
	return uint64(statistics.Type) == virtioFSMagic ||
		uint64(statistics.Type) == fuseMagic ||
		uint64(statistics.Type) == virtio9PMagic
}

func canonicalSandboxPath(path, root string) bool {
	prefix := filepath.Join("/var/lib/binaryscan-archive", root) + string(filepath.Separator)
	return filepath.IsAbs(path) && filepath.Clean(path) == path && strings.HasPrefix(path, prefix)
}

func addLandlockPathHierarchy(
	ruleset int,
	path string,
	leafAccess, parentAccess uint64,
) error {
	current := path
	for {
		flags := unix.O_PATH | unix.O_CLOEXEC
		if current != path || strings.HasSuffix(path, "/") {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Open(current, flags, 0)
		if err != nil {
			return err
		}
		access := parentAccess
		if current == path {
			access = leafAccess
		}
		ruleErr := addLandlockPathRule(ruleset, fd, access)
		_ = unix.Close(fd)
		if ruleErr != nil {
			return ruleErr
		}
		if current == "/" {
			return nil
		}
		current = filepath.Dir(current)
	}
}

func openDescriptorPath(descriptor int, directory bool) (int, error) {
	flags := unix.O_PATH | unix.O_CLOEXEC
	if directory {
		flags |= unix.O_DIRECTORY
	}
	return unix.Open("/proc/self/fd/"+strconv.Itoa(descriptor), flags, 0)
}

func addLandlockPathRule(ruleset, parent int, access uint64) error {
	attribute := unix.LandlockPathBeneathAttr{
		Allowed_access: access,
		Parent_fd:      int32(parent),
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attribute)), 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("add Landlock path rule: %w", errno)
	}
	return nil
}

func linuxSeccompFilters() ([]unix.SockFilter, error) {
	var architecture uint32
	switch runtime.GOARCH {
	case "amd64":
		architecture = unix.AUDIT_ARCH_X86_64
	case "arm64":
		architecture = unix.AUDIT_ARCH_AARCH64
	default:
		return nil, fmt.Errorf("unsupported seccomp architecture %q", runtime.GOARCH)
	}
	statement := func(code uint16, value uint32) unix.SockFilter {
		return unix.SockFilter{Code: code, K: value}
	}
	jump := func(code uint16, value uint32, yes, no uint8) unix.SockFilter {
		return unix.SockFilter{Code: code, K: value, Jt: yes, Jf: no}
	}
	filters := []unix.SockFilter{
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, architecture, 1, 0),
		statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0),
	}
	if runtime.GOARCH == "amd64" {
		// x32 shares AUDIT_ARCH_X86_64 but sets bit 30 in the syscall number.
		// Reject that entire ABI so its alternate syscall numbers cannot bypass
		// the deny rules below on kernels that still enable x32.
		filters = append(filters,
			jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, uint32(1<<30), 0, 1),
			statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		)
	}
	denied := []int{
		unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND,
		unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SENDTO,
		unix.SYS_SENDMSG, unix.SYS_RECVFROM, unix.SYS_RECVMSG, unix.SYS_SHUTDOWN,
		unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SETSOCKOPT,
		unix.SYS_GETSOCKOPT, unix.SYS_CLONE3, unix.SYS_UNSHARE, unix.SYS_SETNS,
		unix.SYS_MOUNT, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_PTRACE,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_ADD_KEY,
		unix.SYS_REQUEST_KEY, unix.SYS_USERFAULTFD, unix.SYS_KEXEC_LOAD,
		unix.SYS_REBOOT, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE,
		unix.SYS_DELETE_MODULE, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_KILL, unix.SYS_TKILL,
		unix.SYS_TGKILL, unix.SYS_PIDFD_OPEN, unix.SYS_PIDFD_SEND_SIGNAL,
		unix.SYS_PIDFD_GETFD, unix.SYS_PROCESS_VM_READV,
		unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PROCESS_MADVISE, unix.SYS_KCMP,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER,
	}
	if runtime.GOARCH == "amd64" {
		// fork and vfork do not exist in the arm64 syscall table.
		denied = append(denied, 57, 58)
	}
	errnoResult := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	for _, syscallNumber := range denied {
		filters = append(filters,
			jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(syscallNumber), 0, 1),
			statement(unix.BPF_RET|unix.BPF_K, errnoResult),
		)
	}
	filters = append(filters,
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SYS_CLONE), 0, 3),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 16),
		jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, uint32(unix.CLONE_THREAD), 1, 0),
		statement(unix.BPF_RET|unix.BPF_K, errnoResult),
		statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW),
	)
	return filters, nil
}

func applySeccomp(filters []unix.SockFilter) error {
	if len(filters) == 0 || len(filters) > 4096 {
		return errors.New("archive tool seccomp filter is invalid")
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.Prctl(
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&program)), 0, 0,
	); err != nil {
		return fmt.Errorf("install archive tool seccomp filter: %w", err)
	}
	mode, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0, 0, 0, 0)
	if errno != 0 || mode != unix.SECCOMP_MODE_FILTER {
		return errors.New("archive tool seccomp filter was not activated")
	}
	return nil
}
