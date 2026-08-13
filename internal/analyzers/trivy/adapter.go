package trivy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Adapter owns the fixed executable, offline cache, allowed input roots, work
// root, and all process/output limits.
type Adapter struct {
	executable             string
	inputRoots             []string
	cacheDirectory         string
	workRoot               string
	maxDuration            time.Duration
	terminationGracePeriod time.Duration
	maxStandardOutputBytes int64
	maxStandardErrorBytes  int64
	maxReportBytes         int64
	maxWorkBytes           int64
	maxResults             int
	maxFindings            int
}

// New constructs an adapter after canonicalizing and validating all
// administrator-controlled paths.
func New(config Config) (*Adapter, error) {
	if config.MaxDuration <= 0 ||
		config.TerminationGracePeriod <= 0 ||
		config.MaxStandardOutputBytes <= 0 ||
		config.MaxStandardErrorBytes <= 0 ||
		config.MaxReportBytes <= 0 ||
		config.MaxWorkBytes < 0 ||
		config.MaxResults <= 0 ||
		config.MaxFindings <= 0 {
		return nil, fmt.Errorf(
			"%w: required limits must be positive and work limit non-negative",
			ErrInvalidConfiguration,
		)
	}
	executable, err := canonicalExecutable(config.Executable)
	if err != nil {
		return nil, fmt.Errorf("%w: executable: %v", ErrInvalidConfiguration, err)
	}
	cacheDirectory, err := canonicalDirectory(config.CacheDirectory)
	if err != nil {
		return nil, fmt.Errorf("%w: cache directory: %v", ErrInvalidConfiguration, err)
	}
	workRoot, err := canonicalDirectory(config.WorkRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: work root: %v", ErrInvalidConfiguration, err)
	}
	if sameOrDescendant(cacheDirectory, workRoot) ||
		sameOrDescendant(workRoot, cacheDirectory) {
		return nil, fmt.Errorf(
			"%w: cache and work roots must not overlap",
			ErrInvalidConfiguration,
		)
	}
	if len(config.InputRoots) == 0 {
		return nil, fmt.Errorf("%w: at least one input root is required", ErrInvalidConfiguration)
	}
	inputRoots := make([]string, 0, len(config.InputRoots))
	seen := make(map[string]struct{}, len(config.InputRoots))
	for _, root := range config.InputRoots {
		canonical, rootErr := canonicalDirectory(root)
		if rootErr != nil {
			return nil, fmt.Errorf("%w: input root: %v", ErrInvalidConfiguration, rootErr)
		}
		if _, found := seen[canonical]; found {
			continue
		}
		seen[canonical] = struct{}{}
		inputRoots = append(inputRoots, canonical)
	}
	return &Adapter{
		executable: executable, inputRoots: inputRoots,
		cacheDirectory: cacheDirectory, workRoot: workRoot,
		maxDuration:            config.MaxDuration,
		terminationGracePeriod: config.TerminationGracePeriod,
		maxStandardOutputBytes: config.MaxStandardOutputBytes,
		maxStandardErrorBytes:  config.MaxStandardErrorBytes,
		maxReportBytes:         config.MaxReportBytes,
		maxWorkBytes:           config.MaxWorkBytes,
		maxResults:             config.MaxResults, maxFindings: config.MaxFindings,
	}, nil
}

// Analyze runs a single offline Trivy image scan. A successful report with
// findings returns a nil error; findings never control process success.
func (a *Adapter) Analyze(ctx context.Context, request Request) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("%w: context is nil", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	source, workDirectory, err := a.validateRequest(request)
	if err != nil {
		return Report{}, err
	}
	outputPath := filepath.Join(workDirectory, rawReportFilename)
	if err := ensurePathAbsent(outputPath); err != nil {
		return Report{}, fmt.Errorf("%w: raw report path: %v", ErrInvalidInput, err)
	}
	if a.maxWorkBytes > 0 {
		if err := checkWorkspaceUsage(
			ctx,
			a.workRoot,
			a.maxWorkBytes,
		); err != nil {
			return Report{}, err
		}
	}
	runtimeDirectory := filepath.Join(workDirectory, "trivy-runtime")
	if err := createPrivateDirectory(runtimeDirectory); err != nil {
		return Report{}, fmt.Errorf("%w: runtime directory: %v", ErrInvalidInput, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, a.maxDuration)
	defer cancel()
	if err := runCtx.Err(); err != nil {
		return Report{}, err
	}
	arguments := a.arguments(source, outputPath)
	environment := a.environment(runtimeDirectory)
	execution, err := runCommand(runCtx, commandSpec{
		Executable:             a.executable,
		Arguments:              arguments,
		Environment:            environment,
		Directory:              workDirectory,
		OutputPath:             outputPath,
		MaxStandardOutputBytes: a.maxStandardOutputBytes,
		MaxStandardErrorBytes:  a.maxStandardErrorBytes,
		MaxReportBytes:         a.maxReportBytes,
		QuotaRoot:              a.workRoot,
		MaxQuotaBytes:          a.maxWorkBytes,
		TerminationGracePeriod: a.terminationGracePeriod,
	})
	if err != nil {
		return Report{}, err
	}
	if execution.ExitCode != 0 {
		return Report{}, &ExecutionError{
			ExitCode: execution.ExitCode,
			Stderr:   sanitizeDiagnostic(execution.Stderr),
		}
	}
	raw, metadata, err := readRawReport(outputPath, a.maxReportBytes)
	if err != nil {
		return Report{}, err
	}
	report, err := parseReport(raw, metadata, a.maxResults, a.maxFindings)
	if err != nil {
		return Report{}, err
	}
	return report, nil
}

func (a *Adapter) validateRequest(request Request) (VerifiedSource, string, error) {
	if err := verifySourceAgain(request.Source); err != nil {
		return VerifiedSource{}, "", err
	}
	if !containedByAny(request.Source.path, a.inputRoots) {
		return VerifiedSource{}, "", fmt.Errorf(
			"%w: source is outside configured input roots",
			ErrInvalidInput,
		)
	}
	workDirectory, err := canonicalDirectory(request.WorkDirectory)
	if err != nil {
		return VerifiedSource{}, "", fmt.Errorf("%w: work directory: %v", ErrInvalidInput, err)
	}
	if workDirectory == a.workRoot || !sameOrDescendant(workDirectory, a.workRoot) {
		return VerifiedSource{}, "", fmt.Errorf(
			"%w: work directory is outside the configured work root",
			ErrInvalidInput,
		)
	}
	if sameOrDescendant(request.Source.path, workDirectory) {
		return VerifiedSource{}, "", fmt.Errorf(
			"%w: source must not be inside the output work directory",
			ErrInvalidInput,
		)
	}
	return request.Source, workDirectory, nil
}

func (a *Adapter) arguments(source VerifiedSource, outputPath string) []string {
	switch source.kind {
	case SourceDockerSaveTAR:
		return []string{
			"image",
			"--input", source.path,
			"--cache-dir", a.cacheDirectory,
			"--cache-backend", "memory",
			"--format", "json",
			"--output", outputPath,
			"--scanners", "vuln",
			"--offline-scan",
			"--skip-db-update",
			"--skip-java-db-update",
			"--disable-telemetry",
			"--skip-version-check",
			"--no-progress",
			"--exit-code", "0",
			"--timeout", a.maxDuration.String(),
		}
	case SourceOCILayout:
		input := source.path + "@" + source.manifestDigest
		return []string{
			"image",
			"--input", input,
			"--cache-dir", a.cacheDirectory,
			"--cache-backend", "memory",
			"--format", "json",
			"--output", outputPath,
			"--scanners", "vuln",
			"--offline-scan",
			"--skip-db-update",
			"--skip-java-db-update",
			"--disable-telemetry",
			"--skip-version-check",
			"--no-progress",
			"--exit-code", "0",
			"--timeout", a.maxDuration.String(),
		}
	case SourceVMImage:
		// The vm subcommand takes the image path positionally; it has no
		// --input flag and identifies partitions and filesystems itself.
		return []string{
			"vm",
			source.path,
			"--cache-dir", a.cacheDirectory,
			"--cache-backend", "memory",
			"--format", "json",
			"--output", outputPath,
			"--scanners", "vuln",
			"--offline-scan",
			"--skip-db-update",
			"--skip-java-db-update",
			"--disable-telemetry",
			"--skip-version-check",
			"--no-progress",
			"--exit-code", "0",
			"--timeout", a.maxDuration.String(),
		}
	default:
		// Unreachable: every verified source kind is handled above. Returning
		// nil keeps the command boundary safe if a future kind is forgotten.
		return nil
	}
}

func (a *Adapter) environment(runtimeDirectory string) []string {
	return []string{
		"HOME=" + runtimeDirectory,
		"TMPDIR=" + runtimeDirectory,
		"XDG_CACHE_HOME=" + runtimeDirectory,
		"TRIVY_CACHE_DIR=" + a.cacheDirectory,
		"TRIVY_OFFLINE_SCAN=true",
		"TRIVY_SKIP_DB_UPDATE=true",
		"TRIVY_SKIP_JAVA_DB_UPDATE=true",
		"TRIVY_DISABLE_TELEMETRY=true",
		"TRIVY_SKIP_VERSION_CHECK=true",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"NO_PROXY=*",
		"DOCKER_HOST=",
		"CONTAINERD_ADDRESS=",
	}
}

func canonicalExecutable(path string) (string, error) {
	canonical, err := canonicalLeaf(path, false)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("file is not executable")
	}
	return canonical, nil
}

func canonicalDirectory(path string) (string, error) {
	return canonicalLeaf(path, true)
}

func containedByAny(path string, roots []string) bool {
	for _, root := range roots {
		if sameOrDescendant(path, root) {
			return true
		}
	}
	return false
}

func sameOrDescendant(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator)) &&
			!filepath.IsAbs(relative))
}

func ensurePathAbsent(path string) error {
	_, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	default:
		return fmt.Errorf("path already exists")
	}
}

func createPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("created path is not a directory")
	}
	return nil
}

func sanitizeDiagnostic(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	var sanitized strings.Builder
	sanitized.Grow(len(value))
	for _, character := range strings.TrimSpace(value) {
		switch {
		case character == '\n' || character == '\t':
			sanitized.WriteRune(character)
		case character < 0x20 || character == 0x7f:
			sanitized.WriteRune('\uFFFD')
		default:
			sanitized.WriteRune(character)
		}
	}
	return sanitized.String()
}
