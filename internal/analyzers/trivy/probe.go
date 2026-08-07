package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	versionProbeOutputBytes = int64(64 << 10)
	versionProbeErrorBytes  = int64(32 << 10)
)

var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// ProbeVersion executes only Trivy's local JSON version command and verifies
// the installed binary matches the deployment lock. It does not inspect a
// registry or perform an update check.
func ProbeVersion(
	ctx context.Context,
	executable string,
	expected string,
	timeout time.Duration,
	terminationGrace time.Duration,
) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: context is nil", ErrInvalidInput)
	}
	if !versionPattern.MatchString(expected) ||
		timeout <= 0 || timeout > time.Minute ||
		terminationGrace <= 0 || terminationGrace > time.Minute {
		return "", fmt.Errorf(
			"%w: invalid version probe settings",
			ErrInvalidConfiguration,
		)
	}
	canonical, err := canonicalExecutable(executable)
	if err != nil {
		return "", fmt.Errorf(
			"%w: executable: %v",
			ErrInvalidConfiguration,
			err,
		)
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := runCommand(runCtx, commandSpec{
		Executable: canonical,
		Arguments:  []string{"version", "--format", "json"},
		Environment: []string{
			"HOME=/tmp",
			"TMPDIR=/tmp",
			"TRIVY_DISABLE_TELEMETRY=true",
			"TRIVY_SKIP_VERSION_CHECK=true",
			"HTTP_PROXY=",
			"HTTPS_PROXY=",
			"ALL_PROXY=",
			"NO_PROXY=*",
			"DOCKER_HOST=",
			"CONTAINERD_ADDRESS=",
		},
		Directory:              filepath.Dir(canonical),
		MaxStandardOutputBytes: versionProbeOutputBytes,
		MaxStandardErrorBytes:  versionProbeErrorBytes,
		TerminationGracePeriod: terminationGrace,
	})
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", &ExecutionError{
			ExitCode: result.ExitCode,
			Stderr:   strings.TrimSpace(result.Stderr),
		}
	}
	raw := []byte(result.Stdout)
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", fmt.Errorf(
			"%w: version output is empty",
			ErrInvalidReport,
		)
	}
	if err := validateJSONTokens(raw); err != nil {
		return "", fmt.Errorf(
			"%w: invalid version JSON: %v",
			ErrInvalidReport,
			err,
		)
	}
	var output struct {
		Version string `json:"Version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&output); err != nil {
		return "", fmt.Errorf(
			"%w: decode version JSON: %v",
			ErrInvalidReport,
			err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf(
			"%w: version JSON has trailing content",
			ErrInvalidReport,
		)
	}
	if !versionPattern.MatchString(output.Version) {
		return "", fmt.Errorf(
			"%w: version JSON does not contain a safe version",
			ErrInvalidReport,
		)
	}
	if output.Version != expected {
		return output.Version, fmt.Errorf(
			"%w: installed Trivy version %q does not match locked version %q",
			ErrInvalidConfiguration,
			output.Version,
			expected,
		)
	}
	return output.Version, nil
}
