package trivy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeVersionUsesLocalJSONCommand(t *testing.T) {
	root := t.TempDir()
	arguments := filepath.Join(root, "arguments")
	environment := filepath.Join(root, "environment")
	executable := writeFakeExecutable(t, root, `
printf '%s\n' "$@" > `+shellQuote(arguments)+`
/usr/bin/env > `+shellQuote(environment)+`
printf '%s' '{"Version":"0.72.0","VulnerabilityDB":{"Version":2}}'
`)

	version, err := ProbeVersion(
		context.Background(),
		executable,
		"0.72.0",
		10*time.Second,
		time.Second,
	)
	if err != nil {
		t.Fatalf("ProbeVersion() error = %v", err)
	}
	if version != "0.72.0" {
		t.Fatalf("version = %q", version)
	}
	if got := readLines(t, arguments); len(got) != 3 ||
		got[0] != "version" || got[1] != "--format" || got[2] != "json" {
		t.Fatalf("arguments = %#v", got)
	}
	settings := strings.Join(readLines(t, environment), "\n")
	for _, expected := range []string{
		"TRIVY_DISABLE_TELEMETRY=true",
		"TRIVY_SKIP_VERSION_CHECK=true",
		"HTTPS_PROXY=",
		"NO_PROXY=*",
		"DOCKER_HOST=",
	} {
		if !containsLine(settings, expected) {
			t.Errorf("environment does not contain %q", expected)
		}
	}
}

func TestProbeVersionRejectsMismatchAndInvalidJSON(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
		want   error
	}{
		{
			name:   "mismatch",
			output: `{"Version":"0.71.0"}`,
			want:   ErrInvalidConfiguration,
		},
		{
			name:   "invalid-json",
			output: `not-json`,
			want:   ErrInvalidReport,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			executable := writeFakeExecutable(
				t,
				root,
				"printf '%s' "+shellQuote(test.output),
			)
			_, err := ProbeVersion(
				context.Background(),
				executable,
				"0.72.0",
				10*time.Second,
				time.Second,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ProbeVersion() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProbeVersionHonorsOutputLimitAndCancellation(t *testing.T) {
	root := t.TempDir()
	large := filepath.Join(root, "large")
	if err := os.WriteFile(
		large,
		[]byte(strings.Repeat("x", int(versionProbeOutputBytes)+1)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	executable := writeFakeExecutable(
		t,
		root,
		"cat "+shellQuote(large),
	)
	_, err := ProbeVersion(
		context.Background(),
		executable,
		"0.72.0",
		10*time.Second,
		time.Second,
	)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("large ProbeVersion() error = %v", err)
	}

	sleeping := writeFakeExecutable(t, root, "sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ProbeVersion(
		ctx,
		sleeping,
		"0.72.0",
		10*time.Second,
		100*time.Millisecond,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ProbeVersion() error = %v", err)
	}
}
