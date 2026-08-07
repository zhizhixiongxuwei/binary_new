package trivy

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

const successfulTrivyReport = `{
  "SchemaVersion": 2,
  "CreatedAt": "2026-07-31T00:00:00Z",
  "ArtifactID": "sha256:cc0c6c8c4f193c42f04ac9e47f34c934a9f4a838563070dea5501d32cbf908c8",
  "ArtifactName": "fixture-image",
  "ArtifactType": "container_image",
  "Metadata": {"OS": {"Family": "alpine", "Name": "3.20"}},
  "ReportID": "019fc6ce-5cff-761b-8c7d-80d2efa8bdba",
  "Trivy": {"Version": "0.72.0"},
  "Results": [{
    "Target": "fixture-image (alpine 3.20)",
    "Class": "os-pkgs",
    "Type": "alpine",
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2026-0001",
      "PkgName": "libfixture",
      "PkgPath": "usr/lib/libfixture.so",
      "InstalledVersion": "1.0.0",
      "FixedVersion": "1.0.1",
      "Severity": "high",
      "Title": "Fixture advisory title",
      "Description": "First line.\nSecond line.",
      "PrimaryURL": "https://avd.example.test/CVE-2026-0001",
      "DataSource": {
        "ID": "fixture-db",
        "Name": "Fixture Security Tracker",
        "URL": "https://security.example.test/advisories"
      },
      "References": [
        "https://avd.example.test/CVE-2026-0001",
        "https://offline.invalid/CVE-2026-0001",
        "javascript:alert(1)"
      ]
    }]
  }]
}`

type adapterFixture struct {
	root       string
	inputRoot  string
	cache      string
	workRoot   string
	source     VerifiedSource
	executable string
	config     Config
}

func TestAdapterUsesOfflineVulnerabilityOnlyArgumentArray(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	argumentsPath := filepath.Join(fixture.root, "arguments.txt")
	environmentPath := filepath.Join(fixture.root, "environment.txt")
	fixture.executable = writeFakeExecutable(t, fixture.root, `
args_file=`+shellQuote(argumentsPath)+`
env_file=`+shellQuote(environmentPath)+`
: > "$args_file"
for argument in "$@"; do
  printf '%s\n' "$argument" >> "$args_file"
done
/usr/bin/env > "$env_file"
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    output=$1
  fi
  shift
done
printf '%s' `+shellQuote(successfulTrivyReport)+` > "$output"
`)
	fixture.config.Executable = fixture.executable
	adapter := mustAdapter(t, fixture.config)
	workDirectory := newWorkDirectory(t, fixture.workRoot)
	markerPath := filepath.Join(workDirectory, "shell-injection-marker.tar")
	t.Setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
	t.Setenv("HTTPS_PROXY", "http://attacker.invalid:8080")

	report, err := adapter.Analyze(context.Background(), Request{
		Source: fixture.source, WorkDirectory: workDirectory,
	})
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(workDirectory, rawReportFilename)
	expected := []string{
		"image",
		"--input", fixture.source.Path(),
		"--cache-dir", fixture.cache,
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
		"--timeout", fixture.config.MaxDuration.String(),
	}
	if actual := readLines(t, argumentsPath); !reflect.DeepEqual(actual, expected) {
		t.Fatalf("arguments = %#v, want %#v", actual, expected)
	}
	for _, argument := range expected {
		if argument == "secret" || argument == "misconfig" ||
			argument == "license" || argument == "sbom" {
			t.Fatalf("forbidden scanner argument %q", argument)
		}
	}
	environment := strings.Join(readLines(t, environmentPath), "\n")
	for _, expectedSetting := range []string{
		"TRIVY_OFFLINE_SCAN=true",
		"TRIVY_SKIP_DB_UPDATE=true",
		"TRIVY_SKIP_JAVA_DB_UPDATE=true",
		"TRIVY_DISABLE_TELEMETRY=true",
		"TRIVY_SKIP_VERSION_CHECK=true",
		"DOCKER_HOST=",
		"CONTAINERD_ADDRESS=",
		"HTTPS_PROXY=",
		"NO_PROXY=*",
	} {
		if !containsLine(environment, expectedSetting) {
			t.Errorf("environment does not contain %q:\n%s", expectedSetting, environment)
		}
	}
	if strings.Contains(environment, "attacker.invalid") {
		t.Fatalf("inherited network environment leaked to Trivy:\n%s", environment)
	}
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected shell marker: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v", report.Findings)
	}
	finding := report.Findings[0]
	if finding.VulnerabilityID != "CVE-2026-0001" ||
		finding.Severity != "HIGH" ||
		finding.PackageName != "libfixture" ||
		finding.PackagePath != "usr/lib/libfixture.so" ||
		finding.InstalledVersion != "1.0.0" ||
		finding.FixedVersion != "1.0.1" ||
		finding.Title != "Fixture advisory title" ||
		finding.DescriptionSummary != "First line. Second line." ||
		finding.Target != "alpine 3.20" ||
		finding.Class != "os-pkgs" ||
		finding.Type != "alpine" ||
		finding.DataSource.ID != "fixture-db" ||
		finding.DataSource.Name != "Fixture Security Tracker" ||
		finding.DataSource.URL != "https://security.example.test/advisories" ||
		!reflect.DeepEqual(finding.References, []string{
			"https://avd.example.test/CVE-2026-0001",
			"https://offline.invalid/CVE-2026-0001",
			"https://security.example.test/advisories",
		}) {
		t.Fatalf("normalized finding = %+v", finding)
	}
	raw := mustReadFile(t, outputPath)
	digest := sha256.Sum256(raw)
	if report.Raw.Path != outputPath ||
		report.Raw.SHA256 != hex.EncodeToString(digest[:]) ||
		report.Raw.SizeBytes != int64(len(raw)) ||
		report.Raw.SchemaVersion != 2 ||
		report.Raw.ArtifactName != "fixture-image" ||
		report.Raw.ArtifactType != "container_image" ||
		report.Raw.ResultCount != 1 ||
		report.Raw.FindingCount != 1 {
		t.Fatalf("raw report metadata = %+v", report.Raw)
	}
}

func TestFindingDoesNotMakeScanFail(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	adapter := mustAdapter(t, fixture.config)
	report, err := adapter.Analyze(context.Background(), Request{
		Source: fixture.source, WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
}

func TestCurrentSASTCCheckerReportEvidenceRegression(t *testing.T) {
	path := os.Getenv("BINARYSCAN_TRIVY_REGRESSION_REPORT")
	if path == "" {
		t.Skip("set BINARYSCAN_TRIVY_REGRESSION_REPORT to the retained real Trivy JSON")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseReport(raw, RawReportMetadata{Path: path}, 10_000, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	if report.Raw.FindingCount != 237 || len(report.Findings) != 237 {
		t.Fatalf("real finding count = %d, want 237", len(report.Findings))
	}
	var osFinding *Finding
	var javaFinding *Finding
	for index := range report.Findings {
		finding := &report.Findings[index]
		if strings.Contains(finding.Target, "/input/oci-layout@") ||
			strings.Contains(finding.Target, "/data/task-work/") {
			t.Fatalf("internal workspace target leaked: %q", finding.Target)
		}
		if finding.VulnerabilityID == "CVE-2026-27456" &&
			finding.PackageName == "bsdutils" {
			osFinding = finding
		}
		if finding.PackagePath != "" {
			javaFinding = finding
		}
	}
	if osFinding == nil || osFinding.Target != "ubuntu 26.04" ||
		osFinding.Title == "" || osFinding.DescriptionSummary == "" ||
		osFinding.DataSource.Name != "Ubuntu CVE Tracker" ||
		len(osFinding.References) < 3 ||
		osFinding.References[0] !=
			"https://avd.aquasec.com/nvd/cve-2026-27456" {
		t.Fatalf("real OS finding evidence = %+v", osFinding)
	}
	if javaFinding == nil || javaFinding.PackagePath == "" {
		t.Fatalf("real language-package path was not retained: %+v", javaFinding)
	}
}

func TestNormalizeTargetOnlyStripsTheExactArtifactPrefix(t *testing.T) {
	for _, test := range []struct {
		name     string
		artifact string
		target   string
		want     string
	}{
		{
			name: "distribution suffix",
			artifact: "/data/task-work/input/oci-layout@sha256:" +
				strings.Repeat("a", 64),
			target: "/data/task-work/input/oci-layout@sha256:" +
				strings.Repeat("a", 64) + " (ubuntu 26.04)",
			want: "ubuntu 26.04",
		},
		{name: "exact artifact", artifact: "fixture", target: "fixture", want: "container image"},
		{name: "different prefix", artifact: "fixture", target: "fixture-tools", want: "fixture-tools"},
		{name: "language target", artifact: "fixture", target: "Java", want: "Java"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeTarget(test.artifact, test.target); got != test.want {
				t.Fatalf("normalizeTarget() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNonZeroExitIsExecutionFailureWithBoundedDiagnostic(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	fixture.executable = writeFakeExecutable(t, fixture.root, `
printf '%s' 'fixed database bundle is unavailable' >&2
exit 7
`)
	fixture.config.Executable = fixture.executable
	adapter := mustAdapter(t, fixture.config)
	_, err := adapter.Analyze(context.Background(), Request{
		Source: fixture.source, WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	var executionError *ExecutionError
	if !errors.As(err, &executionError) {
		t.Fatalf("error = %v, want ExecutionError", err)
	}
	if !errors.Is(err, ErrExecutionFailed) ||
		executionError.ExitCode != 7 ||
		executionError.Stderr != "fixed database bundle is unavailable" {
		t.Fatalf("execution error = %+v", executionError)
	}
}

func TestCancellationTerminatesIgnoringProcessGroup(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	fixture.executable = writeFakeExecutable(t, fixture.root, `
trap '' TERM
while :; do
  /bin/sleep 1
done
`)
	fixture.config.Executable = fixture.executable
	fixture.config.MaxDuration = 5 * time.Second
	fixture.config.TerminationGracePeriod = 40 * time.Millisecond
	adapter := mustAdapter(t, fixture.config)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := adapter.Analyze(ctx, Request{
		Source: fixture.source, WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline", err)
	}
	if elapsed > time.Second {
		t.Fatalf("cancellation took %s; process group was not escalated promptly", elapsed)
	}
}

func TestCancelledContextDoesNotStartExecutable(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	marker := filepath.Join(fixture.root, "started")
	fixture.executable = writeFakeExecutable(t, fixture.root, `
printf 'started' > `+shellQuote(marker)+`
exit 0
`)
	fixture.config.Executable = fixture.executable
	adapter := mustAdapter(t, fixture.config)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.Analyze(ctx, Request{
		Source: fixture.source, WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executable started for cancelled context: %v", err)
	}
}

func TestCumulativeWorkspaceQuotaRejectsPreexistingOutput(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	marker := filepath.Join(fixture.root, "started")
	fixture.executable = writeFakeExecutable(t, fixture.root, `
printf 'started' > `+shellQuote(marker)+`
exit 0
`)
	fixture.config.Executable = fixture.executable
	fixture.config.MaxWorkBytes = 12 << 10
	adapter := mustAdapter(t, fixture.config)
	workDirectory := newWorkDirectory(t, fixture.workRoot)
	if err := os.WriteFile(
		filepath.Join(workDirectory, "previous-output"),
		make([]byte, 8<<10),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	_, err := adapter.Analyze(context.Background(), Request{
		Source: fixture.source, WorkDirectory: workDirectory,
	})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("error = %v, want workspace output limit", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("executable started after preflight quota rejection: %v", err)
	}
}

func TestWorkspaceQuotaChecksFinalProcessOutput(t *testing.T) {
	fixture := newAdapterFixture(t, successfulTrivyReport)
	fixture.executable = writeFakeExecutable(t, fixture.root, `
printf '%20000s' x > burst.bin
exit 0
`)
	fixture.config.Executable = fixture.executable
	fixture.config.MaxWorkBytes = 20 << 10
	adapter := mustAdapter(t, fixture.config)

	_, err := adapter.Analyze(context.Background(), Request{
		Source:        fixture.source,
		WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("error = %v, want cumulative workspace output limit", err)
	}
}

func TestWorkspaceQuotaRejectsLinksSpecialFilesAndMissingRoot(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, root string) {
				if err := os.Symlink(
					t.TempDir(),
					filepath.Join(root, "linked"),
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, root string) {
				if err := syscall.Mkfifo(
					filepath.Join(root, "pipe"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing root",
			setup: func(t *testing.T, root string) {
				if err := os.Remove(root); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "work")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			test.setup(t, root)
			err := checkWorkspaceUsage(
				context.Background(),
				root,
				1<<20,
			)
			if !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("checkWorkspaceUsage() error = %v", err)
			}
		})
	}
}

func TestWorkspaceQuotaHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := checkWorkspaceUsage(ctx, t.TempDir(), 1<<20)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("checkWorkspaceUsage() error = %v", err)
	}
}

func TestWorkspaceQuotaToleratesConcurrentScratchCleanup(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for ctx.Err() == nil {
			directory, err := os.MkdirTemp(root, "trivy-")
			if err != nil {
				return
			}
			for index := 0; index < 32; index++ {
				_ = os.WriteFile(
					filepath.Join(directory, fmt.Sprintf("analyzer-file-%d", index)),
					[]byte("scratch"),
					0o600,
				)
			}
			_ = os.RemoveAll(directory)
		}
	}()
	defer func() {
		cancel()
		<-finished
	}()

	for range 2_000 {
		if err := checkWorkspaceUsage(
			context.Background(),
			root,
			1<<30,
		); err != nil {
			t.Fatalf("concurrent scratch cleanup rejected: %v", err)
		}
	}
}

func TestStandardStreamsAndRawReportHaveIndependentLimits(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "stdout",
			body: `
while :; do
  printf '0123456789abcdef'
done
`,
		},
		{
			name: "stderr",
			body: `
while :; do
  printf '0123456789abcdef' >&2
done
`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdapterFixture(t, successfulTrivyReport)
			fixture.executable = writeFakeExecutable(t, fixture.root, test.body)
			fixture.config.Executable = fixture.executable
			fixture.config.MaxStandardOutputBytes = 64
			fixture.config.MaxStandardErrorBytes = 64
			adapter := mustAdapter(t, fixture.config)
			_, err := adapter.Analyze(context.Background(), Request{
				Source:        fixture.source,
				WorkDirectory: newWorkDirectory(t, fixture.workRoot),
			})
			if !errors.Is(err, ErrOutputLimit) {
				t.Fatalf("error = %v, want output limit", err)
			}
		})
	}

	t.Run("raw JSON file", func(t *testing.T) {
		fixture := newAdapterFixture(t, successfulTrivyReport)
		fixture.config.MaxReportBytes = 128
		adapter := mustAdapter(t, fixture.config)
		_, err := adapter.Analyze(context.Background(), Request{
			Source:        fixture.source,
			WorkDirectory: newWorkDirectory(t, fixture.workRoot),
		})
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("error = %v, want output limit", err)
		}
	})
}

func TestRejectsMaliciousOrOutOfContractJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate keys",
			raw: `{"SchemaVersion":2,"SchemaVersion":2,` +
				`"ArtifactName":"x","ArtifactType":"container_image","Results":[]}`,
		},
		{
			name: "unknown top-level field",
			raw: `{"SchemaVersion":2,"ArtifactName":"x",` +
				`"ArtifactType":"container_image","Results":[],"Unexpected":true}`,
		},
		{
			name: "missing results",
			raw: `{"SchemaVersion":2,"ArtifactName":"x",` +
				`"ArtifactType":"container_image"}`,
		},
		{
			name: "secret scanner payload",
			raw: `{"SchemaVersion":2,"ArtifactName":"x",` +
				`"ArtifactType":"container_image","Results":[{` +
				`"Target":"x","Class":"secret","Type":"text",` +
				`"Secrets":[{"RuleID":"private-key"}]}]}`,
		},
		{
			name: "invalid severity",
			raw: `{"SchemaVersion":2,"ArtifactName":"x",` +
				`"ArtifactType":"container_image","Results":[{` +
				`"Target":"x","Class":"os-pkgs","Type":"alpine",` +
				`"Vulnerabilities":[{"VulnerabilityID":"CVE-1",` +
				`"PkgName":"x","InstalledVersion":"1","Severity":"SEVERE"}]}]}`,
		},
		{
			name: "control character",
			raw: `{"SchemaVersion":2,"ArtifactName":"x",` +
				`"ArtifactType":"container_image","Results":[{` +
				`"Target":"x\u0000y","Class":"os-pkgs","Type":"alpine",` +
				`"Vulnerabilities":[{"VulnerabilityID":"CVE-1",` +
				`"PkgName":"x","InstalledVersion":"1","Severity":"HIGH"}]}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdapterFixture(t, test.raw)
			adapter := mustAdapter(t, fixture.config)
			_, err := adapter.Analyze(context.Background(), Request{
				Source:        fixture.source,
				WorkDirectory: newWorkDirectory(t, fixture.workRoot),
			})
			if !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("error = %v, want invalid report", err)
			}
		})
	}
}

func TestInputMustBeVerifiedAndRemainInsideConfiguredRoots(t *testing.T) {
	root := t.TempDir()
	ordinaryPath := filepath.Join(root, "ordinary.tar")
	writeTAR(t, ordinaryPath, map[string][]byte{"payload.txt": []byte("not an image")})
	if _, err := VerifyDockerSaveTAR(ordinaryPath); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ordinary TAR error = %v, want invalid input", err)
	}

	fixture := newAdapterFixture(t, successfulTrivyReport)
	outside := filepath.Join(fixture.root, "outside")
	mustMkdir(t, outside)
	outsideArchive := filepath.Join(outside, "image.tar")
	writeDockerSaveTAR(t, outsideArchive)
	outsideSource, err := VerifyDockerSaveTAR(outsideArchive)
	if err != nil {
		t.Fatal(err)
	}
	adapter := mustAdapter(t, fixture.config)
	_, err = adapter.Analyze(context.Background(), Request{
		Source: outsideSource, WorkDirectory: newWorkDirectory(t, fixture.workRoot),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("outside source error = %v, want invalid input", err)
	}

	symlinkPath := filepath.Join(fixture.inputRoot, "linked.tar")
	if err := os.Symlink(fixture.source.Path(), symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDockerSaveTAR(symlinkPath); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("symlink error = %v, want invalid input", err)
	}
}

func TestVerifiesSingleManifestOCILayoutAndRejectsImplicitPlatformChoice(t *testing.T) {
	root := t.TempDir()
	single := filepath.Join(root, "single")
	writeOCILayout(t, single, 1)
	source, err := VerifyOCILayout(single)
	if err != nil {
		t.Fatal(err)
	}
	if source.Kind() != SourceOCILayout ||
		source.Path() == "" ||
		source.ManifestDigest() == "" {
		t.Fatalf("source = %+v", source)
	}

	multiple := filepath.Join(root, "multiple")
	digests := writeOCILayout(t, multiple, 2)
	if _, err := VerifyOCILayout(multiple); !errors.Is(err, ErrMultiPlatform) {
		t.Fatalf("multi-platform error = %v, want ErrMultiPlatform", err)
	}
	target, err := VerifyOCILayoutTarget(multiple, digests[1])
	if err != nil {
		t.Fatal(err)
	}
	if target.ManifestDigest() != digests[1] {
		t.Fatalf("target digest = %q, want %q", target.ManifestDigest(), digests[1])
	}
	if _, err := VerifyOCILayoutTarget(
		multiple,
		"sha256:"+strings.Repeat("f", 64),
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown target error = %v, want invalid input", err)
	}

	tampered := filepath.Join(root, "tampered")
	tamperedDigests := writeOCILayout(t, tampered, 1)
	tamperedHex := strings.TrimPrefix(tamperedDigests[0], "sha256:")
	tamperedBlob := filepath.Join(tampered, "blobs", "sha256", tamperedHex)
	tamperedRaw := mustReadFile(t, tamperedBlob)
	tamperedRaw[len(tamperedRaw)-2] = '1'
	if err := os.WriteFile(
		tamperedBlob,
		tamperedRaw,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOCILayout(tampered); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tampered manifest error = %v, want invalid input", err)
	}

	symlinked := filepath.Join(root, "symlinked")
	writeOCILayout(t, symlinked, 1)
	externalBlobs := filepath.Join(root, "external-blobs")
	if err := os.Rename(filepath.Join(symlinked, "blobs"), externalBlobs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalBlobs, filepath.Join(symlinked, "blobs")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOCILayout(symlinked); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("symlinked blob tree error = %v, want invalid input", err)
	}

	configuration := newAdapterFixture(t, successfulTrivyReport).config
	configuration.InputRoots = []string{root}
	adapter := mustAdapter(t, configuration)
	arguments := adapter.arguments(target, "/controlled/output.json")
	if arguments[2] != target.Path()+"@"+digests[1] {
		t.Fatalf("OCI --input value = %q", arguments[2])
	}
}

func newAdapterFixture(t *testing.T, report string) adapterFixture {
	t.Helper()
	root := t.TempDir()
	inputRoot := filepath.Join(root, "input")
	cache := filepath.Join(root, "cache")
	workRoot := filepath.Join(root, "work")
	for _, directory := range []string{inputRoot, cache, workRoot} {
		mustMkdir(t, directory)
	}
	archivePath := filepath.Join(
		inputRoot,
		"image;touch shell-injection-marker.tar",
	)
	writeDockerSaveTAR(t, archivePath)
	source, err := VerifyDockerSaveTAR(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	executable := writeFakeExecutable(t, root, `
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    output=$1
  fi
  shift
done
printf '%s' `+shellQuote(report)+` > "$output"
`)
	config := Config{
		Executable: executable, InputRoots: []string{inputRoot},
		CacheDirectory: cache, WorkRoot: workRoot,
		MaxDuration:            30 * time.Second,
		TerminationGracePeriod: 50 * time.Millisecond,
		MaxStandardOutputBytes: 1024,
		MaxStandardErrorBytes:  1024,
		MaxReportBytes:         1 << 20,
		MaxResults:             100, MaxFindings: 1_000,
	}
	root = mustCanonicalPath(t, root)
	inputRoot = mustCanonicalPath(t, inputRoot)
	cache = mustCanonicalPath(t, cache)
	workRoot = mustCanonicalPath(t, workRoot)
	config.InputRoots = []string{inputRoot}
	config.CacheDirectory = cache
	config.WorkRoot = workRoot
	return adapterFixture{
		root: root, inputRoot: inputRoot, cache: cache, workRoot: workRoot,
		source: source, executable: executable, config: config,
	}
}

func mustAdapter(t *testing.T, config Config) *Adapter {
	t.Helper()
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func newWorkDirectory(t *testing.T, root string) string {
	t.Helper()
	directory, err := os.MkdirTemp(root, "run-")
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeFakeExecutable(t *testing.T, root, body string) string {
	t.Helper()
	file, err := os.CreateTemp(root, "fake-trivy-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	content := "#!/bin/sh\nset -eu\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustCanonicalPath(t *testing.T, path string) string {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func writeDockerSaveTAR(t *testing.T, path string) {
	t.Helper()
	writeTAR(t, path, map[string][]byte{
		"config.json": []byte(`{"architecture":"amd64","os":"linux"}`),
		"layer.tar":   []byte("fixture layer"),
		"manifest.json": []byte(
			`[{"Config":"config.json","RepoTags":["fixture:latest"],` +
				`"Layers":["layer.tar"]}]`,
		),
	})
}

func writeTAR(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, name := range sortedKeys(files) {
		content := files[name]
		if err := writer.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func sortedKeys(values map[string][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for left := 0; left < len(keys); left++ {
		for right := left + 1; right < len(keys); right++ {
			if keys[right] < keys[left] {
				keys[left], keys[right] = keys[right], keys[left]
			}
		}
	}
	return keys
}

func writeOCILayout(t *testing.T, root string, manifestCount int) []string {
	t.Helper()
	mustMkdir(t, root)
	mustMkdir(t, filepath.Join(root, "blobs"))
	mustMkdir(t, filepath.Join(root, "blobs", "sha256"))
	manifests := make([]string, 0, manifestCount)
	digests := make([]string, 0, manifestCount)
	for index := 0; index < manifestCount; index++ {
		content := []byte(fmt.Sprintf(`{"schemaVersion":2,"index":%d}`, index))
		digest := sha256.Sum256(content)
		hexDigest := hex.EncodeToString(digest[:])
		if err := os.WriteFile(
			filepath.Join(root, "blobs", "sha256", hexDigest),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, fmt.Sprintf(
			`{"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
				`"digest":"sha256:%s","size":%d}`,
			hexDigest,
			len(content),
		))
		digests = append(digests, "sha256:"+hexDigest)
	}
	if err := os.WriteFile(
		filepath.Join(root, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	index := `{"schemaVersion":2,"manifests":[` +
		strings.Join(manifests, ",") + `]}`
	if err := os.WriteFile(
		filepath.Join(root, "index.json"),
		[]byte(index),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return digests
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	return strings.Split(strings.TrimSuffix(string(mustReadFile(t, path)), "\n"), "\n")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func containsLine(value, expected string) bool {
	for _, line := range strings.Split(value, "\n") {
		if line == expected {
			return true
		}
	}
	return false
}

func TestValidateJSONRejectsExcessiveNesting(t *testing.T) {
	raw := bytes.Repeat([]byte("["), maxJSONDepth+2)
	raw = append(raw, '0')
	raw = append(raw, bytes.Repeat([]byte("]"), maxJSONDepth+2)...)
	if err := validateJSONTokens(raw); err == nil {
		t.Fatal("validateJSONTokens() error = nil, want depth error")
	}
}
