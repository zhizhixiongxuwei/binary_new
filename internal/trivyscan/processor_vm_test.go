package trivyscan

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/containerarchive"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivydb"
	"binaryscan/internal/trivyhandoff"
)

// ext4Bytes mirrors the analyzer fixture so the copied input passes
// VerifyVMImage: an ext4 superblock sits at offset 1024.
func ext4Bytes() []byte {
	data := make([]byte, 4096)
	sb := data[1024 : 1024+1024]
	binary.LittleEndian.PutUint32(sb[0:4], 1)
	binary.LittleEndian.PutUint32(sb[4:8], 100)
	binary.LittleEndian.PutUint32(sb[0x18:0x1c], 2)
	binary.LittleEndian.PutUint16(sb[0x38:0x3a], 0xef53)
	binary.LittleEndian.PutUint16(sb[0x58:0x5a], 256)
	binary.LittleEndian.PutUint32(sb[0x60:0x64], 0x40|0x80)
	return data
}

func TestProcessorRunsOfflineAdapterForSingleVMImage(t *testing.T) {
	fixture := newProcessorFixture(t, ext4Bytes())
	fixture.format = trivyhandoff.FormatVMImage
	executable := writeRecordingTrivy(t, fixture.root, successfulReportJSON)
	base := trivyadapter.Config{
		Executable:             executable,
		MaxDuration:            30 * time.Second,
		TerminationGracePeriod: 50 * time.Millisecond,
		MaxStandardOutputBytes: 1 << 20,
		MaxStandardErrorBytes:  1 << 20,
		MaxReportBytes:         4 << 20,
		MaxResults:             100,
		MaxFindings:            1_000,
	}
	processor := fixture.processor(t, NewAdapterFactory(base))
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(fixture.repository.publications) != 1 {
		t.Fatalf("publications = %d", len(fixture.repository.publications))
	}
	publication := fixture.repository.publications[0]
	if publication.SourceFormat != trivyhandoff.FormatVMImage ||
		len(publication.Runs) != 1 ||
		publication.Runs[0].Status != "succeeded" ||
		publication.Runs[0].SourceFormat != trivyhandoff.FormatVMImage ||
		publication.Runs[0].Platform != "" ||
		publication.Runs[0].ManifestDigest != "" ||
		len(publication.Runs[0].Findings) != 1 {
		t.Fatalf("publication = %+v", publication)
	}
	invocation, err := os.ReadFile(filepath.Join(fixture.root, "trivy-invocation"))
	if err != nil {
		t.Fatal(err)
	}
	if string(invocation) != "vm" {
		t.Fatalf("Trivy subcommand = %q, want vm", invocation)
	}
}

func TestProcessorRejectsNonImageContentForVMHandoff(t *testing.T) {
	fixture := newProcessorFixture(t, []byte("definitely not a disk image"))
	fixture.format = trivyhandoff.FormatVMImage
	processor := fixture.processor(t, func(
		string,
		string,
		[]string,
		int64,
	) (Analyzer, error) {
		return analyzerFunc(func(
			context.Context,
			trivyadapter.Request,
		) (trivyadapter.Report, error) {
			t.Fatal("analyzer must not run for rejected VM input")
			return trivyadapter.Report{}, nil
		}), nil
	})
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeDeterministicFailure ||
		outcome.ErrorCode != "vm_image_verification_failed" {
		t.Fatalf("outcome = %+v", outcome)
	}
}

func TestBuildQuotaPlanAccountsForVMImageSource(t *testing.T) {
	plans := []sourcePlan{{
		handoff: trivyhandoff.Source{
			Format:           trivyhandoff.FormatVMImage,
			SourceSizeBytes:  8 << 20,
			ImageLogicalPath: "/",
		},
		source: &sourceFile{size: 8 << 20},
		inspection: containerArchiveInspectionStub(
			trivyhandoff.FormatVMImage,
			1,
		),
	}}
	plan, err := buildQuotaPlan(
		context.Background(),
		plans,
		50<<20,
		4<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InputBytes < 8<<20 ||
		plan.ExpandedBytes != 8<<20 ||
		plan.ScanTargets != 1 {
		t.Fatalf("quota plan = %+v", plan)
	}
}

func TestBuildQuotaPlanRejectsMissingVMImageInspection(t *testing.T) {
	plans := []sourcePlan{{
		handoff: trivyhandoff.Source{
			Format:           trivyhandoff.FormatVMImage,
			SourceSizeBytes:  1024,
			ImageLogicalPath: "/",
		},
		source: &sourceFile{size: 1024},
	}}
	if _, err := buildQuotaPlan(
		context.Background(),
		plans,
		1<<20,
		1<<20,
	); err == nil {
		t.Fatal("buildQuotaPlan accepted a VM source without inspection targets")
	}
}

func TestDatabaseUnavailableStaysTransientForVMImage(t *testing.T) {
	fixture := newProcessorFixture(t, ext4Bytes())
	fixture.format = trivyhandoff.FormatVMImage
	processor := fixture.processor(t, NewAdapterFactory(trivyadapter.Config{
		Executable:             "/usr/local/bin/trivy",
		MaxDuration:            time.Second,
		TerminationGracePeriod: time.Millisecond,
		MaxStandardOutputBytes: 1 << 20,
		MaxStandardErrorBytes:  1 << 20,
		MaxReportBytes:         4 << 20,
		MaxResults:             100,
		MaxFindings:            1_000,
	}))
	processor.databases = func(
		context.Context,
		string,
		trivydb.JavaDBPolicy,
	) (DatabaseView, error) {
		return nil, errors.New("db unavailable")
	}
	outcome, err := processor.Process(context.Background(), fixture.lease(false))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Outcome != queue.OutcomeTransientFailure {
		t.Fatalf("outcome = %+v", outcome)
	}
}

// containerArchiveInspectionStub builds the uniform inspection the processor
// constructs for VM sources.
func containerArchiveInspectionStub(
	format string,
	targets int,
) containerarchive.Inspection {
	values := make([]containerarchive.Target, targets)
	return containerarchive.Inspection{Format: format, Targets: values}
}

// writeRecordingTrivy is writeFakeTrivy plus a record of the executed
// subcommand so tests can assert vm (not image) was invoked.
func writeRecordingTrivy(t *testing.T, root, report string) string {
	t.Helper()
	value := filepath.Join(root, "fake-trivy.sh")
	quoted := strings.ReplaceAll(report, "'", "'\"'\"'")
	body := "#!/bin/sh\nset -eu\nprintf '%s' \"$1\" > \"" +
		filepath.Join(root, "trivy-invocation") +
		"\"\noutput=\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  if [ \"$1\" = \"--output\" ]; then shift; output=$1; fi\n" +
		"  shift\n" +
		"done\n" +
		"printf '%s' '" + quoted + "' > \"$output\"\n"
	if err := os.WriteFile(value, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return value
}
