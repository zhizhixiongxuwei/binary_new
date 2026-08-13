package scan

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/queue"
	"binaryscan/internal/trivyhandoff"
)

func TestRootContainerSourcesReturnsVMImageSourceForDiskImages(t *testing.T) {
	sample := Sample{
		StorageKey: "blobs/sha256/" + strings.Repeat("a", 2) + "/" + strings.Repeat("a", 64),
		SHA256:     strings.Repeat("a", 64),
		SizeBytes:  32 << 20,
	}
	for _, format := range []string{
		"ext2", "ext3", "ext4", "raw-img", "mbr-img", "gpt-img",
	} {
		sources := rootContainerSources(format, sample)
		if len(sources) != 1 ||
			sources[0].Format != trivyhandoff.FormatVMImage ||
			sources[0].SourceStorageKey != sample.StorageKey ||
			sources[0].ImageLogicalPath != "/" {
			t.Fatalf("rootContainerSources(%q) = %+v", format, sources)
		}
	}
	for _, format := range []string{
		"docker-tar", "oci-tar", "iso9660", "squashfs", "zip", "unknown",
	} {
		sources := rootContainerSources(format, sample)
		if format == "docker-tar" || format == "oci-tar" {
			if len(sources) != 1 || sources[0].Format != format {
				t.Fatalf("rootContainerSources(%q) = %+v", format, sources)
			}
			continue
		}
		if len(sources) != 0 {
			t.Fatalf("rootContainerSources(%q) = %+v, want none", format, sources)
		}
	}
}

func TestProcessorEnqueuesVMImageSourceForUnsupportedExtraction(t *testing.T) {
	repositoryRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "disk.ext4", ext4Fixture())
	sample.Limits = testExtractionLimits()
	var enqueued []TrivyJobPayload
	var stages []string
	repository := &repositoryStub{
		load: func(context.Context, queue.Lease) (Sample, error) {
			return sample, nil
		},
		publish: func(context.Context, queue.Lease, RootNode) error {
			return nil
		},
		publishTree: func(
			_ context.Context,
			_ queue.Lease,
			rootStatus string,
			nodes []extract.Node,
		) error {
			if rootStatus != "unsupported" || len(nodes) != 0 {
				t.Fatalf("unsupported tree = status %q nodes %d", rootStatus, len(nodes))
			}
			return nil
		},
		enqueueTrivy: func(
			_ context.Context,
			_ queue.Lease,
			payload TrivyJobPayload,
		) error {
			enqueued = append(enqueued, payload)
			return nil
		},
	}
	processor, err := NewProcessor(
		repository,
		&progressStub{report: func(
			_ context.Context,
			_ queue.Lease,
			input queue.ProgressInput,
		) error {
			stages = append(stages, input.TaskStatus)
			return nil
		}},
		detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
			return filetype.Result{
				Format: "ext4", MIMEType: "application/vnd.linux.ext-filesystem",
				Metadata: map[string]any{},
			}, nil
		}},
		repositoryRoot,
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newExtractor = func(Detector, extract.Limits) extractionEngine {
		return extractionEngineStub{
			supports: func(string) bool { return false },
			extract: func(
				context.Context,
				*os.File,
				string,
				string,
			) (extract.Result, error) {
				t.Fatal("unsupported root reached Extract")
				return extract.Result{}, nil
			},
		}
	}

	finish, err := processor.Process(context.Background(), scanLease())
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomePartialSucceeded {
		t.Fatalf("finish = %+v", finish)
	}
	if len(enqueued) != 1 {
		t.Fatalf("enqueued Trivy jobs = %d", len(enqueued))
	}
	payload := enqueued[0]
	if len(payload.Sources) != 1 ||
		payload.Sources[0].Format != trivyhandoff.FormatVMImage ||
		payload.Sources[0].SourceSHA256 != sample.SHA256 {
		t.Fatalf("Trivy payload = %+v", payload)
	}
	if strings.Join(stages, ",") != "IDENTIFYING,EXTRACTING,INDEXING" {
		t.Fatalf("stages = %v", stages)
	}
}

// ext4Fixture mirrors the analyzer-side fixture: an ext4 superblock at offset
// 1024 so the filetype detector classifies it as an ext filesystem.
func ext4Fixture() []byte {
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
