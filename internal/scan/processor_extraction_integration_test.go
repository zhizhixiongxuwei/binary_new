package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"testing"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/queue"
)

func TestProcessorPublishesRootOnlyZIPNodeLimitResult(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range []string{"first.bin", "second.bin"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	repositoryRoot := t.TempDir()
	taskWorkRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "too-many.zip", archive.Bytes())
	sample.Limits = extract.Limits{
		MaxExpandedBytes: 1 << 20,
		MaxNodes:         1,
		MaxDepth:         10,
		MaxRatio:         100,
	}
	var rootStatus string
	var descendants []extract.Node
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
			status string,
			nodes []extract.Node,
		) error {
			rootStatus = status
			descendants = append([]extract.Node(nil), nodes...)
			return nil
		},
	}
	processor, err := NewProcessor(
		repository,
		successProgress(),
		filetype.Detector{},
		repositoryRoot,
		taskWorkRoot,
	)
	if err != nil {
		t.Fatal(err)
	}

	finish, err := processor.Process(context.Background(), scanLease())
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomePartialSucceeded ||
		rootStatus != "limit_reached" ||
		len(descendants) != 0 {
		t.Fatalf(
			"Process() = finish %+v, root %q, descendants %d",
			finish,
			rootStatus,
			len(descendants),
		)
	}
	entries, err := os.ReadDir(taskWorkRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("task work root contains %d entries after processing", len(entries))
	}
}
