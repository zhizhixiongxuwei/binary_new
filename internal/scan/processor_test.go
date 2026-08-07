package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
	"binaryscan/internal/queue"
	"binaryscan/internal/workspace"
)

func TestRootNodePreservesIdentificationCandidateMetadata(t *testing.T) {
	sample := Sample{
		DisplayName: "polyglot.bin",
		SizeBytes:   4096,
		SHA256:      strings.Repeat("a", 64),
		StorageKey:  "sha256/aa/" + strings.Repeat("a", 64),
	}
	detected := filetype.Result{
		Format:   "pe32",
		MIMEType: "application/vnd.microsoft.portable-executable",
		Metadata: map[string]any{
			"identification_candidates": []map[string]any{
				{
					"format":    "pe32",
					"category":  "executable",
					"mime_type": "application/vnd.microsoft.portable-executable",
					"evidence":  "pe_coff_optional_and_section_tables",
				},
				{
					"format":    "zip",
					"category":  "archive",
					"mime_type": "application/zip",
					"evidence":  "zip_eocd_central_directory_and_local_headers",
				},
			},
			"identification_ambiguous": true,
		},
	}
	node, err := rootNode(sample, detected)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Candidates []struct {
			Format   string `json:"format"`
			Evidence string `json:"evidence"`
		} `json:"identification_candidates"`
		Ambiguous bool `json:"identification_ambiguous"`
	}
	if err := json.Unmarshal(node.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if !metadata.Ambiguous ||
		len(metadata.Candidates) != 2 ||
		metadata.Candidates[0].Format != "pe32" ||
		metadata.Candidates[1].Format != "zip" ||
		metadata.Candidates[1].Evidence !=
			"zip_eocd_central_directory_and_local_headers" {
		t.Fatalf("persisted metadata = %s", node.MetadataJSON)
	}
}

type repositoryStub struct {
	load        func(context.Context, queue.Lease) (Sample, error)
	publish     func(context.Context, queue.Lease, RootNode) error
	publishTree func(
		context.Context,
		queue.Lease,
		string,
		[]extract.Node,
	) error
	enqueueTrivy func(context.Context, queue.Lease, TrivyJobPayload) error
}

func (s *repositoryStub) Load(
	ctx context.Context,
	lease queue.Lease,
) (Sample, error) {
	return s.load(ctx, lease)
}

func (s *repositoryStub) Publish(
	ctx context.Context,
	lease queue.Lease,
	node RootNode,
) error {
	return s.publish(ctx, lease, node)
}

func (s *repositoryStub) PublishTree(
	ctx context.Context,
	lease queue.Lease,
	rootStatus string,
	nodes []extract.Node,
) error {
	if s.publishTree != nil {
		return s.publishTree(ctx, lease, rootStatus, nodes)
	}
	return nil
}

func (s *repositoryStub) EnqueueTrivy(
	ctx context.Context,
	lease queue.Lease,
	payload TrivyJobPayload,
) error {
	if s.enqueueTrivy != nil {
		return s.enqueueTrivy(ctx, lease, payload)
	}
	return nil
}

type progressStub struct {
	report func(context.Context, queue.Lease, queue.ProgressInput) error
}

func (s *progressStub) TaskProgress(
	ctx context.Context,
	lease queue.Lease,
	input queue.ProgressInput,
) error {
	return s.report(ctx, lease, input)
}

type detectorStub struct {
	detect func(io.ReaderAt, int64) (filetype.Result, error)
}

func (s detectorStub) Detect(
	source io.ReaderAt,
	size int64,
) (filetype.Result, error) {
	return s.detect(source, size)
}

type extractionEngineStub struct {
	supports func(string) bool
	extract  func(
		context.Context,
		*os.File,
		string,
		string,
	) (extract.Result, error)
}

type workDirectoryStub struct {
	path    string
	cleanup func() error
}

func (s workDirectoryStub) Path() string { return s.path }
func (s workDirectoryStub) Cleanup() error {
	return s.cleanup()
}

func (s extractionEngineStub) Supports(format string) bool {
	return s.supports(format)
}

func (s extractionEngineStub) Extract(
	ctx context.Context,
	source *os.File,
	format string,
	workDirectory string,
) (extract.Result, error) {
	return s.extract(ctx, source, format, workDirectory)
}

func TestProcessorIdentifiesAndPublishesVerifiedRoot(t *testing.T) {
	root := t.TempDir()
	content := []byte("\x7fELF root sample")
	sample := writeSample(t, root, "firmware.bin", content)
	lease := scanLease()
	var published RootNode
	var order []string
	repository := &repositoryStub{
		load: func(_ context.Context, actual queue.Lease) (Sample, error) {
			order = append(order, "load")
			if actual.JobID != lease.JobID {
				t.Fatalf("Load lease = %+v", actual)
			}
			return sample, nil
		},
		publish: func(
			_ context.Context,
			actual queue.Lease,
			node RootNode,
		) error {
			order = append(order, "publish")
			if actual.FencingToken != lease.FencingToken {
				t.Fatalf("Publish lease = %+v", actual)
			}
			published = node
			return nil
		},
	}
	progress := &progressStub{
		report: func(
			_ context.Context,
			actual queue.Lease,
			input queue.ProgressInput,
		) error {
			order = append(order, "progress")
			if actual.JobID != lease.JobID || input.TaskStatus != input.Stage ||
				(input.TaskStatus != "IDENTIFYING" && input.TaskStatus != "REPORTING") {
				t.Fatalf("TaskProgress(%+v, %+v)", actual, input)
			}
			return nil
		},
	}
	detector := detectorStub{detect: func(source io.ReaderAt, size int64) (filetype.Result, error) {
		order = append(order, "detect")
		if size != int64(len(content)) {
			t.Fatalf("Detect size = %d", size)
		}
		actual := make([]byte, len(content))
		if _, err := source.ReadAt(actual, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, content) {
			t.Fatalf("Detect content = %q", actual)
		}
		return filetype.Result{
			Format: "elf64", MIMEType: "application/x-elf",
			Architecture: "x86_64", Metadata: map[string]any{"bits": 64},
		}, nil
	}}
	processor := newTestProcessor(t, repository, progress, detector, root)

	finish, err := processor.Process(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomeSucceeded {
		t.Fatalf("Process() finish = %+v", finish)
	}
	if strings.Join(order, ",") != "load,progress,detect,publish,progress" {
		t.Fatalf("call order = %v", order)
	}
	if published.LogicalPath != "/" ||
		published.LogicalPathHash != sha256.Sum256([]byte("/")) ||
		published.DisplayName != sample.DisplayName ||
		published.Format != "elf64" ||
		published.MIMEType != "application/x-elf" ||
		published.Architecture != "x86_64" ||
		published.SizeBytes != sample.SizeBytes ||
		published.SHA256 != sample.SHA256 ||
		published.StorageKey != sample.StorageKey ||
		string(published.MetadataJSON) != `{"bits":64}` {
		t.Fatalf("published root = %+v", published)
	}
}

func TestProcessorExtractsIndexesAndPublishesArchiveTree(t *testing.T) {
	repositoryRoot := t.TempDir()
	taskWorkRoot := t.TempDir()
	content := []byte("verified archive bytes")
	sample := writeSample(t, repositoryRoot, "archive.bin", content)
	sample.Limits = testExtractionLimits()
	lease := scanLease()
	child := extract.Node{
		LocalID: 1, LogicalPath: "/payload", DisplayName: "payload",
		NodeType: extract.NodeTypeFile, Depth: 1, Format: "unknown",
		MIMEType: "application/octet-stream", SizeBytes: 7,
		ExtractionStatus: extract.StatusExtracted,
	}
	var stages []string
	var workDirectory string
	var publishedRootStatus string
	var publishedNodes []extract.Node
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
			publishedRootStatus = rootStatus
			publishedNodes = append([]extract.Node(nil), nodes...)
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
				Format: "gzip", MIMEType: "application/gzip",
				Metadata: map[string]any{},
			}, nil
		}},
		repositoryRoot,
		taskWorkRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	processor.newExtractor = func(
		_ Detector,
		limits extract.Limits,
	) extractionEngine {
		if limits != sample.Limits {
			t.Fatalf("extractor limits = %+v, want %+v", limits, sample.Limits)
		}
		return extractionEngineStub{
			supports: func(format string) bool {
				return format == "gzip"
			},
			extract: func(
				_ context.Context,
				source *os.File,
				format string,
				work string,
			) (extract.Result, error) {
				if format != "gzip" {
					t.Fatalf("Extract format = %q", format)
				}
				actual := make([]byte, len(content))
				if _, err := source.ReadAt(actual, 0); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, content) {
					t.Fatalf("Extract source = %q", actual)
				}
				info, err := os.Lstat(work)
				if err != nil || !info.IsDir() ||
					info.Mode()&os.ModeSymlink != 0 {
					t.Fatalf("Extract work directory = %q (%v)", work, err)
				}
				workDirectory = work
				return extract.Result{
					Nodes: []extract.Node{child}, ExpandedBytes: 7,
				}, nil
			},
		}
	}

	finish, err := processor.Process(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomeSucceeded ||
		strings.Join(stages, ",") != "IDENTIFYING,EXTRACTING,INDEXING,REPORTING" ||
		publishedRootStatus != "extracted" ||
		len(publishedNodes) != 1 ||
		publishedNodes[0].LogicalPath != child.LogicalPath {
		t.Fatalf(
			"Process = finish=%+v stages=%v root=%q nodes=%+v",
			finish, stages, publishedRootStatus, publishedNodes,
		)
	}
	if workDirectory == "" {
		t.Fatal("extractor did not receive a work directory")
	}
	if _, err := os.Lstat(workDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("work directory was not removed: %v", err)
	}
}

func TestProcessorEnqueuesOnlyContainerImageArchivesAfterTreePublication(
	t *testing.T,
) {
	tests := []struct {
		name        string
		format      string
		partial     bool
		wantEnqueue bool
	}{
		{
			name: "Docker Save", format: "docker-tar",
			wantEnqueue: true,
		},
		{
			name: "partial OCI archive", format: "oci-tar",
			partial: true, wantEnqueue: true,
		},
		{name: "ordinary TAR", format: "tar"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			sample := writeSample(
				t, repositoryRoot, "image.tar", []byte("container archive"),
			)
			sample.Limits = testExtractionLimits()
			var calls []string
			enqueueCalls := 0
			repository := &repositoryStub{
				load: func(context.Context, queue.Lease) (Sample, error) {
					return sample, nil
				},
				publish: func(context.Context, queue.Lease, RootNode) error {
					return nil
				},
				publishTree: func(
					context.Context,
					queue.Lease,
					string,
					[]extract.Node,
				) error {
					calls = append(calls, "tree")
					return nil
				},
				enqueueTrivy: func(
					_ context.Context,
					lease queue.Lease,
					payload TrivyJobPayload,
				) error {
					calls = append(calls, "trivy")
					enqueueCalls++
					if len(payload.Sources) != 1 {
						t.Fatalf("Trivy handoff sources = %+v", payload.Sources)
					}
					source := payload.Sources[0]
					if lease.JobID != scanLease().JobID ||
						payload.SchemaVersion != TrivyJobPayloadSchemaVersion ||
						source.Format != test.format ||
						source.SourceStorageKey != sample.StorageKey ||
						source.SourceSHA256 != sample.SHA256 ||
						source.SourceSizeBytes != sample.SizeBytes ||
						source.ImageLogicalPath != "/" ||
						payload.MaxExpandedBytes !=
							sample.Limits.MaxExpandedBytes ||
						payload.MaxArchiveRatio != int(sample.Limits.MaxRatio) ||
						payload.UpstreamPartial != test.partial {
						t.Fatalf("Trivy handoff = lease %+v payload %+v", lease, payload)
					}
					return nil
				},
			}
			processor, err := NewProcessor(
				repository,
				successProgress(),
				detectorStub{detect: func(
					io.ReaderAt,
					int64,
				) (filetype.Result, error) {
					return filetype.Result{
						Format: test.format, Metadata: map[string]any{},
					}, nil
				}},
				repositoryRoot,
				t.TempDir(),
			)
			if err != nil {
				t.Fatal(err)
			}
			processor.newExtractor = func(
				Detector,
				extract.Limits,
			) extractionEngine {
				return extractionEngineStub{
					supports: func(string) bool { return true },
					extract: func(
						context.Context,
						*os.File,
						string,
						string,
					) (extract.Result, error) {
						return extract.Result{Partial: test.partial}, nil
					},
				}
			}

			finish, err := processor.Process(context.Background(), scanLease())
			if err != nil {
				t.Fatal(err)
			}
			wantOutcome := queue.OutcomeSucceeded
			if test.partial {
				wantOutcome = queue.OutcomePartialSucceeded
			}
			if finish.Outcome != wantOutcome {
				t.Fatalf("finish outcome = %q, want %q", finish.Outcome, wantOutcome)
			}
			if test.wantEnqueue {
				if enqueueCalls != 1 ||
					strings.Join(calls, ",") != "tree,trivy" {
					t.Fatalf("handoff calls = %v, enqueue=%d", calls, enqueueCalls)
				}
			} else if enqueueCalls != 0 ||
				strings.Join(calls, ",") != "tree" {
				t.Fatalf("ordinary TAR handoff calls = %v", calls)
			}
		})
	}
}

func TestProcessorPublishesAtMostTenNestedContainerImagesToCAS(t *testing.T) {
	repositoryRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "bundle.zip", []byte("archive"))
	sample.Limits = testExtractionLimits()
	var published []extract.Node
	var handoff TrivyJobPayload
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
			_ string,
			nodes []extract.Node,
		) error {
			published = append([]extract.Node(nil), nodes...)
			return nil
		},
		enqueueTrivy: func(
			_ context.Context,
			_ queue.Lease,
			payload TrivyJobPayload,
		) error {
			handoff = payload
			return nil
		},
	}
	detector := detectorStub{detect: func(
		io.ReaderAt,
		int64,
	) (filetype.Result, error) {
		return filetype.Result{
			Format: "zip", MIMEType: "application/zip",
			Metadata: map[string]any{},
		}, nil
	}}
	processor := newTestProcessor(
		t,
		repository,
		successProgress(),
		detector,
		repositoryRoot,
	)
	processor.newExtractor = func(Detector, extract.Limits) extractionEngine {
		return extractionEngineStub{
			supports: func(string) bool { return true },
			extract: func(
				_ context.Context,
				_ *os.File,
				_ string,
				workRoot string,
			) (extract.Result, error) {
				result := extract.Result{}
				for index := 0; index < 11; index++ {
					content := []byte(fmt.Sprintf("nested-image-%02d", index))
					digest := sha256.Sum256(content)
					workPath := filepath.Join(
						workRoot,
						fmt.Sprintf("image-%02d.tar", index),
					)
					if err := os.WriteFile(workPath, content, 0o600); err != nil {
						return extract.Result{}, err
					}
					logicalPath := fmt.Sprintf("/image-%02d.tar", index)
					result.Nodes = append(result.Nodes, extract.Node{
						LocalID: index + 1, LogicalPath: logicalPath,
						DisplayName: filepath.Base(logicalPath),
						NodeType:    extract.NodeTypeFile, Depth: 1,
						Format: "docker-tar", SizeBytes: int64(len(content)),
						SHA256:           hex.EncodeToString(digest[:]),
						ExtractionStatus: extract.StatusExtracted,
					})
					result.ContainerImages = append(
						result.ContainerImages,
						extract.ContainerImage{
							LocalID: index + 1, LogicalPath: logicalPath,
							Format:    "docker-tar",
							SHA256:    hex.EncodeToString(digest[:]),
							SizeBytes: int64(len(content)), WorkPath: workPath,
						},
					)
				}
				return result, nil
			},
		}
	}

	finish, err := processor.Process(context.Background(), scanLease())
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomePartialSucceeded ||
		len(handoff.Sources) != 10 ||
		!handoff.UpstreamPartial ||
		len(published) != 11 {
		t.Fatalf(
			"finish=%+v handoff=%+v nodes=%d",
			finish,
			handoff,
			len(published),
		)
	}
	for index := 0; index < 10; index++ {
		node := published[index]
		if node.StorageKey == "" ||
			handoff.Sources[index].ImageLogicalPath != node.LogicalPath ||
			handoff.Sources[index].SourceStorageKey != node.StorageKey {
			t.Fatalf("selected nested image %d = %+v", index, node)
		}
		if _, err := os.Stat(
			filepath.Join(repositoryRoot, node.StorageKey),
		); err != nil {
			t.Fatalf("selected CAS blob %d: %v", index, err)
		}
	}
	overflow := published[10]
	if overflow.StorageKey == "" ||
		overflow.ExtractionStatus != extract.StatusLimitExceeded ||
		overflow.ErrorCode != extract.LimitMaxContainerImages {
		t.Fatalf("overflow node = %+v", overflow)
	}
	if _, err := os.Stat(
		filepath.Join(repositoryRoot, overflow.StorageKey),
	); err != nil {
		t.Fatalf("retained overflow CAS blob: %v", err)
	}
}

func TestProcessorReturnsTrivyHandoffErrorAfterPublishingTree(t *testing.T) {
	repositoryRoot := t.TempDir()
	sample := writeSample(
		t, repositoryRoot, "image.tar", []byte("container archive"),
	)
	sample.Limits = testExtractionLimits()
	handoffError := errors.New("queue unavailable")
	treePublished := false
	repository := &repositoryStub{
		load: func(context.Context, queue.Lease) (Sample, error) {
			return sample, nil
		},
		publish: func(context.Context, queue.Lease, RootNode) error {
			return nil
		},
		publishTree: func(
			context.Context,
			queue.Lease,
			string,
			[]extract.Node,
		) error {
			treePublished = true
			return nil
		},
		enqueueTrivy: func(
			context.Context,
			queue.Lease,
			TrivyJobPayload,
		) error {
			if !treePublished {
				t.Fatal("Trivy handoff ran before tree publication")
			}
			return handoffError
		},
	}
	processor, err := NewProcessor(
		repository,
		successProgress(),
		detectorStub{detect: func(
			io.ReaderAt,
			int64,
		) (filetype.Result, error) {
			return filetype.Result{
				Format: "docker-tar", Metadata: map[string]any{},
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
			supports: func(string) bool { return true },
			extract: func(
				context.Context,
				*os.File,
				string,
				string,
			) (extract.Result, error) {
				return extract.Result{}, nil
			},
		}
	}
	if _, err := processor.Process(
		context.Background(), scanLease(),
	); !errors.Is(err, handoffError) {
		t.Fatalf("Process() error = %v, want handoff error", err)
	}
}

func TestProcessorPublishesPartialLimitAndSkipsExtractionAtZeroNodeBudget(
	t *testing.T,
) {
	repositoryRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "archive.bin", []byte("archive"))
	sample.Limits = testExtractionLimits()
	sample.Limits.MaxNodes = 0
	var rootStatus string
	var nodeCount int
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
			actualRootStatus string,
			nodes []extract.Node,
		) error {
			rootStatus = actualRootStatus
			nodeCount = len(nodes)
			return nil
		},
	}
	processor, err := NewProcessor(
		repository,
		successProgress(),
		detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
			return filetype.Result{
				Format: "zip", MIMEType: "application/zip",
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
			supports: func(string) bool { return true },
			extract: func(
				context.Context,
				*os.File,
				string,
				string,
			) (extract.Result, error) {
				t.Fatal("Extract called with zero descendant node budget")
				return extract.Result{}, nil
			},
		}
	}

	finish, err := processor.Process(context.Background(), scanLease())
	if err != nil {
		t.Fatal(err)
	}
	if finish.Outcome != queue.OutcomePartialSucceeded ||
		rootStatus != "limit_reached" || nodeCount != 0 {
		t.Fatalf(
			"Process = finish=%+v root=%q nodeCount=%d",
			finish, rootStatus, nodeCount,
		)
	}
}

func TestProcessorMarksRecognizedUnsupportedContainerPartial(t *testing.T) {
	repositoryRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "archive.bin", []byte("archive"))
	sample.Limits = testExtractionLimits()
	var stages []string
	var rootStatus string
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
			actualRootStatus string,
			nodes []extract.Node,
		) error {
			rootStatus = actualRootStatus
			if len(nodes) != 0 {
				t.Fatalf("unsupported tree nodes = %+v", nodes)
			}
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
				Format: "rar", MIMEType: "application/vnd.rar",
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
	if finish.Outcome != queue.OutcomePartialSucceeded ||
		rootStatus != "unsupported" ||
		strings.Join(stages, ",") != "IDENTIFYING,EXTRACTING,INDEXING,REPORTING" {
		t.Fatalf(
			"Process = finish=%+v root=%q stages=%v",
			finish, rootStatus, stages,
		)
	}
}

func TestProcessorCleansWorkspaceAfterExtractorError(t *testing.T) {
	repositoryRoot := t.TempDir()
	sample := writeSample(t, repositoryRoot, "archive.bin", []byte("archive"))
	sample.Limits = testExtractionLimits()
	extractError := errors.New("temporary disk read failure")
	repository := processorRepository(sample, nil)
	processor, err := NewProcessor(
		repository,
		successProgress(),
		detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
			return filetype.Result{
				Format: "tar", MIMEType: "application/x-tar",
				Metadata: map[string]any{},
			}, nil
		}},
		repositoryRoot,
		t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var workDirectory string
	processor.newExtractor = func(Detector, extract.Limits) extractionEngine {
		return extractionEngineStub{
			supports: func(string) bool { return true },
			extract: func(
				_ context.Context,
				_ *os.File,
				_ string,
				work string,
			) (extract.Result, error) {
				workDirectory = work
				return extract.Result{}, extractError
			},
		}
	}

	if _, err := processor.Process(
		context.Background(), scanLease(),
	); !errors.Is(err, extractError) {
		t.Fatalf("Process error = %v", err)
	}
	if workDirectory == "" {
		t.Fatal("extractor did not receive a work directory")
	}
	if _, err := os.Lstat(workDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("work directory was not removed: %v", err)
	}
}

func TestProcessorReturnsAndCombinesWorkspaceCleanupErrors(t *testing.T) {
	tests := []struct {
		name       string
		extractErr error
	}{
		{name: "successful extraction"},
		{name: "extractor failure", extractErr: errors.New("extract failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			sample := writeSample(
				t, repositoryRoot, "archive.bin", []byte("archive"),
			)
			sample.Limits = testExtractionLimits()
			processor, err := NewProcessor(
				processorRepository(sample, nil),
				successProgress(),
				detectorStub{detect: func(
					io.ReaderAt,
					int64,
				) (filetype.Result, error) {
					return filetype.Result{
						Format: "tar", MIMEType: "application/x-tar",
						Metadata: map[string]any{},
					}, nil
				}},
				repositoryRoot,
				t.TempDir(),
			)
			if err != nil {
				t.Fatal(err)
			}
			cleanupErr := errors.New("workspace cleanup failed")
			cleanupCalls := 0
			var identity workspace.Identity
			workPath := t.TempDir()
			processor.newWorkspace = func(
				_ string,
				actual workspace.Identity,
			) (workDirectory, error) {
				identity = actual
				return workDirectoryStub{
					path: workPath,
					cleanup: func() error {
						cleanupCalls++
						return cleanupErr
					},
				}, nil
			}
			processor.newExtractor = func(
				Detector,
				extract.Limits,
			) extractionEngine {
				return extractionEngineStub{
					supports: func(string) bool { return true },
					extract: func(
						context.Context,
						*os.File,
						string,
						string,
					) (extract.Result, error) {
						return extract.Result{}, test.extractErr
					},
				}
			}

			_, err = processor.Process(context.Background(), scanLease())
			if !errors.Is(err, cleanupErr) {
				t.Fatalf("Process() error = %v, want cleanup error", err)
			}
			if test.extractErr != nil && !errors.Is(err, test.extractErr) {
				t.Fatalf("Process() error = %v, want extractor error", err)
			}
			if cleanupCalls != 1 {
				t.Fatalf("Cleanup() calls = %d, want 1", cleanupCalls)
			}
			lease := scanLease()
			if identity.JobID != lease.JobID ||
				identity.TaskID != lease.TaskID ||
				identity.TaskAttemptID != *lease.TaskAttemptID ||
				identity.FencingToken != lease.FencingToken ||
				identity.Kind != string(lease.Kind) {
				t.Fatalf("workspace identity = %+v", identity)
			}
		})
	}
}

func TestProcessorMapsUnsafeMissingAndMismatchedSamplesToDeterministicFailure(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string) Sample
		code    string
	}{
		{
			name: "missing",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				return sampleForContent("missing.bin", []byte("missing"))
			},
			code: "sample_missing",
		},
		{
			name: "size mismatch",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := writeSample(t, root, "size.bin", []byte("content"))
				sample.SizeBytes++
				return sample
			},
			code: "sample_content_mismatch",
		},
		{
			name: "hash mismatch",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				claimed := sampleForContent("hash.bin", []byte("claimed"))
				writeAtStorageKey(t, root, claimed.StorageKey, []byte("altered"))
				claimed.SizeBytes = int64(len("altered"))
				return claimed
			},
			code: "sample_content_mismatch",
		},
		{
			name: "absolute storage key",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("absolute.bin", []byte("content"))
				sample.StorageKey = "/etc/passwd"
				return sample
			},
			code: "sample_path_unsafe",
		},
		{
			name: "traversing storage key",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("traversal.bin", []byte("content"))
				sample.StorageKey = "blobs/sha256/../../etc/passwd"
				return sample
			},
			code: "sample_path_unsafe",
		},
		{
			name: "wrong sha shard",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("shard.bin", []byte("content"))
				sample.StorageKey = "blobs/sha256/00/" + sample.SHA256
				return sample
			},
			code: "sample_path_unsafe",
		},
		{
			name: "final symlink",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("symlink.bin", []byte("content"))
				target := filepath.Join(t.TempDir(), "outside.bin")
				if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
					t.Fatal(err)
				}
				fullPath := filepath.Join(root, filepath.FromSlash(sample.StorageKey))
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, fullPath); err != nil {
					t.Fatal(err)
				}
				return sample
			},
			code: "sample_path_unsafe",
		},
		{
			name: "intermediate symlink",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("dir-symlink.bin", []byte("content"))
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(root, "blobs")); err != nil {
					t.Fatal(err)
				}
				return sample
			},
			code: "sample_path_unsafe",
		},
		{
			name: "non regular sample",
			prepare: func(t *testing.T, root string) Sample {
				t.Helper()
				sample := sampleForContent("directory.bin", []byte("content"))
				if err := os.MkdirAll(
					filepath.Join(root, filepath.FromSlash(sample.StorageKey)),
					0o700,
				); err != nil {
					t.Fatal(err)
				}
				return sample
			},
			code: "sample_path_unsafe",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sample := test.prepare(t, root)
			repository := &repositoryStub{
				load: func(context.Context, queue.Lease) (Sample, error) {
					return sample, nil
				},
				publish: func(context.Context, queue.Lease, RootNode) error {
					t.Fatal("unsafe sample was published")
					return nil
				},
			}
			progress := &progressStub{
				report: func(context.Context, queue.Lease, queue.ProgressInput) error {
					t.Fatal("unsafe sample advanced to identification")
					return nil
				},
			}
			detector := detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
				t.Fatal("unsafe sample reached detector")
				return filetype.Result{}, nil
			}}
			processor := newTestProcessor(t, repository, progress, detector, root)

			finish, err := processor.Process(context.Background(), scanLease())
			if err != nil {
				t.Fatal(err)
			}
			if finish.Outcome != queue.OutcomeDeterministicFailure ||
				finish.ErrorCode != test.code ||
				finish.ErrorMessage == "" {
				t.Fatalf("Process() finish = %+v", finish)
			}
		})
	}
}

func TestProcessorMapsLoadClassificationAndReturnsOperationalErrors(t *testing.T) {
	temporary := errors.New("database unavailable")
	tests := []struct {
		name      string
		loadError error
		code      string
		wantError error
	}{
		{name: "missing", loadError: ErrSampleMissing, code: "sample_missing"},
		{name: "unsafe", loadError: ErrUnsafeSample, code: "sample_path_unsafe"},
		{name: "mismatch", loadError: ErrSampleMismatch, code: "sample_content_mismatch"},
		{name: "limits", loadError: ErrInvalidLimits, code: "task_limits_invalid"},
		{name: "database", loadError: temporary, wantError: temporary},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &repositoryStub{
				load: func(context.Context, queue.Lease) (Sample, error) {
					return Sample{}, test.loadError
				},
				publish: func(context.Context, queue.Lease, RootNode) error {
					t.Fatal("Publish called after Load failure")
					return nil
				},
			}
			processor := newTestProcessor(
				t,
				repository,
				&progressStub{report: func(
					context.Context,
					queue.Lease,
					queue.ProgressInput,
				) error {
					t.Fatal("TaskProgress called after Load failure")
					return nil
				}},
				detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
					t.Fatal("Detect called after Load failure")
					return filetype.Result{}, nil
				}},
				t.TempDir(),
			)

			finish, err := processor.Process(context.Background(), scanLease())
			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Fatalf("Process() error = %v, want %v", err, test.wantError)
				}
				return
			}
			if err != nil || finish.Outcome != queue.OutcomeDeterministicFailure ||
				finish.ErrorCode != test.code {
				t.Fatalf("Process() = (%+v, %v)", finish, err)
			}
		})
	}
}

func TestProcessorReturnsProgressDetectorAndPublishErrors(t *testing.T) {
	root := t.TempDir()
	sample := writeSample(t, root, "errors.bin", []byte("content"))
	lease := scanLease()

	t.Run("progress", func(t *testing.T) {
		progressError := errors.New("progress database error")
		processor := newTestProcessor(
			t,
			processorRepository(sample, nil),
			&progressStub{report: func(
				context.Context,
				queue.Lease,
				queue.ProgressInput,
			) error {
				return progressError
			}},
			detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
				t.Fatal("Detect called after progress failure")
				return filetype.Result{}, nil
			}},
			root,
		)
		if _, err := processor.Process(context.Background(), lease); !errors.Is(err, progressError) {
			t.Fatalf("Process() error = %v", err)
		}
	})

	t.Run("reporting progress", func(t *testing.T) {
		progressError := errors.New("reporting progress database error")
		published := false
		repository := &repositoryStub{
			load: func(context.Context, queue.Lease) (Sample, error) {
				return sample, nil
			},
			publish: func(
				context.Context,
				queue.Lease,
				RootNode,
			) error {
				published = true
				return nil
			},
		}
		processor := newTestProcessor(
			t,
			repository,
			&progressStub{report: func(
				_ context.Context,
				_ queue.Lease,
				input queue.ProgressInput,
			) error {
				if input.Stage == "REPORTING" {
					return progressError
				}
				return nil
			}},
			unknownDetector(),
			root,
		)
		if _, err := processor.Process(
			context.Background(),
			lease,
		); !errors.Is(err, progressError) || !published {
			t.Fatalf("Process() = (published=%v, error=%v)", published, err)
		}
	})

	t.Run("detector", func(t *testing.T) {
		detectorError := errors.New("temporary read failure")
		processor := newTestProcessor(
			t,
			processorRepository(sample, nil),
			successProgress(),
			detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
				return filetype.Result{}, detectorError
			}},
			root,
		)
		if _, err := processor.Process(context.Background(), lease); !errors.Is(err, detectorError) {
			t.Fatalf("Process() error = %v", err)
		}
	})

	t.Run("publish", func(t *testing.T) {
		publishError := errors.New("transaction deadlock")
		processor := newTestProcessor(
			t,
			processorRepository(sample, publishError),
			successProgress(),
			unknownDetector(),
			root,
		)
		if _, err := processor.Process(context.Background(), lease); !errors.Is(err, publishError) {
			t.Fatalf("Process() error = %v", err)
		}
	})
}

func TestNewProcessorValidatesDependenciesAndRoot(t *testing.T) {
	repository := processorRepository(Sample{}, nil)
	progress := successProgress()
	detector := unknownDetector()
	tests := []struct {
		name       string
		repository Repository
		progress   ProgressReporter
		detector   Detector
		root       string
		workRoot   string
	}{
		{
			name: "repository", progress: progress, detector: detector,
			root: t.TempDir(), workRoot: t.TempDir(),
		},
		{
			name: "progress", repository: repository, detector: detector,
			root: t.TempDir(), workRoot: t.TempDir(),
		},
		{
			name: "detector", repository: repository, progress: progress,
			root: t.TempDir(), workRoot: t.TempDir(),
		},
		{
			name: "relative root", repository: repository, progress: progress,
			detector: detector, root: "relative", workRoot: t.TempDir(),
		},
		{
			name: "filesystem root", repository: repository, progress: progress,
			detector: detector, root: string(filepath.Separator),
			workRoot: t.TempDir(),
		},
		{
			name: "relative work root", repository: repository, progress: progress,
			detector: detector, root: t.TempDir(), workRoot: "relative",
		},
		{
			name: "overlapping roots", repository: repository, progress: progress,
			detector: detector, root: t.TempDir(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "overlapping roots" {
				test.workRoot = filepath.Join(test.root, "work")
			}
			if _, err := NewProcessor(
				test.repository, test.progress, test.detector,
				test.root, test.workRoot,
			); err == nil {
				t.Fatal("NewProcessor() error = nil")
			}
		})
	}
}

func newTestProcessor(
	t *testing.T,
	repository Repository,
	progress ProgressReporter,
	detector Detector,
	root string,
) *Processor {
	t.Helper()
	processor, err := NewProcessor(
		repository, progress, detector, root, t.TempDir(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func processorRepository(sample Sample, publishError error) Repository {
	return &repositoryStub{
		load: func(context.Context, queue.Lease) (Sample, error) {
			return sample, nil
		},
		publish: func(context.Context, queue.Lease, RootNode) error {
			return publishError
		},
	}
}

func successProgress() ProgressReporter {
	return &progressStub{
		report: func(context.Context, queue.Lease, queue.ProgressInput) error {
			return nil
		},
	}
}

func unknownDetector() Detector {
	return detectorStub{detect: func(io.ReaderAt, int64) (filetype.Result, error) {
		return filetype.Result{
			Format: "unknown", MIMEType: "application/octet-stream",
			Metadata: map[string]any{},
		}, nil
	}}
}

func testExtractionLimits() extract.Limits {
	return extract.Limits{
		MaxExpandedBytes: 1024 * 1024,
		MaxNodes:         100,
		MaxDepth:         10,
		MaxRatio:         100,
	}
}

func scanLease() queue.Lease {
	attemptID := uint64(19)
	return queue.Lease{
		JobID:         "123e4567-e89b-42d3-a456-426614174000",
		TaskID:        "123e4567-e89b-42d3-a456-426614174001",
		TaskAttemptID: &attemptID,
		Kind:          queue.KindScan, Attempt: 1, MaxAttempts: 3,
		FencingToken: 7, Owner: "scan-worker-1",
	}
}

func writeSample(
	t *testing.T,
	root string,
	displayName string,
	content []byte,
) Sample {
	t.Helper()
	sample := sampleForContent(displayName, content)
	writeAtStorageKey(t, root, sample.StorageKey, content)
	return sample
}

func sampleForContent(displayName string, content []byte) Sample {
	digest := sha256.Sum256(content)
	encoded := hex.EncodeToString(digest[:])
	return Sample{
		TaskID: scanLease().TaskID, UploadID: "123e4567-e89b-42d3-a456-426614174002",
		BlobID: 7, DisplayName: displayName, SizeBytes: int64(len(content)),
		SHA256: encoded, StorageKey: "blobs/sha256/" + encoded[:2] + "/" + encoded,
	}
}

func writeAtStorageKey(
	t *testing.T,
	root string,
	storageKey string,
	content []byte,
) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
