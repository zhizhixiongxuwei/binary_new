package decompile

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestServiceExportsTaskCurrentFunctionSources(t *testing.T) {
	root := t.TempDir()
	privateTemp := t.TempDir()
	t.Setenv("TMPDIR", privateTemp)
	createdAt := time.Date(2026, 8, 4, 1, 2, 3, 0, time.UTC)
	exportedAt := createdAt.Add(time.Minute)
	const source = "int verify_header(void) { return 1; }\n"
	storageKey := filepath.ToSlash(filepath.Join(
		"decompile", testResultID, "source.c",
	))
	storagePath := filepath.Join(root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(storagePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storagePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	size := uint64(len(source))
	repository := &repositoryStub{
		list: func(_ context.Context, query ListQuery) (Page, error) {
			if query.TaskID != testTaskID ||
				query.PageSize != maxSourceArchiveResults || query.After != nil {
				t.Fatalf("archive List() query = %#v", query)
			}
			return Page{
				Items: []Result{
					{
						ID: testResultID, FileNodeID: "42",
						SymbolKey: "FUN_140001000", SymbolKind: "function",
						DisplayName: "verify/header", Location: "0x140001000",
						Signature: "int verify_header(void)", Language: "c",
						EngineName: "ghidra", EngineVersion: "12.1.2",
						Status: "complete", SizeBytes: &size, CreatedAt: createdAt,
						StorageKey:    storageKey,
						ContentSHA256: sourceSHA256(source),
					},
					{
						ID: nextResultID, FileNodeID: "42",
						SymbolKey: "unsupported", SymbolKind: "function",
						DisplayName: "unsupported", Language: "c",
						EngineName: "ghidra", EngineVersion: "12.1.2",
						Status: "unsupported", CreatedAt: createdAt.Add(time.Second),
					},
				},
			}, nil
		},
		getSource: func(_ context.Context, query SourceQuery) (SourceDescriptor, error) {
			if query.TaskID != testTaskID || query.ResultID != testResultID {
				t.Fatalf("archive GetSource() query = %#v", query)
			}
			return SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: storageKey, SHA256: sourceSHA256(source),
				SizeBytes: size, SizeKnown: true,
			}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return exportedAt }

	archive, err := service.ExportSources(context.Background(), SourceArchiveQuery{
		TaskID: testTaskID, IncludeCombined: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.archiveCalls != 1 {
		t.Fatalf("source archive snapshot calls = %d, want 1", repository.archiveCalls)
	}
	temporaryPath := archive.Content.(*removingArchiveFile).File.Name()
	if filepath.Dir(temporaryPath) != privateTemp {
		t.Fatalf("temporary archive directory = %q, want %q", filepath.Dir(temporaryPath), privateTemp)
	}
	if _, err := os.Stat(temporaryPath); !os.IsNotExist(err) {
		t.Fatalf("temporary archive was not unlinked immediately: %v", err)
	}
	payload, err := io.ReadAll(archive.Content)
	if err != nil {
		t.Fatal(err)
	}
	if archive.ResultCount != 2 || archive.SizeBytes != uint64(len(payload)) ||
		archive.Filename != "binaryscan-"+testTaskID+
			"-decompile-sources.zip" {
		t.Fatalf("archive metadata = %#v", archive)
	}
	digest := sourceSHA256(string(payload))
	if archive.SHA256 != digest {
		t.Fatalf("archive sha = %s, want %s", archive.SHA256, digest)
	}
	if _, err := hex.DecodeString(archive.SHA256); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(opened)
		closeErr := opened.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		files[file.Name] = string(content)
	}
	functionPath := ""
	for name := range files {
		if strings.HasPrefix(name, "functions/") {
			functionPath = name
		}
	}
	if functionPath == "" || files[functionPath] != source ||
		!strings.Contains(files["all-functions.c"], source) {
		t.Fatalf("archive files = %#v", files)
	}
	var manifest sourceArchiveManifest
	if err := json.Unmarshal([]byte(files["manifest.json"]), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ResultCount != 2 || manifest.SourceCount != 1 ||
		manifest.CombinedPath != "all-functions.c" ||
		manifest.Items[0].ArchivePath != functionPath ||
		manifest.Items[1].ArchivePath != "" ||
		!manifest.ExportGeneratedAt.Equal(exportedAt) ||
		manifest.SourcePolicy != "current_task_source_metadata" {
		t.Fatalf("manifest = %#v", manifest)
	}
	const replacement = "unrelated replacement"
	if err := os.WriteFile(temporaryPath, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := archive.Content.Close(); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(temporaryPath); err != nil || string(value) != replacement {
		t.Fatalf("archive Close removed or changed a replacement: %q, %v", value, err)
	}
}

func TestServiceRejectsInvalidTaskSourceArchiveBeforeRepository(t *testing.T) {
	repository := &repositoryStub{}
	service, err := NewService(repository, Config{RepositoryRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ExportSources(
		context.Background(),
		SourceArchiveQuery{TaskID: "invalid"},
	); err != ErrInvalidInput {
		t.Fatalf("ExportSources() error = %v", err)
	}
	if repository.listCalled || repository.sourceCalled {
		t.Fatal("invalid archive request reached repository")
	}
}

func TestServiceRejectsSourceArchiveWhenResultPageHasMore(t *testing.T) {
	repository := &repositoryStub{
		list: func(_ context.Context, query ListQuery) (Page, error) {
			if query.PageSize != maxSourceArchiveResults {
				t.Fatalf("archive page size = %d", query.PageSize)
			}
			return Page{HasMore: true}, nil
		},
	}
	service, err := NewService(repository, Config{RepositoryRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.ExportSources(
		context.Background(),
		SourceArchiveQuery{TaskID: testTaskID},
	); !errors.Is(err, ErrExportTooLarge) {
		t.Fatalf("ExportSources() error = %v, want ErrExportTooLarge", err)
	}
}

func TestServiceRejectsSourceArchiveExpandedPayloadOverBudget(t *testing.T) {
	tests := []struct {
		name            string
		size            uint64
		includeCombined bool
	}{
		{
			name: "single source",
			size: maxSourceArchiveBytes + 1,
		},
		{
			name:            "combined source duplicate",
			size:            maxSourceArchiveBytes / 2,
			includeCombined: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size := test.size
			repository := &repositoryStub{
				list: func(_ context.Context, _ ListQuery) (Page, error) {
					return Page{Items: []Result{{
						ID: testResultID, FileNodeID: "42",
						SymbolKey: "FUN_140001000", SymbolKind: "function",
						DisplayName: "verify_header", Language: "c",
						EngineName: "ghidra", EngineVersion: "12.1.2",
						Status: "complete", SizeBytes: &size,
						StorageKey: filepath.ToSlash(filepath.Join(
							"decompile", testResultID, "source.c",
						)),
						ContentSHA256: strings.Repeat("0", 64),
					}}}, nil
				},
				getSource: func(_ context.Context, _ SourceQuery) (SourceDescriptor, error) {
					return SourceDescriptor{
						ResultID: testResultID, Status: "complete",
						StorageKey: filepath.ToSlash(filepath.Join(
							"decompile", testResultID, "source.c",
						)),
						SHA256:    strings.Repeat("0", 64),
						SizeBytes: size, SizeKnown: true,
					}, nil
				},
			}
			service, err := NewService(
				repository,
				Config{RepositoryRoot: t.TempDir()},
			)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := service.ExportSources(
				context.Background(),
				SourceArchiveQuery{
					TaskID: testTaskID, IncludeCombined: test.includeCombined,
				},
			); !errors.Is(err, ErrExportTooLarge) {
				t.Fatalf(
					"ExportSources() error = %v, want ErrExportTooLarge",
					err,
				)
			}
		})
	}
}

func TestServiceSourceArchiveFailsClosedAndRemovesTemporaryFile(t *testing.T) {
	const source = "int verify_header(void) { return 1; }\n"
	tests := []struct {
		name  string
		setup func(*testing.T, string, string)
		sha   string
	}{
		{
			name: "missing source",
			setup: func(*testing.T, string, string) {
			},
			sha: sourceSHA256(source),
		},
		{
			name: "digest mismatch",
			setup: func(t *testing.T, root, storageKey string) {
				t.Helper()
				path := filepath.Join(root, filepath.FromSlash(storageKey))
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			sha: strings.Repeat("0", 64),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			privateTemp := t.TempDir()
			t.Setenv("TMPDIR", privateTemp)
			storageKey := filepath.ToSlash(filepath.Join(
				"decompile", testResultID, "source.c",
			))
			test.setup(t, root, storageKey)
			size := uint64(len(source))
			repository := &repositoryStub{
				list: func(_ context.Context, _ ListQuery) (Page, error) {
					return Page{Items: []Result{{
						ID: testResultID, FileNodeID: "42",
						SymbolKey: "FUN_140001000", SymbolKind: "function",
						DisplayName: "verify_header", Language: "c",
						EngineName: "ghidra", EngineVersion: "12.1.2",
						Status: "complete", SizeBytes: &size,
						StorageKey:    storageKey,
						ContentSHA256: test.sha,
					}}}, nil
				},
				getSource: func(_ context.Context, _ SourceQuery) (SourceDescriptor, error) {
					return SourceDescriptor{
						ResultID: testResultID, Status: "complete",
						StorageKey: storageKey, SHA256: test.sha,
						SizeBytes: size, SizeKnown: true,
					}, nil
				},
			}
			service, err := NewService(repository, Config{RepositoryRoot: root})
			if err != nil {
				t.Fatal(err)
			}

			if _, err := service.ExportSources(
				context.Background(),
				SourceArchiveQuery{TaskID: testTaskID},
			); !errors.Is(err, ErrSourceUnavailable) {
				t.Fatalf(
					"ExportSources() error = %v, want ErrSourceUnavailable",
					err,
				)
			}
			for _, directory := range []string{root, privateTemp} {
				matches, err := filepath.Glob(filepath.Join(
					directory, ".decompile-sources-*.zip",
				))
				if err != nil {
					t.Fatal(err)
				}
				if len(matches) != 0 {
					t.Fatalf("temporary source archives remain: %v", matches)
				}
			}
		})
	}
}

func TestSafeSourceCommentPreservesUTF8AndNeutralizesControls(t *testing.T) {
	value := strings.Repeat("界", 180) + "*/\n\x00\u202ehidden"
	safe := safeSourceComment(value)
	if !utf8.ValidString(safe) || len(safe) > 512 ||
		strings.Contains(safe, "*/") || strings.ContainsRune(safe, '\x00') ||
		strings.ContainsRune(safe, '\u202e') || strings.ContainsRune(safe, '\n') {
		t.Fatalf("unsafe source comment = %q", safe)
	}
}
