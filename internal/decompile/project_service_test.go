package decompile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"binaryscan/internal/auth"
)

const testSourceProjectID = "923e4567-e89b-42d3-a456-426614174009"

type sourceProjectRepositoryStub struct {
	page             SourceProjectPage
	record           sourceProjectRecord
	deletion         sourceProjectDeletion
	legacyEntries    []legacySourceProjectEntry
	err              error
	listQuery        SourceProjectListQuery
	getQuery         SourceProjectQuery
	beginDeleteQuery SourceProjectQuery
	completeQuery    SourceProjectQuery
	completeCalls    int
	previewRecord    sourceProjectDeletionPreviewRecord
	previewCounts    SourceProjectDeletionCounts
	confirmRecord    sourceProjectDeletionConfirmRecord
	operation        SourceProjectDeletionOperation
	operationQuery   SourceProjectDeletionOperationQuery
}

func (s *sourceProjectRepositoryStub) Enqueue(
	context.Context,
	CreateRecord,
) (Request, bool, error) {
	return Request{}, false, nil
}

func (s *sourceProjectRepositoryStub) GetRequest(
	context.Context,
	RequestQuery,
) (Request, error) {
	return Request{}, nil
}

func (s *sourceProjectRepositoryStub) List(
	context.Context,
	ListQuery,
) (Page, error) {
	return Page{}, nil
}

func (s *sourceProjectRepositoryStub) GetSource(
	context.Context,
	SourceQuery,
) (SourceDescriptor, error) {
	return SourceDescriptor{}, nil
}

func (s *sourceProjectRepositoryStub) ListSourceProjects(
	_ context.Context,
	query SourceProjectListQuery,
) (SourceProjectPage, error) {
	s.listQuery = query
	return s.page, s.err
}

func (s *sourceProjectRepositoryStub) GetSourceProject(
	_ context.Context,
	query SourceProjectQuery,
) (sourceProjectRecord, error) {
	s.getQuery = query
	return s.record, s.err
}

func (s *sourceProjectRepositoryStub) BeginSourceProjectDeletion(
	_ context.Context,
	query SourceProjectQuery,
) (sourceProjectDeletion, error) {
	s.beginDeleteQuery = query
	return s.deletion, s.err
}

func (s *sourceProjectRepositoryStub) CompleteSourceProjectDeletion(
	_ context.Context,
	query SourceProjectQuery,
) error {
	s.completeCalls++
	s.completeQuery = query
	return s.err
}

func (s *sourceProjectRepositoryStub) ListLegacySourceProjectEntries(
	context.Context,
	SourceProjectQuery,
) ([]legacySourceProjectEntry, error) {
	return s.legacyEntries, s.err
}

func (s *sourceProjectRepositoryStub) CreateSourceProjectDeletionPreview(
	_ context.Context,
	record sourceProjectDeletionPreviewRecord,
) (SourceProjectDeletionCounts, error) {
	s.previewRecord = record
	return s.previewCounts, s.err
}

func (s *sourceProjectRepositoryStub) ConfirmSourceProjectDeletion(
	_ context.Context,
	record sourceProjectDeletionConfirmRecord,
) (SourceProjectDeletionOperation, error) {
	s.confirmRecord = record
	return s.operation, s.err
}

func (s *sourceProjectRepositoryStub) GetSourceProjectDeletionOperation(
	_ context.Context,
	query SourceProjectDeletionOperationQuery,
) (SourceProjectDeletionOperation, error) {
	s.operationQuery = query
	return s.operation, s.err
}

func TestSourceProjectServiceListsWithOpaqueDescendingCursor(t *testing.T) {
	createdAt := time.Date(2026, 8, 10, 4, 5, 6, 0, time.UTC)
	repository := &sourceProjectRepositoryStub{page: SourceProjectPage{
		Items:   []SourceProject{{ID: testSourceProjectID, CreatedAt: createdAt}},
		HasMore: true,
	}}
	service, err := NewService(repository, Config{RepositoryRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ListProjects(context.Background(), SourceProjectListQuery{
		TaskID: testTaskID, PageSize: 1,
	})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("ListProjects() page/error = %#v/%v", first, err)
	}
	_, err = service.ListProjects(context.Background(), SourceProjectListQuery{
		TaskID: testTaskID, Cursor: first.NextCursor, PageSize: 25,
	})
	if err != nil || repository.listQuery.After == nil ||
		repository.listQuery.After.ID != testSourceProjectID ||
		!repository.listQuery.After.CreatedAt.Equal(createdAt) {
		t.Fatalf("decoded source project query/error = %#v/%v", repository.listQuery, err)
	}
	if _, err := service.ListProjects(context.Background(), SourceProjectListQuery{
		TaskID: testTaskID, Cursor: "not-canonical", PageSize: 1,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid project cursor error = %v", err)
	}
}

func TestSourceProjectDeletionPreviewHashesOneTimeConfirmationToken(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	operationID := "a23e4567-e89b-42d3-a456-42661417400a"
	repository := &sourceProjectRepositoryStub{
		previewCounts: SourceProjectDeletionCounts{
			CAnalysisRuns: 2, CAnalysisFindings: 8, Reports: 1,
		},
		operation: SourceProjectDeletionOperation{
			ID: operationID, ProjectID: testSourceProjectID, Status: "pending",
		},
	}
	service, err := NewService(repository, Config{
		RepositoryRoot: t.TempDir(),
		NewID: func() (string, error) {
			return operationID, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	preview, err := service.PreviewProjectDeletion(
		context.Background(),
		SourceProjectDeletionPreviewInput{
			TaskID: testTaskID, ProjectID: testSourceProjectID,
			UserID: 7, Role: auth.RoleOperator,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, decodeErr := base64.RawURLEncoding.DecodeString(preview.ConfirmationToken)
	digest := sha256.Sum256([]byte(preview.ConfirmationToken))
	if decodeErr != nil || len(raw) != 32 ||
		repository.previewRecord.TokenHash != hex.EncodeToString(digest[:]) ||
		repository.previewRecord.TokenHash == preview.ConfirmationToken ||
		!preview.ExpiresAt.Equal(now.Add(SourceProjectDeletionTokenTTL)) ||
		preview.TypedSuffix != testSourceProjectID[len(testSourceProjectID)-8:] {
		t.Fatalf("deletion preview/record = %#v/%#v", preview, repository.previewRecord)
	}

	operation, err := service.ConfirmProjectDeletion(
		context.Background(),
		ConfirmSourceProjectDeletionInput{
			TaskID: testTaskID, ProjectID: testSourceProjectID,
			UserID: 7, Role: auth.RoleOperator,
			ConfirmationToken: preview.ConfirmationToken, Cascade: true,
			TypedSuffix: preview.TypedSuffix,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID != operationID ||
		repository.confirmRecord.TokenHash != repository.previewRecord.TokenHash ||
		repository.confirmRecord.OperationID != operationID ||
		!repository.confirmRecord.CreatedAt.Equal(now) {
		t.Fatalf("confirmed operation/record = %#v/%#v", operation, repository.confirmRecord)
	}
}

func TestDeleteSourceProjectRequiresCascadeConfirmationWithoutTouchingStorage(t *testing.T) {
	root := t.TempDir()
	projectRoot := filepath.Join(root, "source-projects", testSourceProjectID)
	otherRoot := filepath.Join(root, "source-projects", testResultID)
	if err := os.MkdirAll(filepath.Join(projectRoot, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(otherRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "src", "decompiled.c"), []byte("void f() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repository := &sourceProjectRepositoryStub{deletion: sourceProjectDeletion{
		Project: sourceProjectRecord{SourceProject: SourceProject{
			ID: testSourceProjectID, LayoutVersion: SourceProjectLayoutV1,
		}, RootStorageKey: "source-projects/" + testSourceProjectID},
	}}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	err = service.DeleteProject(context.Background(), DeleteSourceProjectInput{
		TaskID: testTaskID, ProjectID: testSourceProjectID, UserID: 7,
		Role: auth.RoleOperator,
	})
	if !errors.Is(err, ErrDeletionConfirmationRequired) {
		t.Fatalf("DeleteProject() error = %v, want confirmation required", err)
	}
	if _, err := os.Lstat(projectRoot); err != nil {
		t.Fatalf("unconfirmed deletion touched project directory: %v", err)
	}
	if _, err := os.Lstat(otherRoot); err != nil {
		t.Fatalf("other project directory was affected: %v", err)
	}
	if repository.completeCalls != 0 {
		t.Fatalf("unconfirmed deletion completed cleanup %d times", repository.completeCalls)
	}
}

func TestDeleteSourceProjectRejectsSymlinkedVersionDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	marker := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "source-projects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "source-projects", testSourceProjectID)); err != nil {
		t.Fatal(err)
	}
	repository := &sourceProjectRepositoryStub{deletion: sourceProjectDeletion{
		Project: sourceProjectRecord{SourceProject: SourceProject{
			ID: testSourceProjectID, LayoutVersion: SourceProjectLayoutV1,
		}, RootStorageKey: "source-projects/" + testSourceProjectID},
	}}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	err = service.removeSourceProjectFiles(
		context.Background(), testTaskID, repository.deletion,
	)
	if !errors.Is(err, ErrSourceUnavailable) || repository.completeCalls != 0 {
		t.Fatalf("symlink deletion error/completions = %v/%d", err, repository.completeCalls)
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "keep" {
		t.Fatalf("outside marker changed: %q/%v", content, err)
	}
}

func TestDeleteLegacySourceProjectRejectsStorageKeyForAnotherResult(t *testing.T) {
	root := t.TempDir()
	for _, resultID := range []string{testResultID, testJobID} {
		directory := filepath.Join(root, "decompile", resultID)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "source.java"), []byte("class A {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repository := &sourceProjectRepositoryStub{deletion: sourceProjectDeletion{
		Project: sourceProjectRecord{SourceProject: SourceProject{
			ID: testSourceProjectID, LayoutVersion: SourceProjectLayoutLegacyV1,
		}},
		LegacyFiles: []legacySourceProjectFile{{
			ResultID:   testResultID,
			StorageKey: "decompile/" + testJobID + "/source.java",
		}},
	}}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	err = service.removeSourceProjectFiles(
		context.Background(), testTaskID, repository.deletion,
	)
	if !errors.Is(err, ErrSourceUnavailable) || repository.completeCalls != 0 {
		t.Fatalf("mismatched legacy deletion error/completions = %v/%d", err, repository.completeCalls)
	}
	for _, resultID := range []string{testResultID, testJobID} {
		if _, statErr := os.Stat(filepath.Join(root, "decompile", resultID, "source.java")); statErr != nil {
			t.Fatalf("legacy source %s was affected: %v", resultID, statErr)
		}
	}
}

func TestExportSourceProjectArchivesCanonicalDirectory(t *testing.T) {
	root := t.TempDir()
	privateTemp := t.TempDir()
	t.Setenv("TMPDIR", privateTemp)
	storageRoot := filepath.Join(root, "source-projects", testSourceProjectID)
	if err := os.MkdirAll(filepath.Join(storageRoot, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	source := []byte("void f(void) {}\n")
	manifest, err := json.MarshalIndent(nativeProjectManifest{
		SchemaVersion: "binaryscan-source-project/v1",
		ProjectID:     testSourceProjectID, LayoutVersion: SourceProjectLayoutV1,
		SourceKind: SourceProjectKindGhidraPseudoC, Language: "c",
		EngineName: "ghidra", EngineVersion: "12.1.2", Status: "complete",
		CanonicalSource: projectManifestFile{
			Path: "src/decompiled.c", SHA256: projectTestSHA(source),
			SizeBytes: uint64(len(source)),
		},
		SourceFileCount: 1, SymbolCount: 1,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifest = append(manifest, '\n')
	if err := os.WriteFile(filepath.Join(storageRoot, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(storageRoot, "src", "decompiled.c"), source, 0o600); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 10, 5, 6, 7, 0, time.UTC)
	repository := &sourceProjectRepositoryStub{record: sourceProjectRecord{
		SourceProject: SourceProject{
			ID: testSourceProjectID, TaskID: testTaskID,
			LayoutVersion: SourceProjectLayoutV1,
			SourceKind:    SourceProjectKindGhidraPseudoC, Language: "c",
			EngineName: "ghidra", EngineVersion: "12.1.2", Status: "complete",
			SourceFileCount: 1, SymbolCount: 1,
			SourceSizeBytes: uint64(len(source)), CreatedAt: createdAt,
		},
		RootStorageKey:      "source-projects/" + testSourceProjectID,
		CanonicalStorageKey: "source-projects/" + testSourceProjectID + "/src/decompiled.c",
		CanonicalSHA256:     projectTestSHA(source), CanonicalSizeBytes: uint64(len(source)),
		CanonicalSizeKnown: true,
		ManifestStorageKey: "source-projects/" + testSourceProjectID + "/manifest.json",
		ManifestSHA256:     projectTestSHA(manifest), ManifestSizeBytes: uint64(len(manifest)),
		ManifestSizeKnown: true,
	}}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := service.ExportProject(context.Background(), SourceProjectArchiveQuery{
		TaskID: testTaskID, ProjectID: testSourceProjectID,
	})
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := archive.Content.(*removingArchiveFile).File.Name()
	if filepath.Dir(temporaryPath) != privateTemp {
		t.Fatalf("temporary archive directory = %q, want %q", filepath.Dir(temporaryPath), privateTemp)
	}
	if _, err := os.Stat(temporaryPath); !os.IsNotExist(err) {
		t.Fatalf("temporary project archive was not unlinked immediately: %v", err)
	}
	defer archive.Content.Close()
	raw, err := io.ReadAll(archive.Content)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		value, readErr := io.ReadAll(opened)
		closeErr := opened.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(errors.Join(readErr, closeErr))
		}
		contents[file.Name] = string(value)
	}
	if contents["manifest.json"] != string(manifest) ||
		contents["src/decompiled.c"] != string(source) || len(contents) != 2 ||
		archive.ResultCount != 1 || archive.SHA256 != projectTestSHA(raw) {
		t.Fatalf("source project archive = %#v / %#v", archive, contents)
	}
}

func TestExportSourceProjectRejectsUndeclaredAndTamperedBytecodeFiles(t *testing.T) {
	for _, test := range []struct {
		name     string
		extra    bool
		emptyDir bool
		source   []byte
	}{
		{name: "undeclared file", extra: true, source: []byte("class A {}\n")},
		{name: "undeclared empty directory", emptyDir: true, source: []byte("class A {}\n")},
		{name: "tampered source", source: []byte("class B {}\n")},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			storageRoot := filepath.Join(root, "source-projects", testSourceProjectID)
			sourcePath := filepath.Join(storageRoot, "src", "main", "java", "A.java")
			if err := os.MkdirAll(filepath.Dir(sourcePath), 0o700); err != nil {
				t.Fatal(err)
			}
			original := []byte("class A {}\n")
			manifest, err := json.MarshalIndent(bytecodeProjectManifest{
				SchemaVersion: "binaryscan-source-project/v1",
				ProjectID:     testSourceProjectID, LayoutVersion: SourceProjectLayoutV1,
				SourceKind: SourceProjectKindJava, Language: "java",
				EngineName: "vineflower", EngineVersion: "1.11", Status: "complete",
				SourceFileCount: 1, SymbolCount: 1,
				Files: []bytecodeProjectEntry{{
					ResultID: testResultID, SymbolKey: "class:A", BinaryName: "A",
					DisplayName: "A", Language: "java", Status: "complete",
					LogicalPath: "src/main/java/A.java",
					SHA256:      projectTestSHA(original), SizeBytes: uint64(len(original)),
				}},
			}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			manifest = append(manifest, '\n')
			if err := os.WriteFile(filepath.Join(storageRoot, "manifest.json"), manifest, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sourcePath, test.source, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.extra {
				if err := os.WriteFile(filepath.Join(storageRoot, "undeclared.txt"), []byte("no"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.emptyDir {
				if err := os.Mkdir(filepath.Join(storageRoot, "undeclared"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			repository := &sourceProjectRepositoryStub{record: sourceProjectRecord{
				SourceProject: SourceProject{
					ID: testSourceProjectID, TaskID: testTaskID,
					LayoutVersion: SourceProjectLayoutV1,
					SourceKind:    SourceProjectKindJava, Language: "java",
					EngineName: "vineflower", EngineVersion: "1.11", Status: "complete",
					SourceFileCount: 1, SymbolCount: 1,
					SourceSizeBytes: uint64(len(original)), CreatedAt: time.Now(),
				},
				RootStorageKey:     "source-projects/" + testSourceProjectID,
				ManifestStorageKey: "source-projects/" + testSourceProjectID + "/manifest.json",
				ManifestSHA256:     projectTestSHA(manifest), ManifestSizeBytes: uint64(len(manifest)),
				ManifestSizeKnown: true,
			}}
			service, err := NewService(repository, Config{RepositoryRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			archive, err := service.ExportProject(context.Background(), SourceProjectArchiveQuery{
				TaskID: testTaskID, ProjectID: testSourceProjectID,
			})
			if archive.Content != nil {
				archive.Content.Close()
			}
			if !errors.Is(err, ErrSourceUnavailable) {
				t.Fatalf("ExportProject() error = %v, want source unavailable", err)
			}
		})
	}
}

func TestExportLegacySourceProjectRejectsAnotherResultsStoragePath(t *testing.T) {
	root := t.TempDir()
	source := []byte("class Other {}\n")
	repository := &sourceProjectRepositoryStub{
		record: sourceProjectRecord{SourceProject: SourceProject{
			ID: testSourceProjectID, TaskID: testTaskID,
			LayoutVersion: SourceProjectLayoutLegacyV1,
			SourceKind:    SourceProjectKindJava, Language: "java",
			EngineName: "vineflower", EngineVersion: "1.11", Status: "complete",
			SourceFileCount: 1, SymbolCount: 1,
			SourceSizeBytes: uint64(len(source)), CreatedAt: time.Now(),
		}},
		legacyEntries: []legacySourceProjectEntry{{
			Result: Result{
				ID: testResultID, SymbolKey: "class:A", DisplayName: "A",
				Language: "java", Status: "complete", CreatedAt: time.Now(),
			},
			Descriptor: SourceDescriptor{
				ResultID: testResultID, Status: "complete",
				StorageKey: "decompile/" + testJobID + "/source.java",
				SHA256:     projectTestSHA(source), SizeBytes: uint64(len(source)),
				SizeKnown: true,
			},
		}},
	}
	service, err := NewService(repository, Config{RepositoryRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := service.ExportProject(context.Background(), SourceProjectArchiveQuery{
		TaskID: testTaskID, ProjectID: testSourceProjectID,
	})
	if archive.Content != nil {
		archive.Content.Close()
	}
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("ExportProject() error = %v, want source unavailable", err)
	}
}

func projectTestSHA(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
