package decompile

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryListsSourceProjectsNewestFirst(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	createdAt := time.Date(2026, 8, 10, 1, 2, 3, 0, time.UTC)
	completedAt := createdAt.Add(time.Minute)
	mock.ExpectBegin()
	expectTaskExists(mock, testTaskID)
	mock.ExpectQuery(`(?s)SELECT project.id, project.task_id.*FROM decompile_source_projects project.*JOIN file_nodes node.*project.task_id = \? AND project.deleted_at IS NULL.*ORDER BY project.created_at DESC, project.id DESC.*LIMIT \?`).
		WithArgs(testTaskID, 2).
		WillReturnRows(sourceProjectRows().
			AddRow(
				testSourceProjectID, testTaskID, testJobID, uint64(42),
				"bin/app", SourceProjectLayoutV1,
				SourceProjectKindGhidraPseudoC, "ghidra-pseudoc", "ghidra",
				"11.4", "complete", uint64(1), uint64(18), uint64(4096),
				createdAt, completedAt,
				"source-projects/"+testSourceProjectID,
				"source-projects/"+testSourceProjectID+"/src/decompiled.c",
				strings.Repeat("a", 64), uint64(4096),
				"source-projects/"+testSourceProjectID+"/manifest.json",
				strings.Repeat("b", 64), uint64(512), nil, nil,
			).
			AddRow(
				testResultID, testTaskID, nil, uint64(43), "classes/app.jar",
				SourceProjectLayoutLegacyV1, SourceProjectKindJava, "java",
				"vineflower", "1.11", "partial", uint64(2), uint64(3),
				uint64(2048), createdAt.Add(-time.Minute), completedAt,
				nil, nil, nil, nil, nil, nil, nil, nil, nil,
			))
	mock.ExpectCommit()

	page, err := repository.ListSourceProjects(
		context.Background(),
		SourceProjectListQuery{TaskID: testTaskID, PageSize: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || !page.HasMore {
		t.Fatalf("source project page = %#v", page)
	}
	project := page.Items[0]
	if project.ID != testSourceProjectID || project.FileNodeID != "42" ||
		project.TargetPath != "bin/app" ||
		project.CanonicalFilename != "decompiled.c" ||
		!project.ManifestAvailable || project.SymbolCount != 18 ||
		project.CompletedAt == nil || !project.CompletedAt.Equal(completedAt) {
		t.Fatalf("source project = %#v", project)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestInsertPublishedSourceProjectUsesAnalyzerRunAsProjectID(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	project := PublishedSourceProject{
		ID: testSourceProjectID, LayoutVersion: SourceProjectLayoutV1,
		SourceKind: SourceProjectKindGhidraPseudoC, Language: "ghidra-pseudoc",
		RootStorageKey:      "source-projects/" + testSourceProjectID,
		CanonicalStorageKey: "source-projects/" + testSourceProjectID + "/src/decompiled.c",
		CanonicalSHA256:     strings.Repeat("a", 64), CanonicalSizeBytes: 4096,
		ManifestStorageKey: "source-projects/" + testSourceProjectID + "/manifest.json",
		ManifestSHA256:     strings.Repeat("b", 64), ManifestSizeBytes: 512,
		SourceFileCount: 1, SymbolCount: 18, SourceSizeBytes: 4096,
	}
	mock.ExpectExec(`(?s)INSERT INTO decompile_source_projects`).
		WithArgs(
			testSourceProjectID, testTaskID, uint64(42), testJobID,
			SourceProjectLayoutV1, SourceProjectKindGhidraPseudoC,
			"ghidra-pseudoc", "ghidra", "11.4", "complete",
			project.RootStorageKey, project.CanonicalStorageKey,
			project.CanonicalSHA256, project.CanonicalSizeBytes,
			project.ManifestStorageKey, project.ManifestSHA256,
			project.ManifestSizeBytes, project.SourceFileCount,
			project.SymbolCount, project.SourceSizeBytes,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := insertPublishedSourceProject(
		context.Background(), tx, testTaskID, 42, testJobID,
		"ghidra", "11.4", "complete", project,
	); err != nil {
		t.Fatal(err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func sourceProjectRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "task_id", "job_id", "file_node_id", "logical_path",
		"layout_version", "source_kind", "language", "engine_name",
		"engine_version", "status", "source_file_count", "symbol_count",
		"source_size_bytes", "created_at", "completed_at", "root_storage_key",
		"canonical_storage_key", "canonical_sha256", "canonical_size_bytes",
		"manifest_storage_key", "manifest_sha256", "manifest_size_bytes",
		"deleted_at", "storage_deleted_at",
	})
}
