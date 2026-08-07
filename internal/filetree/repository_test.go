package filetree

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryListRootUsesStableCursorAndLookahead(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*WHERE id = \?.*LIMIT 1`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(
		`(?s)SELECT n\.id.*EXISTS \(.*child\.task_id = n\.task_id AND child\.parent_id = n\.id.*`+
			`WHERE n\.task_id = \? AND n\.parent_id IS NULL AND n\.id > \?.*`+
			`ORDER BY n\.id ASC.*LIMIT \?`,
	).
		WithArgs(testTaskID, uint64(0), 3).
		WillReturnRows(fileNodeRows().
			AddRow(uint64(11), nil, "/", "sample.tar", nil, "file", 0, "tar",
				"application/x-tar", nil, uint64(4096), hash("a"), "extracted",
				nil, nil, nil, nil, nil, true).
			AddRow(uint64(12), nil, "/other", "other", nil, "file", 0, nil,
				nil, nil, nil, nil, "indexed", nil, nil, nil, nil, nil, false).
			AddRow(uint64(13), nil, "/third", "third", nil, "file", 0, nil,
				nil, nil, uint64(3), hash("b"), "indexed", nil, nil,
				nil, nil, nil, false))
	mock.ExpectCommit()

	page, err := repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 2,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 2 || page.NextCursor != "12" {
		t.Fatalf("List() page = %#v", page)
	}
	root := page.Items[0]
	if root.ID != "11" || root.ParentID != nil || root.Format != "tar" ||
		root.Architecture != "" || root.SizeBytes == nil || *root.SizeBytes != 4096 ||
		!root.HasChildren || root.ErrorCode != "" {
		t.Fatalf("root node = %#v", root)
	}
	if page.Items[1].SizeBytes != nil || page.Items[1].SHA256 != "" {
		t.Fatalf("nullable node fields = %#v", page.Items[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListDirectChildrenChecksParentOwnership(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	parent := uint64(41)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*WHERE id = \?.*LIMIT 1`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM file_nodes.*WHERE task_id = \? AND id = \?.*LIMIT 1`).
		WithArgs(testTaskID, parent).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(
		`(?s)SELECT n\.id.*WHERE n\.task_id = \? AND n\.parent_id = \? AND n\.id > \?.*`+
			`ORDER BY n\.id ASC.*LIMIT \?`,
	).
		WithArgs(testTaskID, parent, uint64(50), 101).
		WillReturnRows(fileNodeRows().
			AddRow(uint64(51), parent, "/bin/app", "app", "b64:YXBw", "file", 1, "elf64",
				"application/x-elf", "x86_64", uint64(8192), hash("c"),
				"failed", "corrupt_binary", "truncated",
				uint64(1), "/", "tar", false))
	mock.ExpectCommit()

	page, err := repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, ParentID: &parent, Cursor: 50, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Items) != 1 || page.NextCursor != "" {
		t.Fatalf("List() page = %#v", page)
	}
	node := page.Items[0]
	if node.ParentID == nil || *node.ParentID != "41" ||
		node.Architecture != "x86_64" || node.ErrorCode != "corrupt_binary" ||
		node.ErrorMessage != "truncated" || node.ArchiveNameID != "b64:YXBw" ||
		node.SourceContainer == nil || node.SourceContainer.ID != "1" ||
		node.SourceContainer.LogicalPath != "/" ||
		node.SourceContainer.Format != "tar" {
		t.Fatalf("child node = %#v", node)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryPreservesUnsignedBIGINTNodeIDs(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	queryParent := uint64(1)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT 1.*FROM file_nodes`).
		WithArgs(testTaskID, queryParent).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*n\.parent_id = \?.*ORDER BY n\.id ASC`).
		WithArgs(testTaskID, queryParent, uint64(0), 2).
		WillReturnRows(fileNodeRows().AddRow(
			"18446744073709551615", "18446744073709551614",
			"/large-id", "large-id", nil, "file", 1,
			nil, nil, nil, uint64(1), nil, "indexed", nil, nil,
			uint64(1), "/", "zip", false,
		))
	mock.ExpectCommit()

	page, err := repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, ParentID: &queryParent, PageSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 ||
		page.Items[0].ID != "18446744073709551615" ||
		page.Items[0].ParentID == nil ||
		*page.Items[0].ParentID != "18446744073709551614" {
		t.Fatalf("unsigned BIGINT node = %#v", page.Items)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryRejectsNodeSizeOutsideAPIContract(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \?`).
		WithArgs(testTaskID, uint64(0), 2).
		WillReturnRows(fileNodeRows().AddRow(
			uint64(11), nil, "/", "sample.tar", nil, "file", 0,
			"tar", "application/x-tar", nil, maxFileNodeSizeBytes+1,
			nil, "extracted", nil, nil, nil, nil, nil, false,
		))
	mock.ExpectRollback()

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "size is outside accepted bounds") {
		t.Fatalf("List() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryRejectsIncompleteSourceContainerRelation(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \?`).
		WithArgs(testTaskID, uint64(0), 2).
		WillReturnRows(fileNodeRows().AddRow(
			uint64(11), nil, "/entry", "entry", nil, "file", 1,
			"elf64", "application/x-elf", nil, uint64(1),
			nil, "indexed", nil, nil, uint64(1), nil, "zip", false,
		))
	mock.ExpectRollback()

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 1,
	})
	if err == nil || !strings.Contains(
		err.Error(),
		"source container is inconsistent",
	) {
		t.Fatalf("List() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryListMapsMissingTaskOrParent(t *testing.T) {
	t.Run("task", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*WHERE id = \?.*LIMIT 1`).
			WithArgs(testTaskID).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		_, err = repository.List(context.Background(), ListQuery{
			TaskID: testTaskID, PageSize: 100,
		})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("List() error = %v, want ErrNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("parent from another task", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		parent := uint64(9)
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*WHERE id = \?.*LIMIT 1`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
		mock.ExpectQuery(`(?s)SELECT 1.*FROM file_nodes.*WHERE task_id = \? AND id = \?.*LIMIT 1`).
			WithArgs(testTaskID, parent).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		_, err = repository.List(context.Background(), ListQuery{
			TaskID: testTaskID, ParentID: &parent, PageSize: 100,
		})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("List() error = %v, want ErrNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMySQLRepositoryListWrapsDatabaseFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	privateError := errors.New("database unavailable")
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WillReturnError(privateError)
	mock.ExpectRollback()

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 100,
	})
	if !errors.Is(err, privateError) {
		t.Fatalf("List() error = %v, want wrapped private error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListRollsBackListQueryFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	privateError := errors.New("file nodes unavailable")

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \?`).
		WithArgs(testTaskID, uint64(0), 101).
		WillReturnError(privateError)
	mock.ExpectRollback()

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 100,
	})
	if !errors.Is(err, privateError) {
		t.Fatalf("List() error = %v, want wrapped private error", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListReportsRollbackFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	rollbackError := errors.New("rollback unavailable")

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback().WillReturnError(rollbackError)

	_, err = repository.List(context.Background(), ListQuery{
		TaskID: testTaskID, PageSize: 100,
	})
	if !errors.Is(err, ErrNotFound) || !errors.Is(err, rollbackError) {
		t.Fatalf(
			"List() error = %v, want joined ErrNotFound and rollback error",
			err,
		)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %v", err)
	}
}

func TestMySQLRepositoryListReportsTransactionFailures(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		beginError := errors.New("begin unavailable")
		mock.ExpectBegin().WillReturnError(beginError)

		_, err = repository.List(context.Background(), ListQuery{
			TaskID: testTaskID, PageSize: 100,
		})
		if !errors.Is(err, beginError) {
			t.Fatalf("List() error = %v, want wrapped begin error", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
	})

	t.Run("commit", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		commitError := errors.New("commit unavailable")

		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
		mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \?`).
			WithArgs(testTaskID, uint64(0), 101).
			WillReturnRows(fileNodeRows())
		mock.ExpectCommit().WillReturnError(commitError)

		_, err = repository.List(context.Background(), ListQuery{
			TaskID: testTaskID, PageSize: 100,
		})
		if !errors.Is(err, commitError) {
			t.Fatalf("List() error = %v, want wrapped commit error", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet SQL expectations: %v", err)
		}
	})
}

func TestMySQLRepositoryGetReturnsStructuredMetadataAndSourceParent(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks.*WHERE id = \?.*deleted_at IS NULL`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(
		`(?s)SELECT n\.id.*n\.metadata_json, parent\.logical_path.*`+
			`LEFT JOIN file_nodes parent.*WHERE n\.task_id = \? AND n\.id = \?.*LIMIT 1`,
	).
		WithArgs(testTaskID, uint64(51)).
		WillReturnRows(fileDetailRows().AddRow(
			uint64(51), uint64(41), "/bin/app", "app", "b64:YXBw", "file", 2,
			"elf64", "application/x-elf", "x86_64", uint64(8192), hash("a"),
			"indexed", nil, nil, uint64(1), "/", "tar", true,
			`{"detection":{"compiler":"gcc"},"identification_candidates":[{"format":"elf64","category":"executable","mime_type":"application/x-elf","evidence":"elf_header_and_bounded_program_tables"}]}`, "/bin",
		))
	mock.ExpectCommit()

	detail, err := repository.Get(context.Background(), GetQuery{
		TaskID: testTaskID,
		FileID: 51,
	})
	if err != nil {
		t.Fatal(err)
	}
	if detail.ID != "51" || detail.ParentID == nil ||
		*detail.ParentID != "41" || detail.SourceParent == nil ||
		detail.SourceParent.ID != "41" ||
		detail.SourceParent.LogicalPath != "/bin" ||
		detail.ArchiveNameID != "b64:YXBw" ||
		detail.SourceContainer == nil ||
		detail.SourceContainer.ID != "1" ||
		detail.SourceContainer.LogicalPath != "/" ||
		detail.SourceContainer.Format != "tar" ||
		string(detail.MetadataJSON) !=
			`{"detection":{"compiler":"gcc"},"identification_candidates":[{"format":"elf64","category":"executable","mime_type":"application/x-elf","evidence":"elf_header_and_bounded_program_tables"}]}` ||
		!detail.HasChildren {
		t.Fatalf("Get() detail = %#v", detail)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryGetRootUsesNullMetadataAndSourceParent(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \? AND n\.id = \?`).
		WithArgs(testTaskID, uint64(1)).
		WillReturnRows(fileDetailRows().AddRow(
			uint64(1), nil, "/", "root", nil, "file", 0,
			nil, nil, nil, nil, nil, "indexed", nil, nil,
			nil, nil, nil, false,
			nil, nil,
		))
	mock.ExpectCommit()

	detail, err := repository.Get(context.Background(), GetQuery{
		TaskID: testTaskID,
		FileID: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if detail.ParentID != nil || detail.SourceParent != nil ||
		detail.SourceContainer != nil ||
		string(detail.MetadataJSON) != "null" {
		t.Fatalf("Get() root detail = %#v", detail)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryGetDistinguishesMissingTaskAndNode(t *testing.T) {
	t.Run("task", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
			WithArgs(testTaskID).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		_, err = repository.Get(context.Background(), GetQuery{
			TaskID: testTaskID,
			FileID: 51,
		})
		if !errors.Is(err, ErrTaskNotFound) {
			t.Fatalf("Get() error = %v, want ErrTaskNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("node", func(t *testing.T) {
		database, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		repository := NewMySQLRepository(database)
		mock.ExpectBegin()
		mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
			WithArgs(testTaskID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
		mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \? AND n\.id = \?`).
			WithArgs(testTaskID, uint64(51)).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		_, err = repository.Get(context.Background(), GetQuery{
			TaskID: testTaskID,
			FileID: 51,
		})
		if !errors.Is(err, ErrNodeNotFound) {
			t.Fatalf("Get() error = %v, want ErrNodeNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMySQLRepositoryGetRejectsInvalidMetadata(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := NewMySQLRepository(database)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT 1.*FROM tasks`).
		WithArgs(testTaskID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(1))
	mock.ExpectQuery(`(?s)SELECT n\.id.*WHERE n\.task_id = \? AND n\.id = \?`).
		WithArgs(testTaskID, uint64(51)).
		WillReturnRows(fileDetailRows().AddRow(
			uint64(51), nil, "/bad", "bad", nil, "file", 0,
			nil, nil, nil, nil, nil, "indexed", nil, nil,
			nil, nil, nil, false,
			`{"broken"`, nil,
		))
	mock.ExpectRollback()

	_, err = repository.Get(context.Background(), GetQuery{
		TaskID: testTaskID,
		FileID: 51,
	})
	if err == nil || !strings.Contains(err.Error(), "metadata is not valid JSON") {
		t.Fatalf("Get() error = %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func fileNodeRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "parent_id", "logical_path", "display_name", "archive_name_id", "node_type",
		"depth", "format", "mime_type", "architecture", "size_bytes",
		"sha256", "extraction_status", "error_code", "error_message",
		"source_id", "source_logical_path", "source_format",
		"has_children",
	})
}

func fileDetailRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "parent_id", "logical_path", "display_name", "archive_name_id", "node_type",
		"depth", "format", "mime_type", "architecture", "size_bytes",
		"sha256", "extraction_status", "error_code", "error_message",
		"source_id", "source_logical_path", "source_format",
		"has_children", "metadata_json", "parent_logical_path",
	})
}

func hash(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value[:64]
}
