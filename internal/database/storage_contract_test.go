package database

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"binaryscan/db/migrations"
)

var createTablePattern = regexp.MustCompile(
	`(?is)CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)\s*\((.*?)\)\s*ENGINE=`,
)

func TestStorageSchemaKeepsLargePayloadsOutsideMySQL(t *testing.T) {
	tables := migrationCreateTables(t)
	for tableName, definition := range tables {
		for _, line := range strings.Split(definition, "\n") {
			fields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(line, ",")))
			if len(fields) < 2 || isTableConstraint(fields[0]) {
				continue
			}
			columnType := strings.ToUpper(strings.Trim(fields[1], "`"))
			columnType, _, _ = strings.Cut(columnType, "(")
			if tableName == "trivy_database_bundles" &&
				strings.Trim(fields[0], "`") == "manifest_json" {
				continue
			}
			switch columnType {
			case "BLOB", "TINYBLOB", "MEDIUMBLOB", "LONGBLOB",
				"TEXT", "TINYTEXT", "MEDIUMTEXT", "LONGTEXT":
				t.Errorf(
					"table %s stores unbounded payload type %s; use a storage key instead",
					tableName, columnType,
				)
			}
		}
	}

	referenceContracts := map[string][]string{
		"blobs":             {"storage_key", "sha256", "size_bytes"},
		"upload_parts":      {"storage_key", "sha256", "size_bytes"},
		"file_nodes":        {"storage_key", "sha256", "size_bytes"},
		"decompile_results": {"storage_key", "content_sha256", "size_bytes"},
		"decompile_source_projects": {
			"root_storage_key", "manifest_storage_key", "manifest_sha256",
			"manifest_size_bytes",
		},
		"artifacts": {"storage_key", "sha256", "size_bytes"},
		"reports":   {"storage_key", "sha256", "size_bytes"},
	}
	for tableName, requiredColumns := range referenceContracts {
		definition, exists := tables[tableName]
		if !exists {
			t.Errorf("storage reference table %s is missing", tableName)
			continue
		}
		columns := tableColumns(definition)
		for _, column := range requiredColumns {
			if _, exists := columns[column]; !exists {
				t.Errorf("table %s is missing storage reference column %s", tableName, column)
			}
		}
		for _, forbidden := range []string{
			"body", "bytes", "content", "file_data", "payload_data", "source_code",
		} {
			if _, exists := columns[forbidden]; exists {
				t.Errorf(
					"table %s contains inline large-payload column %s",
					tableName, forbidden,
				)
			}
		}
	}
}

func migrationCreateTables(t *testing.T) map[string]string {
	t.Helper()
	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	sort.Strings(files)
	tables := make(map[string]string)
	for _, name := range files {
		content, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read embedded migration %s: %v", name, err)
		}
		for _, match := range createTablePattern.FindAllStringSubmatch(string(content), -1) {
			tables[strings.ToLower(match[1])] = match[2]
		}
	}
	return tables
}

func tableColumns(definition string) map[string]struct{} {
	columns := make(map[string]struct{})
	for _, line := range strings.Split(definition, "\n") {
		fields := strings.Fields(strings.TrimSpace(strings.TrimSuffix(line, ",")))
		if len(fields) < 2 || isTableConstraint(fields[0]) {
			continue
		}
		columns[strings.ToLower(strings.Trim(fields[0], "`"))] = struct{}{}
	}
	return columns
}

func isTableConstraint(firstField string) bool {
	switch strings.ToUpper(strings.Trim(firstField, "`")) {
	case "PRIMARY", "UNIQUE", "KEY", "CONSTRAINT", "CHECK", "FOREIGN":
		return true
	default:
		return false
	}
}
