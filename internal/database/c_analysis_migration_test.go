package database

import (
	"strings"
	"testing"

	"binaryscan/db/migrations"
)

func TestCAnalysisMigrationIsBoundedFencedAndReversible(t *testing.T) {
	raw, err := migrations.FS.ReadFile("00029_c_analysis_domain.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatalf("C analysis migration sections = %d", len(sections))
	}
	up, down := sections[0], sections[1]
	for _, fragment := range []string{
		"'c_analysis'",
		"CREATE TABLE IF NOT EXISTS c_analysis_runs",
		"CREATE TABLE IF NOT EXISTS c_analysis_findings",
		"REFERENCES analyzer_runs (task_id, id) ON DELETE CASCADE",
		"REFERENCES decompile_source_projects (task_id, id) ON DELETE CASCADE",
		"uq_c_analysis_runs_active_project",
		") VIRTUAL",
		"deletion_started_at TIMESTAMP(6) NULL",
		"chk_c_analysis_runs_deletion",
		"source_size_bytes <= 134217728",
		"total_functions <= 3000",
		"finding_count <= 10000",
		"diagnostic_count <= 1000",
		"OCTET_LENGTH(snippet) <= 1024",
		"'cwe-327-328-weak-crypto'",
		"worker_kind = 'c_analysis' AND analyzer_name = 'binaryscan-c-checker'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("C analysis up migration lacks %q", fragment)
		}
	}
	for _, fragment := range []string{
		"DROP TABLE IF EXISTS c_analysis_findings",
		"DROP TABLE IF EXISTS c_analysis_runs",
		"DELETE FROM worker_readiness WHERE worker_kind = 'c_analysis'",
		"DELETE FROM jobs WHERE kind = 'c_analysis'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("C analysis down migration lacks %q", fragment)
		}
	}
}
