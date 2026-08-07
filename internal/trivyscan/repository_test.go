package trivyscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	trivyadapter "binaryscan/internal/analyzers/trivy"
	"binaryscan/internal/queue"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMySQLRepositoryPublishesProvenanceRawFindingAndRiskAtomically(t *testing.T) {
	repository, mock, roots := newRepositoryFixture(t)
	lease := repositoryLease()
	publication := repositoryPublication(t, roots.taskWork)
	run := publication.Runs[0]
	runID := expectedRunID(lease, run)
	artifactID := stableUUID(
		"binaryscan.trivy.artifact.v1",
		lease.TaskID,
		"71",
		runID,
	)
	expectFreshPublication(
		t,
		mock,
		lease,
		publication,
		runID,
		artifactID,
	)

	summary, err := repository.PublishWithSummary(
		context.Background(),
		lease,
		publication,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Succeeded != 1 || summary.Failed != 0 {
		t.Fatalf("replay summary = %+v", summary)
	}
	storageKey := rawArtifactStorageKey(lease.TaskID, 71, runID)
	content, err := os.ReadFile(filepath.Join(
		roots.repository,
		filepath.FromSlash(storageKey),
	))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != run.Raw.SHA256 ||
		int64(len(content)) != run.Raw.SizeBytes {
		t.Fatal("published raw artifact does not match bounded metadata")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryReplayReusesCompletedRunWithoutDuplicates(t *testing.T) {
	repository, mock, roots := newRepositoryFixture(t)
	lease := repositoryLease()
	publication := repositoryPublication(t, roots.taskWork)
	run := publication.Runs[0]
	runID := expectedRunID(lease, run)
	artifactID := stableUUID(
		"binaryscan.trivy.artifact.v1",
		lease.TaskID,
		"71",
		runID,
	)
	expectFreshPublication(t, mock, lease, publication, runID, artifactID)
	summary, err := repository.PublishWithSummary(
		context.Background(),
		lease,
		publication,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Succeeded != 1 || summary.Failed != 0 {
		t.Fatalf("replay summary = %+v", summary)
	}

	parameters, err := publication.parameters(run)
	if err != nil {
		t.Fatal(err)
	}
	storageKey := rawArtifactStorageKey(lease.TaskID, 71, runID)
	mock.ExpectBegin()
	expectLeaseLock(mock, lease)
	expectExistingBundle(mock, publication)
	mock.ExpectQuery(`SELECT task_id, task_attempt_id, job_id, analyzer_name, analyzer_version,`).
		WithArgs(runID).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "job_id", "analyzer_name",
			"analyzer_version", "parameters_json", "status",
		}).AddRow(
			lease.TaskID,
			71,
			lease.JobID,
			AnalyzerName,
			publication.AnalyzerVersion,
			[]byte(parameters),
			"succeeded",
		))
	mock.ExpectQuery(`SELECT id, storage_key, sha256, size_bytes, state, deleted_at`).
		WithArgs(lease.TaskID, runID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "storage_key", "sha256", "size_bytes", "state", "deleted_at",
		}).AddRow(
			artifactID,
			storageKey,
			run.Raw.SHA256,
			run.Raw.SizeBytes,
			"published",
			nil,
		))
	mock.ExpectQuery(`SELECT COUNT\(\*\), COALESCE\(SUM\(`).
		WithArgs(publication.Snapshot.Bundle.ID, lease.TaskID, runID).
		WillReturnRows(sqlmock.NewRows([]string{
			"finding_count", "matched_database_count",
		}).AddRow(1, 1))
	expectRiskAndRevalidation(mock, lease)
	mock.ExpectCommit()

	summary, err = repository.PublishWithSummary(
		context.Background(),
		lease,
		publication,
	)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Succeeded != 1 || summary.Failed != 0 {
		t.Fatalf("completed replay summary = %+v", summary)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLRepositoryDoesNotPublishAfterLeaseLoss(t *testing.T) {
	repository, mock, roots := newRepositoryFixture(t)
	lease := repositoryLease()
	publication := repositoryPublication(t, roots.taskWork)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT job.task_attempt_id, attempt.fencing_token, task.status`).
		WithArgs(
			lease.JobID,
			lease.TaskID,
			lease.Owner,
			lease.FencingToken,
			lease.FencingToken,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_attempt_id", "fencing_token", "status",
		}))
	mock.ExpectRollback()

	err := repository.Publish(context.Background(), lease, publication)
	if !errors.Is(err, queue.ErrLeaseLost) {
		t.Fatalf("Publish() error = %v", err)
	}
	artifactRoot := filepath.Join(roots.repository, "artifacts")
	if _, err := os.Stat(artifactRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lease loss published an artifact: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryAcceptsConfigured256MiBReportLimitAndRejectsSymlinkRaw(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	root := t.TempDir()
	repositoryRoot := filepath.Join(root, "repository")
	workRoot := filepath.Join(root, "work")
	if err := os.Mkdir(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMySQLRepository(
		db,
		repositoryRoot,
		workRoot,
		256<<20,
	); err != nil {
		t.Fatalf("256 MiB limit rejected: %v", err)
	}
	target := filepath.Join(workRoot, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workRoot, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openConfinedRegular(workRoot, link, true); err == nil {
		t.Fatal("raw report leaf symlink was accepted")
	}
}

func TestRunParametersRecordExactPrimaryJavaDBToolAndOfflineMode(t *testing.T) {
	root := t.TempDir()
	publication := repositoryPublication(t, root)
	raw, err := publication.parameters(publication.Runs[0])
	if err != nil {
		t.Fatal(err)
	}
	var parameters runParameters
	if err := json.Unmarshal(raw, &parameters); err != nil {
		t.Fatal(err)
	}
	if parameters.Analyzer.Name != AnalyzerName ||
		parameters.Analyzer.Version != "0.72.0" ||
		parameters.TrivyDB.ID != publication.Snapshot.Trivy.ID ||
		parameters.JavaDB == nil ||
		parameters.JavaDB.ID != publication.Snapshot.Java.ID ||
		parameters.Scanner != "vuln" ||
		!parameters.Offline ||
		parameters.CacheBackend != "memory" ||
		parameters.RawArtifact == nil ||
		parameters.RawArtifact.SHA256 != publication.Runs[0].Raw.SHA256 {
		t.Fatalf("parameters = %+v", parameters)
	}
}

type repositoryRoots struct {
	repository string
	taskWork   string
}

func newRepositoryFixture(
	t *testing.T,
) (*MySQLRepository, sqlmock.Sqlmock, repositoryRoots) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	roots := repositoryRoots{
		repository: filepath.Join(root, "repository"),
		taskWork:   filepath.Join(root, "task-work"),
	}
	if err := os.Mkdir(roots.repository, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(roots.taskWork, 0o700); err != nil {
		t.Fatal(err)
	}
	repository, err := NewMySQLRepository(
		db,
		roots.repository,
		roots.taskWork,
		256<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	return repository, mock, roots
}

func repositoryLease() queue.Lease {
	attemptID := uint64(71)
	return queue.Lease{
		JobID:         "123e4567-e89b-42d3-a456-000000000001",
		TaskID:        "123e4567-e89b-42d3-a456-000000000002",
		TaskAttemptID: &attemptID,
		Kind:          queue.KindTrivy,
		Attempt:       1,
		MaxAttempts:   3,
		FencingToken:  99,
		Owner:         "trivy-test",
		LeaseUntil:    time.Now().Add(time.Minute),
	}
}

func repositoryPublication(t *testing.T, taskWorkRoot string) Publication {
	t.Helper()
	raw := []byte(`{"SchemaVersion":2,"ArtifactName":"fixture",` +
		`"ArtifactType":"container_image","Results":[]}`)
	rawDirectory := filepath.Join(taskWorkRoot, "job", "output")
	if err := os.MkdirAll(rawDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(rawDirectory, "trivy-result.json")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	sourceHash := stringsOf("a", 64)
	started := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	return Publication{
		AnalyzerVersion:  "0.72.0",
		SourceFormat:     "docker-tar",
		SourceSHA256:     sourceHash,
		SourceStorageKey: "blobs/sha256/aa/" + sourceHash,
		StartedAt:        started,
		CompletedAt:      started.Add(time.Second),
		Snapshot:         testSnapshot(),
		Runs: []RunResult{{
			TargetKey:        "docker:" + sourceHash,
			ImageLogicalPath: "/",
			Platform:         "linux/amd64",
			References:       []string{"fixture:latest"},
			Status:           "succeeded",
			Raw: &trivyadapter.RawReportMetadata{
				Path:          rawPath,
				SHA256:        hex.EncodeToString(hash[:]),
				SizeBytes:     int64(len(raw)),
				SchemaVersion: 2,
				ArtifactName:  "fixture",
				ArtifactType:  "container_image",
				ResultCount:   1,
				FindingCount:  1,
			},
			Findings: []trivyadapter.Finding{{
				VulnerabilityID:    "CVE-2026-0001",
				Severity:           "CRITICAL",
				PackageName:        "libfixture",
				PackagePath:        "usr/lib/libfixture.so",
				InstalledVersion:   "1.0.0",
				FixedVersion:       "1.0.1",
				Title:              "Fixture advisory",
				DescriptionSummary: "A bounded advisory summary.",
				Target:             "alpine 3.20",
				Class:              "os-pkgs",
				Type:               "alpine",
				DataSource: trivyadapter.DataSource{
					ID: "alpine", Name: "Alpine SecDB",
					URL: "https://secdb.alpinelinux.org/",
				},
				References: []string{
					"https://avd.aquasec.com/nvd/cve-2026-0001",
					"https://security.alpinelinux.org/vuln/CVE-2026-0001",
				},
			}},
		}},
	}
}

func expectedRunID(lease queue.Lease, run RunResult) string {
	return stableUUID(
		"binaryscan.trivy.run.v1",
		lease.TaskID,
		"71",
		lease.JobID,
		run.TargetKey,
	)
}

func expectFreshPublication(
	t *testing.T,
	mock sqlmock.Sqlmock,
	lease queue.Lease,
	publication Publication,
	runID string,
	artifactID string,
) {
	t.Helper()
	mock.ExpectBegin()
	expectLeaseLock(mock, lease)
	expectNewBundle(mock, publication)
	mock.ExpectQuery(`SELECT task_id, task_attempt_id, job_id, analyzer_name, analyzer_version,`).
		WithArgs(runID).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_id", "task_attempt_id", "job_id", "analyzer_name",
			"analyzer_version", "parameters_json", "status",
		}))
	mock.ExpectExec(`INSERT INTO analyzer_runs`).
		WithArgs(
			runID,
			lease.TaskID,
			uint64(71),
			lease.JobID,
			publication.AnalyzerVersion,
			sqlmock.AnyArg(),
			"succeeded",
			0,
			"",
			"",
			publication.StartedAt,
			publication.CompletedAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT id, storage_key, sha256, size_bytes, state, deleted_at`).
		WithArgs(lease.TaskID, runID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "storage_key", "sha256", "size_bytes", "state", "deleted_at",
		}))
	run := publication.Runs[0]
	finding := run.Findings[0]
	dataSource := finding.DataSource
	evidence, err := json.Marshal(findingEvidence{
		PackageName:      finding.PackageName,
		InstalledVersion: finding.InstalledVersion,
		FixedVersion:     finding.FixedVersion,
		PackagePath:      finding.PackagePath,
		Target:           finding.Target,
		Class:            finding.Class,
		Type:             finding.Type,
		ImageLogicalPath: run.ImageLogicalPath,
		ImagePlatform:    run.Platform,
		ImageReferences:  run.References,
		ManifestDigest:   run.ManifestDigest,
		DataSource:       &dataSource,
	})
	if err != nil {
		t.Fatal(err)
	}
	references, err := json.Marshal(finding.References)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`INSERT INTO artifacts`).
		WithArgs(
			artifactID,
			lease.TaskID,
			uint64(71),
			runID,
			rawArtifactStorageKey(lease.TaskID, 71, runID),
			run.Raw.SHA256,
			run.Raw.SizeBytes,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`DELETE FROM vulnerability_findings`).
		WithArgs(lease.TaskID, runID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	prepared := mock.ExpectPrepare(`INSERT INTO vulnerability_findings`).
		WillBeClosed()
	prepared.ExpectExec().
		WithArgs(
			lease.TaskID,
			runID,
			publication.Snapshot.Bundle.ID,
			"/",
			"linux/amd64",
			"CVE-2026-0001",
			"CRITICAL",
			"libfixture",
			"1.0.0",
			"1.0.1",
			"Fixture advisory",
			"A bounded advisory summary.",
			evidence,
			references,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	expectRiskAndRevalidation(mock, lease)
	mock.ExpectCommit()
}

func expectNewBundle(mock sqlmock.Sqlmock, publication Publication) {
	snapshot := publication.Snapshot
	mock.ExpectQuery(`(?s)SELECT version, generated_at, content_sha256, trivy_db_version,.*FROM trivy_database_bundles.*FOR UPDATE`).
		WithArgs(snapshot.Bundle.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"version", "generated_at", "content_sha256", "trivy_db_version",
			"trivy_java_db_version", "manifest_json",
		}))
	mock.ExpectExec(`INSERT INTO trivy_database_bundles`).
		WithArgs(
			snapshot.Bundle.ID, snapshot.Bundle.Version,
			snapshot.Bundle.GeneratedAt, snapshot.Bundle.ContentSHA256,
			snapshot.Trivy.Version, snapshot.Java.Version,
			snapshot.Bundle.ManifestJSON,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
}

func expectExistingBundle(mock sqlmock.Sqlmock, publication Publication) {
	snapshot := publication.Snapshot
	mock.ExpectQuery(`(?s)SELECT version, generated_at, content_sha256, trivy_db_version,.*FROM trivy_database_bundles.*FOR UPDATE`).
		WithArgs(snapshot.Bundle.ID).
		WillReturnRows(sqlmock.NewRows([]string{
			"version", "generated_at", "content_sha256", "trivy_db_version",
			"trivy_java_db_version", "manifest_json",
		}).AddRow(
			snapshot.Bundle.Version, snapshot.Bundle.GeneratedAt,
			snapshot.Bundle.ContentSHA256, snapshot.Trivy.Version,
			snapshot.Java.Version, snapshot.Bundle.ManifestJSON,
		))
}

func expectLeaseLock(mock sqlmock.Sqlmock, lease queue.Lease) {
	mock.ExpectQuery(`SELECT job.task_attempt_id, attempt.fencing_token, task.status`).
		WithArgs(
			lease.JobID,
			lease.TaskID,
			lease.Owner,
			lease.FencingToken,
			lease.FencingToken,
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"task_attempt_id", "fencing_token", "status",
		}).AddRow(71, lease.FencingToken, "REPORTING"))
}

func expectRiskAndRevalidation(mock sqlmock.Sqlmock, lease queue.Lease) {
	mock.ExpectExec(`UPDATE tasks\s+SET risk_level = \(`).
		WithArgs(lease.TaskID, lease.TaskID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT 1\s+FROM jobs job`).
		WithArgs(
			lease.JobID,
			lease.TaskID,
			uint64(71),
			lease.Owner,
			lease.FencingToken,
			lease.FencingToken,
		).
		WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(1))
}

func stringsOf(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
