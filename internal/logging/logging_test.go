package logging

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewWritesJSONLogFile(t *testing.T) {
	dir := t.TempDir()
	logger, closer, err := New("api", "debug", dir)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("started", "request_id", "test-request")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("log files = %d, want 1", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"service":"api"`) || !strings.Contains(string(raw), `"request_id":"test-request"`) {
		t.Fatalf("unexpected log entry: %s", raw)
	}
}

func TestNewRedactsSensitiveAttributesIncludingNestedAndWithValues(t *testing.T) {
	dir := t.TempDir()
	logger, closer, err := New("api", "debug", dir)
	if err != nil {
		t.Fatal(err)
	}
	logger = logger.With(
		"session_token", "session-value",
		"component", "authentication",
	)
	logger.Info(
		"request rejected",
		"password", "password-value",
		"request",
		slog.GroupValue(
			slog.String("authorization", "Bearer credential"),
			slog.String("task_id", "task-safe"),
		),
		"sample_sha256", strings.Repeat("a", 64),
	)
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"session-value", "password-value", "Bearer credential",
	} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("sensitive value %q leaked in log: %s", secret, raw)
		}
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record["session_token"] != redactedValue ||
		record["password"] != redactedValue ||
		record["component"] != "authentication" ||
		record["sample_sha256"] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected redacted record: %#v", record)
	}
	request, ok := record["request"].(map[string]any)
	if !ok || request["authorization"] != redactedValue ||
		request["task_id"] != "task-safe" {
		t.Fatalf("unexpected nested record: %#v", record["request"])
	}
}

func TestSensitiveLogKeyAvoidsBenignMetadata(t *testing.T) {
	for _, key := range []string{
		"request_id", "content_type", "session_count", "tokenizer_version",
		"sample_sha256", "task_id",
	} {
		if sensitiveLogKey(key) {
			t.Errorf("benign key %q was classified as sensitive", key)
		}
	}
	for _, key := range []string{
		"new_password", "mysql-root-password", "session_id", "access_token",
		"client_secret", "Cookie", "sample_content",
	} {
		if !sensitiveLogKey(key) {
			t.Errorf("sensitive key %q was not classified as sensitive", key)
		}
	}
}

func TestDailyLogWriterRotatesAndPrunesOnlyExpiredOwnedRegularFiles(
	t *testing.T,
) {
	directory := t.TempDir()
	prefix := "api-node"
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	oldPath := filepath.Join(directory, prefix+"-2026-06-30.jsonl")
	boundaryPath := filepath.Join(directory, prefix+"-2026-07-01.jsonl")
	foreignPath := filepath.Join(directory, "other-node-2026-06-01.jsonl")
	for _, path := range []string{oldPath, boundaryPath, foreignPath} {
		if err := os.WriteFile(path, []byte("retained"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outsidePath := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(outsidePath, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, prefix+"-2026-06-29.jsonl")
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		t.Fatal(err)
	}

	writer, err := newDailyLogWriter(directory, prefix, func() time.Time {
		return now
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("expired log still exists: %v", err)
	}
	for _, path := range []string{boundaryPath, foreignPath, linkPath, outsidePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("retained path %s: %v", path, err)
		}
	}

	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(0, 0, 1)
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, date := range []string{"2026-07-31", "2026-08-01"} {
		path := filepath.Join(directory, prefix+"-"+date+".jsonl")
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("rotated log mode = %v", info.Mode())
		}
	}
	outside, err := os.ReadFile(outsidePath)
	if err != nil || string(outside) != "outside" {
		t.Fatalf("symlink target changed: %q, %v", outside, err)
	}
}

func TestDailyLogWriterRejectsSymlinkDirectoryAndLogFile(t *testing.T) {
	realDirectory := t.TempDir()
	linkDirectory := filepath.Join(t.TempDir(), "logs")
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := newDailyLogWriter(
		linkDirectory,
		"api-node",
		time.Now,
	); err == nil {
		t.Fatal("symlink log directory was accepted")
	}

	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	logPath := filepath.Join(realDirectory, "api-node-2026-07-31.jsonl")
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), logPath); err != nil {
		t.Fatal(err)
	}
	writer, err := newDailyLogWriter(
		realDirectory,
		"api-node",
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("blocked")); err == nil {
		t.Fatal("symlink log file was followed")
	}
}
