package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testDSN = "user:password@tcp(mysql:3306)/binaryscan"

func TestLoadDSNPrefersExplicitSecretFile(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", "environment-dsn")
	secret := filepath.Join(t.TempDir(), "mysql_dsn")
	if err := os.WriteFile(secret, []byte(testDSN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_MYSQL_DSN_FILE", secret)

	cfg, err := Load("api")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.MySQLDSN != testDSN {
		t.Fatalf("MySQLDSN = %q, want secret file value", cfg.MySQLDSN)
	}
}

func TestLoadDSNDoesNotFallBackWhenExplicitSecretIsMissing(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_MYSQL_DSN_FILE", filepath.Join(t.TempDir(), "missing"))

	_, err := Load("api")
	if err == nil || !strings.Contains(err.Error(), "inspect MySQL DSN secret") {
		t.Fatalf("Load() error = %v, want explicit secret error", err)
	}
}

func TestLoadConstructsDSNFromYAMLAndPasswordSecret(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("p@ss:/word\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "api.yaml")
	yaml := "server:\n  listen: \":9090\"\ndatabase:\n  host: mysql\n  port: 3306\n  name: binaryscan\n  user: app\n  password_file: " + password + "\n  max_open_connections: 32\n  max_idle_connections: 8\n"
	if err := os.WriteFile(configFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN_FILE", "")
	// LookupEnv distinguishes an explicitly empty DSN secret variable, so remove it.
	if err := os.Unsetenv("BINARYSCAN_MYSQL_DSN_FILE"); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("api")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.MySQLMaxOpenConns != 32 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if !strings.Contains(cfg.MySQLDSN, "app:") || !strings.Contains(cfg.MySQLDSN, "@tcp(mysql:3306)/binaryscan") {
		t.Fatalf("constructed DSN has unexpected non-secret fields: %q", cfg.MySQLDSN)
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	cfg := Config{
		Service:              "api",
		HTTPAddr:             "not-an-address",
		MySQLDSN:             testDSN,
		ShutdownTimeout:      -1,
		HeartbeatInterval:    -1,
		DatabasePingTimeout:  -1,
		MySQLMaxOpenConns:    1,
		MySQLMaxIdleConns:    2,
		MySQLConnMaxLifetime: -1,
		MySQLConnMaxIdleTime: -1,
		LogLevel:             "verbose",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want validation errors")
	}
	for _, want := range []string{"host:port", "SHUTDOWN_TIMEOUT", "MAX_IDLE_CONNS", "LOG_LEVEL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Validate() error = %q, want %q", err, want)
		}
	}
}

func TestValidateRequiresTwoMySQLConnectionsForMigrationLock(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "mysql_dsn")
	if err := os.WriteFile(secret, []byte(testDSN+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN_FILE", secret)
	t.Setenv("BINARYSCAN_MYSQL_MAX_OPEN_CONNS", "20")
	t.Setenv("BINARYSCAN_MYSQL_MAX_IDLE_CONNS", "5")
	cfg, err := Load("maintenance")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MySQLMaxOpenConns = 1
	cfg.MySQLMaxIdleConns = 1

	err = cfg.Validate()
	const want = "must be at least 2 because schema migrations reserve a dedicated advisory-lock connection"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() error = %v, want %q", err, want)
	}
}

func TestConfigFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listne: ':8080'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", path)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	_, err := Load("api")
	if err == nil || !strings.Contains(err.Error(), "field listne not found") {
		t.Fatalf("Load() error = %v, want unknown field error", err)
	}
}

func TestStorageEnvironmentOverridesConfigFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
storage:
  uploads_root: /from-file/uploads
  repository_root: /from-file/repository
  task_work_root: /from-file/work
  min_free_bytes: 2147483648
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_UPLOAD_ROOT", "/from-env/uploads")
	t.Setenv("BINARYSCAN_REPOSITORY_ROOT", "/from-env/repository")
	t.Setenv("BINARYSCAN_TASK_WORK_ROOT", "/from-env/work")
	t.Setenv("BINARYSCAN_STORAGE_MIN_FREE_BYTES", "3221225472")
	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UploadsRoot != "/from-env/uploads" ||
		cfg.RepositoryRoot != "/from-env/repository" ||
		cfg.TaskWorkRoot != "/from-env/work" ||
		cfg.StorageMinFreeBytes != 3*1024*1024*1024 {
		t.Fatalf("storage environment overrides not applied: %#v", cfg)
	}
}

func TestStorageEnvironmentRejectsRelativePath(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_UPLOAD_ROOT", "relative/uploads")
	_, err := Load("api")
	if err == nil || !strings.Contains(err.Error(), "storage.uploads_root") {
		t.Fatalf("Load() error = %v, want absolute storage path error", err)
	}
}

func TestRawSampleDownloadIsDisabledByDefault(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED", "")

	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RawSampleDownloadEnabled {
		t.Fatal("raw sample download is enabled by default")
	}
}

func TestRawSampleDownloadConfigurationAndEnvironmentOverride(
	t *testing.T,
) {
	configFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
features:
  raw_sample_download_enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED", "")

	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RawSampleDownloadEnabled {
		t.Fatal("raw sample YAML setting was not applied")
	}

	t.Setenv("BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED", "false")
	cfg, err = Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RawSampleDownloadEnabled {
		t.Fatal("raw sample environment override was not applied")
	}
}

func TestRawSampleDownloadRejectsInvalidEnvironmentValue(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED", "sometimes")

	_, err := Load("api")
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED must be a boolean",
		) {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestArchiveSandboxConfigurationAndEnvironmentOverrides(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
archive_sandbox:
  enabled: true
  socket: /from-file/archive.sock
  input_root: /from-file/input
  output_root: /from-file/output
  timeout_seconds: 120
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_ARCHIVE_SOCKET", "/from-env/archive.sock")
	t.Setenv("BINARYSCAN_ARCHIVE_INPUT_ROOT", "/from-env/input")
	t.Setenv("BINARYSCAN_ARCHIVE_OUTPUT_ROOT", "/from-env/output")
	t.Setenv("BINARYSCAN_ARCHIVE_TIMEOUT", "3m")

	cfg, err := Load("scan-worker")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ArchiveSandboxEnabled ||
		cfg.ArchiveSandboxSocket != "/from-env/archive.sock" ||
		cfg.ArchiveSandboxInputRoot != "/from-env/input" ||
		cfg.ArchiveSandboxOutputRoot != "/from-env/output" ||
		cfg.ArchiveSandboxTimeout != 3*time.Minute {
		t.Fatalf("archive sandbox environment overrides = %#v", cfg)
	}
}

func TestArchiveSandboxRejectsUnsafeConfiguration(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_ARCHIVE_SANDBOX_ENABLED", "true")
	t.Setenv("BINARYSCAN_ARCHIVE_INPUT_ROOT", "/sandbox")
	t.Setenv("BINARYSCAN_ARCHIVE_OUTPUT_ROOT", "/sandbox/output")
	t.Setenv("BINARYSCAN_ARCHIVE_SOCKET", "relative/archive.sock")
	t.Setenv("BINARYSCAN_ARCHIVE_TIMEOUT", "25h")

	_, err := Load("scan-worker")
	if err == nil {
		t.Fatal("Load() error = nil, want unsafe archive sandbox errors")
	}
	for _, want := range []string{
		"must not overlap",
		"canonical absolute socket path",
		"no greater than 1200",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Load() error = %q, want %q", err, want)
		}
	}
}

func TestArchiveSandboxRejectsInvalidEnabledEnvironment(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_ARCHIVE_SANDBOX_ENABLED", "sometimes")

	_, err := Load("scan-worker")
	if err == nil || !strings.Contains(
		err.Error(),
		"BINARYSCAN_ARCHIVE_SANDBOX_ENABLED must be a boolean",
	) {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoginRateLimitDefaults(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD", "")
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "")
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS", "")

	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginRateLimitThreshold != 10 ||
		cfg.LoginRateLimitWindow != time.Minute ||
		cfg.LoginRateLimitBlock != 5*time.Minute {
		t.Fatalf("login rate limit defaults = %#v", cfg)
	}
}

func TestPasswordMinimumDefaultsToProductionPolicyAndAllowsExplicitDevOverride(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_AUTH_PASSWORD_MIN_BYTES", "")

	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthPasswordMinimumBytes != 11 {
		t.Fatalf("default password minimum = %d, want 11", cfg.AuthPasswordMinimumBytes)
	}
	t.Setenv("BINARYSCAN_AUTH_PASSWORD_MIN_BYTES", "8")
	cfg, err = Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthPasswordMinimumBytes != 8 {
		t.Fatalf("development password minimum = %d, want 8", cfg.AuthPasswordMinimumBytes)
	}
}

func TestPasswordMinimumRejectsValuesOutsideSupportedRange(t *testing.T) {
	for _, value := range []string{"7", "129"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("BINARYSCAN_CONFIG_FILE", "")
			t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
			t.Setenv("BINARYSCAN_AUTH_PASSWORD_MIN_BYTES", value)
			if _, err := Load("api"); err == nil ||
				!strings.Contains(err.Error(), "password minimum") {
				t.Fatalf("Load() error = %v, want password minimum rejection", err)
			}
		})
	}
}

func TestLoginRateLimitConfigurationAndEnvironmentOverrides(
	t *testing.T,
) {
	configFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
auth:
  login_rate_limit_threshold: 12
  login_rate_limit_window_seconds: 90
  login_rate_limit_block_seconds: 600
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD", "20")
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "120")
	t.Setenv("BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS", "900")

	cfg, err := Load("api")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LoginRateLimitThreshold != 20 ||
		cfg.LoginRateLimitWindow != 2*time.Minute ||
		cfg.LoginRateLimitBlock != 15*time.Minute {
		t.Fatalf("login rate limit overrides = %#v", cfg)
	}
}

func TestLoginRateLimitRejectsInvalidEnvironmentValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		env   string
		value string
		want  string
	}{
		{
			name:  "non numeric threshold",
			env:   "BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD",
			value: "many", want: "must be an integer",
		},
		{
			name:  "threshold above maximum",
			env:   "BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD",
			value: "1001", want: "login rate limit",
		},
		{
			name:  "window above maximum",
			env:   "BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
			value: "3601", want: "login rate limit",
		},
		{
			name:  "block above maximum",
			env:   "BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS",
			value: "86401", want: "login rate limit",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BINARYSCAN_CONFIG_FILE", "")
			t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
			t.Setenv(
				"BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD",
				"",
			)
			t.Setenv(
				"BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
				"",
			)
			t.Setenv(
				"BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS",
				"",
			)
			t.Setenv(test.env, test.value)
			_, err := Load("api")
			if err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTrivyConfigurationFileAndEnvironmentOverrides(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
trivy:
  executable: /from-file/bin/trivy
  version: 0.71.0
  database_root: /from-file/trivy-cache
  max_duration_seconds: 900
  termination_grace_seconds: 15
  max_standard_output_bytes: 2097152
  max_standard_error_bytes: 3145728
  max_report_bytes: 33554432
  max_results: 15000
  max_findings: 16000
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_TRIVY_EXECUTABLE", "/from-env/bin/trivy")
	t.Setenv("BINARYSCAN_TRIVY_VERSION", "0.72.0")
	t.Setenv("BINARYSCAN_TRIVY_DB_ROOT", "/from-env/trivy-cache")
	t.Setenv("BINARYSCAN_TRIVY_MAX_DURATION", "18m")
	t.Setenv("BINARYSCAN_TRIVY_TERMINATION_GRACE", "12s")
	t.Setenv("BINARYSCAN_TRIVY_MAX_STANDARD_OUTPUT_BYTES", "4194304")
	t.Setenv("BINARYSCAN_TRIVY_MAX_STANDARD_ERROR_BYTES", "5242880")
	t.Setenv("BINARYSCAN_TRIVY_MAX_REPORT_BYTES", "67108864")
	t.Setenv("BINARYSCAN_TRIVY_MAX_RESULTS", "18000")
	t.Setenv("BINARYSCAN_TRIVY_MAX_FINDINGS", "19000")

	cfg, err := Load("trivy-worker")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.TrivyExecutable != "/from-env/bin/trivy" ||
		cfg.TrivyVersion != "0.72.0" ||
		cfg.TrivyDBRoot != "/from-env/trivy-cache" ||
		cfg.TrivyMaxDuration.String() != "18m0s" ||
		cfg.TrivyTerminationGrace.String() != "12s" ||
		cfg.TrivyMaxStandardOutputBytes != 4*1024*1024 ||
		cfg.TrivyMaxStandardErrorBytes != 5*1024*1024 ||
		cfg.TrivyMaxReportBytes != 64*1024*1024 ||
		cfg.TrivyMaxResults != 18_000 ||
		cfg.TrivyMaxFindings != 19_000 {
		t.Fatalf("Trivy environment overrides not applied: %#v", cfg)
	}
}

func TestQueueResourceSlotConfigurationAndEnvironmentOverrides(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "api.yaml")
	if err := os.WriteFile(configFile, []byte(`
queue:
  heavy_slots: 2
  trivy_slots: 1
  native_slots: 1
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BINARYSCAN_CONFIG_FILE", configFile)
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_QUEUE_HEAVY_SLOTS", "1")
	t.Setenv("BINARYSCAN_QUEUE_TRIVY_SLOTS", "1")
	t.Setenv("BINARYSCAN_QUEUE_NATIVE_SLOTS", "1")

	cfg, err := Load("scan-worker")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QueueHeavySlots != 1 ||
		cfg.QueueTrivySlots != 1 ||
		cfg.QueueNativeSlots != 1 {
		t.Fatalf(
			"queue resource slots = heavy %d, Trivy %d, native %d",
			cfg.QueueHeavySlots,
			cfg.QueueTrivySlots,
			cfg.QueueNativeSlots,
		)
	}
}

func TestQueueNativeSlotsDefaultToOne(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	cfg, err := Load("native-worker")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QueueNativeSlots != 1 {
		t.Fatalf("QueueNativeSlots = %d, want 1", cfg.QueueNativeSlots)
	}
}

func TestQueueResourceSlotConfigurationRejectsInvalidBounds(t *testing.T) {
	tests := []struct {
		name   string
		heavy  string
		trivy  string
		native string
		wanted string
	}{
		{
			name: "too few global slots", heavy: "0", trivy: "1", native: "1",
			wanted: "queue.heavy_slots",
		},
		{
			name: "too many global slots", heavy: "3", trivy: "1", native: "1",
			wanted: "queue.heavy_slots",
		},
		{
			name: "zero Trivy slots", heavy: "1", trivy: "0", native: "1",
			wanted: "queue.trivy_slots",
		},
		{
			name: "Trivy exceeds global", heavy: "1", trivy: "2", native: "1",
			wanted: "queue.trivy_slots",
		},
		{
			name: "zero native slots", heavy: "1", trivy: "1", native: "0",
			wanted: "queue.native_slots",
		},
		{
			name: "native exceeds global", heavy: "1", trivy: "1", native: "2",
			wanted: "queue.native_slots",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BINARYSCAN_CONFIG_FILE", "")
			t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
			t.Setenv("BINARYSCAN_QUEUE_HEAVY_SLOTS", test.heavy)
			t.Setenv("BINARYSCAN_QUEUE_TRIVY_SLOTS", test.trivy)
			t.Setenv("BINARYSCAN_QUEUE_NATIVE_SLOTS", test.native)

			_, err := Load("scan-worker")
			if err == nil || !strings.Contains(err.Error(), test.wanted) {
				t.Fatalf("Load() error = %v, want %q", err, test.wanted)
			}
		})
	}
}

func TestTrivyConfigurationRejectsUnsafeOrUnboundedValues(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_TRIVY_EXECUTABLE", "relative/trivy")
	t.Setenv("BINARYSCAN_TRIVY_DB_ROOT", "/")
	t.Setenv("BINARYSCAN_TRIVY_MAX_DURATION", "25h")
	t.Setenv("BINARYSCAN_TRIVY_MAX_REPORT_BYTES", "1073741825")
	t.Setenv("BINARYSCAN_TRIVY_MAX_FINDINGS", "100001")

	_, err := Load("trivy-worker")
	if err == nil {
		t.Fatal("Load() error = nil, want Trivy validation errors")
	}
	for _, expected := range []string{
		"trivy.database_root",
		"trivy.executable",
		"Trivy duration",
		"trivy.max_report_bytes",
		"Trivy result limits",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Load() error = %q, want %q", err, expected)
		}
	}
}

func TestConfigurationRejectsOverlappingStorageTrustRoots(t *testing.T) {
	tests := []struct {
		name       string
		firstEnv   string
		firstPath  string
		secondEnv  string
		secondPath string
		want       string
	}{
		{
			name:     "Trivy database equals uploads",
			firstEnv: "BINARYSCAN_TRIVY_DB_ROOT", firstPath: "/shared",
			secondEnv: "BINARYSCAN_UPLOAD_ROOT", secondPath: "/shared",
			want: "trivy.database_root and storage.uploads_root must not overlap",
		},
		{
			name:     "Trivy database contains repository",
			firstEnv: "BINARYSCAN_TRIVY_DB_ROOT", firstPath: "/shared",
			secondEnv: "BINARYSCAN_REPOSITORY_ROOT", secondPath: "/shared/repository",
			want: "trivy.database_root and storage.repository_root must not overlap",
		},
		{
			name:     "task work contains Trivy database",
			firstEnv: "BINARYSCAN_TRIVY_DB_ROOT", firstPath: "/shared/trivy",
			secondEnv: "BINARYSCAN_TASK_WORK_ROOT", secondPath: "/shared",
			want: "trivy.database_root and storage.task_work_root must not overlap",
		},
		{
			name:     "uploads contain repository",
			firstEnv: "BINARYSCAN_UPLOAD_ROOT", firstPath: "/shared",
			secondEnv: "BINARYSCAN_REPOSITORY_ROOT", secondPath: "/shared/repository",
			want: "storage.uploads_root and storage.repository_root must not overlap",
		},
		{
			name:     "task work contains uploads",
			firstEnv: "BINARYSCAN_UPLOAD_ROOT", firstPath: "/shared/uploads",
			secondEnv: "BINARYSCAN_TASK_WORK_ROOT", secondPath: "/shared",
			want: "storage.uploads_root and storage.task_work_root must not overlap",
		},
		{
			name:     "repository equals task work",
			firstEnv: "BINARYSCAN_REPOSITORY_ROOT", firstPath: "/shared",
			secondEnv: "BINARYSCAN_TASK_WORK_ROOT", secondPath: "/shared",
			want: "storage.repository_root and storage.task_work_root must not overlap",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("BINARYSCAN_CONFIG_FILE", "")
			t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
			t.Setenv("BINARYSCAN_UPLOAD_ROOT", "/safe/uploads")
			t.Setenv("BINARYSCAN_REPOSITORY_ROOT", "/safe/repository")
			t.Setenv("BINARYSCAN_TASK_WORK_ROOT", "/safe/task-work")
			t.Setenv("BINARYSCAN_TRIVY_DB_ROOT", "/safe/trivy")
			t.Setenv(test.firstEnv, test.firstPath)
			t.Setenv(test.secondEnv, test.secondPath)

			_, err := Load("trivy-worker")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestStorageMinimumFreeBytesMustBePositive(t *testing.T) {
	t.Setenv("BINARYSCAN_CONFIG_FILE", "")
	t.Setenv("BINARYSCAN_MYSQL_DSN", testDSN)
	t.Setenv("BINARYSCAN_STORAGE_MIN_FREE_BYTES", "0")

	_, err := Load("api")
	if err == nil || !strings.Contains(err.Error(), "STORAGE_MIN_FREE_BYTES") {
		t.Fatalf("Load() error = %v, want positive low-water error", err)
	}
}
