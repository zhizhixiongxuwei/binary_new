package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

const defaultDSNSecretPath = "/run/secrets/mysql_dsn"

type Config struct {
	Service string

	HTTPAddr            string
	TrustedProxies      []string
	ShutdownTimeout     time.Duration
	HeartbeatInterval   time.Duration
	DatabasePingTimeout time.Duration

	DatabaseDriver       string
	MySQLDSN             string
	MySQLMaxOpenConns    int
	MySQLMaxIdleConns    int
	MySQLConnMaxLifetime time.Duration
	MySQLConnMaxIdleTime time.Duration

	UploadsRoot         string
	RepositoryRoot      string
	TaskWorkRoot        string
	StorageMinFreeBytes int64

	ArchiveSandboxEnabled    bool
	ArchiveSandboxSocket     string
	ArchiveSandboxInputRoot  string
	ArchiveSandboxOutputRoot string
	ArchiveSandboxRunRoot    string
	ArchiveSandboxTimeout    time.Duration

	TrivyExecutable             string
	TrivyVersion                string
	TrivyDBRoot                 string
	TrivyMaxDuration            time.Duration
	TrivyTerminationGrace       time.Duration
	TrivyMaxStandardOutputBytes int64
	TrivyMaxStandardErrorBytes  int64
	TrivyMaxReportBytes         int64
	TrivyMaxResults             int
	TrivyMaxFindings            int

	GhidraExecutable             string
	GhidraScriptDirectory        string
	GhidraVersion                string
	GhidraJavaExecutable         string
	GhidraJavaVersionLine        string
	GhidraMaxDuration            time.Duration
	GhidraTerminationGrace       time.Duration
	GhidraMaxStandardOutputBytes int64
	GhidraMaxStandardErrorBytes  int64
	GhidraMaxIndexBytes          int64
	GhidraMaxOutputBytes         int64
	GhidraMaxFunctions           int

	CCheckerURL                  string
	CCheckerVersion              string
	CAnalysisMaxDuration         time.Duration
	CAnalysisMaxResponseBytes    int64
	CAnalysisMaxFindings         int
	CAnalysisMaxDiagnostics      int
	JavaCheckerURL               string
	JavaCheckerVersion           string
	JavaAnalysisMaxDuration      time.Duration
	JavaAnalysisMaxResponseBytes int64
	JavaAnalysisMaxFindings      int
	JavaAnalysisMaxDiagnostics   int
	PythonCheckerURL            string
	PythonCheckerVersion        string
	PythonAnalysisMaxDuration   time.Duration
	PythonAnalysisMaxResponseBytes int64
	PythonAnalysisMaxFindings   int
	PythonAnalysisMaxDiagnostics int

	QueueLeaseInterval time.Duration
	QueuePollInterval  time.Duration
	QueueHeavySlots    int
	QueueTrivySlots    int
	QueueNativeSlots   int

	MaxUploadBytes   int64
	MaxExpandedBytes int64
	MaxArchiveRatio  int
	MaxDepth         int
	MaxFileNodes     int
	MaxNestedImages  int

	IncompleteUploadRetention time.Duration
	SampleRetention           time.Duration

	CookieSecure             bool
	SessionTTL               time.Duration
	LoginFailureThreshold    uint32
	LoginLockDuration        time.Duration
	LoginRateLimitThreshold  uint32
	LoginRateLimitWindow     time.Duration
	LoginRateLimitBlock      time.Duration
	AuthPasswordMinimumBytes int
	Argon2MemoryKiB          uint32
	Argon2Iterations         uint32
	Argon2Parallelism        uint8
	RawSampleDownloadEnabled bool

	LogLevel      string
	LogFormat     string
	LogDir        string
	LogMaxSizeMB  int
	LogMaxBackups int
	LogMaxAgeDays int
}

func Load(service string) (Config, error) {
	cfg := Config{
		Service:                      service,
		HTTPAddr:                     ":8080",
		DatabaseDriver:               "mysql",
		ShutdownTimeout:              durationOrDefault("BINARYSCAN_SHUTDOWN_TIMEOUT", 15*time.Second),
		HeartbeatInterval:            durationOrDefault("BINARYSCAN_HEARTBEAT_INTERVAL", 10*time.Second),
		DatabasePingTimeout:          durationOrDefault("BINARYSCAN_DATABASE_PING_TIMEOUT", 2*time.Second),
		MySQLMaxOpenConns:            intOrDefault("BINARYSCAN_MYSQL_MAX_OPEN_CONNS", 16),
		MySQLMaxIdleConns:            intOrDefault("BINARYSCAN_MYSQL_MAX_IDLE_CONNS", 4),
		MySQLConnMaxLifetime:         durationOrDefault("BINARYSCAN_MYSQL_CONN_MAX_LIFETIME", 30*time.Minute),
		MySQLConnMaxIdleTime:         durationOrDefault("BINARYSCAN_MYSQL_CONN_MAX_IDLE_TIME", 5*time.Minute),
		UploadsRoot:                  "/data/uploads",
		RepositoryRoot:               "/data/repository",
		TaskWorkRoot:                 "/data/task-work",
		StorageMinFreeBytes:          5 * 1024 * 1024 * 1024,
		ArchiveSandboxSocket:         "/run/binaryscan-archive/archive.sock",
		ArchiveSandboxInputRoot:      "/var/lib/binaryscan-archive/input",
		ArchiveSandboxOutputRoot:     "/var/lib/binaryscan-archive/output",
		ArchiveSandboxRunRoot:        "/var/lib/binaryscan-archive/run",
		ArchiveSandboxTimeout:        20 * time.Minute,
		TrivyExecutable:              "/usr/local/bin/trivy",
		TrivyVersion:                 "0.72.0",
		TrivyDBRoot:                  "/opt/trivy-cache",
		TrivyMaxDuration:             20 * time.Minute,
		TrivyTerminationGrace:        10 * time.Second,
		TrivyMaxStandardOutputBytes:  1 * 1024 * 1024,
		TrivyMaxStandardErrorBytes:   1 * 1024 * 1024,
		TrivyMaxReportBytes:          64 * 1024 * 1024,
		TrivyMaxResults:              20_000,
		TrivyMaxFindings:             20_000,
		GhidraExecutable:             "/opt/ghidra/support/analyzeHeadless",
		GhidraScriptDirectory:        "/opt/binaryscan/analyzers/ghidra",
		GhidraVersion:                "12.1.2",
		GhidraJavaExecutable:         "/opt/java/openjdk/bin/java",
		GhidraJavaVersionLine:        `openjdk version "21.0.7" 2025-04-15 LTS`,
		GhidraMaxDuration:            20 * time.Minute,
		GhidraTerminationGrace:       10 * time.Second,
		GhidraMaxStandardOutputBytes: 8 * 1024 * 1024,
		GhidraMaxStandardErrorBytes:  8 * 1024 * 1024,
		GhidraMaxIndexBytes:          32 * 1024 * 1024,
		GhidraMaxOutputBytes:         128 * 1024 * 1024,
		GhidraMaxFunctions:           3_000,
		CCheckerURL:                  "http://c-checker:8080",
		CCheckerVersion:              "0.1.0",
		CAnalysisMaxDuration:         10 * time.Minute,
		CAnalysisMaxResponseBytes:    32 * 1024 * 1024,
		CAnalysisMaxFindings:         10_000,
		CAnalysisMaxDiagnostics:      1_000,
		JavaCheckerURL:               "http://java-checker:8080",
		JavaCheckerVersion:           "0.1.0",
		JavaAnalysisMaxDuration:      10 * time.Minute,
		JavaAnalysisMaxResponseBytes: 32 * 1024 * 1024,
		JavaAnalysisMaxFindings:      10_000,
		JavaAnalysisMaxDiagnostics:   1_000,
		PythonCheckerURL:             "http://python-checker:8080",
		PythonCheckerVersion:         "0.1.0",
		PythonAnalysisMaxDuration:    10 * time.Minute,
		PythonAnalysisMaxResponseBytes: 32 * 1024 * 1024,
		PythonAnalysisMaxFindings:    10_000,
		PythonAnalysisMaxDiagnostics: 1_000,
		QueueLeaseInterval:           60 * time.Second,
		QueuePollInterval:            2 * time.Second,
		QueueHeavySlots:              1,
		QueueTrivySlots:              1,
		QueueNativeSlots:             1,
		MaxUploadBytes:               2 * 1024 * 1024 * 1024,
		MaxExpandedBytes:             10 * 1024 * 1024 * 1024,
		MaxArchiveRatio:              50,
		MaxDepth:                     6,
		MaxFileNodes:                 20_000,
		MaxNestedImages:              3,
		IncompleteUploadRetention:    12 * time.Hour,
		SampleRetention:              15 * 24 * time.Hour,
		SessionTTL:                   12 * time.Hour,
		LoginFailureThreshold:        5,
		LoginLockDuration:            15 * time.Minute,
		LoginRateLimitThreshold:      10,
		LoginRateLimitWindow:         time.Minute,
		LoginRateLimitBlock:          5 * time.Minute,
		AuthPasswordMinimumBytes:     11,
		Argon2MemoryKiB:              64 * 1024,
		Argon2Iterations:             3,
		Argon2Parallelism:            2,
		LogLevel:                     "info",
		LogFormat:                    "json",
		LogMaxSizeMB:                 100,
		LogMaxBackups:                5,
		LogMaxAgeDays:                15,
	}

	fileCfg, err := loadConfigFile()
	if err != nil {
		return Config{}, err
	}
	applyFileConfig(&cfg, fileCfg)
	if err := applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}

	dsn, err := loadDSN(fileCfg)
	if err != nil {
		return Config{}, err
	}
	cfg.MySQLDSN = dsn

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.Service) == "" {
		errs = append(errs, errors.New("service name is required"))
	}
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		errs = append(errs, fmt.Errorf("BINARYSCAN_HTTP_ADDR must be host:port: %w", err))
	}
	if strings.TrimSpace(c.MySQLDSN) == "" {
		errs = append(errs, errors.New("MySQL DSN is required; set BINARYSCAN_MYSQL_DSN_FILE or BINARYSCAN_MYSQL_DSN"))
	}
	if c.DatabaseDriver != "mysql" {
		errs = append(errs, errors.New("database.driver must be mysql"))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("BINARYSCAN_SHUTDOWN_TIMEOUT must be positive"))
	}
	if c.HeartbeatInterval <= 0 {
		errs = append(errs, errors.New("BINARYSCAN_HEARTBEAT_INTERVAL must be positive"))
	}
	if c.DatabasePingTimeout <= 0 {
		errs = append(errs, errors.New("BINARYSCAN_DATABASE_PING_TIMEOUT must be positive"))
	}
	if c.MySQLMaxOpenConns < 2 {
		errs = append(errs, errors.New(
			"BINARYSCAN_MYSQL_MAX_OPEN_CONNS must be at least 2 because schema migrations reserve a dedicated advisory-lock connection",
		))
	}
	if c.MySQLMaxIdleConns < 0 || c.MySQLMaxIdleConns > c.MySQLMaxOpenConns {
		errs = append(errs, errors.New("BINARYSCAN_MYSQL_MAX_IDLE_CONNS must be between zero and max open connections"))
	}
	if c.MySQLConnMaxLifetime <= 0 || c.MySQLConnMaxIdleTime <= 0 {
		errs = append(errs, errors.New("MySQL connection lifetimes must be positive"))
	}
	for _, proxy := range c.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				errs = append(errs, fmt.Errorf("server.trusted_proxies contains invalid IP or CIDR %q", proxy))
			}
		}
	}
	roots := map[string]string{
		"storage.uploads_root":    c.UploadsRoot,
		"storage.repository_root": c.RepositoryRoot,
		"storage.task_work_root":  c.TaskWorkRoot,
		"trivy.database_root":     c.TrivyDBRoot,
	}
	for name, path := range roots {
		if !validRootPath(path) {
			errs = append(errs, fmt.Errorf("%s must be an absolute path below the filesystem root", name))
		}
	}
	writableRoots := []string{
		"storage.uploads_root",
		"storage.repository_root",
		"storage.task_work_root",
	}
	for index, first := range writableRoots {
		for _, second := range writableRoots[index+1:] {
			errs = appendRootOverlapError(errs, roots, first, second)
		}
	}
	for _, protected := range []string{"trivy.database_root"} {
		for _, writable := range writableRoots {
			errs = appendRootOverlapError(errs, roots, protected, writable)
		}
	}
	if c.ArchiveSandboxEnabled {
		archiveRoots := map[string]string{
			"archive_sandbox.input_root":  c.ArchiveSandboxInputRoot,
			"archive_sandbox.output_root": c.ArchiveSandboxOutputRoot,
			"archive_sandbox.run_root":    c.ArchiveSandboxRunRoot,
		}
		for name, value := range archiveRoots {
			if !validRootPath(value) {
				errs = append(errs, fmt.Errorf(
					"%s must be an absolute path below the filesystem root",
					name,
				))
			}
		}
		archiveNames := []string{
			"archive_sandbox.input_root",
			"archive_sandbox.output_root",
			"archive_sandbox.run_root",
		}
		for index, first := range archiveNames {
			for _, second := range archiveNames[index+1:] {
				errs = appendRootOverlapError(errs, archiveRoots, first, second)
			}
		}
		archiveParent := filepath.Dir(c.ArchiveSandboxInputRoot)
		if filepath.Base(c.ArchiveSandboxInputRoot) != "input" ||
			filepath.Base(c.ArchiveSandboxOutputRoot) != "output" ||
			filepath.Base(c.ArchiveSandboxRunRoot) != "run" ||
			filepath.Dir(c.ArchiveSandboxOutputRoot) != archiveParent ||
			filepath.Dir(c.ArchiveSandboxRunRoot) != archiveParent {
			errs = append(errs, errors.New(
				"archive_sandbox roots must be input, output, and run under one dedicated parent",
			))
		}
		for name, value := range roots {
			if validRootPath(archiveParent) && validRootPath(value) &&
				pathsOverlap(archiveParent, value) {
				errs = append(errs, fmt.Errorf(
					"archive_sandbox parent and %s must not overlap", name,
				))
			}
		}
		if !filepath.IsAbs(c.ArchiveSandboxSocket) ||
			filepath.Clean(c.ArchiveSandboxSocket) == string(filepath.Separator) ||
			filepath.Clean(c.ArchiveSandboxSocket) != c.ArchiveSandboxSocket {
			errs = append(errs, errors.New(
				"archive_sandbox.socket must be a canonical absolute socket path",
			))
		}
		socketParent := filepath.Dir(c.ArchiveSandboxSocket)
		if !validRootPath(socketParent) ||
			validRootPath(archiveParent) && pathsOverlap(socketParent, archiveParent) {
			errs = append(errs, errors.New(
				"archive_sandbox socket parent must not overlap archive data roots",
			))
		}
		if c.ArchiveSandboxTimeout <= 0 ||
			c.ArchiveSandboxTimeout > 20*time.Minute {
			errs = append(errs, errors.New(
				"archive_sandbox.timeout_seconds must be positive and no greater than 1200",
			))
		}
	}
	if !filepath.IsAbs(c.TrivyExecutable) ||
		filepath.Clean(c.TrivyExecutable) == "/" ||
		filepath.Clean(c.TrivyExecutable) != c.TrivyExecutable {
		errs = append(errs, errors.New(
			"trivy.executable must be a canonical absolute file path",
		))
	}
	if !validToolVersion(c.TrivyVersion) {
		errs = append(errs, errors.New(
			"trivy.version must contain 1-128 safe ASCII version characters",
		))
	}
	if c.TrivyMaxDuration <= 0 || c.TrivyMaxDuration > 20*time.Minute ||
		c.TrivyTerminationGrace <= 0 ||
		c.TrivyTerminationGrace > time.Minute {
		errs = append(errs, errors.New(
			"Trivy duration must be at most 20 minutes and termination grace at most one minute",
		))
	}
	if c.TrivyMaxStandardOutputBytes <= 0 ||
		c.TrivyMaxStandardOutputBytes > 64*1024*1024 ||
		c.TrivyMaxStandardErrorBytes <= 0 ||
		c.TrivyMaxStandardErrorBytes > 64*1024*1024 {
		errs = append(errs, errors.New(
			"Trivy standard output limits must be positive and no greater than 64 MiB",
		))
	}
	if c.TrivyMaxReportBytes <= 0 ||
		c.TrivyMaxReportBytes > 64*1024*1024 {
		errs = append(errs, errors.New(
			"trivy.max_report_bytes must be positive and no greater than 64 MiB",
		))
	}
	if c.TrivyMaxResults <= 0 || c.TrivyMaxResults > 20_000 ||
		c.TrivyMaxFindings <= 0 || c.TrivyMaxFindings > 20_000 {
		errs = append(errs, errors.New(
			"Trivy result limits are outside accepted bounds",
		))
	}
	for name, value := range map[string]string{
		"ghidra.executable":       c.GhidraExecutable,
		"ghidra.script_directory": c.GhidraScriptDirectory,
		"ghidra.java_executable":  c.GhidraJavaExecutable,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) == "/" ||
			filepath.Clean(value) != value {
			errs = append(errs, fmt.Errorf(
				"%s must be a canonical absolute path", name,
			))
		}
	}
	if !validToolVersion(c.GhidraVersion) ||
		strings.TrimSpace(c.GhidraJavaVersionLine) == "" ||
		len(c.GhidraJavaVersionLine) > 256 {
		errs = append(errs, errors.New("Ghidra and Java versions are invalid"))
	}
	if c.GhidraMaxDuration <= 0 || c.GhidraMaxDuration > 20*time.Minute ||
		c.GhidraTerminationGrace <= 0 ||
		c.GhidraTerminationGrace > time.Minute ||
		c.GhidraMaxStandardOutputBytes <= 0 ||
		c.GhidraMaxStandardOutputBytes > 64*1024*1024 ||
		c.GhidraMaxStandardErrorBytes <= 0 ||
		c.GhidraMaxStandardErrorBytes > 64*1024*1024 ||
		c.GhidraMaxIndexBytes <= 0 ||
		c.GhidraMaxIndexBytes > 32*1024*1024 ||
		c.GhidraMaxOutputBytes <= 0 ||
		c.GhidraMaxOutputBytes > 128*1024*1024 ||
		c.GhidraMaxFunctions <= 0 || c.GhidraMaxFunctions > 3_000 {
		errs = append(errs, errors.New("Ghidra execution limits are invalid"))
	}
	checkerURL, checkerURLErr := url.Parse(c.CCheckerURL)
	if checkerURLErr != nil || checkerURL.Scheme != "http" && checkerURL.Scheme != "https" ||
		checkerURL.Host == "" || checkerURL.User != nil || checkerURL.RawQuery != "" ||
		checkerURL.Fragment != "" || c.CCheckerVersion != "0.1.0" {
		errs = append(errs, errors.New("c_analysis checker URL or version is invalid"))
	}
	if c.CAnalysisMaxDuration <= 0 || c.CAnalysisMaxDuration > 10*time.Minute ||
		c.CAnalysisMaxResponseBytes <= 0 ||
		c.CAnalysisMaxResponseBytes > 32*1024*1024 ||
		c.CAnalysisMaxFindings <= 0 || c.CAnalysisMaxFindings > 10_000 ||
		c.CAnalysisMaxDiagnostics <= 0 || c.CAnalysisMaxDiagnostics > 1_000 {
		errs = append(errs, errors.New("C analysis execution limits are invalid"))
	}
	javaCheckerURL, javaCheckerURLErr := url.Parse(c.JavaCheckerURL)
	if javaCheckerURLErr != nil ||
		javaCheckerURL.Scheme != "http" && javaCheckerURL.Scheme != "https" ||
		javaCheckerURL.Host == "" || javaCheckerURL.User != nil ||
		javaCheckerURL.RawQuery != "" || javaCheckerURL.Fragment != "" ||
		c.JavaCheckerVersion != "0.1.0" {
		errs = append(errs, errors.New("java_analysis checker URL or version is invalid"))
	}
	if c.JavaAnalysisMaxDuration <= 0 ||
		c.JavaAnalysisMaxDuration > 10*time.Minute ||
		c.JavaAnalysisMaxResponseBytes <= 0 ||
		c.JavaAnalysisMaxResponseBytes > 32*1024*1024 ||
		c.JavaAnalysisMaxFindings <= 0 || c.JavaAnalysisMaxFindings > 10_000 ||
		c.JavaAnalysisMaxDiagnostics <= 0 || c.JavaAnalysisMaxDiagnostics > 1_000 {
		errs = append(errs, errors.New("Java analysis execution limits are invalid"))
	}
	pythonCheckerURL, pythonCheckerURLErr := url.Parse(c.PythonCheckerURL)
	if pythonCheckerURLErr != nil ||
		pythonCheckerURL.Scheme != "http" && pythonCheckerURL.Scheme != "https" ||
		pythonCheckerURL.Host == "" || pythonCheckerURL.User != nil ||
		pythonCheckerURL.RawQuery != "" || pythonCheckerURL.Fragment != "" ||
		c.PythonCheckerVersion != "0.1.0" {
		errs = append(errs, errors.New("python_analysis checker URL or version is invalid"))
	}
	if c.PythonAnalysisMaxDuration <= 0 ||
		c.PythonAnalysisMaxDuration > 10*time.Minute ||
		c.PythonAnalysisMaxResponseBytes <= 0 ||
		c.PythonAnalysisMaxResponseBytes > 32*1024*1024 ||
		c.PythonAnalysisMaxFindings <= 0 || c.PythonAnalysisMaxFindings > 10_000 ||
		c.PythonAnalysisMaxDiagnostics <= 0 || c.PythonAnalysisMaxDiagnostics > 1_000 {
		errs = append(errs, errors.New("Python analysis execution limits are invalid"))
	}
	if c.StorageMinFreeBytes <= 0 {
		errs = append(errs, errors.New("BINARYSCAN_STORAGE_MIN_FREE_BYTES must be positive"))
	}
	if c.QueueLeaseInterval <= 0 || c.QueuePollInterval <= 0 || c.HeartbeatInterval <= 0 {
		errs = append(errs, errors.New("queue lease, heartbeat, and poll intervals must be positive"))
	} else if c.QueueLeaseInterval <= c.HeartbeatInterval {
		errs = append(errs, errors.New("queue.lease_seconds must be greater than queue.heartbeat_seconds"))
	}
	if c.QueueHeavySlots < 1 || c.QueueHeavySlots > 2 {
		errs = append(errs, errors.New(
			"queue.heavy_slots must be between 1 and 2",
		))
	}
	if c.QueueTrivySlots < 1 || c.QueueTrivySlots > c.QueueHeavySlots {
		errs = append(errs, errors.New(
			"queue.trivy_slots must be between 1 and queue.heavy_slots",
		))
	}
	if c.QueueNativeSlots < 1 || c.QueueNativeSlots > c.QueueHeavySlots {
		errs = append(errs, errors.New(
			"queue.native_slots must be between 1 and queue.heavy_slots",
		))
	}
	if c.MaxUploadBytes <= 0 || c.MaxUploadBytes > 2*1024*1024*1024 {
		errs = append(errs, errors.New("limits.max_upload_bytes must be positive and no greater than 2 GiB"))
	}
	if c.MaxExpandedBytes <= 0 || c.MaxExpandedBytes > 10*1024*1024*1024 {
		errs = append(errs, errors.New("limits.max_expanded_bytes must be positive and no greater than 10 GiB"))
	}
	if c.MaxArchiveRatio <= 0 || c.MaxArchiveRatio > 50 {
		errs = append(errs, errors.New("limits.max_archive_ratio must be between 1 and 50"))
	}
	if c.MaxDepth <= 0 || c.MaxDepth > 6 {
		errs = append(errs, errors.New("limits.max_depth must be between 1 and 6"))
	}
	if c.MaxFileNodes <= 0 || c.MaxFileNodes > 20_000 {
		errs = append(errs, errors.New("limits.max_file_nodes must be between 1 and 20000"))
	}
	if c.MaxNestedImages <= 0 || c.MaxNestedImages > 3 {
		errs = append(errs, errors.New("limits.max_nested_images must be between 1 and 3"))
	}
	if c.IncompleteUploadRetention <= 0 || c.IncompleteUploadRetention > 12*time.Hour ||
		c.SampleRetention <= 0 || c.SampleRetention > 15*24*time.Hour {
		errs = append(errs, errors.New("retention values must be positive and no greater than 12 hours / 15 days"))
	}
	if c.SessionTTL <= 0 || c.SessionTTL > 7*24*time.Hour {
		errs = append(errs, errors.New("auth.session_ttl_hours must be positive and no greater than 168"))
	}
	if c.LoginFailureThreshold == 0 || c.LoginFailureThreshold > 100 || c.LoginLockDuration <= 0 {
		errs = append(errs, errors.New("auth login failure and lock settings are invalid"))
	}
	if c.LoginRateLimitThreshold == 0 ||
		c.LoginRateLimitThreshold > 1000 ||
		c.LoginRateLimitWindow < time.Second ||
		c.LoginRateLimitWindow > time.Hour ||
		c.LoginRateLimitBlock < time.Second ||
		c.LoginRateLimitBlock > 24*time.Hour {
		errs = append(errs, errors.New(
			"auth login rate limit threshold, window, or block settings are invalid",
		))
	}
	if c.Argon2MemoryKiB < 8*1024 || c.Argon2MemoryKiB > 1024*1024 ||
		c.Argon2Iterations == 0 || c.Argon2Iterations > 20 ||
		c.Argon2Parallelism == 0 || c.Argon2Parallelism > 16 {
		errs = append(errs, errors.New("auth Argon2id settings are outside accepted bounds"))
	}
	if c.AuthPasswordMinimumBytes < 8 || c.AuthPasswordMinimumBytes > 128 {
		errs = append(errs, errors.New(
			"auth password minimum must be between 8 and 128 bytes",
		))
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("BINARYSCAN_LOG_LEVEL must be debug, info, warn, or error"))
	}
	if c.LogFormat != "json" {
		errs = append(errs, errors.New("logging.format must be json"))
	}
	if c.LogDir != "" && !strings.HasPrefix(c.LogDir, "/") {
		errs = append(errs, errors.New("BINARYSCAN_LOG_DIR must be an absolute path"))
	}
	if c.LogMaxSizeMB <= 0 || c.LogMaxBackups <= 0 || c.LogMaxAgeDays <= 0 {
		errs = append(errs, errors.New("logging rotation values must be positive"))
	}
	return errors.Join(errs...)
}

func loadDSN(fileCfg fileConfig) (string, error) {
	secretPath, explicitlySet := os.LookupEnv("BINARYSCAN_MYSQL_DSN_FILE")
	secretPath = strings.TrimSpace(secretPath)

	if secretPath != "" {
		return readSecret(secretPath)
	}
	if explicitlySet {
		return "", errors.New("BINARYSCAN_MYSQL_DSN_FILE cannot be empty")
	}
	if fileCfg.Database.DSNFile != "" {
		return readSecret(fileCfg.Database.DSNFile)
	}

	if _, err := os.Stat(defaultDSNSecretPath); err == nil {
		return readSecret(defaultDSNSecretPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect default MySQL DSN secret: %w", err)
	}

	if dsn := strings.TrimSpace(os.Getenv("BINARYSCAN_MYSQL_DSN")); dsn != "" {
		return dsn, nil
	}

	host := stringOrDefault("BINARYSCAN_DB_HOST", fileCfg.Database.Host)
	port := intOrFallback("BINARYSCAN_DB_PORT", fileCfg.Database.Port)
	name := stringOrDefault("BINARYSCAN_DB_NAME", fileCfg.Database.Name)
	user := stringOrDefault("BINARYSCAN_DB_USER", fileCfg.Database.User)
	passwordFile := stringOrDefault("BINARYSCAN_DB_PASSWORD_FILE", fileCfg.Database.PasswordFile)
	if host == "" || port <= 0 || name == "" || user == "" || passwordFile == "" {
		return "", errors.New("database configuration requires host, port, name, user, and password_file when a full DSN is not provided")
	}
	password, err := readSecret(passwordFile)
	if err != nil {
		return "", fmt.Errorf("read database password: %w", err)
	}
	driverCfg := mysql.NewConfig()
	driverCfg.Net = "tcp"
	driverCfg.Addr = net.JoinHostPort(host, strconv.Itoa(port))
	driverCfg.User = user
	driverCfg.Passwd = password
	driverCfg.DBName = name
	driverCfg.ParseTime = true
	driverCfg.Loc = time.UTC
	driverCfg.Timeout = 5 * time.Second
	driverCfg.ReadTimeout = 30 * time.Second
	driverCfg.WriteTimeout = 30 * time.Second
	return driverCfg.FormatDSN(), nil
}

func readSecret(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect MySQL DSN secret %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("MySQL DSN secret %q is not a regular file", path)
	}
	if info.Size() > 16*1024 {
		return "", fmt.Errorf("MySQL DSN secret %q exceeds 16 KiB", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read MySQL DSN secret %q: %w", path, err)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("MySQL DSN secret %q is empty", path)
	}
	return value, nil
}

func durationOrDefault(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return -1
	}
	return parsed
}

func intOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}

func intOrFallback(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return -1
	}
	return parsed
}

func stringOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

type fileConfig struct {
	Server struct {
		Listen         string   `yaml:"listen"`
		TrustedProxies []string `yaml:"trusted_proxies"`
	} `yaml:"server"`
	Database struct {
		Host               string `yaml:"host"`
		Port               int    `yaml:"port"`
		Name               string `yaml:"name"`
		User               string `yaml:"user"`
		PasswordFile       string `yaml:"password_file"`
		Driver             string `yaml:"driver"`
		DSNFile            string `yaml:"dsn_file"`
		MaxOpenConnections int    `yaml:"max_open_connections"`
		MaxIdleConnections int    `yaml:"max_idle_connections"`
	} `yaml:"database"`
	Storage struct {
		UploadsRoot      string `yaml:"uploads_root"`
		RepositoryRoot   string `yaml:"repository_root"`
		TaskWorkRoot     string `yaml:"task_work_root"`
		MinimumFreeBytes int64  `yaml:"min_free_bytes"`
	} `yaml:"storage"`
	ArchiveSandbox struct {
		Enabled        bool   `yaml:"enabled"`
		Socket         string `yaml:"socket"`
		InputRoot      string `yaml:"input_root"`
		OutputRoot     string `yaml:"output_root"`
		RunRoot        string `yaml:"run_root"`
		TimeoutSeconds int    `yaml:"timeout_seconds"`
	} `yaml:"archive_sandbox"`
	Trivy struct {
		Executable              string `yaml:"executable"`
		Version                 string `yaml:"version"`
		DatabaseRoot            string `yaml:"database_root"`
		MaxDurationSeconds      int    `yaml:"max_duration_seconds"`
		TerminationGraceSeconds int    `yaml:"termination_grace_seconds"`
		MaxStandardOutputBytes  int64  `yaml:"max_standard_output_bytes"`
		MaxStandardErrorBytes   int64  `yaml:"max_standard_error_bytes"`
		MaxReportBytes          int64  `yaml:"max_report_bytes"`
		MaxResults              int    `yaml:"max_results"`
		MaxFindings             int    `yaml:"max_findings"`
	} `yaml:"trivy"`
	Ghidra struct {
		Executable              string `yaml:"executable"`
		ScriptDirectory         string `yaml:"script_directory"`
		Version                 string `yaml:"version"`
		JavaExecutable          string `yaml:"java_executable"`
		JavaVersionLine         string `yaml:"java_version_line"`
		MaxDurationSeconds      int    `yaml:"max_duration_seconds"`
		TerminationGraceSeconds int    `yaml:"termination_grace_seconds"`
		MaxStandardOutputBytes  int64  `yaml:"max_standard_output_bytes"`
		MaxStandardErrorBytes   int64  `yaml:"max_standard_error_bytes"`
		MaxIndexBytes           int64  `yaml:"max_index_bytes"`
		MaxOutputBytes          int64  `yaml:"max_output_bytes"`
		MaxFunctions            int    `yaml:"max_functions"`
	} `yaml:"ghidra"`
	CAnalysis struct {
		CheckerURL       string `yaml:"checker_url"`
		CheckerVersion   string `yaml:"checker_version"`
		TimeoutSeconds   int    `yaml:"timeout_seconds"`
		MaxResponseBytes int64  `yaml:"max_response_bytes"`
		MaxFindings      int    `yaml:"max_findings"`
		MaxDiagnostics   int    `yaml:"max_diagnostics"`
	} `yaml:"c_analysis"`
	JavaAnalysis struct {
		CheckerURL       string `yaml:"checker_url"`
		CheckerVersion   string `yaml:"checker_version"`
		TimeoutSeconds   int    `yaml:"timeout_seconds"`
		MaxResponseBytes int64  `yaml:"max_response_bytes"`
		MaxFindings      int    `yaml:"max_findings"`
		MaxDiagnostics   int    `yaml:"max_diagnostics"`
	} `yaml:"java_analysis"`
	PythonAnalysis struct {
		CheckerURL       string `yaml:"checker_url"`
		CheckerVersion   string `yaml:"checker_version"`
		TimeoutSeconds   int    `yaml:"timeout_seconds"`
		MaxResponseBytes int64  `yaml:"max_response_bytes"`
		MaxFindings      int    `yaml:"max_findings"`
		MaxDiagnostics   int    `yaml:"max_diagnostics"`
	} `yaml:"python_analysis"`
	Queue struct {
		LeaseSeconds     int `yaml:"lease_seconds"`
		HeartbeatSeconds int `yaml:"heartbeat_seconds"`
		PollSeconds      int `yaml:"poll_seconds"`
		HeavySlots       int `yaml:"heavy_slots"`
		TrivySlots       int `yaml:"trivy_slots"`
		NativeSlots      int `yaml:"native_slots"`
	} `yaml:"queue"`
	Limits struct {
		MaxUploadBytes   int64 `yaml:"max_upload_bytes"`
		MaxExpandedBytes int64 `yaml:"max_expanded_bytes"`
		MaxArchiveRatio  int   `yaml:"max_archive_ratio"`
		MaxDepth         int   `yaml:"max_depth"`
		MaxFileNodes     int   `yaml:"max_file_nodes"`
		MaxNestedImages  int   `yaml:"max_nested_images"`
	} `yaml:"limits"`
	Retention struct {
		IncompleteUploadHours int `yaml:"incomplete_upload_hours"`
		SampleDays            int `yaml:"sample_days"`
	} `yaml:"retention"`
	Auth struct {
		CookieSecure                bool   `yaml:"cookie_secure"`
		SessionTTLHours             int    `yaml:"session_ttl_hours"`
		LoginFailureThreshold       uint32 `yaml:"login_failure_threshold"`
		LoginLockMinutes            int    `yaml:"login_lock_minutes"`
		LoginRateLimitThreshold     uint32 `yaml:"login_rate_limit_threshold"`
		LoginRateLimitWindowSeconds int    `yaml:"login_rate_limit_window_seconds"`
		LoginRateLimitBlockSeconds  int    `yaml:"login_rate_limit_block_seconds"`
		PasswordMinimumBytes        int    `yaml:"password_minimum_bytes"`
		Argon2MemoryKiB             uint32 `yaml:"argon2_memory_kib"`
		Argon2Iterations            uint32 `yaml:"argon2_iterations"`
		Argon2Parallelism           uint8  `yaml:"argon2_parallelism"`
	} `yaml:"auth"`
	Features struct {
		RawSampleDownloadEnabled bool `yaml:"raw_sample_download_enabled"`
	} `yaml:"features"`
	Logging struct {
		Format     string `yaml:"format"`
		Directory  string `yaml:"directory"`
		MaxSizeMB  int    `yaml:"max_size_mb"`
		MaxBackups int    `yaml:"max_backups"`
		MaxAgeDays int    `yaml:"max_age_days"`
	} `yaml:"logging"`
}

func loadConfigFile() (fileConfig, error) {
	path := strings.TrimSpace(os.Getenv("BINARYSCAN_CONFIG_FILE"))
	if path == "" {
		return fileConfig{}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("inspect config file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fileConfig{}, fmt.Errorf("config file %q is not a regular file", path)
	}
	if info.Size() > 1024*1024 {
		return fileConfig{}, fmt.Errorf("config file %q exceeds 1 MiB", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config file %q: %w", path, err)
	}
	var cfg fileConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return fileConfig{}, fmt.Errorf("parse config file %q: %w", path, err)
	}
	return cfg, nil
}

func applyFileConfig(cfg *Config, fileCfg fileConfig) {
	if fileCfg.Server.Listen != "" {
		cfg.HTTPAddr = fileCfg.Server.Listen
	}
	cfg.TrustedProxies = append([]string(nil), fileCfg.Server.TrustedProxies...)
	if fileCfg.Database.Driver != "" {
		cfg.DatabaseDriver = fileCfg.Database.Driver
	}
	if fileCfg.Database.MaxOpenConnections != 0 {
		cfg.MySQLMaxOpenConns = fileCfg.Database.MaxOpenConnections
	}
	if fileCfg.Database.MaxIdleConnections != 0 {
		cfg.MySQLMaxIdleConns = fileCfg.Database.MaxIdleConnections
	}
	if fileCfg.Queue.HeartbeatSeconds != 0 {
		cfg.HeartbeatInterval = time.Duration(fileCfg.Queue.HeartbeatSeconds) * time.Second
	}
	if fileCfg.Queue.LeaseSeconds != 0 {
		cfg.QueueLeaseInterval = time.Duration(fileCfg.Queue.LeaseSeconds) * time.Second
	}
	if fileCfg.Queue.PollSeconds != 0 {
		cfg.QueuePollInterval = time.Duration(fileCfg.Queue.PollSeconds) * time.Second
	}
	if fileCfg.Queue.HeavySlots != 0 {
		cfg.QueueHeavySlots = fileCfg.Queue.HeavySlots
	}
	if fileCfg.Queue.TrivySlots != 0 {
		cfg.QueueTrivySlots = fileCfg.Queue.TrivySlots
	}
	if fileCfg.Queue.NativeSlots != 0 {
		cfg.QueueNativeSlots = fileCfg.Queue.NativeSlots
	}
	if fileCfg.Storage.UploadsRoot != "" {
		cfg.UploadsRoot = fileCfg.Storage.UploadsRoot
	}
	if fileCfg.Storage.RepositoryRoot != "" {
		cfg.RepositoryRoot = fileCfg.Storage.RepositoryRoot
	}
	if fileCfg.Storage.TaskWorkRoot != "" {
		cfg.TaskWorkRoot = fileCfg.Storage.TaskWorkRoot
	}
	if fileCfg.Storage.MinimumFreeBytes != 0 {
		cfg.StorageMinFreeBytes = fileCfg.Storage.MinimumFreeBytes
	}
	cfg.ArchiveSandboxEnabled = fileCfg.ArchiveSandbox.Enabled
	if fileCfg.ArchiveSandbox.Socket != "" {
		cfg.ArchiveSandboxSocket = fileCfg.ArchiveSandbox.Socket
	}
	if fileCfg.ArchiveSandbox.InputRoot != "" {
		cfg.ArchiveSandboxInputRoot = fileCfg.ArchiveSandbox.InputRoot
	}
	if fileCfg.ArchiveSandbox.OutputRoot != "" {
		cfg.ArchiveSandboxOutputRoot = fileCfg.ArchiveSandbox.OutputRoot
	}
	if fileCfg.ArchiveSandbox.RunRoot != "" {
		cfg.ArchiveSandboxRunRoot = fileCfg.ArchiveSandbox.RunRoot
	}
	if fileCfg.ArchiveSandbox.TimeoutSeconds != 0 {
		cfg.ArchiveSandboxTimeout = time.Duration(
			fileCfg.ArchiveSandbox.TimeoutSeconds,
		) * time.Second
	}
	if fileCfg.Trivy.Executable != "" {
		cfg.TrivyExecutable = fileCfg.Trivy.Executable
	}
	if fileCfg.Trivy.Version != "" {
		cfg.TrivyVersion = fileCfg.Trivy.Version
	}
	if fileCfg.Trivy.DatabaseRoot != "" {
		cfg.TrivyDBRoot = fileCfg.Trivy.DatabaseRoot
	}
	if fileCfg.Trivy.MaxDurationSeconds != 0 {
		cfg.TrivyMaxDuration = time.Duration(
			fileCfg.Trivy.MaxDurationSeconds,
		) * time.Second
	}
	if fileCfg.Trivy.TerminationGraceSeconds != 0 {
		cfg.TrivyTerminationGrace = time.Duration(
			fileCfg.Trivy.TerminationGraceSeconds,
		) * time.Second
	}
	if fileCfg.Trivy.MaxStandardOutputBytes != 0 {
		cfg.TrivyMaxStandardOutputBytes =
			fileCfg.Trivy.MaxStandardOutputBytes
	}
	if fileCfg.Trivy.MaxStandardErrorBytes != 0 {
		cfg.TrivyMaxStandardErrorBytes =
			fileCfg.Trivy.MaxStandardErrorBytes
	}
	if fileCfg.Trivy.MaxReportBytes != 0 {
		cfg.TrivyMaxReportBytes = fileCfg.Trivy.MaxReportBytes
	}
	if fileCfg.Trivy.MaxResults != 0 {
		cfg.TrivyMaxResults = fileCfg.Trivy.MaxResults
	}
	if fileCfg.Trivy.MaxFindings != 0 {
		cfg.TrivyMaxFindings = fileCfg.Trivy.MaxFindings
	}
	if fileCfg.Ghidra.Executable != "" {
		cfg.GhidraExecutable = fileCfg.Ghidra.Executable
	}
	if fileCfg.Ghidra.ScriptDirectory != "" {
		cfg.GhidraScriptDirectory = fileCfg.Ghidra.ScriptDirectory
	}
	if fileCfg.Ghidra.Version != "" {
		cfg.GhidraVersion = fileCfg.Ghidra.Version
	}
	if fileCfg.Ghidra.JavaExecutable != "" {
		cfg.GhidraJavaExecutable = fileCfg.Ghidra.JavaExecutable
	}
	if fileCfg.Ghidra.JavaVersionLine != "" {
		cfg.GhidraJavaVersionLine = fileCfg.Ghidra.JavaVersionLine
	}
	if fileCfg.Ghidra.MaxDurationSeconds != 0 {
		cfg.GhidraMaxDuration =
			time.Duration(fileCfg.Ghidra.MaxDurationSeconds) * time.Second
	}
	if fileCfg.Ghidra.TerminationGraceSeconds != 0 {
		cfg.GhidraTerminationGrace =
			time.Duration(fileCfg.Ghidra.TerminationGraceSeconds) * time.Second
	}
	if fileCfg.Ghidra.MaxStandardOutputBytes != 0 {
		cfg.GhidraMaxStandardOutputBytes =
			fileCfg.Ghidra.MaxStandardOutputBytes
	}
	if fileCfg.Ghidra.MaxStandardErrorBytes != 0 {
		cfg.GhidraMaxStandardErrorBytes =
			fileCfg.Ghidra.MaxStandardErrorBytes
	}
	if fileCfg.Ghidra.MaxIndexBytes != 0 {
		cfg.GhidraMaxIndexBytes = fileCfg.Ghidra.MaxIndexBytes
	}
	if fileCfg.Ghidra.MaxOutputBytes != 0 {
		cfg.GhidraMaxOutputBytes = fileCfg.Ghidra.MaxOutputBytes
	}
	if fileCfg.Ghidra.MaxFunctions != 0 {
		cfg.GhidraMaxFunctions = fileCfg.Ghidra.MaxFunctions
	}
	if fileCfg.CAnalysis.CheckerURL != "" {
		cfg.CCheckerURL = fileCfg.CAnalysis.CheckerURL
	}
	if fileCfg.CAnalysis.CheckerVersion != "" {
		cfg.CCheckerVersion = fileCfg.CAnalysis.CheckerVersion
	}
	if fileCfg.CAnalysis.TimeoutSeconds != 0 {
		cfg.CAnalysisMaxDuration = time.Duration(fileCfg.CAnalysis.TimeoutSeconds) * time.Second
	}
	if fileCfg.CAnalysis.MaxResponseBytes != 0 {
		cfg.CAnalysisMaxResponseBytes = fileCfg.CAnalysis.MaxResponseBytes
	}
	if fileCfg.CAnalysis.MaxFindings != 0 {
		cfg.CAnalysisMaxFindings = fileCfg.CAnalysis.MaxFindings
	}
	if fileCfg.CAnalysis.MaxDiagnostics != 0 {
		cfg.CAnalysisMaxDiagnostics = fileCfg.CAnalysis.MaxDiagnostics
	}
	if fileCfg.JavaAnalysis.CheckerURL != "" {
		cfg.JavaCheckerURL = fileCfg.JavaAnalysis.CheckerURL
	}
	if fileCfg.JavaAnalysis.CheckerVersion != "" {
		cfg.JavaCheckerVersion = fileCfg.JavaAnalysis.CheckerVersion
	}
	if fileCfg.JavaAnalysis.TimeoutSeconds != 0 {
		cfg.JavaAnalysisMaxDuration =
			time.Duration(fileCfg.JavaAnalysis.TimeoutSeconds) * time.Second
	}
	if fileCfg.JavaAnalysis.MaxResponseBytes != 0 {
		cfg.JavaAnalysisMaxResponseBytes = fileCfg.JavaAnalysis.MaxResponseBytes
	}
	if fileCfg.JavaAnalysis.MaxFindings != 0 {
		cfg.JavaAnalysisMaxFindings = fileCfg.JavaAnalysis.MaxFindings
	}
	if fileCfg.JavaAnalysis.MaxDiagnostics != 0 {
		cfg.JavaAnalysisMaxDiagnostics = fileCfg.JavaAnalysis.MaxDiagnostics
	}
	if fileCfg.PythonAnalysis.CheckerURL != "" {
		cfg.PythonCheckerURL = fileCfg.PythonAnalysis.CheckerURL
	}
	if fileCfg.PythonAnalysis.CheckerVersion != "" {
		cfg.PythonCheckerVersion = fileCfg.PythonAnalysis.CheckerVersion
	}
	if fileCfg.PythonAnalysis.TimeoutSeconds != 0 {
		cfg.PythonAnalysisMaxDuration =
			time.Duration(fileCfg.PythonAnalysis.TimeoutSeconds) * time.Second
	}
	if fileCfg.PythonAnalysis.MaxResponseBytes != 0 {
		cfg.PythonAnalysisMaxResponseBytes = fileCfg.PythonAnalysis.MaxResponseBytes
	}
	if fileCfg.PythonAnalysis.MaxFindings != 0 {
		cfg.PythonAnalysisMaxFindings = fileCfg.PythonAnalysis.MaxFindings
	}
	if fileCfg.PythonAnalysis.MaxDiagnostics != 0 {
		cfg.PythonAnalysisMaxDiagnostics = fileCfg.PythonAnalysis.MaxDiagnostics
	}
	if fileCfg.Limits.MaxUploadBytes != 0 {
		cfg.MaxUploadBytes = fileCfg.Limits.MaxUploadBytes
	}
	if fileCfg.Limits.MaxExpandedBytes != 0 {
		cfg.MaxExpandedBytes = fileCfg.Limits.MaxExpandedBytes
	}
	if fileCfg.Limits.MaxArchiveRatio != 0 {
		cfg.MaxArchiveRatio = fileCfg.Limits.MaxArchiveRatio
	}
	if fileCfg.Limits.MaxDepth != 0 {
		cfg.MaxDepth = fileCfg.Limits.MaxDepth
	}
	if fileCfg.Limits.MaxFileNodes != 0 {
		cfg.MaxFileNodes = fileCfg.Limits.MaxFileNodes
	}
	if fileCfg.Limits.MaxNestedImages != 0 {
		cfg.MaxNestedImages = fileCfg.Limits.MaxNestedImages
	}
	if fileCfg.Retention.IncompleteUploadHours != 0 {
		cfg.IncompleteUploadRetention = time.Duration(fileCfg.Retention.IncompleteUploadHours) * time.Hour
	}
	if fileCfg.Retention.SampleDays != 0 {
		cfg.SampleRetention = time.Duration(fileCfg.Retention.SampleDays) * 24 * time.Hour
	}
	cfg.CookieSecure = fileCfg.Auth.CookieSecure
	if fileCfg.Auth.SessionTTLHours != 0 {
		cfg.SessionTTL = time.Duration(fileCfg.Auth.SessionTTLHours) * time.Hour
	}
	if fileCfg.Auth.LoginFailureThreshold != 0 {
		cfg.LoginFailureThreshold = fileCfg.Auth.LoginFailureThreshold
	}
	if fileCfg.Auth.LoginLockMinutes != 0 {
		cfg.LoginLockDuration = time.Duration(fileCfg.Auth.LoginLockMinutes) * time.Minute
	}
	if fileCfg.Auth.LoginRateLimitThreshold != 0 {
		cfg.LoginRateLimitThreshold =
			fileCfg.Auth.LoginRateLimitThreshold
	}
	if fileCfg.Auth.LoginRateLimitWindowSeconds != 0 {
		cfg.LoginRateLimitWindow = time.Duration(
			fileCfg.Auth.LoginRateLimitWindowSeconds,
		) * time.Second
	}
	if fileCfg.Auth.LoginRateLimitBlockSeconds != 0 {
		cfg.LoginRateLimitBlock = time.Duration(
			fileCfg.Auth.LoginRateLimitBlockSeconds,
		) * time.Second
	}
	if fileCfg.Auth.PasswordMinimumBytes != 0 {
		cfg.AuthPasswordMinimumBytes = fileCfg.Auth.PasswordMinimumBytes
	}
	if fileCfg.Auth.Argon2MemoryKiB != 0 {
		cfg.Argon2MemoryKiB = fileCfg.Auth.Argon2MemoryKiB
	}
	if fileCfg.Auth.Argon2Iterations != 0 {
		cfg.Argon2Iterations = fileCfg.Auth.Argon2Iterations
	}
	if fileCfg.Auth.Argon2Parallelism != 0 {
		cfg.Argon2Parallelism = fileCfg.Auth.Argon2Parallelism
	}
	cfg.RawSampleDownloadEnabled =
		fileCfg.Features.RawSampleDownloadEnabled
	if fileCfg.Logging.Format != "" {
		cfg.LogFormat = fileCfg.Logging.Format
	}
	if fileCfg.Logging.Directory != "" {
		cfg.LogDir = fileCfg.Logging.Directory
	}
	if fileCfg.Logging.MaxSizeMB != 0 {
		cfg.LogMaxSizeMB = fileCfg.Logging.MaxSizeMB
	}
	if fileCfg.Logging.MaxBackups != 0 {
		cfg.LogMaxBackups = fileCfg.Logging.MaxBackups
	}
	if fileCfg.Logging.MaxAgeDays != 0 {
		cfg.LogMaxAgeDays = fileCfg.Logging.MaxAgeDays
	}
}

func applyEnvironment(cfg *Config) error {
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_HTTP_ADDR")); value != "" {
		cfg.HTTPAddr = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_LOG_LEVEL")); value != "" {
		cfg.LogLevel = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_LOG_DIR")); value != "" {
		cfg.LogDir = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_AUTH_PASSWORD_MIN_BYTES")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_AUTH_PASSWORD_MIN_BYTES must be an integer: %w",
				err,
			)
		}
		cfg.AuthPasswordMinimumBytes = parsed
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_UPLOAD_ROOT")); value != "" {
		cfg.UploadsRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_REPOSITORY_ROOT")); value != "" {
		cfg.RepositoryRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TASK_WORK_ROOT")); value != "" {
		cfg.TaskWorkRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_SANDBOX_ENABLED")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_ARCHIVE_SANDBOX_ENABLED must be a boolean: %w",
				err,
			)
		}
		cfg.ArchiveSandboxEnabled = parsed
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_SOCKET")); value != "" {
		cfg.ArchiveSandboxSocket = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_INPUT_ROOT")); value != "" {
		cfg.ArchiveSandboxInputRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_OUTPUT_ROOT")); value != "" {
		cfg.ArchiveSandboxOutputRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_SANDBOX_RUN_ROOT")); value != "" {
		cfg.ArchiveSandboxRunRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_ARCHIVE_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.ArchiveSandboxTimeout = -1
		} else {
			cfg.ArchiveSandboxTimeout = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TRIVY_EXECUTABLE")); value != "" {
		cfg.TrivyExecutable = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TRIVY_VERSION")); value != "" {
		cfg.TrivyVersion = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TRIVY_DB_ROOT")); value != "" {
		cfg.TrivyDBRoot = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_EXECUTABLE")); value != "" {
		cfg.GhidraExecutable = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_SCRIPT_DIRECTORY")); value != "" {
		cfg.GhidraScriptDirectory = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_VERSION")); value != "" {
		cfg.GhidraVersion = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_JAVA_EXECUTABLE")); value != "" {
		cfg.GhidraJavaExecutable = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_JAVA_VERSION_LINE")); value != "" {
		cfg.GhidraJavaVersionLine = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_C_CHECKER_URL")); value != "" {
		cfg.CCheckerURL = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_C_CHECKER_VERSION")); value != "" {
		cfg.CCheckerVersion = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_C_ANALYSIS_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.CAnalysisMaxDuration = -1
		} else {
			cfg.CAnalysisMaxDuration = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_JAVA_CHECKER_URL")); value != "" {
		cfg.JavaCheckerURL = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_JAVA_CHECKER_VERSION")); value != "" {
		cfg.JavaCheckerVersion = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_PYTHON_CHECKER_URL")); value != "" {
		cfg.PythonCheckerURL = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_PYTHON_CHECKER_VERSION")); value != "" {
		cfg.PythonCheckerVersion = value
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_PYTHON_ANALYSIS_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.PythonAnalysisMaxDuration = -1
		} else {
			cfg.PythonAnalysisMaxDuration = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_PYTHON_ANALYSIS_MAX_RESPONSE_BYTES")); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			cfg.PythonAnalysisMaxResponseBytes = -1
		} else {
			cfg.PythonAnalysisMaxResponseBytes = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_JAVA_ANALYSIS_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.JavaAnalysisMaxDuration = -1
		} else {
			cfg.JavaAnalysisMaxDuration = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_MAX_DURATION")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.GhidraMaxDuration = -1
		} else {
			cfg.GhidraMaxDuration = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_GHIDRA_TERMINATION_GRACE")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.GhidraTerminationGrace = -1
		} else {
			cfg.GhidraTerminationGrace = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TRIVY_MAX_DURATION")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.TrivyMaxDuration = -1
		} else {
			cfg.TrivyMaxDuration = parsed
		}
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_TRIVY_TERMINATION_GRACE")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.TrivyTerminationGrace = -1
		} else {
			cfg.TrivyTerminationGrace = parsed
		}
	}
	cfg.StorageMinFreeBytes = int64OrFallback(
		"BINARYSCAN_STORAGE_MIN_FREE_BYTES",
		cfg.StorageMinFreeBytes,
	)
	cfg.TrivyMaxStandardOutputBytes = int64OrFallback(
		"BINARYSCAN_TRIVY_MAX_STANDARD_OUTPUT_BYTES",
		cfg.TrivyMaxStandardOutputBytes,
	)
	cfg.TrivyMaxStandardErrorBytes = int64OrFallback(
		"BINARYSCAN_TRIVY_MAX_STANDARD_ERROR_BYTES",
		cfg.TrivyMaxStandardErrorBytes,
	)
	cfg.TrivyMaxReportBytes = int64OrFallback(
		"BINARYSCAN_TRIVY_MAX_REPORT_BYTES",
		cfg.TrivyMaxReportBytes,
	)
	cfg.TrivyMaxResults = intOrFallback(
		"BINARYSCAN_TRIVY_MAX_RESULTS",
		cfg.TrivyMaxResults,
	)
	cfg.TrivyMaxFindings = intOrFallback(
		"BINARYSCAN_TRIVY_MAX_FINDINGS",
		cfg.TrivyMaxFindings,
	)
	cfg.GhidraMaxStandardOutputBytes = int64OrFallback(
		"BINARYSCAN_GHIDRA_MAX_STANDARD_OUTPUT_BYTES",
		cfg.GhidraMaxStandardOutputBytes,
	)
	cfg.GhidraMaxStandardErrorBytes = int64OrFallback(
		"BINARYSCAN_GHIDRA_MAX_STANDARD_ERROR_BYTES",
		cfg.GhidraMaxStandardErrorBytes,
	)
	cfg.GhidraMaxIndexBytes = int64OrFallback(
		"BINARYSCAN_GHIDRA_MAX_INDEX_BYTES", cfg.GhidraMaxIndexBytes,
	)
	cfg.GhidraMaxOutputBytes = int64OrFallback(
		"BINARYSCAN_GHIDRA_MAX_OUTPUT_BYTES", cfg.GhidraMaxOutputBytes,
	)
	cfg.GhidraMaxFunctions = intOrFallback(
		"BINARYSCAN_GHIDRA_MAX_FUNCTIONS", cfg.GhidraMaxFunctions,
	)
	cfg.CAnalysisMaxResponseBytes = int64OrFallback(
		"BINARYSCAN_C_ANALYSIS_MAX_RESPONSE_BYTES", cfg.CAnalysisMaxResponseBytes,
	)
	cfg.CAnalysisMaxFindings = intOrFallback(
		"BINARYSCAN_C_ANALYSIS_MAX_FINDINGS", cfg.CAnalysisMaxFindings,
	)
	cfg.CAnalysisMaxDiagnostics = intOrFallback(
		"BINARYSCAN_C_ANALYSIS_MAX_DIAGNOSTICS", cfg.CAnalysisMaxDiagnostics,
	)
	cfg.JavaAnalysisMaxResponseBytes = int64OrFallback(
		"BINARYSCAN_JAVA_ANALYSIS_MAX_RESPONSE_BYTES",
		cfg.JavaAnalysisMaxResponseBytes,
	)
	cfg.JavaAnalysisMaxFindings = intOrFallback(
		"BINARYSCAN_JAVA_ANALYSIS_MAX_FINDINGS", cfg.JavaAnalysisMaxFindings,
	)
	cfg.JavaAnalysisMaxDiagnostics = intOrFallback(
		"BINARYSCAN_JAVA_ANALYSIS_MAX_DIAGNOSTICS",
		cfg.JavaAnalysisMaxDiagnostics,
	)
	cfg.QueueHeavySlots = intOrFallback(
		"BINARYSCAN_QUEUE_HEAVY_SLOTS",
		cfg.QueueHeavySlots,
	)
	cfg.QueueTrivySlots = intOrFallback(
		"BINARYSCAN_QUEUE_TRIVY_SLOTS",
		cfg.QueueTrivySlots,
	)
	cfg.QueueNativeSlots = intOrFallback(
		"BINARYSCAN_QUEUE_NATIVE_SLOTS",
		cfg.QueueNativeSlots,
	)
	if value := strings.TrimSpace(
		os.Getenv("BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD"),
	); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_LOGIN_RATE_LIMIT_THRESHOLD must be an integer: %w",
				err,
			)
		}
		cfg.LoginRateLimitThreshold = uint32(parsed)
	}
	if value := strings.TrimSpace(
		os.Getenv("BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS"),
	); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_LOGIN_RATE_LIMIT_WINDOW_SECONDS must be an integer: %w",
				err,
			)
		}
		cfg.LoginRateLimitWindow =
			time.Duration(parsed) * time.Second
	}
	if value := strings.TrimSpace(
		os.Getenv("BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS"),
	); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_LOGIN_RATE_LIMIT_BLOCK_SECONDS must be an integer: %w",
				err,
			)
		}
		cfg.LoginRateLimitBlock =
			time.Duration(parsed) * time.Second
	}
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_COOKIE_SECURE")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("BINARYSCAN_COOKIE_SECURE must be a boolean: %w", err)
		}
		cfg.CookieSecure = parsed
	}
	if value := strings.TrimSpace(
		os.Getenv("BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED"),
	); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf(
				"BINARYSCAN_RAW_SAMPLE_DOWNLOAD_ENABLED must be a boolean: %w",
				err,
			)
		}
		cfg.RawSampleDownloadEnabled = parsed
	}
	cfg.MySQLMaxOpenConns = intOrFallback("BINARYSCAN_MYSQL_MAX_OPEN_CONNS", cfg.MySQLMaxOpenConns)
	cfg.MySQLMaxIdleConns = intOrFallback("BINARYSCAN_MYSQL_MAX_IDLE_CONNS", cfg.MySQLMaxIdleConns)
	if value := strings.TrimSpace(os.Getenv("BINARYSCAN_HEARTBEAT_INTERVAL")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			cfg.HeartbeatInterval = -1
		} else {
			cfg.HeartbeatInterval = parsed
		}
	}
	return nil
}

func int64OrFallback(name string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return -1
	}
	return parsed
}

func validToolVersion(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, current := range value {
		if (current >= 'a' && current <= 'z') ||
			(current >= 'A' && current <= 'Z') ||
			(current >= '0' && current <= '9') ||
			current == '.' || current == '_' ||
			current == '+' || current == '-' {
			continue
		}
		return false
	}
	return true
}

func pathsOverlap(first, second string) bool {
	relative, err := filepath.Rel(first, second)
	if err == nil &&
		(relative == "." ||
			(relative != ".." &&
				!strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil &&
		(relative == "." ||
			(relative != ".." &&
				!strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func validRootPath(value string) bool {
	return filepath.IsAbs(value) &&
		filepath.Clean(value) != string(filepath.Separator) &&
		filepath.Clean(value) == value
}

func appendRootOverlapError(
	errs []error,
	roots map[string]string,
	first string,
	second string,
) []error {
	firstPath := roots[first]
	secondPath := roots[second]
	if validRootPath(firstPath) &&
		validRootPath(secondPath) &&
		pathsOverlap(firstPath, secondPath) {
		return append(
			errs,
			fmt.Errorf("%s and %s must not overlap", first, second),
		)
	}
	return errs
}
