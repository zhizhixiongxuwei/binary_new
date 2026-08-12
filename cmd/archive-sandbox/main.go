package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"binaryscan/internal/archivesandbox"
	"binaryscan/internal/config"
)

const (
	defaultFileExecutable     = "/usr/bin/file"
	defaultBSDTarExecutable   = "/usr/bin/bsdtar"
	defaultSevenZipExecutable = "/usr/bin/7zz"
	fileVersion               = "5.46"
	libarchiveVersion         = "3.8.3"
	sevenZipVersion           = "24.09"
)

func main() {
	if handled, err := archivesandbox.MaybeRunToolLauncher(os.Args); handled {
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "binaryscan-archive-tool-launcher: %v\n", err)
			os.Exit(126)
		}
		return
	}
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "binaryscan-archive-sandbox: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("archive-sandbox")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if !cfg.ArchiveSandboxEnabled {
		return errors.New("archive sandbox is disabled")
	}
	runRoot := cfg.ArchiveSandboxRunRoot
	for _, root := range []string{
		cfg.ArchiveSandboxInputRoot, cfg.ArchiveSandboxOutputRoot, runRoot,
	} {
		if err := ensurePrivateDirectory(root); err != nil {
			return err
		}
	}
	fileTool, err := verifiedTool(
		envOrDefault("BINARYSCAN_FILE_EXECUTABLE", defaultFileExecutable),
		[]string{"--version"}, fileVersion,
	)
	if err != nil {
		return fmt.Errorf("verify libmagic frontend: %w", err)
	}
	archiveTool, err := verifiedTool(
		envOrDefault("BINARYSCAN_BSDTAR_EXECUTABLE", defaultBSDTarExecutable),
		[]string{"--version"}, libarchiveVersion,
	)
	if err != nil {
		return fmt.Errorf("verify libarchive frontend: %w", err)
	}
	sevenZipTool, err := verifiedTool(
		envOrDefault("BINARYSCAN_7ZZ_EXECUTABLE", defaultSevenZipExecutable),
		[]string{"-h"}, sevenZipVersion,
	)
	if err != nil {
		return fmt.Errorf("verify 7zz: %w", err)
	}
	server, err := archivesandbox.NewServer(archivesandbox.ServerConfig{
		SocketPath: cfg.ArchiveSandboxSocket, SocketMode: 0o600,
		InputRoot: cfg.ArchiveSandboxInputRoot, OutputRoot: cfg.ArchiveSandboxOutputRoot,
		RunRoot: runRoot, LibmagicExecutable: fileTool, LibmagicVersion: fileVersion,
		LibarchiveExecutable: archiveTool, LibarchiveVersion: libarchiveVersion,
		SevenZipExecutable: sevenZipTool, SevenZipVersion: sevenZipVersion,
		MaxConcurrent: 1, TerminationGrace: 10 * time.Second,
		MonitorInterval:    100 * time.Millisecond,
		MaxDiagnosticBytes: 1 << 20,
	})
	if err != nil {
		return fmt.Errorf("initialize archive sandbox: %w", err)
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx)
}

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("archive sandbox directory is invalid")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create archive sandbox directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox directory is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure archive sandbox directory: %w", err)
		}
	}
	return nil
}

func verifiedTool(path string, arguments []string, expectedVersion string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || expectedVersion == "" {
		return "", errors.New("archive tool configuration is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("archive tool path cannot be resolved")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("archive tool is not a regular executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, resolved, arguments...)
	command.Env = []string{"HOME=/tmp", "PATH=/usr/bin:/bin", "TZ=UTC", "LANG=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("execute version probe: %w", err)
	}
	if len(output) > 64<<10 || !strings.Contains(string(output), expectedVersion) {
		return "", fmt.Errorf("tool version does not contain %q", expectedVersion)
	}
	return resolved, nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
