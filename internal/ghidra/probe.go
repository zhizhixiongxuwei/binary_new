package ghidra

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const installationMetadataLimit = 1 << 20

var javaVersionLinePattern = regexp.MustCompile(
	`^(?:openjdk|java) version "([^"]+)"(?: ([0-9]{4}-[0-9]{2}-[0-9]{2}))?(?: .*)?$`,
)

// ProbeInstallation verifies immutable runtime metadata and the export script
// without starting Java. The native worker stays lightweight until it claims a
// decompilation job.
func ProbeInstallation(
	ghidraExecutable string,
	ghidraScriptDirectory string,
	expectedGhidraVersion string,
	javaExecutable string,
	expectedJavaVersionLine string,
) error {
	for name, value := range map[string]string{
		"Ghidra executable": ghidraExecutable,
		"Java executable":   javaExecutable,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s path is not canonical and absolute", name)
		}
		if err := verifyExecutableFile(value, name == "Java executable"); err != nil {
			return fmt.Errorf("%s is invalid: %w", name, err)
		}
	}
	if err := verifyScriptDirectory(ghidraScriptDirectory); err != nil {
		return fmt.Errorf("Ghidra script directory is invalid: %w", err)
	}
	if expectedGhidraVersion == "" || strings.TrimSpace(expectedGhidraVersion) != expectedGhidraVersion {
		return errors.New("expected Ghidra version is invalid")
	}
	ghidraRoot := filepath.Dir(filepath.Dir(ghidraExecutable))
	properties, err := readMetadata(
		filepath.Join(ghidraRoot, "Ghidra", "application.properties"),
		false,
	)
	if err != nil {
		return fmt.Errorf("read Ghidra application metadata: %w", err)
	}
	if properties["application.name"] != "Ghidra" ||
		properties["application.version"] != expectedGhidraVersion {
		return errors.New("Ghidra application metadata does not match the configured version")
	}

	match := javaVersionLinePattern.FindStringSubmatch(expectedJavaVersionLine)
	if match == nil || strings.TrimSpace(expectedJavaVersionLine) != expectedJavaVersionLine {
		return errors.New("expected Java version line is invalid")
	}
	javaRoot := filepath.Dir(filepath.Dir(javaExecutable))
	release, err := readMetadata(filepath.Join(javaRoot, "release"), true)
	if err != nil {
		return fmt.Errorf("read Java release metadata: %w", err)
	}
	if release["JAVA_VERSION"] != match[1] ||
		(match[2] != "" && release["JAVA_VERSION_DATE"] != match[2]) ||
		release["OS_NAME"] != "Linux" || release["OS_ARCH"] != "x86_64" {
		return errors.New("Java release metadata does not match the configured runtime")
	}
	return nil
}

func verifyScriptDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		directory == string(filepath.Separator) {
		return errors.New("path is not canonical and absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}
	filename := filepath.Join(directory, exportScriptFilename)
	info, err = os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > installationMetadataLimit {
		return errors.New("export script is not a bounded regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	return file.Close()
}

func verifyExecutableFile(filename string, requireELFAMD64 bool) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("path is not a non-empty executable regular file")
	}
	if !requireELFAMD64 {
		return nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	header := make([]byte, 20)
	if _, err := io.ReadFull(file, header); err != nil {
		return err
	}
	if !bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) ||
		header[4] != 2 || header[5] != 1 || header[6] != 1 ||
		binary.LittleEndian.Uint16(header[18:20]) != 62 {
		return errors.New("path is not a Linux ELF64 x86-64 executable")
	}
	return nil
}

func readMetadata(filename string, quoted bool) (map[string]string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > installationMetadataLimit {
		return nil, errors.New("metadata is not a bounded regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(io.LimitReader(file, installationMetadataLimit+1))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != name || name == "" {
			return nil, errors.New("metadata contains a malformed line")
		}
		if quoted {
			if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' ||
				strings.ContainsAny(value[1:len(value)-1], "\"\r\n") {
				return nil, errors.New("release metadata contains an invalid quoted value")
			}
			value = value[1 : len(value)-1]
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("metadata contains a duplicate key")
		}
		values[name] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func ProbeVersion(
	ctx context.Context,
	executable string,
	expectedLine string,
	timeout time.Duration,
	grace time.Duration,
) error {
	if executable == "" || expectedLine == "" || timeout <= 0 || grace <= 0 {
		return errors.New("tool version probe input is invalid")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := newBoundedBuffer(64<<10, nil)
	command := exec.Command(executable, "-version")
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start version probe: %w", err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	var err error
	select {
	case err = <-wait:
	case <-probeCtx.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		timer := time.NewTimer(grace)
		select {
		case err = <-wait:
			timer.Stop()
		case <-timer.C:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			err = <-wait
		}
		return probeCtx.Err()
	}
	if err != nil {
		return fmt.Errorf("version probe failed: %w", err)
	}
	if output.exceeded {
		return ErrOutputLimit
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.TrimSpace(line) == expectedLine {
			return nil
		}
	}
	return fmt.Errorf(
		"tool version mismatch: expected exact line %q", expectedLine,
	)
}
