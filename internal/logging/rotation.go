package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const logRetentionDays = 30

type dailyLogWriter struct {
	mu          sync.Mutex
	directory   string
	prefix      string
	now         func() time.Time
	currentDate string
	file        *os.File
}

func newDailyLogWriter(
	directory string,
	prefix string,
	now func() time.Time,
) (*dailyLogWriter, error) {
	if now == nil {
		return nil, errors.New("log rotation clock is required")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect log directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("log path must be a non-symlink directory")
	}
	writer := &dailyLogWriter{
		directory: filepath.Clean(directory),
		prefix:    prefix,
		now:       now,
	}
	if err := writer.prune(now().UTC()); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *dailyLogWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	date := w.now().UTC().Format(time.DateOnly)
	if w.file == nil || w.currentDate != date {
		if err := w.rotate(date); err != nil {
			return 0, err
		}
	}
	return w.file.Write(value)
}

func (w *dailyLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	w.currentDate = ""
	return err
}

func (w *dailyLogWriter) rotate(date string) error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("close previous structured log: %w", err)
		}
		w.file = nil
	}
	if err := w.prune(w.now().UTC()); err != nil {
		return err
	}
	path := filepath.Join(w.directory, w.prefix+"-"+date+".jsonl")
	fd, err := unix.Open(
		path,
		unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("open structured log file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("create structured log file handle")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("inspect structured log file: %w", err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return errors.New("structured log path is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("set structured log permissions: %w", err)
	}
	w.file = file
	w.currentDate = date
	return nil
}

func (w *dailyLogWriter) prune(now time.Time) error {
	entries, err := os.ReadDir(w.directory)
	if err != nil {
		return fmt.Errorf("list structured logs: %w", err)
	}
	cutoff, err := time.Parse(
		time.DateOnly,
		now.UTC().AddDate(0, 0, -logRetentionDays).Format(time.DateOnly),
	)
	if err != nil {
		return fmt.Errorf("calculate structured log retention cutoff: %w", err)
	}
	filePrefix := w.prefix + "-"
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, filePrefix) ||
			!strings.HasSuffix(name, ".jsonl") ||
			entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		dateText := strings.TrimSuffix(
			strings.TrimPrefix(name, filePrefix),
			".jsonl",
		)
		date, err := time.Parse(time.DateOnly, dateText)
		if err != nil || date.Format(time.DateOnly) != dateText ||
			!date.Before(cutoff) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect expired structured log: %w", err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(w.directory, name)); err != nil {
			return fmt.Errorf("remove expired structured log: %w", err)
		}
	}
	return nil
}

var _ io.WriteCloser = (*dailyLogWriter)(nil)
