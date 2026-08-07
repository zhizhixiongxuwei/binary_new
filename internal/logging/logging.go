package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

func New(service, level, logDir string) (*slog.Logger, io.Closer, error) {
	writer := io.Writer(os.Stdout)
	var closer io.Closer = io.NopCloser(nilReader{})

	if logDir != "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, nil, fmt.Errorf("read hostname: %w", err)
		}
		prefix := fmt.Sprintf("%s-%s", sanitize(service), sanitize(hostname))
		file, err := newDailyLogWriter(logDir, prefix, time.Now)
		if err != nil {
			return nil, nil, err
		}
		writer = io.MultiWriter(os.Stdout, file)
		closer = file
	}

	hostname, _ := os.Hostname()
	handler := newRedactingHandler(
		slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: parseLevel(level)}),
	)
	logger := slog.New(handler).With(
		slog.String("service", service),
		slog.String("instance", hostname),
	)
	return logger, closer, nil
}

func parseLevel(value string) slog.Level {
	switch strings.ToLower(value) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func sanitize(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }
