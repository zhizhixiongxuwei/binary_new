package logging

import (
	"context"
	"log/slog"
	"strings"
	"unicode"
)

const redactedValue = "[REDACTED]"

type redactingHandler struct {
	next slog.Handler
}

func newRedactingHandler(next slog.Handler) slog.Handler {
	return redactingHandler{next: next}
}

func (h redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attribute slog.Attr) bool {
		clean.AddAttrs(redactAttribute(attribute))
		return true
	})
	return h.next.Handle(ctx, clean)
}

func (h redactingHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, 0, len(attributes))
	for _, attribute := range attributes {
		clean = append(clean, redactAttribute(attribute))
	}
	return redactingHandler{next: h.next.WithAttrs(clean)}
}

func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{next: h.next.WithGroup(name)}
}

func redactAttribute(attribute slog.Attr) slog.Attr {
	if attribute.Equal(slog.Attr{}) {
		return attribute
	}
	if sensitiveLogKey(attribute.Key) {
		return slog.String(attribute.Key, redactedValue)
	}
	value := attribute.Value.Resolve()
	if value.Kind() != slog.KindGroup {
		attribute.Value = value
		return attribute
	}
	group := value.Group()
	clean := make([]slog.Attr, 0, len(group))
	for _, nested := range group {
		clean = append(clean, redactAttribute(nested))
	}
	attribute.Value = slog.GroupValue(clean...)
	return attribute
}

func sensitiveLogKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return false
	}
	switch normalized {
	case "session_count", "token_count":
		return false
	}
	switch normalized {
	case "authorization", "proxy-authorization", "proxy_authorization",
		"cookie", "set-cookie", "set_cookie", "request_body", "response_body",
		"request_headers", "response_headers", "headers", "credentials",
		"payload", "sample_content", "sample_bytes", "source_content",
		"source_code":
		return true
	}
	for _, token := range strings.FieldsFunc(normalized, func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	}) {
		switch token {
		case "password", "passwd", "secret", "token", "session", "cookie":
			return true
		}
	}
	return false
}
