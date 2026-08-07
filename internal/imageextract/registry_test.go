package imageextract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestRegistryCanonicalRoutingAndSnapshot(t *testing.T) {
	registry := NewRegistry()
	raw := ExtractorFunc(func(context.Context, Request, Sink) error { return nil })
	if err := registry.Register(" RAW-IMG ", raw); err != nil {
		t.Fatalf("register raw: %v", err)
	}
	if _, found := registry.Lookup("raw-img"); !found {
		t.Fatal("canonical lookup did not find extractor")
	}
	if err := registry.Register("raw-img", raw); !errors.Is(err, ErrDuplicateFormat) {
		t.Fatalf("duplicate error = %v", err)
	}

	engine, err := NewEngine(registry, Limits{})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if err := registry.Register("iso9660", raw); err != nil {
		t.Fatalf("register after snapshot: %v", err)
	}
	if got := engine.Formats(); !slices.Equal(got, []string{"raw-img"}) {
		t.Fatalf("engine formats = %v", got)
	}
	formats := engine.Formats()
	formats[0] = "changed"
	if got := engine.Formats()[0]; got != "raw-img" {
		t.Fatalf("formats result aliases engine state: %q", got)
	}
	_, err = engine.Extract(context.Background(), Request{
		Format: "iso9660", Source: bytes.NewReader(nil), SizeBytes: 0,
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("late registration affected engine: %v", err)
	}
}

func TestRegistryRejectsInvalidRegistrations(t *testing.T) {
	extractor := ExtractorFunc(func(context.Context, Request, Sink) error { return nil })
	for _, format := range []string{"", "-raw", "raw image", "raw/image", "\x00raw"} {
		if err := NewRegistry().Register(format, extractor); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("format %q error = %v", format, err)
		}
	}
	if err := NewRegistry().Register("raw", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil extractor error = %v", err)
	}
	var nilRegistry *Registry
	if err := nilRegistry.Register("raw", extractor); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil registry error = %v", err)
	}
	if formats := nilRegistry.Formats(); formats == nil || len(formats) != 0 {
		t.Fatalf("nil registry formats = %#v", formats)
	}
}

func TestRegistryConcurrentLookup(t *testing.T) {
	registry := NewRegistry()
	extractor := ExtractorFunc(func(context.Context, Request, Sink) error { return nil })
	const count = 32
	done := make(chan struct{}, count*2)
	for index := 0; index < count; index++ {
		format := fmt.Sprintf("format-%02d", index)
		go func() {
			_ = registry.Register(format, extractor)
			done <- struct{}{}
		}()
		go func() {
			registry.Lookup(format)
			done <- struct{}{}
		}()
	}
	for index := 0; index < count*2; index++ {
		<-done
	}
	if len(registry.Formats()) != count {
		t.Fatalf("registered formats = %d", len(registry.Formats()))
	}
}
