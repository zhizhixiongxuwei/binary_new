package bytecode

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRoutingEngineRoutesAndBindsChildDescriptors(t *testing.T) {
	jvm := EngineFunc{
		EngineDescriptor: Descriptor{Name: "jvm-child", Version: "1.2.3"},
		SupportedFormats: []Format{FormatClass, FormatJAR},
		Run: func(context.Context, Request) (Output, error) {
			return Output{Status: StatusUnsupported, Warnings: []string{"jvm"}}, nil
		},
	}
	pyc := EngineFunc{
		EngineDescriptor: Descriptor{Name: "pyc-child", Version: "4.5.6"},
		SupportedFormats: []Format{FormatPYC},
		Run: func(context.Context, Request) (Output, error) {
			return Output{Status: StatusUnsupported, Warnings: []string{"pyc"}}, nil
		},
	}
	router, err := NewRoutingEngine(jvm, pyc)
	if err != nil {
		t.Fatal(err)
	}
	if router.Descriptor().Name != RoutingEngineName ||
		!strings.Contains(router.Descriptor().Version, "1.0.0-cfg") ||
		len(router.ConfigFingerprint()) != 64 || !router.Supports(FormatClass) ||
		!router.Supports(FormatPYC) || router.Supports(FormatAPK) {
		t.Fatalf("routing identity/capabilities = %#v", router)
	}
	output, err := router.Decompile(context.Background(), Request{
		Input: Input{Format: FormatPYC},
	})
	if err != nil || !strings.Contains(strings.Join(output.Warnings, ""), "pyc") {
		t.Fatalf("PYC route = %#v, %v", output, err)
	}

	reordered, err := NewRoutingEngine(pyc, jvm)
	if err != nil || reordered.Descriptor() != router.Descriptor() ||
		reordered.ConfigFingerprint() != router.ConfigFingerprint() {
		t.Fatalf("route order changed identity: %#v, %v", reordered, err)
	}
	pyc.EngineDescriptor.Version = "4.5.7"
	upgraded, err := NewRoutingEngine(jvm, pyc)
	if err != nil || upgraded.ConfigFingerprint() == router.ConfigFingerprint() ||
		upgraded.Descriptor() == router.Descriptor() {
		t.Fatalf("child upgrade did not change identity: %#v, %v", upgraded, err)
	}
	_, err = NewRoutingEngine(jvm, EngineFunc{
		EngineDescriptor: Descriptor{Name: "duplicate", Version: "1.0.0"},
		SupportedFormats: []Format{FormatClass}, Run: func(
			context.Context, Request,
		) (Output, error) {
			return Output{}, nil
		},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("duplicate route error = %v", err)
	}
}
