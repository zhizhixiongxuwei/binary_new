package bytecode

import (
	"errors"
	"strings"
	"testing"
)

func TestCacheKeyIsDeterministicAndBoundarySafe(t *testing.T) {
	digest := strings.Repeat("a", 64)
	descriptor := Descriptor{Name: "vineflower", Version: "1.11.1"}
	first, err := CacheKey(
		digest, FormatJAR, descriptor, []string{"--one", "a b", ""}, Limits{},
	)
	if err != nil {
		t.Fatalf("CacheKey() error = %v", err)
	}
	second, err := CacheKey(
		digest, FormatJAR, descriptor, []string{"--one", "a b", ""}, Limits{},
	)
	if err != nil || first != second || len(first) != 64 {
		t.Fatalf("CacheKey() = %q, %v; repeated = %q", first, err, second)
	}

	variants := []struct {
		name       string
		digest     string
		format     Format
		descriptor Descriptor
		arguments  []string
	}{
		{"input", strings.Repeat("b", 64), FormatJAR, descriptor, []string{"--one", "a b", ""}},
		{"format", digest, FormatWAR, descriptor, []string{"--one", "a b", ""}},
		{"engine", digest, FormatJAR, Descriptor{Name: "cfr", Version: "1.11.1"}, []string{"--one", "a b", ""}},
		{"version", digest, FormatJAR, Descriptor{Name: "vineflower", Version: "1.11.2"}, []string{"--one", "a b", ""}},
		{"order", digest, FormatJAR, descriptor, []string{"a b", "--one", ""}},
		{"boundary", digest, FormatJAR, descriptor, []string{"--onea", " b", ""}},
		{"empty", digest, FormatJAR, descriptor, []string{"--one", "a b"}},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			key, err := CacheKey(
				variant.digest, variant.format, variant.descriptor,
				variant.arguments, Limits{},
			)
			if err != nil {
				t.Fatalf("CacheKey() error = %v", err)
			}
			if key == first {
				t.Fatalf("CacheKey() did not bind %s", variant.name)
			}
		})
	}
}

func TestCacheKeyRejectsInvalidMaterial(t *testing.T) {
	validDigest := strings.Repeat("c", 64)
	tests := []struct {
		name       string
		digest     string
		format     Format
		descriptor Descriptor
		arguments  []string
	}{
		{"digest", "ABC", FormatClass, Descriptor{Name: "cfr", Version: "1"}, nil},
		{"format", validDigest, Format("invalid"), Descriptor{Name: "cfr", Version: "1"}, nil},
		{"name", validDigest, FormatClass, Descriptor{Name: "bad name", Version: "1"}, nil},
		{"version", validDigest, FormatClass, Descriptor{Name: "cfr", Version: ""}, nil},
		{"nul argument", validDigest, FormatClass, Descriptor{Name: "cfr", Version: "1"}, []string{"a\x00b"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CacheKey(
				test.digest, test.format, test.descriptor, test.arguments, Limits{},
			)
			if err == nil ||
				(!errors.Is(err, ErrInvalidRequest) &&
					!errors.Is(err, ErrInvalidConfiguration)) {
				t.Fatalf("CacheKey() error = %v", err)
			}
		})
	}
}

func TestCacheKeyBindsEveryBehaviorChangingLimit(t *testing.T) {
	digest := strings.Repeat("d", 64)
	descriptor := Descriptor{Name: "fixture", Version: "1"}
	base, err := CacheKey(digest, FormatClass, descriptor, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	variants := []Limits{
		{MaxDuration: DefaultMaxDuration - 1},
		{MaxInputBytes: DefaultMaxInputBytes - 1},
		{MaxClasses: DefaultMaxClasses - 1},
		{MaxMethods: DefaultMaxMethods - 1},
		{MaxArtifacts: DefaultMaxArtifacts - 1},
		{MaxArtifactBytes: DefaultMaxArtifactBytes - 1},
		{MaxClassErrors: DefaultMaxClassErrors - 1},
	}
	for index, limits := range variants {
		key, err := CacheKey(digest, FormatClass, descriptor, nil, limits)
		if err != nil {
			t.Fatalf("variant %d error = %v", index, err)
		}
		if key == base {
			t.Fatalf("cache key did not bind limit variant %d", index)
		}
	}
}

func TestCacheKeyContractSchemaGolden(t *testing.T) {
	key, err := CacheKey(
		strings.Repeat("e", 64), FormatPYC,
		Descriptor{Name: "fixture", Version: "2.0"},
		[]string{"--mode", "bytecode"}, Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "1d85e1bc8fede2af8b23d6d8293b40f7e6bd21b2c71aca0d967d949f8945c861"
	if key != expected {
		t.Fatalf("CacheKey() = %s, want schema golden %s", key, expected)
	}
}

func TestFormatsCoverDeclaredBytecodeInputs(t *testing.T) {
	for _, format := range []Format{
		FormatClass, FormatJAR, FormatWAR, FormatEAR, FormatAPK, FormatPYC,
	} {
		if !format.Valid() {
			t.Fatalf("format %q is not valid", format)
		}
	}
	if Format("macho").Valid() {
		t.Fatal("native format unexpectedly accepted by bytecode contract")
	}
}
