package trivyhandoff

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestVersionTwoRoundTripPreservesBoundSourcesAndLimits(t *testing.T) {
	firstHash := strings.Repeat("a", 64)
	secondHash := strings.Repeat("b", 64)
	value := Payload{
		SchemaVersion: SchemaVersion,
		Sources: []Source{
			{
				Format:           "docker-tar",
				SourceStorageKey: "blobs/sha256/aa/" + firstHash,
				SourceSHA256:     firstHash,
				SourceSizeBytes:  4096,
				ImageLogicalPath: "/",
			},
			{
				Format:           "oci-tar",
				SourceStorageKey: "blobs/sha256/bb/" + secondHash,
				SourceSHA256:     secondHash,
				SourceSizeBytes:  8192,
				ImageLogicalPath: "/nested/image.tar",
			},
		},
		MaxExpandedBytes: 64 << 20,
		MaxArchiveRatio:  100,
		UpstreamPartial:  true,
	}
	raw, err := Encode(value, 10<<30, MaxSources)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, 10<<30, MaxSources)
	if err != nil {
		t.Fatal(err)
	}
	if !equalPayload(decoded, value) {
		t.Fatalf("Decode(Encode()) = %+v, want %+v", decoded, value)
	}
}

func TestDecodeNormalizesLegacySingleSource(t *testing.T) {
	digest := strings.Repeat("a", 64)
	raw := []byte(`{"schema_version":1,"format":"docker-tar",` +
		`"source_storage_key":"blobs/sha256/aa/` + digest + `",` +
		`"source_sha256":"` + digest + `","source_size_bytes":4096,` +
		`"image_logical_path":"/","upstream_partial":false}`)
	value, err := Decode(raw, 10<<30, MaxSources)
	if err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != LegacySchemaVersion ||
		len(value.Sources) != 1 ||
		value.Sources[0].SourceSHA256 != digest ||
		value.MaxExpandedBytes != 0 ||
		value.MaxArchiveRatio != 0 {
		t.Fatalf("legacy decode = %+v", value)
	}
}

func TestVersionTwoRejectsUnboundedOrAmbiguousBatches(t *testing.T) {
	digest := strings.Repeat("a", 64)
	source := Source{
		Format:           "docker-tar",
		SourceStorageKey: "blobs/sha256/aa/" + digest,
		SourceSHA256:     digest,
		SourceSizeBytes:  8,
		ImageLogicalPath: "/nested.tar",
	}
	valid := Payload{
		SchemaVersion:    SchemaVersion,
		Sources:          []Source{source},
		MaxExpandedBytes: 16,
		MaxArchiveRatio:  100,
	}
	cases := []Payload{
		func() Payload {
			value := valid
			value.MaxExpandedBytes = 0
			return value
		}(),
		func() Payload {
			value := valid
			value.Sources = []Source{source, source}
			return value
		}(),
		func() Payload {
			value := valid
			value.Sources = append([]Source(nil), source)
			value.Sources[0].SourceSizeBytes = 17
			return value
		}(),
		func() Payload {
			value := valid
			value.Sources = make([]Source, MaxSources+1)
			for index := range value.Sources {
				value.Sources[index] = source
				value.Sources[index].ImageLogicalPath =
					"/image-" + string(rune('a'+index))
			}
			return value
		}(),
	}
	for index, value := range cases {
		if _, err := Encode(value, 10<<30, MaxSources); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}

	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	if _, err := Decode(raw, 10<<30, MaxSources); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func equalPayload(left Payload, right Payload) bool {
	if left.SchemaVersion != right.SchemaVersion ||
		left.MaxExpandedBytes != right.MaxExpandedBytes ||
		left.MaxArchiveRatio != right.MaxArchiveRatio ||
		left.UpstreamPartial != right.UpstreamPartial ||
		len(left.Sources) != len(right.Sources) {
		return false
	}
	for index := range left.Sources {
		if left.Sources[index] != right.Sources[index] {
			return false
		}
	}
	return true
}
