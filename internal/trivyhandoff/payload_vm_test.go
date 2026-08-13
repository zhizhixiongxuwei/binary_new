package trivyhandoff

import "testing"

func TestVMImageSourceRoundTrip(t *testing.T) {
	value := Payload{
		SchemaVersion: SchemaVersion,
		Sources: []Source{{
			Format:           FormatVMImage,
			SourceStorageKey: "blobs/sha256/" + repeatA64()[:2] + "/" + repeatA64(),
			SourceSHA256:     repeatA64(),
			SourceSizeBytes:  32 << 20,
			ImageLogicalPath: "/",
		}},
		MaxExpandedBytes: 50 << 30,
		MaxArchiveRatio:  50,
	}
	raw, err := Encode(value, 10<<30, MaxSources)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw, 10<<30, MaxSources)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Sources[0].Format != FormatVMImage {
		t.Fatalf("decoded source = %+v", decoded.Sources[0])
	}
}

func TestRejectsUnsupportedSourceFormat(t *testing.T) {
	value := Payload{
		SchemaVersion: SchemaVersion,
		Sources: []Source{{
			Format:           "squashfs",
			SourceStorageKey: "blobs/sha256/" + repeatA64()[:2] + "/" + repeatA64(),
			SourceSHA256:     repeatA64(),
			SourceSizeBytes:  1024,
			ImageLogicalPath: "/",
		}},
		MaxExpandedBytes: 1 << 20,
		MaxArchiveRatio:  50,
	}
	if _, err := Encode(value, 10<<30, MaxSources); err == nil {
		t.Fatal("Encode accepted an unsupported source format")
	}
}

func repeatA64() string {
	value := ""
	for range 64 {
		value += "a"
	}
	return value
}
