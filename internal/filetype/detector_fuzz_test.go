package filetype

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"testing"
)

const maxFuzzDetectionInputBytes = 128 << 10
const maxFuzzMetadataJSONBytes = 256 << 10

// FuzzDetectorDetect exercises the content detector with both structurally
// valid seeds and malformed prefixes. The size guard keeps every generated
// case inside a small, deterministic inspection envelope.
func FuzzDetectorDetect(f *testing.F) {
	validTAR := detectorFuzzTAR("payload.bin", []byte("payload"))
	validGZIP := detectorFuzzGZIP("payload.tar", validTAR)
	validZIP := append(
		[]byte{'P', 'K', 0x05, 0x06},
		make([]byte, 18)...,
	)
	anomalousTAR := detectorFuzzTAR("../../outside.bin", validGZIP)
	peZIP := detectorFuzzPEZIP()
	tarExt := detectorFuzzTARExt()

	for _, seed := range [][]byte{
		nil,
		[]byte("plain data"),
		validZIP,
		validTAR,
		validGZIP,
		anomalousTAR,
		[]byte{'P', 'K', 0x03, 0x04},
		[]byte{0x1f, 0x8b, 0x08},
		[]byte{0x7f, 'E', 'L', 'F'},
		[]byte{0xca, 0xfe, 0xba, 0xbe},
		structuredPEFixture(false),
		structuredPEFixture(true),
		structuredELFFixture(false, true),
		structuredELFFixture(true, false),
		structuredMachThinFixture(false, false),
		structuredMachThinFixture(true, true),
		structuredMachFatFixture(),
		peZIP,
		tarExt,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzDetectionInputBytes {
			return
		}

		detected, err := (Detector{}).Detect(
			bytes.NewReader(data),
			int64(len(data)),
		)
		if err != nil {
			t.Fatalf("Detect() returned an error for an in-memory reader: %v", err)
		}
		if detected.Format == "" || detected.MIMEType == "" {
			t.Fatalf("Detect() returned an incomplete result: %+v", detected)
		}
		if detected.Metadata == nil {
			t.Fatalf("Detect() returned nil metadata: %+v", detected)
		}
		if detected.Format != "unknown" && !fuzzSupportedFormat(detected.Format) {
			t.Fatalf("Detect() returned an undeclared format: %+v", detected)
		}
		encoded, err := json.Marshal(detected.Metadata)
		if err != nil {
			t.Fatalf("metadata is not JSON serializable: %v", err)
		}
		if len(encoded) > maxFuzzMetadataJSONBytes {
			t.Fatalf("metadata exceeds fuzz bound: %d bytes", len(encoded))
		}
		candidates, ok := detected.Metadata["identification_candidates"].([]identificationCandidate)
		if !ok || len(candidates) > maxCandidates {
			t.Fatalf("invalid candidate metadata: %+v", detected.Metadata)
		}
		seen := make(map[string]struct{}, len(candidates))
		for _, candidate := range candidates {
			descriptor, declared := candidateDescriptors[candidate.Format]
			if !declared ||
				candidate.Category != descriptor.category ||
				candidate.MIMEType != descriptor.mimeType ||
				candidate.Evidence != descriptor.evidence {
				t.Fatalf("invalid candidate: %+v", candidate)
			}
			if _, duplicate := seen[candidate.Format]; duplicate {
				t.Fatalf("duplicate candidate: %+v", candidates)
			}
			seen[candidate.Format] = struct{}{}
		}
		ambiguous, hasAmbiguous := detected.Metadata["identification_ambiguous"].(bool)
		if hasAmbiguous != (len(candidates) > 1) ||
			hasAmbiguous && !ambiguous {
			t.Fatalf("invalid ambiguity metadata: %+v", detected.Metadata)
		}
	})
}

func fuzzSupportedFormat(format string) bool {
	for _, supported := range supportedFormats {
		if format == supported {
			return true
		}
	}
	return false
}

func detectorFuzzTAR(name string, body []byte) []byte {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(body)),
	}); err != nil {
		panic(err)
	}
	if _, err := writer.Write(body); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func detectorFuzzGZIP(name string, body []byte) []byte {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	writer.Name = name
	if _, err := writer.Write(body); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return append([]byte(nil), output.Bytes()...)
}

func detectorFuzzPEZIP() []byte {
	prefix := peFixture(false, false, 3)
	end := make([]byte, 22)
	copy(end, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint32(end[16:20], uint32(len(prefix)))
	return append(prefix, end...)
}

func detectorFuzzTARExt() []byte {
	body := make([]byte, 2048)
	ext := extFixture("ext4")
	copy(body[512:1536], ext[1024:2048])
	return detectorFuzzTAR("filesystem.bin", body)
}
