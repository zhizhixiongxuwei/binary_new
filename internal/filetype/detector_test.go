package filetype

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"testing"
)

type fakeMagicClassifier struct {
	result MagicResult
	err    error
}

func (classifier fakeMagicClassifier) Classify(
	context.Context,
	io.ReaderAt,
	int64,
) (MagicResult, error) {
	return classifier.result, classifier.err
}

func TestDetectorEnrichesStructuralIdentificationWithLibmagic(t *testing.T) {
	data := sevenZipFixture()
	detector := NewDetector(fakeMagicClassifier{result: MagicResult{
		MIMEType: "application/x-7z-compressed",
		Version:  "5.45",
	}})
	result, err := detector.DetectContext(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "7z" {
		t.Fatalf("Format = %q, want structural 7z result", result.Format)
	}
	magic, ok := result.Metadata["libmagic"].(map[string]any)
	if !ok || magic["mime_type"] != "application/x-7z-compressed" ||
		magic["version"] != "5.45" {
		t.Fatalf("libmagic metadata = %#v", result.Metadata["libmagic"])
	}
}

func TestDetectorDoesNotLetLibmagicOverrideStructuralFormat(t *testing.T) {
	data := classFixture()
	detector := NewDetector(fakeMagicClassifier{result: MagicResult{
		MIMEType: "application/x-dosexec",
		Version:  "5.45",
	}})
	result, err := detector.Detect(
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "java-class" ||
		result.MIMEType != "application/java-vm" {
		t.Fatalf("libmagic overrode structural result: %#v", result)
	}
}

func TestDetectorRecognizesSupportedFormats(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		format string
	}{
		{"PE32 executable", peFixture(false, false, 3), "pe32"},
		{"PE32+ DLL", peFixture(true, true, 2), "pe32+"},
		{"ELF32", elfFixture(false), "elf32"},
		{"ELF64", elfFixture(true), "elf64"},
		{"Mach-O thin", machThinFixture(), "macho-thin"},
		{"Mach-O fat", machFatFixture(), "macho-fat"},
		{"Java class", classFixture(), "java-class"},
		{"DEX", dexFixture(), "dex"},
		{"DEX 041 container", dex041Fixture(), "dex"},
		{"PYC", pycFixture(), "pyc"},
		{"ZIP", zipFixture(t, "file.txt"), "zip"},
		{"JAR", zipFixture(t, "META-INF/MANIFEST.MF"), "jar"},
		{"WAR", zipFixture(t, "WEB-INF/web.xml"), "war"},
		{"EAR", zipFixture(t, "META-INF/application.xml"), "ear"},
		{"APK", zipFixture(t, "AndroidManifest.xml"), "apk"},
		{"TAR", tarFixture(t, map[string]string{"file.txt": "x"}), "tar"},
		{"Docker TAR", dockerTARFixture(t), "docker-tar"},
		{"OCI TAR", ociTARFixture(t), "oci-tar"},
		{"GZIP", append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, make([]byte, 8)...), "gzip"},
		{"BZIP2", []byte{'B', 'Z', 'h', '9', 0x31, 0x41, 0x59, 0x26, 0x53, 0x59}, "bzip2"},
		{"XZ", xzFixture(), "xz"},
		{"ZSTD", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0}, "zstd"},
		{"7Z", sevenZipFixture(), "7z"},
		{"RAR4", rar4Fixture(), "rar"},
		{"RAR5", rar5Fixture(), "rar"},
		{"CPIO", cpioFixture(), "cpio"},
		{"binary CPIO", binaryCPIOFixture(), "cpio"},
		{"CAB", cabFixture(), "cab"},
		{"AR", arFixture(map[string]string{"file.o": "x"}), "ar"},
		{"DEB", arOrderedFixture([]arEntry{
			{"debian-binary", "2.0\n"}, {"control.tar.xz", "x"}, {"data.tar.xz", "x"},
		}), "deb"},
		{"RPM", rpmFixture(), "rpm"},
		{"ISO9660", isoFixture(false), "iso9660"},
		{"UDF", isoFixture(true), "udf"},
		{"EXT2", extFixture("ext2"), "ext2"},
		{"EXT3", extFixture("ext3"), "ext3"},
		{"EXT4", extFixture("ext4"), "ext4"},
		{"SquashFS", squashFixture(), "squashfs"},
		{"MBR image", mbrFixture(false), "mbr-img"},
		{"GPT image", mbrFixture(true), "gpt-img"},
		{"4K GPT image", gptSectorFixture(4096), "gpt-img"},
	}
	detector := Detector{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := detector.Detect(bytes.NewReader(test.data), int64(len(test.data)))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if got.Format != test.format {
				t.Fatalf("Detect() format = %q, want %q; result=%+v", got.Format, test.format, got)
			}
			if got.MIMEType == "" || got.Metadata == nil {
				t.Fatalf("Detect() returned incomplete result: %+v", got)
			}
			switch got.Format {
			case "pe32", "elf32":
				if got.Metadata["bits"] != 32 {
					t.Fatalf("%s bits = %#v", got.Format, got.Metadata["bits"])
				}
			case "pe32+", "elf64":
				if got.Metadata["bits"] != 64 {
					t.Fatalf("%s bits = %#v", got.Format, got.Metadata["bits"])
				}
			}
			candidates, ok := got.Metadata["identification_candidates"].([]identificationCandidate)
			if !ok || len(candidates) != 1 ||
				candidates[0].Format != got.Format ||
				candidates[0].MIMEType != got.MIMEType ||
				candidates[0].Category == "" ||
				candidates[0].Evidence == "" ||
				got.Metadata["identification_ambiguous"] != nil {
				t.Fatalf("single-format candidates = %#v", got.Metadata)
			}
		})
	}
}

func TestDetectorRejectsDamaged7ZAndCABHeaders(t *testing.T) {
	bad7Z := sevenZipFixture()
	bad7Z[8] ^= 0xff
	badCAB := cabFixture()
	binary.LittleEndian.PutUint32(badCAB[8:12], uint32(len(badCAB)+1))
	for _, test := range []struct {
		name   string
		data   []byte
		format string
	}{
		{name: "7z start-header CRC", data: bad7Z, format: "7z"},
		{name: "CAB cabinet size", data: badCAB, format: "cab"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mustDetect(t, test.data); got.Format == test.format {
				t.Fatalf("damaged input detected as %q: %+v", test.format, got)
			}
		})
	}
}

func TestDetectorReports4096ByteGPTSectorSize(t *testing.T) {
	image := gptSectorFixture(4096)
	result, err := (Detector{}).Detect(
		bytes.NewReader(image), int64(len(image)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "gpt-img" || result.Metadata["sector_size"] != uint64(4096) {
		t.Fatalf("Detect() = %#v", result)
	}
}

func TestDEBClassificationUsesCurrentMemberRules(t *testing.T) {
	tests := []struct {
		name    string
		entries []arEntry
		format  string
	}{
		{
			name: "ignorable extension and trailing member",
			entries: []arEntry{
				{"debian-binary", "2.7\nFuture: value\n"},
				{"_feature", "x"},
				{"control.tar.zst", "x"},
				{"data.tar.bz2", "x"},
				{"future-member", "x"},
			},
			format: "deb",
		},
		{
			name: "bzip2 control is unsupported",
			entries: []arEntry{
				{"debian-binary", "2.0\n"},
				{"control.tar.bz2", "x"},
				{"data.tar.xz", "x"},
			},
			format: "ar",
		},
		{
			name: "unexpected member before data",
			entries: []arEntry{
				{"debian-binary", "2.0\n"},
				{"control.tar.xz", "x"},
				{"unexpected", "x"},
				{"data.tar.xz", "x"},
			},
			format: "ar",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mustDetect(t, arOrderedFixture(test.entries))
			if got.Format != test.format {
				t.Fatalf("format = %q, want %q", got.Format, test.format)
			}
			if test.format == "deb" && got.Metadata["version"] != "2.7" {
				t.Fatalf("version metadata = %#v", got.Metadata["version"])
			}
		})
	}
}

func TestPEMetadataDistinguishesExecutableDLLAndDriverCandidate(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		kind            string
		subsystem       string
		driverCandidate bool
	}{
		{"exe", peFixture(false, false, 3), "executable", "windows-console", false},
		{"dll", peFixture(true, true, 2), "dll", "windows-gui", false},
		{"sys candidate", peFixture(true, false, 1), "executable", "native", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mustDetect(t, test.data)
			if got.Metadata["kind"] != test.kind ||
				got.Metadata["subsystem"] != test.subsystem ||
				got.Metadata["driver_candidate"] != test.driverCandidate {
				t.Fatalf("PE metadata = %#v", got.Metadata)
			}
		})
	}
}

func TestCAFEBABEConflictUsesMinimumStructure(t *testing.T) {
	if got := mustDetect(t, classFixture()); got.Format != "java-class" {
		t.Fatalf("valid class detected as %q", got.Format)
	}
	if got := mustDetect(t, machFatFixture()); got.Format != "macho-fat" {
		t.Fatalf("valid fat Mach-O detected as %q", got.Format)
	}
	if got := mustDetect(t, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61}); got.Format != "unknown" {
		t.Fatalf("truncated CAFEBABE detected as %q", got.Format)
	}
}

func TestMachORejectsCommandTableConsumedBeforeDeclaredCommandCount(t *testing.T) {
	data := make([]byte, 48)
	binary.BigEndian.PutUint32(data[:4], 0xfeedfacf)
	binary.BigEndian.PutUint32(data[4:8], 0x01000007)
	binary.BigEndian.PutUint32(data[12:16], 2)
	binary.BigEndian.PutUint32(data[16:20], 2)
	binary.BigEndian.PutUint32(data[20:24], 16)
	binary.BigEndian.PutUint32(data[32:36], 1)
	binary.BigEndian.PutUint32(data[36:40], 16)

	if got := mustDetect(t, data); got.Format != "unknown" {
		t.Fatalf("malformed Mach-O detected as %q", got.Format)
	}
}

func TestZIPDerivedPriorityAndMalformedDirectory(t *testing.T) {
	mixed := zipFixture(t,
		"META-INF/MANIFEST.MF", "WEB-INF/web.xml", "AndroidManifest.xml",
	)
	if got := mustDetect(t, mixed); got.Format != "apk" {
		t.Fatalf("mixed ZIP detected as %q, want apk", got.Format)
	}
	malformed := append([]byte(nil), zipFixture(t, "META-INF/MANIFEST.MF")...)
	eocd := bytes.LastIndex(malformed, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint32(malformed[eocd+16:eocd+20], uint32(len(malformed)+100))
	if got := mustDetect(t, malformed); got.Format != "unknown" {
		t.Fatalf("malformed ZIP detected as %q", got.Format)
	}
}

func TestZIPMultiVolumeAndCountMismatchRemainDetectable(t *testing.T) {
	multiVolume := zipFixture(t, "payload.txt")
	eocd := bytes.LastIndex(multiVolume, []byte{'P', 'K', 5, 6})
	if eocd < 0 {
		t.Fatal("ZIP EOCD not found")
	}
	binary.LittleEndian.PutUint16(
		multiVolume[eocd+4:eocd+6],
		1,
	)
	detected := mustDetect(t, multiVolume)
	if detected.Format != "zip" ||
		detected.Metadata["multi_volume"] != true ||
		detected.Metadata["classification_limited"] != true {
		t.Fatalf("multi-volume ZIP result = %+v", detected)
	}
	finalVolume := append([]byte(nil), multiVolume[10:]...)
	detected = mustDetect(t, finalVolume)
	if detected.Format != "zip" ||
		detected.Metadata["multi_volume"] != true {
		t.Fatalf("final ZIP volume result = %+v", detected)
	}

	countMismatch := zipFixture(t, "payload.txt")
	eocd = bytes.LastIndex(countMismatch, []byte{'P', 'K', 5, 6})
	binary.LittleEndian.PutUint16(
		countMismatch[eocd+8:eocd+10],
		0,
	)
	detected = mustDetect(t, countMismatch)
	if detected.Format != "zip" ||
		detected.Metadata["metadata_validation"] !=
			"deferred_to_extractor" {
		t.Fatalf("count-mismatch ZIP result = %+v", detected)
	}
}

func TestTARContainerClassificationRequiresStructure(t *testing.T) {
	fakeDocker := tarFixture(t, map[string]string{
		"manifest.json": `[{"Config":"","Layers":[]}]`,
	})
	if got := mustDetect(t, fakeDocker); got.Format != "tar" {
		t.Fatalf("invalid Docker manifest detected as %q", got.Format)
	}
	mixed := tarFixture(t, map[string]string{
		"manifest.json": `[{"Config":"config.json","Layers":["layer.tar"]}]`,
		"oci-layout":    `{"imageLayoutVersion":"1.0.0"}`,
		"index.json": `{"schemaVersion":2,"manifests":[{"digest":"sha256:` +
			strings.Repeat("a", 64) + `"}]}`,
		"blobs/sha256/" + strings.Repeat("a", 64): "{}",
	})
	if got := mustDetect(t, mixed); got.Format != "oci-tar" {
		t.Fatalf("OCI/Docker conflict detected as %q, want oci-tar", got.Format)
	}
}

func TestTARV7AndEmptyValidation(t *testing.T) {
	validV7 := v7TARFixture(
		t,
		[]v7TAREntry{{name: "payload.txt", body: []byte("v7")}},
	)
	if got := mustDetect(t, validV7); got.Format != "tar" {
		t.Fatalf("V7 tar detected as %q", got.Format)
	}
	if got := mustDetect(t, make([]byte, 1024)); got.Format != "tar" ||
		got.Metadata["entries"] != 0 {
		t.Fatalf("empty tar result = %+v", got)
	}
	if got := mustDetect(t, make([]byte, maxEmptyTARBytes)); got.Format != "tar" {
		t.Fatalf("bounded empty tar detected as %q", got.Format)
	}

	leadingZero := make([]byte, 1536)
	leadingZero[len(leadingZero)-1] = 1
	badChecksum := append([]byte(nil), validV7...)
	badChecksum[0] ^= 1
	arbitraryTail := append([]byte(nil), validV7...)
	arbitraryTail[300] = 'x'
	setV7TARChecksum(arbitraryTail[:512])
	invalidType := append([]byte(nil), validV7...)
	invalidType[156] = 'x'
	setV7TARChecksum(invalidType[:512])

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "single zero block", data: make([]byte, 512)},
		{name: "leading zero disk", data: leadingZero},
		{name: "oversized all-zero image", data: make([]byte, maxEmptyTARBytes+512)},
		{name: "random block", data: bytes.Repeat([]byte{0xa5}, 512)},
		{name: "bad checksum", data: badChecksum},
		{name: "arbitrary V7 extension tail", data: arbitraryTail},
		{name: "invalid V7 type", data: invalidType},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mustDetect(t, test.data); got.Format == "tar" {
				t.Fatalf("malformed input detected as tar: %+v", got)
			}
		})
	}
}

func TestTARV7ClassificationReachesStructuralProbeCap(t *testing.T) {
	entries := make([]v7TAREntry, 4097)
	for index := range entries {
		entries[index].name = fmt.Sprintf("entry-%05d", index)
	}
	got := mustDetect(t, v7TARFixture(t, entries))
	if got.Format != "tar" || got.Metadata["entries"] != 4096 {
		t.Fatalf("V7 cap result = %+v", got)
	}
}

func TestDEBClassificationScansBeyondLegacyMemberCap(t *testing.T) {
	entries := make([]arEntry, 0, 4100)
	entries = append(entries, arEntry{"debian-binary", "2.0\n"})
	for index := 0; index < 4097; index++ {
		entries = append(entries, arEntry{
			name: fmt.Sprintf("_f%05d", index),
		})
	}
	entries = append(entries,
		arEntry{"control.tar", "x"},
		arEntry{"data.tar.lzma", "x"},
	)
	got := mustDetect(t, arOrderedFixture(entries))
	if got.Format != "deb" || got.Metadata["entries"] != 4100 {
		t.Fatalf("large DEB result = %+v", got)
	}
}

func TestARClassificationMemberCapIsExplicit(t *testing.T) {
	entries := make([]arEntry, 0, maxArchiveEntries+1)
	entries = append(entries,
		arEntry{"debian-binary", "2.0\n"},
		arEntry{"control.tar", "x"},
		arEntry{"data.tar", "x"},
	)
	for len(entries) < maxArchiveEntries+1 {
		entries = append(entries, arEntry{name: "_extension"})
	}
	got := mustDetect(t, arOrderedFixture(entries))
	if got.Format != "ar" ||
		got.Metadata["entries"] != maxArchiveEntries ||
		got.Metadata["classification_limited"] != true {
		t.Fatalf("AR cap result = %+v", got)
	}
}

func TestPYCRejectsUnknownMagicWithCRLF(t *testing.T) {
	forged := make([]byte, 16)
	copy(forged, []byte{0x34, 0x12, '\r', '\n'})
	if got := mustDetect(t, forged); got.Format != "unknown" {
		t.Fatalf("unknown PYC magic detected as %q", got.Format)
	}
}

func TestPYCVersionSpecificHeaders(t *testing.T) {
	tests := []struct {
		magic      uint16
		headerSize int
		version    string
	}{
		{62211, 8, "2.7"},
		{3230, 12, "3.3"},
		{3379, 12, "3.6"},
		{3394, 16, "3.7"},
		{3627, 16, "3.14"},
	}
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			data := make([]byte, test.headerSize+1)
			binary.LittleEndian.PutUint16(data[:2], test.magic)
			copy(data[2:4], "\r\n")
			data[test.headerSize] = 0xe3
			got := mustDetect(t, data)
			if got.Format != "pyc" ||
				got.Metadata["python_version"] != test.version ||
				got.Metadata["header_size"] != test.headerSize {
				t.Fatalf("PYC result = %+v", got)
			}
		})
	}
}

func TestZSTDRequiresFrameAndBlockHeaders(t *testing.T) {
	valid := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0}
	if got := mustDetect(t, valid); got.Format != "zstd" {
		t.Fatalf("valid ZSTD detected as %q", got.Format)
	}
	for _, invalid := range [][]byte{
		{0x28, 0xb5, 0x2f, 0xfd, 0x20},
		{0x28, 0xb5, 0x2f, 0xfd, 0x28, 0, 1, 0, 0},
	} {
		if got := mustDetect(t, invalid); got.Format != "unknown" {
			t.Fatalf("invalid ZSTD detected as %q", got.Format)
		}
	}
}

func TestRPMDetectionDefersUntrustedLeadAndHeaderMetadata(t *testing.T) {
	data := rpmFixture()
	binary.BigEndian.PutUint16(data[6:8], 1)
	binary.BigEndian.PutUint16(data[8:10], 18)
	got := mustDetect(t, data)
	if got.Format != "rpm" ||
		got.Architecture != "" ||
		got.Metadata["probe"] != "lead_magic" ||
		got.Metadata["metadata_validation"] != "deferred_to_extractor" {
		t.Fatalf("RPM result = %+v", got)
	}
}

func TestRPMMagicRemainsRecognizedWhenMetadataIsMalformed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "metadata-entry-limit",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(data[104:108], 100_001)
				return data
			},
		},
		{
			name: "malicious-reserved-lead",
			mutate: func(data []byte) []byte {
				for index := 80; index < 96; index++ {
					data[index] = 0xff
				}
				return data
			},
		},
		{
			name: "header-offset-overflow",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[112+16+8:112+16+12],
					0x7fffffff,
				)
				return data
			},
		},
		{
			name: "header-type-corrupt",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[112+16+4:112+16+8],
					4,
				)
				return data
			},
		},
		{
			name: "magic-only",
			mutate: func(data []byte) []byte {
				return data[:4]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(rpmFixture())
			if got := mustDetect(t, data); got.Format != "rpm" {
				t.Fatalf("RPM magic detected as %+v", got)
			}
		})
	}
}

func TestShortAndMalformedInputsAreUnknownWithoutPanic(t *testing.T) {
	inputs := [][]byte{
		nil,
		{0xca, 0xfe, 0xba, 0xbe},
		{'M', 'Z'},
		{'P', 'K', 3, 4},
		append([]byte("ustar"), make([]byte, 600)...),
		bytes.Repeat([]byte{0xff}, 4096),
	}
	for index, input := range inputs {
		t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
			got, err := (Detector{}).Detect(bytes.NewReader(input), int64(len(input)))
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if got.Format != "unknown" || got.MIMEType != "application/octet-stream" ||
				got.Architecture != "" || got.Metadata == nil ||
				len(got.Metadata) != 1 {
				t.Fatalf("unknown result is not stable: %+v", got)
			}
			candidates, ok := got.Metadata["identification_candidates"].([]identificationCandidate)
			if !ok || len(candidates) != 0 {
				t.Fatalf("unknown candidates = %#v", got.Metadata)
			}
		})
	}
}

func TestDetectorRejectsInvalidArguments(t *testing.T) {
	if _, err := (Detector{}).Detect(nil, 0); err == nil {
		t.Fatal("Detect(nil) succeeded")
	}
	if _, err := (Detector{}).Detect(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("Detect(negative size) succeeded")
	}
}

func TestDetectorInspectionIsBounded(t *testing.T) {
	source := &countingReaderAt{}
	got, err := (Detector{}).Detect(source, 10<<30)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if got.Format != "unknown" {
		t.Fatalf("zero source detected as %q", got.Format)
	}
	if source.total > maxInspectionBytes {
		t.Fatalf("detector read %d bytes, limit is %d", source.total, maxInspectionBytes)
	}
	if source.largest > maxSingleRead {
		t.Fatalf("largest read was %d bytes, limit is %d", source.largest, maxSingleRead)
	}
}

func TestRPMProbeIsConstantAndRespectsInspectionBudget(t *testing.T) {
	data := largeRPMIndexFixture(100_000)
	t.Run("magic-only-probe", func(t *testing.T) {
		source := &countingDataReaderAt{
			reader: bytes.NewReader(data),
		}
		reader := &boundedReader{
			source: source,
			size:   int64(len(data)),
		}
		got, found, err := detectRPM(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !found || got.Format != "rpm" {
			t.Fatalf("large-index RPM detected as %+v", got)
		}
		if source.total != 4 ||
			source.largest != 4 ||
			reader.consumed != 4 {
			t.Fatalf(
				"RPM detector reads: total=%d largest=%d",
				source.total,
				source.largest,
			)
		}
	})

	t.Run("nearly-exhausted-budget", func(t *testing.T) {
		source := &countingDataReaderAt{
			reader: bytes.NewReader(data),
		}
		reader := &boundedReader{
			source:   source,
			size:     int64(len(data)),
			consumed: maxInspectionBytes - 4,
		}
		got, found, err := detectRPM(reader)
		if err != nil {
			t.Fatal(err)
		}
		if !found || got.Format != "rpm" {
			t.Fatal("RPM detection did not use the remaining magic-byte budget")
		}
		if source.total != 4 ||
			reader.consumed != maxInspectionBytes {
			t.Fatalf(
				"RPM detector exceeded remaining budget: source=%d consumed=%d",
				source.total,
				reader.consumed,
			)
		}
	})

	t.Run("insufficient-budget", func(t *testing.T) {
		source := &countingDataReaderAt{
			reader: bytes.NewReader(data),
		}
		reader := &boundedReader{
			source:   source,
			size:     int64(len(data)),
			consumed: maxInspectionBytes - 3,
		}
		_, found, err := detectRPM(reader)
		if err != nil {
			t.Fatal(err)
		}
		if found || source.total != 0 ||
			reader.consumed != maxInspectionBytes-3 {
			t.Fatalf(
				"RPM detector bypassed budget: found=%t source=%d consumed=%d",
				found,
				source.total,
				reader.consumed,
			)
		}
	})
}

func mustDetect(t *testing.T, data []byte) Result {
	t.Helper()
	got, err := (Detector{}).Detect(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	return got
}

type countingReaderAt struct {
	total   int64
	largest int64
}

func (reader *countingReaderAt) ReadAt(buffer []byte, _ int64) (int, error) {
	length := int64(len(buffer))
	reader.total += length
	if length > reader.largest {
		reader.largest = length
	}
	clear(buffer)
	return len(buffer), nil
}

var _ io.ReaderAt = (*countingReaderAt)(nil)

type countingDataReaderAt struct {
	reader  io.ReaderAt
	total   int64
	largest int64
}

func (reader *countingDataReaderAt) ReadAt(
	buffer []byte,
	offset int64,
) (int, error) {
	length := int64(len(buffer))
	if length > reader.largest {
		reader.largest = length
	}
	count, err := reader.reader.ReadAt(buffer, offset)
	reader.total += int64(count)
	return count, err
}

var _ io.ReaderAt = (*countingDataReaderAt)(nil)

func peFixture(is64, dll bool, subsystem uint16) []byte {
	optionalSize := 96
	magic := uint16(0x10b)
	machine := uint16(0x14c)
	if is64 {
		optionalSize, magic, machine = 112, 0x20b, 0x8664
	}
	data := make([]byte, 0x80+24+optionalSize+40)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:], []byte{'P', 'E', 0, 0})
	binary.LittleEndian.PutUint16(data[0x84:0x86], machine)
	binary.LittleEndian.PutUint16(data[0x86:0x88], 1)
	binary.LittleEndian.PutUint16(data[0x94:0x96], uint16(optionalSize))
	characteristics := uint16(0x0002)
	if dll {
		characteristics |= 0x2000
	}
	binary.LittleEndian.PutUint16(data[0x96:0x98], characteristics)
	binary.LittleEndian.PutUint16(data[0x98:0x9a], magic)
	binary.LittleEndian.PutUint16(data[0x98+68:0x98+70], subsystem)
	return data
}

func elfFixture(is64 bool) []byte {
	size := 52
	class := byte(1)
	if is64 {
		size, class = 64, 2
	}
	data := make([]byte, size)
	copy(data, []byte{0x7f, 'E', 'L', 'F', class, 1, 1})
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 0x3e)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	if is64 {
		binary.LittleEndian.PutUint16(data[0x34:0x36], uint16(size))
	} else {
		binary.LittleEndian.PutUint16(data[0x28:0x2a], uint16(size))
	}
	return data
}

func machThinFixture() []byte {
	data := make([]byte, 32)
	binary.BigEndian.PutUint32(data[:4], 0xfeedfacf)
	binary.BigEndian.PutUint32(data[4:8], 0x01000007)
	binary.BigEndian.PutUint32(data[12:16], 2)
	return data
}

func machFatFixture() []byte {
	thin := machThinFixture()
	data := make([]byte, 28+len(thin))
	binary.BigEndian.PutUint32(data[:4], 0xcafebabe)
	binary.BigEndian.PutUint32(data[4:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 0x01000007)
	binary.BigEndian.PutUint32(data[16:20], 28)
	binary.BigEndian.PutUint32(data[20:24], uint32(len(thin)))
	copy(data[28:], thin)
	return data
}

func classFixture() []byte {
	data := make([]byte, 31)
	copy(data, []byte{0xca, 0xfe, 0xba, 0xbe})
	binary.BigEndian.PutUint16(data[6:8], 61)
	binary.BigEndian.PutUint16(data[8:10], 3)
	data[10] = 1
	binary.BigEndian.PutUint16(data[11:13], 1)
	data[13] = 'A'
	data[14] = 7
	binary.BigEndian.PutUint16(data[15:17], 1)
	binary.BigEndian.PutUint16(data[17:19], 0x21)
	binary.BigEndian.PutUint16(data[19:21], 2)
	return data
}

func dexFixture() []byte {
	data := make([]byte, 0x70)
	copy(data, []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[36:40], 0x70)
	binary.LittleEndian.PutUint32(data[40:44], 0x12345678)
	return data
}

func dex041Fixture() []byte {
	data := make([]byte, 0x78)
	copy(data, []byte("dex\n041\x00"))
	binary.LittleEndian.PutUint32(data[32:36], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[36:40], 0x78)
	binary.LittleEndian.PutUint32(data[40:44], 0x12345678)
	binary.LittleEndian.PutUint32(data[112:116], uint32(len(data)))
	return data
}

func pycFixture() []byte {
	data := make([]byte, 17)
	binary.LittleEndian.PutUint16(data[:2], 3627)
	copy(data[2:4], "\r\n")
	data[16] = 0xe3
	return data
}

func zipFixture(t *testing.T, names ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func tarFixture(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := []byte(entries[name])
		if err := writer.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

type v7TAREntry struct {
	name string
	body []byte
}

func v7TARFixture(t *testing.T, entries []v7TAREntry) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, entry := range entries {
		if entry.name == "" || len(entry.name) > 100 {
			t.Fatalf("invalid V7 fixture name %q", entry.name)
		}
		header := make([]byte, 512)
		copy(header[:100], entry.name)
		writeV7TAROctal(header[100:108], 0o600)
		writeV7TAROctal(header[108:116], 0)
		writeV7TAROctal(header[116:124], 0)
		writeV7TAROctal(header[124:136], int64(len(entry.body)))
		writeV7TAROctal(header[136:148], 0)
		header[156] = '0'
		setV7TARChecksum(header)
		output.Write(header)
		output.Write(entry.body)
		if remainder := len(entry.body) % 512; remainder != 0 {
			output.Write(make([]byte, 512-remainder))
		}
	}
	output.Write(make([]byte, 1024))
	return output.Bytes()
}

func writeV7TAROctal(field []byte, value int64) {
	encoded := fmt.Sprintf("%0*o", len(field)-1, value)
	copy(field, encoded)
	field[len(field)-1] = 0
}

func setV7TARChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	sum := int64(0)
	for _, value := range header {
		sum += int64(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func dockerTARFixture(t *testing.T) []byte {
	return tarFixture(t, map[string]string{
		"manifest.json": `[{"Config":"config.json","RepoTags":["sample:latest"],"Layers":["layer.tar"]}]`,
		"config.json":   "{}",
		"layer.tar":     "",
	})
}

func ociTARFixture(t *testing.T) []byte {
	return tarFixture(t, map[string]string{
		"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
		"index.json": `{"schemaVersion":2,"manifests":[{"digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`,
		"blobs/sha256/" + strings.Repeat("a", 64): "{}",
	})
}

func xzFixture() []byte {
	data := []byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(data[8:12], crc32.ChecksumIEEE(data[6:8]))
	return data
}

func sevenZipFixture() []byte {
	data := make([]byte, 32)
	copy(data, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 4})
	binary.LittleEndian.PutUint32(data[8:12], crc32.ChecksumIEEE(data[12:32]))
	return data
}

func rar4Fixture() []byte {
	data := make([]byte, 20)
	copy(data, []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00})
	data[9] = 0x73
	binary.LittleEndian.PutUint16(data[12:14], 13)
	return data
}

func rar5Fixture() []byte {
	data := make([]byte, 14)
	copy(data, []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x01, 0})
	data[12], data[13] = 1, 1
	binary.LittleEndian.PutUint32(data[8:12], crc32.ChecksumIEEE(data[12:14]))
	return data
}

func cpioFixture() []byte {
	return []byte("070701" + strings.Repeat("00000000", 11) + "00000001" + "00000000" + "\x00")
}

func binaryCPIOFixture() []byte {
	data := make([]byte, 28)
	binary.LittleEndian.PutUint16(data[:2], 0x71c7)
	binary.LittleEndian.PutUint16(data[20:22], 2)
	copy(data[26:], "x\x00")
	return data
}

func cabFixture() []byte {
	data := make([]byte, 100)
	copy(data, "MSCF")
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[16:20], 36)
	data[24], data[25] = 3, 1
	binary.LittleEndian.PutUint16(data[26:28], 1)
	binary.LittleEndian.PutUint16(data[28:30], 1)
	return data
}

func arFixture(entries map[string]string) []byte {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]arEntry, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, arEntry{name, entries[name]})
	}
	return arOrderedFixture(ordered)
}

type arEntry struct {
	name    string
	content string
}

func arOrderedFixture(entries []arEntry) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("!<arch>\n")
	for _, entry := range entries {
		content := []byte(entry.content)
		fmt.Fprintf(&buffer, "%-16s%-12d%-6d%-6d%-8s%-10d`\n",
			entry.name+"/", 0, 0, 0, "100644", len(content))
		buffer.Write(content)
		if len(content)&1 != 0 {
			buffer.WriteByte('\n')
		}
	}
	return buffer.Bytes()
}

func rpmFixture() []byte {
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[8:10], 18)
	copy(lead[10:76], "fixture-1.0-1")
	binary.BigEndian.PutUint16(lead[76:78], 1)
	binary.BigEndian.PutUint16(lead[78:80], 5)

	signature := rpmHeaderFixture(nil, nil)
	main := rpmHeaderFixture(
		[]rpmHeaderFixtureEntry{
			{tag: 1022, valueType: 6, value: "x86_64"},
			{tag: 1124, valueType: 6, value: "cpio"},
			{tag: 1125, valueType: 6, value: "none"},
		},
		nil,
	)
	data := append(lead, signature...)
	data = append(data, main...)
	return append(data, []byte("payload")...)
}

func largeRPMIndexFixture(entryCount int) []byte {
	if entryCount < 3 {
		panic("large RPM fixture needs at least three entries")
	}
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	binary.BigEndian.PutUint16(lead[8:10], 18)
	copy(lead[10:76], "large-index-1.0-1")
	binary.BigEndian.PutUint16(lead[76:78], 1)
	binary.BigEndian.PutUint16(lead[78:80], 5)

	signature := rpmHeaderFixture(nil, nil)
	store := []byte("x86_64\x00cpio\x00none\x00")
	main := make([]byte, 16+entryCount*16+len(store))
	copy(main[:8], []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(main[8:12], uint32(entryCount))
	binary.BigEndian.PutUint32(main[12:16], uint32(len(store)))
	writeIndex := func(index int, tag, valueType, offset, count uint32) {
		entry := main[16+index*16 : 16+(index+1)*16]
		binary.BigEndian.PutUint32(entry[0:4], tag)
		binary.BigEndian.PutUint32(entry[4:8], valueType)
		binary.BigEndian.PutUint32(entry[8:12], offset)
		binary.BigEndian.PutUint32(entry[12:16], count)
	}
	writeIndex(0, 1022, 6, 0, 1)
	writeIndex(1, 1124, 6, 7, 1)
	writeIndex(2, 1125, 6, 12, 1)
	for index := 3; index < entryCount; index++ {
		writeIndex(
			index,
			uint32(200_000+index),
			7,
			uint32(len(store)),
			0,
		)
	}
	copy(main[16+entryCount*16:], store)
	data := append(lead, signature...)
	data = append(data, main...)
	return append(data, 'x')
}

type rpmHeaderFixtureEntry struct {
	tag       uint32
	valueType uint32
	value     string
}

func rpmHeaderFixture(
	entries []rpmHeaderFixtureEntry,
	extraData []byte,
) []byte {
	var indexes bytes.Buffer
	var store bytes.Buffer
	for _, entry := range entries {
		var encoded [16]byte
		binary.BigEndian.PutUint32(encoded[0:4], entry.tag)
		binary.BigEndian.PutUint32(encoded[4:8], entry.valueType)
		binary.BigEndian.PutUint32(encoded[8:12], uint32(store.Len()))
		binary.BigEndian.PutUint32(encoded[12:16], 1)
		indexes.Write(encoded[:])
		store.WriteString(entry.value)
		store.WriteByte(0)
	}
	store.Write(extraData)
	var output bytes.Buffer
	output.Write([]byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0})
	var counts [8]byte
	binary.BigEndian.PutUint32(counts[0:4], uint32(len(entries)))
	binary.BigEndian.PutUint32(counts[4:8], uint32(store.Len()))
	output.Write(counts[:])
	output.Write(indexes.Bytes())
	output.Write(store.Bytes())
	return output.Bytes()
}

func isoFixture(udf bool) []byte {
	data := make([]byte, 20*2048)
	if udf {
		copy(data[16*2048+1:], "BEA01")
		copy(data[17*2048+1:], "NSR03")
		copy(data[18*2048+1:], "TEA01")
		return data
	}
	data[16*2048] = 1
	copy(data[16*2048+1:], "CD001")
	data[16*2048+6] = 1
	return data
}

func extFixture(format string) []byte {
	data := make([]byte, 4096)
	superblock := data[1024:2048]
	binary.LittleEndian.PutUint32(superblock[0:4], 128)
	binary.LittleEndian.PutUint32(superblock[4:8], 1024)
	binary.LittleEndian.PutUint16(superblock[0x38:0x3a], 0xef53)
	binary.LittleEndian.PutUint16(superblock[0x58:0x5a], 256)
	switch format {
	case "ext3":
		binary.LittleEndian.PutUint32(superblock[0x5c:0x60], 0x4)
	case "ext4":
		binary.LittleEndian.PutUint32(superblock[0x60:0x64], 0x40)
	}
	return data
}

func squashFixture() []byte {
	data := make([]byte, 4096)
	copy(data, "hsqs")
	binary.LittleEndian.PutUint32(data[12:16], 4096)
	binary.LittleEndian.PutUint16(data[20:22], 1)
	binary.LittleEndian.PutUint16(data[22:24], 12)
	binary.LittleEndian.PutUint16(data[28:30], 4)
	binary.LittleEndian.PutUint64(data[40:48], uint64(len(data)))
	return data
}

func mbrFixture(gpt bool) []byte {
	if gpt {
		return gptSectorFixture(512)
	}
	data := make([]byte, 100*512)
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], 50)
	return data
}

func gptSectorFixture(sectorSize int) []byte {
	const totalSectors = 100
	data := make([]byte, totalSectors*sectorSize)
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[4] = 0xee
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], totalSectors-1)
	header := data[sectorSize : sectorSize+92]
	copy(header, "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], 1)
	binary.LittleEndian.PutUint64(header[32:40], totalSectors-1)
	firstUsable := uint64(34)
	if sectorSize == 4096 {
		firstUsable = 6
	}
	binary.LittleEndian.PutUint64(header[40:48], firstUsable)
	binary.LittleEndian.PutUint64(header[48:56], 98)
	binary.LittleEndian.PutUint64(header[72:80], 2)
	binary.LittleEndian.PutUint32(header[80:84], 128)
	binary.LittleEndian.PutUint32(header[84:88], 128)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header))
	return data
}
