package filetype

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDetectorReportsStrictPEZIPPolyglotCandidates(t *testing.T) {
	data := peZIPPolyglotFixture(t)
	detected := mustDetect(t, data)
	if detected.Format != "pe32" {
		t.Fatalf("primary format = %q, want pe32", detected.Format)
	}
	candidates := identificationCandidates(t, detected)
	if !reflect.DeepEqual(candidateFormats(candidates), []string{"pe32", "zip"}) {
		t.Fatalf("candidate formats = %+v", candidates)
	}
	if detected.Metadata["identification_ambiguous"] != true {
		t.Fatalf("ambiguity flag = %#v", detected.Metadata)
	}
	for _, candidate := range candidates {
		if candidate.Category == "" || candidate.MIMEType == "" ||
			candidate.Evidence == "" ||
			strings.ContainsAny(candidate.Evidence, "/\\ \t\r\n") {
			t.Fatalf("candidate has unsafe evidence: %+v", candidate)
		}
	}
}

func TestDetectorReportsStrictTARExtPolyglotCandidates(t *testing.T) {
	data := tarExtPolyglotFixture(t)
	detected := mustDetect(t, data)
	if detected.Format != "tar" {
		t.Fatalf("primary format = %q, want tar", detected.Format)
	}
	candidates := identificationCandidates(t, detected)
	if !reflect.DeepEqual(candidateFormats(candidates), []string{"tar", "ext4"}) {
		t.Fatalf("candidate formats = %+v", candidates)
	}
	if detected.Metadata["identification_ambiguous"] != true {
		t.Fatalf("ambiguity flag = %#v", detected.Metadata)
	}
}

func TestPrimaryArchiveDispatchRemainsCompatibleForTARZIPPolyglot(t *testing.T) {
	tarData := v7TARFixture(t, []v7TAREntry{{
		name: "payload.bin",
		body: []byte("payload"),
	}})
	data := appendRebasedZIP(t, tarData, zipFixture(t, "appended.bin"))
	detected := mustDetect(t, data)
	if detected.Format != "tar" {
		t.Fatalf("primary archive dispatch changed to %q", detected.Format)
	}
	candidates := identificationCandidates(t, detected)
	if !reflect.DeepEqual(candidateFormats(candidates), []string{"zip", "tar"}) {
		t.Fatalf("priority-ordered candidates = %+v", candidates)
	}
	if detected.Metadata["identification_ambiguous"] != true {
		t.Fatalf("ambiguity flag = %#v", detected.Metadata)
	}
}

func TestDetectorDoesNotTreatEmbeddedMagicAsCandidate(t *testing.T) {
	unadjustedZIP := zipFixture(t, "payload.bin")
	input := append(bytes.Repeat([]byte{'X'}, 257), unadjustedZIP...)
	copy(input[17:], []byte{'M', 'Z'})
	copy(input[79:], []byte{0x7f, 'E', 'L', 'F'})
	copy(input[141:], []byte("ustar"))

	detected := mustDetect(t, input)
	if detected.Format != "unknown" {
		t.Fatalf("embedded signatures detected as %+v", detected)
	}
	if candidates := identificationCandidates(t, detected); len(candidates) != 0 {
		t.Fatalf("embedded signatures produced candidates: %+v", candidates)
	}
	if _, exists := detected.Metadata["identification_ambiguous"]; exists {
		t.Fatalf("unknown result has ambiguity flag: %#v", detected.Metadata)
	}
}

func TestDeferredOrCorruptPrimaryDoesNotBecomeStrictCandidate(t *testing.T) {
	rpmWithExt := make([]byte, 4096)
	copy(rpmWithExt, []byte{0xed, 0xab, 0xee, 0xdb})
	ext := extFixture("ext4")
	copy(rpmWithExt[1024:2048], ext[1024:2048])
	tests := []struct {
		name string
		data []byte
	}{
		{name: "RPM magic only", data: []byte{0xed, 0xab, 0xee, 0xdb}},
		{
			name: "weak RPM primary blocks strict EXT supplement",
			data: rpmWithExt,
		},
		{
			name: "ZIP deferred validation",
			data: func() []byte {
				data := zipFixture(t, "payload.bin")
				eocd := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
				binary.LittleEndian.PutUint16(data[eocd+8:eocd+10], 0)
				return data
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detected := mustDetect(t, test.data)
			if detected.Format == "unknown" {
				t.Fatalf("existing primary recognition changed: %+v", detected)
			}
			if candidates := identificationCandidates(t, detected); len(candidates) != 0 {
				t.Fatalf("weak primary became strict candidate: %+v", candidates)
			}
			if _, exists := detected.Metadata["identification_ambiguous"]; exists {
				t.Fatalf("weak primary is marked ambiguous: %#v", detected.Metadata)
			}
		})
	}
}

func TestIdentificationCandidatesAreDeterministicAndRoundTripJSON(t *testing.T) {
	data := peZIPPolyglotFixture(t)
	first := mustDetect(t, data)
	second := mustDetect(t, data)
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("candidate output is not deterministic:\n%s\n%s",
			firstJSON, secondJSON)
	}
	if len(firstJSON) > 128<<10 {
		t.Fatalf("polyglot metadata is not bounded: %d", len(firstJSON))
	}
	var roundTrip struct {
		Metadata struct {
			Candidates []identificationCandidate `json:"identification_candidates"`
			Ambiguous  bool                      `json:"identification_ambiguous"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(firstJSON, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !roundTrip.Metadata.Ambiguous ||
		!reflect.DeepEqual(
			candidateFormats(roundTrip.Metadata.Candidates),
			[]string{"pe32", "zip"},
		) {
		t.Fatalf("round-trip metadata = %+v", roundTrip.Metadata)
	}
}

func TestCandidateCatalogMatchesSupportedFormatsAndHardLimit(t *testing.T) {
	formats := make([]string, 0, len(candidateDescriptors))
	for format, descriptor := range candidateDescriptors {
		if descriptor.category == "" ||
			descriptor.mimeType == "" ||
			descriptor.evidence == "" {
			t.Fatalf("incomplete descriptor for %s: %+v", format, descriptor)
		}
		formats = append(formats, format)
	}
	sort.Strings(formats)
	if !reflect.DeepEqual(formats, supportedFormats) {
		t.Fatalf("candidate catalog = %v, supported formats = %v",
			formats, supportedFormats)
	}
	if maxCandidates != 8 {
		t.Fatalf("candidate hard limit = %d, want 8", maxCandidates)
	}
}

func TestPolyglotCandidateInspectionSharesGlobalReadBudget(t *testing.T) {
	data := peZIPPolyglotFixture(t)
	source := &countingDataReaderAt{reader: bytes.NewReader(data)}
	detected, err := (Detector{}).Detect(source, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if detected.Format != "pe32" ||
		len(identificationCandidates(t, detected)) != 2 {
		t.Fatalf("polyglot result = %+v", detected)
	}
	if source.total > maxInspectionBytes {
		t.Fatalf("detector read %d bytes, limit is %d",
			source.total, maxInspectionBytes)
	}
	if source.largest > maxSingleRead {
		t.Fatalf("largest read = %d, limit is %d",
			source.largest, maxSingleRead)
	}
}

func TestSupplementaryProbeErrorDoesNotReplacePrimary(t *testing.T) {
	data := peFixture(false, false, 3)
	source := &candidateFailingReaderAt{
		data:      data,
		maxLength: 100,
		err:       errors.New("supplementary read failed"),
	}
	detected, err := (Detector{}).Detect(source, int64(len(data)))
	if err != nil {
		t.Fatalf("supplementary error escaped Detect: %v", err)
	}
	if detected.Format != "pe32" {
		t.Fatalf("primary result = %+v", detected)
	}
	candidates := identificationCandidates(t, detected)
	if !reflect.DeepEqual(candidateFormats(candidates), []string{"pe32"}) {
		t.Fatalf("candidates after supplementary error = %+v", candidates)
	}
}

func identificationCandidates(
	t *testing.T,
	detected Result,
) []identificationCandidate {
	t.Helper()
	candidates, ok := detected.Metadata["identification_candidates"].([]identificationCandidate)
	if !ok {
		t.Fatalf("candidate metadata has type %T",
			detected.Metadata["identification_candidates"])
	}
	if len(candidates) > maxCandidates {
		t.Fatalf("candidate count = %d, limit is %d",
			len(candidates), maxCandidates)
	}
	return candidates
}

func candidateFormats(candidates []identificationCandidate) []string {
	formats := make([]string, len(candidates))
	for index, candidate := range candidates {
		formats[index] = candidate.Format
	}
	return formats
}

func peZIPPolyglotFixture(t *testing.T) []byte {
	t.Helper()
	prefix := peFixture(false, false, 3)
	return appendRebasedZIP(t, prefix, zipFixture(t, "payload.bin"))
}

func appendRebasedZIP(t *testing.T, prefix, zipData []byte) []byte {
	t.Helper()
	archive := append([]byte(nil), zipData...)
	eocd := bytes.LastIndex(archive, []byte{'P', 'K', 5, 6})
	if eocd < 0 {
		t.Fatal("ZIP EOCD not found")
	}
	directoryOffset := int(binary.LittleEndian.Uint32(
		archive[eocd+16 : eocd+20],
	))
	directorySize := int(binary.LittleEndian.Uint32(
		archive[eocd+12 : eocd+16],
	))
	for offset := directoryOffset; offset < directoryOffset+directorySize; {
		if offset+46 > len(archive) ||
			!bytes.Equal(archive[offset:offset+4], []byte{'P', 'K', 1, 2}) {
			t.Fatal("invalid ZIP fixture central directory")
		}
		localOffset := binary.LittleEndian.Uint32(
			archive[offset+42 : offset+46],
		)
		binary.LittleEndian.PutUint32(
			archive[offset+42:offset+46],
			localOffset+uint32(len(prefix)),
		)
		nameLength := int(binary.LittleEndian.Uint16(
			archive[offset+28 : offset+30],
		))
		extraLength := int(binary.LittleEndian.Uint16(
			archive[offset+30 : offset+32],
		))
		commentLength := int(binary.LittleEndian.Uint16(
			archive[offset+32 : offset+34],
		))
		offset += 46 + nameLength + extraLength + commentLength
	}
	binary.LittleEndian.PutUint32(
		archive[eocd+16:eocd+20],
		uint32(directoryOffset+len(prefix)),
	)
	return append(prefix, archive...)
}

func tarExtPolyglotFixture(t *testing.T) []byte {
	t.Helper()
	body := make([]byte, 2048)
	ext := extFixture("ext4")
	copy(body[512:1536], ext[1024:2048])
	return v7TARFixture(t, []v7TAREntry{{
		name: "filesystem.bin",
		body: body,
	}})
}

type candidateFailingReaderAt struct {
	data      []byte
	maxLength int
	err       error
}

func (reader *candidateFailingReaderAt) ReadAt(
	buffer []byte,
	offset int64,
) (int, error) {
	if len(buffer) > reader.maxLength {
		return 0, reader.err
	}
	return bytes.NewReader(reader.data).ReadAt(buffer, offset)
}

var _ io.ReaderAt = (*candidateFailingReaderAt)(nil)
