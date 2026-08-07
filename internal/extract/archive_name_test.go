package extract

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestZIPAndTARPreserveInvalidUTF8ArchiveNameIdentity(t *testing.T) {
	rawName := []byte{'b', 'a', 'd', 0xff, '.', 'b', 'i', 'n'}
	for _, archiveFormat := range []string{"zip", "tar"} {
		t.Run(archiveFormat, func(t *testing.T) {
			var fixture []byte
			switch archiveFormat {
			case "zip":
				fixture = zipFixture(t, []zipEntry{{
					name: string(rawName), body: []byte("payload"),
				}})
			case "tar":
				fixture = tarWithRawName(t, rawName, []byte("payload"))
			}
			result := runExtract(t, fixture, archiveFormat, generousLimits())
			node := findNodeWithCode(t, result.Nodes, "invalid_archive_path")
			expected := "b64:" + base64.StdEncoding.EncodeToString(rawName)
			if node.ArchiveNameID != expected ||
				node.ExtractionStatus != StatusInvalidPath ||
				strings.Contains(node.LogicalPath, "\uFFFD") {
				t.Fatalf("node=%+v expected identity=%q", node, expected)
			}
		})
	}
}

func TestZIPAndTARNormalizeUnicodeAndSuffixNameCollisions(t *testing.T) {
	const (
		nfcName = "caf\u00e9.txt"
		nfdName = "cafe\u0301.txt"
	)
	for _, archiveFormat := range []string{"zip", "tar"} {
		t.Run(archiveFormat, func(t *testing.T) {
			fixture := regularNamesFixture(
				t, archiveFormat, []string{nfcName, nfdName},
			)
			result := runExtract(t, fixture, archiveFormat, generousLimits())
			first := findNode(t, result.Nodes, "/"+nfcName)
			collision := findNodeWithCode(
				t, result.Nodes, "unicode_normalization_collision",
			)
			if first.DisplayName != nfcName ||
				first.ArchiveNameID != archiveNameID(nfcName) ||
				collision.ArchiveNameID != archiveNameID(nfdName) ||
				!strings.HasPrefix(collision.LogicalPath, "/"+nfcName+"~") ||
				collision.DisplayName != strings.TrimPrefix(
					collision.LogicalPath, "/",
				) {
				t.Fatalf(
					"first=%+v collision=%+v result=%+v",
					first, collision, result,
				)
			}
		})
	}
}

func TestZIPAndTARDuplicateNamesReceiveDeterministicSuffix(t *testing.T) {
	const name = "same.txt"
	for _, archiveFormat := range []string{"zip", "tar"} {
		t.Run(archiveFormat, func(t *testing.T) {
			fixture := regularNamesFixture(
				t, archiveFormat, []string{name, name},
			)
			firstRun := runExtract(
				t, fixture, archiveFormat, generousLimits(),
			)
			secondRun := runExtract(
				t, fixture, archiveFormat, generousLimits(),
			)
			firstCollision := findNodeWithCode(
				t, firstRun.Nodes, "duplicate_archive_name",
			)
			secondCollision := findNodeWithCode(
				t, secondRun.Nodes, "duplicate_archive_name",
			)
			if firstCollision.LogicalPath != secondCollision.LogicalPath ||
				!strings.HasPrefix(firstCollision.LogicalPath, "/"+name+"~") ||
				firstCollision.ArchiveNameID != archiveNameID(name) {
				t.Fatalf(
					"first=%+v second=%+v",
					firstCollision, secondCollision,
				)
			}
		})
	}
}

func TestTraversalNameIsQuarantinedWithoutSanitizedFallback(t *testing.T) {
	const name = "../safe.txt"
	for _, archiveFormat := range []string{"zip", "tar"} {
		t.Run(archiveFormat, func(t *testing.T) {
			result := runExtract(
				t,
				regularNamesFixture(t, archiveFormat, []string{name}),
				archiveFormat,
				generousLimits(),
			)
			rejected := findNodeWithCode(
				t, result.Nodes, "invalid_archive_path",
			)
			if rejected.ArchiveNameID != archiveNameID(name) ||
				!strings.HasPrefix(
					rejected.LogicalPath, "/__rejected_entry_",
				) {
				t.Fatalf("rejected=%+v", rejected)
			}
			for _, node := range result.Nodes {
				if node.LogicalPath == "/safe.txt" ||
					strings.HasPrefix(node.LogicalPath, "/safe.txt~") {
					t.Fatalf("traversal path received a fallback: %+v", node)
				}
			}
		})
	}
}

func TestOverlongArchiveNameUsesBoundedDigestIdentifier(t *testing.T) {
	name := strings.Repeat("x", maxLogicalPathBytes+1)
	identity := archiveNameID(name)
	if !strings.HasPrefix(identity, "sha256:") || len(identity) != 71 {
		t.Fatalf("archiveNameID() = %q", identity)
	}
}

func regularNamesFixture(
	t *testing.T,
	archiveFormat string,
	names []string,
) []byte {
	t.Helper()
	switch archiveFormat {
	case "zip":
		entries := make([]zipEntry, 0, len(names))
		for _, name := range names {
			entries = append(entries, zipEntry{
				name: name, body: []byte(name), mode: 0o600,
			})
		}
		return zipFixture(t, entries)
	case "tar":
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		for _, name := range names {
			body := []byte(name)
			if err := writer.WriteHeader(&tar.Header{
				Name: name, Typeflag: tar.TypeReg, Mode: 0o600,
				Size: int64(len(body)),
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(body); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return output.Bytes()
	default:
		t.Fatalf("unsupported format %q", archiveFormat)
		return nil
	}
}

func tarWithRawName(t *testing.T, rawName []byte, body []byte) []byte {
	t.Helper()
	if len(rawName) == 0 || len(rawName) > 100 {
		t.Fatal("raw TAR test name is outside the legacy header field")
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	placeholder := strings.Repeat("x", len(rawName))
	if err := writer.WriteHeader(&tar.Header{
		Name: placeholder, Typeflag: tar.TypeReg, Mode: 0o600,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	fixture := append([]byte(nil), output.Bytes()...)
	copy(fixture[:len(rawName)], rawName)
	for index := 148; index < 156; index++ {
		fixture[index] = ' '
	}
	var checksum int
	for _, value := range fixture[:512] {
		checksum += int(value)
	}
	copy(fixture[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
	return fixture
}
