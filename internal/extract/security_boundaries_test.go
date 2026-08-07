package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestArchiveSecurityRejectsTraversalAndAbsolutePathsEndToEnd(
	t *testing.T,
) {
	entries := []zipEntry{
		{name: "../outside.txt", body: []byte("traversal"), store: true},
		{name: "/absolute.txt", body: []byte("absolute"), store: true},
		{name: "safe.txt", body: []byte("safe"), store: true},
	}
	tests := []struct {
		name   string
		format string
		data   []byte
	}{
		{
			name:   "zip",
			format: "zip",
			data:   zipFixture(t, entries),
		},
		{
			name:   "tar",
			format: "tar",
			data:   entryLimitTARFixture(t, entries),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runExtract(
				t,
				test.data,
				test.format,
				generousLimits(),
			)
			if !result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != len(entries) {
				t.Fatalf("result = %+v", result)
			}

			rejectedNames := map[string]bool{
				"../outside.txt": false,
				"/absolute.txt":  false,
			}
			for _, node := range result.Nodes {
				if node.ExtractionStatus != StatusInvalidPath {
					continue
				}
				if node.NodeType != NodeTypeFile ||
					node.ErrorCode != "invalid_archive_path" ||
					node.StorageKey != "" ||
					!strings.HasPrefix(
						node.LogicalPath,
						"/__rejected_entry_",
					) {
					t.Fatalf("rejected node = %+v", node)
				}
				var metadata map[string]any
				if err := json.Unmarshal(
					node.MetadataJSON,
					&metadata,
				); err != nil {
					t.Fatal(err)
				}
				rawName, ok := metadata["archive_path"].(string)
				if !ok {
					t.Fatalf("rejected metadata = %#v", metadata)
				}
				if _, expected := rejectedNames[rawName]; !expected {
					t.Fatalf("unexpected rejected name %q", rawName)
				}
				rejectedNames[rawName] = true
			}
			for rawName, found := range rejectedNames {
				if !found {
					t.Errorf("unsafe name %q was not quarantined", rawName)
				}
			}

			safe := findNode(t, result.Nodes, "/safe.txt")
			if safe.ExtractionStatus != StatusExtracted ||
				safe.SizeBytes != 4 ||
				safe.SHA256 == "" {
				t.Fatalf("safe node = %+v", safe)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestArchiveSecurityLinksAndSpecialNodesAreNeverMaterialized(
	t *testing.T,
) {
	t.Run("tar-link-escapes-and-special-types", func(t *testing.T) {
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		headers := []*tar.Header{
			{
				Name:     "safe.txt",
				Typeflag: tar.TypeReg,
				Mode:     0o600,
				Size:     4,
			},
			{
				Name:     "symlink",
				Typeflag: tar.TypeSymlink,
				Mode:     0o777,
				Linkname: "../../outside",
			},
			{
				Name:     "hardlink",
				Typeflag: tar.TypeLink,
				Mode:     0o600,
				Linkname: "/etc/shadow",
			},
			{
				Name:     "char-device",
				Typeflag: tar.TypeChar,
				Mode:     0o600,
				Devmajor: 1,
				Devminor: 3,
			},
			{
				Name:     "block-device",
				Typeflag: tar.TypeBlock,
				Mode:     0o600,
				Devmajor: 8,
				Devminor: 0,
			},
			{
				Name:     "fifo",
				Typeflag: tar.TypeFifo,
				Mode:     0o600,
			},
		}
		for index, header := range headers {
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if index == 0 {
				if _, err := writer.Write([]byte("safe")); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		result := runExtract(
			t,
			output.Bytes(),
			"tar",
			generousLimits(),
		)
		if result.Partial ||
			result.LimitCode != "" ||
			len(result.Nodes) != len(headers) {
			t.Fatalf("result = %+v", result)
		}
		if safe := findNode(t, result.Nodes, "/safe.txt"); safe.NodeType != NodeTypeFile ||
			safe.ExtractionStatus != StatusExtracted ||
			safe.SHA256 == "" {
			t.Fatalf("safe node = %+v", safe)
		}

		want := map[string]struct {
			nodeType string
			target   string
		}{
			"/symlink":      {NodeTypeSymlink, "../../outside"},
			"/hardlink":     {NodeTypeHardlink, "/etc/shadow"},
			"/char-device":  {NodeTypeSpecial, ""},
			"/block-device": {NodeTypeSpecial, ""},
			"/fifo":         {NodeTypeSpecial, ""},
		}
		for logicalPath, expected := range want {
			node := findNode(t, result.Nodes, logicalPath)
			if node.NodeType != expected.nodeType ||
				node.ExtractionStatus != StatusRecorded ||
				node.SHA256 != "" ||
				node.StorageKey != "" {
				t.Fatalf("%s node = %+v", logicalPath, node)
			}
			if expected.target == "" {
				continue
			}
			var metadata map[string]any
			if err := json.Unmarshal(
				node.MetadataJSON,
				&metadata,
			); err != nil {
				t.Fatal(err)
			}
			if metadata["link_target"] != expected.target ||
				metadata["link_target_truncated"] != false {
				t.Fatalf("%s metadata = %#v", logicalPath, metadata)
			}
		}
		assertCleanWorkDirectory(t)
	})

	t.Run("zip-symlink-fifo-device-and-socket", func(t *testing.T) {
		data := zipFixture(t, []zipEntry{
			{
				name: "symlink",
				body: []byte("../../outside"),
				mode: os.ModeSymlink | 0o777,
			},
			{
				name: "fifo",
				mode: os.ModeNamedPipe | 0o600,
			},
			{
				name: "device",
				mode: os.ModeDevice | os.ModeCharDevice | 0o600,
			},
			{
				name: "socket",
				mode: os.ModeSocket | 0o600,
			},
			{
				name: "safe.txt",
				body: []byte("safe"),
			},
		})
		result := runExtract(t, data, "zip", generousLimits())
		if result.Partial ||
			result.LimitCode != "" ||
			len(result.Nodes) != 5 {
			t.Fatalf("result = %+v", result)
		}
		for _, logicalPath := range []string{
			"/symlink",
			"/fifo",
			"/device",
			"/socket",
		} {
			node := findNode(t, result.Nodes, logicalPath)
			wantType := NodeTypeSpecial
			if logicalPath == "/symlink" {
				wantType = NodeTypeSymlink
			}
			if node.NodeType != wantType ||
				node.ExtractionStatus != StatusRecorded ||
				node.SHA256 != "" ||
				node.StorageKey != "" {
				t.Fatalf("%s node = %+v", logicalPath, node)
			}
		}
		if safe := findNode(t, result.Nodes, "/safe.txt"); safe.ExtractionStatus != StatusExtracted ||
			safe.SHA256 == "" {
			t.Fatalf("safe node = %+v", safe)
		}
		assertCleanWorkDirectory(t)
	})
}

func TestArchiveSecurityTenLayerBoundaryAndEleventhLayerLimit(
	t *testing.T,
) {
	for _, format := range []string{"zip", "tar"} {
		t.Run(format+"/ten-layers-accepted", func(t *testing.T) {
			data := archiveSecurityNestedFixture(t, format, 10)
			result := runExtract(
				t,
				data,
				format,
				generousLimits(),
			)
			if result.Partial ||
				result.LimitCode != "" ||
				len(result.Nodes) != 10 {
				t.Fatalf("result = %+v", result)
			}
			leaf := result.Nodes[len(result.Nodes)-1]
			if leaf.DisplayName != "leaf.txt" ||
				leaf.Depth != 10 ||
				leaf.ExtractionStatus != StatusExtracted ||
				leaf.SHA256 == "" {
				t.Fatalf("leaf = %+v", leaf)
			}
			for _, node := range result.Nodes {
				if node.ExtractionStatus != StatusExtracted {
					t.Fatalf("unexpected limited node = %+v", node)
				}
			}
			assertCleanWorkDirectory(t)
		})

		t.Run(format+"/eleventh-layer-limited", func(t *testing.T) {
			data := archiveSecurityNestedFixture(t, format, 11)
			result := runExtract(
				t,
				data,
				format,
				generousLimits(),
			)
			if !result.Partial ||
				result.LimitCode != LimitMaxDepth ||
				len(result.Nodes) != 10 {
				t.Fatalf("result = %+v", result)
			}
			limited := result.Nodes[len(result.Nodes)-1]
			if limited.Depth != 10 ||
				limited.ExtractionStatus != StatusDepthLimited ||
				limited.ErrorCode != LimitMaxDepth ||
				limited.Format != format {
				t.Fatalf("limited node = %+v", limited)
			}
			for _, node := range result.Nodes {
				if node.DisplayName == "leaf.txt" {
					t.Fatalf("depth-limited leaf was expanded: %+v", node)
				}
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestArchiveSecurityHundredToOneRatioBoundary(
	t *testing.T,
) {
	const targetZIPBytes = 1024
	zipCases := []struct {
		name      string
		payload   int
		wantLimit bool
	}{
		{
			name:    "exact-boundary",
			payload: targetZIPBytes * 100,
		},
		{
			name:      "one-byte-over",
			payload:   targetZIPBytes*100 + 1,
			wantLimit: true,
		},
	}
	for _, test := range zipCases {
		t.Run("zip/"+test.name, func(t *testing.T) {
			data := archiveSecuritySizedZIP(
				t,
				test.payload,
				targetZIPBytes,
			)
			capacity := int64(len(data)) * defaultMaxRatio
			if int64(test.payload) != capacity &&
				int64(test.payload) != capacity+1 {
				t.Fatalf(
					"fixture payload=%d capacity=%d",
					test.payload,
					capacity,
				)
			}

			result := runExtract(
				t,
				data,
				"zip",
				generousLimits(),
			)
			node := findNode(t, result.Nodes, "/payload.bin")
			assertArchiveSecurityRatioResult(
				t,
				result,
				node,
				capacity,
				test.wantLimit,
			)
			assertCleanWorkDirectory(t)
		})
	}

	for _, test := range []struct {
		name      string
		over      int64
		wantLimit bool
	}{
		{name: "exact-boundary"},
		{name: "one-byte-over", over: 1, wantLimit: true},
	} {
		t.Run("tar-sparse/"+test.name, func(t *testing.T) {
			data, logicalBytes := archiveSecurityExactRatioSparseTAR(
				t,
				test.over,
			)
			capacity := int64(len(data)) * defaultMaxRatio
			if logicalBytes != capacity+test.over {
				t.Fatalf(
					"fixture logical=%d capacity=%d over=%d",
					logicalBytes,
					capacity,
					test.over,
				)
			}

			result := runExtract(
				t,
				data,
				"tar",
				generousLimits(),
			)
			node := findNode(t, result.Nodes, "/sparse.bin")
			assertArchiveSecurityRatioResult(
				t,
				result,
				node,
				capacity,
				test.wantLimit,
			)
			assertCleanWorkDirectory(t)
		})
	}
}

func archiveSecurityNestedFixture(
	t *testing.T,
	format string,
	archiveLayers int,
) []byte {
	t.Helper()
	if archiveLayers < 1 {
		t.Fatal("archive layer count must be positive")
	}
	wrap := func(name string, body []byte) []byte {
		switch format {
		case "zip":
			return zipFixture(t, []zipEntry{{
				name:  name,
				body:  body,
				store: true,
			}})
		case "tar":
			return entryLimitTARFixture(t, []zipEntry{{
				name: name,
				body: body,
			}})
		default:
			t.Fatalf("unsupported fixture format %q", format)
			return nil
		}
	}

	data := wrap("leaf.txt", []byte("leaf"))
	for layer := 2; layer <= archiveLayers; layer++ {
		data = wrap(
			fmt.Sprintf("layer-%02d.%s", layer-1, format),
			data,
		)
	}
	return data
}

func archiveSecuritySizedZIP(
	t *testing.T,
	payloadBytes int,
	targetBytes int,
) []byte {
	t.Helper()
	if payloadBytes < 0 || targetBytes <= 0 {
		t.Fatal("invalid sized ZIP fixture request")
	}
	build := func(commentBytes int) []byte {
		var output bytes.Buffer
		writer := zip.NewWriter(&output)
		if err := writer.SetComment(strings.Repeat("c", commentBytes)); err != nil {
			t.Fatal(err)
		}
		entry, err := writer.CreateHeader(&zip.FileHeader{
			Name:   "payload.bin",
			Method: zip.Deflate,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(bytes.Repeat(
			[]byte{0},
			payloadBytes,
		)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), output.Bytes()...)
	}

	base := build(0)
	commentBytes := targetBytes - len(base)
	if commentBytes < 0 {
		t.Fatalf(
			"compressed ZIP fixture is %d bytes, target is %d",
			len(base),
			targetBytes,
		)
	}
	data := build(commentBytes)
	if len(data) != targetBytes {
		t.Fatalf("sized ZIP = %d bytes, want %d", len(data), targetBytes)
	}
	return data
}

func archiveSecurityExactRatioSparseTAR(
	t *testing.T,
	over int64,
) ([]byte, int64) {
	t.Helper()
	logicalBytes := int64(300 << 10)
	for attempt := 0; attempt < 8; attempt++ {
		data := archiveSecuritySparseTAR(t, logicalBytes)
		wanted := int64(len(data))*defaultMaxRatio + over
		if logicalBytes == wanted {
			return data, logicalBytes
		}
		logicalBytes = wanted
	}
	t.Fatal("sparse TAR fixture size did not converge")
	return nil, 0
}

func archiveSecuritySparseTAR(
	t *testing.T,
	logicalBytes int64,
) []byte {
	t.Helper()
	var paxBody []byte
	for _, record := range [][2]string{
		{"GNU.sparse.major", "1"},
		{"GNU.sparse.minor", "0"},
		{"GNU.sparse.name", "sparse.bin"},
		{"GNU.sparse.realsize", strconv.FormatInt(logicalBytes, 10)},
	} {
		paxBody = append(
			paxBody,
			makePAXRecord(record[0], record[1])...,
		)
	}
	paxPadded :=
		(len(paxBody) + tarBlockBytes - 1) &^ (tarBlockBytes - 1)
	const sparseMapBytes = tarBlockBytes
	mainOffset := tarBlockBytes + paxPadded
	endOffset := mainOffset + tarBlockBytes + sparseMapBytes
	output := make([]byte, endOffset+2*tarBlockBytes)

	putUSTARTARHeader(
		t,
		output[:tarBlockBytes],
		"PaxHeaders/sparse",
		tar.TypeXHeader,
		int64(len(paxBody)),
	)
	copy(output[tarBlockBytes:tarBlockBytes+len(paxBody)], paxBody)
	putUSTARTARHeader(
		t,
		output[mainOffset:mainOffset+tarBlockBytes],
		"placeholder",
		tar.TypeReg,
		sparseMapBytes,
	)
	copy(
		output[mainOffset+tarBlockBytes:mainOffset+2*tarBlockBytes],
		[]byte("0\n"),
	)
	return output
}

func assertArchiveSecurityRatioResult(
	t *testing.T,
	result Result,
	node Node,
	capacity int64,
	wantLimit bool,
) {
	t.Helper()
	if result.ExpandedBytes != capacity ||
		node.SizeBytes != capacity {
		t.Fatalf(
			"result=%+v node=%+v capacity=%d",
			result,
			node,
			capacity,
		)
	}
	if wantLimit {
		if !result.Partial ||
			result.LimitCode != LimitMaxRatio ||
			node.ExtractionStatus != StatusLimitExceeded ||
			node.ErrorCode != LimitMaxRatio ||
			node.SHA256 != "" {
			t.Fatalf("limited result=%+v node=%+v", result, node)
		}
		return
	}
	if result.Partial ||
		result.LimitCode != "" ||
		node.ExtractionStatus != StatusExtracted ||
		node.ErrorCode != "" ||
		node.SHA256 == "" {
		t.Fatalf("boundary result=%+v node=%+v", result, node)
	}
}
