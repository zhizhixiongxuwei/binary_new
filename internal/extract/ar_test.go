package extract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan/internal/filetype"

	"github.com/klauspost/compress/zstd"
	xzlib "github.com/ulikunitz/xz"
	lzmalib "github.com/ulikunitz/xz/lzma"
)

func TestARExtractsSysVGNUAndBSDMembers(t *testing.T) {
	gnuName := "dir/gnu-long-member-name.txt"
	bsdName := "bsd-long-member-name.txt"
	data := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "short.txt/", body: []byte("odd")},
		{rawName: "//", body: []byte(gnuName + "/\n")},
		{rawName: "/0", body: []byte("gnu")},
		arBSDEntry(bsdName, []byte("bsd")),
		{rawName: "/", body: []byte{0, 0, 0, 0}},
	})

	result := runARExtract(t, data, arProfileGeneric, generousLimits())
	if result.Partial ||
		result.parserDecoderMemoryUsed != 0 ||
		result.parserDecoderMemoryPeak < int64(len(gnuName)+2) {
		t.Fatalf("result = %+v", result)
	}
	if node := findNode(t, result.Nodes, "/short.txt"); node.SizeBytes != 3 || node.ExtractionStatus != StatusExtracted {
		t.Fatalf("short node = %+v", node)
	}
	gnu := findNode(t, result.Nodes, "/dir/gnu-long-member-name.txt")
	bsd := findNode(t, result.Nodes, "/"+bsdName)
	for _, test := range []struct {
		node     Node
		encoding string
	}{
		{node: gnu, encoding: arMemberNameEncodingGNU},
		{node: bsd, encoding: arMemberNameEncodingBSD},
	} {
		var metadata map[string]any
		if err := json.Unmarshal(test.node.MetadataJSON, &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata["ar_name_encoding"] != test.encoding {
			t.Fatalf("metadata = %+v", metadata)
		}
	}
	if countNodesWithCode(result.Nodes, "ar_symbol_table_skipped") != 1 {
		t.Fatalf("symbol-table diagnostic missing: %+v", result.Nodes)
	}
	assertCleanWorkDirectory(t)
}

func TestAREngineDispatchesARAndDEBProfiles(t *testing.T) {
	arResult := runExtract(
		t,
		arArchiveFixture(t, []arFixtureEntry{{
			rawName: "file/",
			body:    []byte("ar"),
		}}),
		"ar",
		generousLimits(),
	)
	if arResult.Partial ||
		findNode(t, arResult.Nodes, "/file").ExtractionStatus !=
			StatusExtracted {
		t.Fatalf("AR result = %+v", arResult)
	}

	tarBody := arTARFixture(t, "payload", []byte("deb"))
	debResult := runExtract(
		t,
		arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "control.tar/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
		}),
		"deb",
		generousLimits(),
	)
	if debResult.Partial ||
		findNode(t, debResult.Nodes, "/data.tar/payload").
			ExtractionStatus != StatusExtracted {
		t.Fatalf("DEB result = %+v", debResult)
	}
}

func TestARInvalidDEBScanNameAvoidsOccupiedPaths(t *testing.T) {
	state := operationState{
		engine: NewEngine(filetype.Detector{}, generousLimits()),
		nextID: 7,
		nodes: []Node{{
			LocalID:       1,
			ParentLocalID: 0,
			LogicalPath:   "/outer",
			NodeType:      NodeTypeDirectory,
			Depth:         1,
		}},
		paths: map[string]struct{}{
			"/outer":                            {},
			"/outer/__deb_duplicate_member_7":   {},
			"/outer/__deb_duplicate_member_7_1": {},
		},
		nodeIndex: map[int]int{1: 0},
	}
	location, err := state.uniqueQuarantineLocation(
		1,
		"deb_duplicate",
	)
	if err != nil {
		t.Fatal(err)
	}
	if location.logical != "/outer/__deb_duplicate_member_7_2" ||
		location.parentID != 1 ||
		location.depth != 2 {
		t.Fatalf("unique scan location = %+v", location)
	}
}

func TestARPathCollisionsAreRemappedAndRecursivelyScanned(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "hidden.txt",
		body: []byte("visible"),
	}})
	data := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "dup.zip/", body: []byte("first")},
		{rawName: "dup.zip/", body: nested},
	})

	result := runARExtract(t, data, arProfileGeneric, generousLimits())
	if !result.Partial ||
		countNodesWithCode(result.Nodes, "duplicate_logical_path") != 1 {
		t.Fatalf("result = %+v", result)
	}
	var duplicate, payload *Node
	for index := range result.Nodes {
		node := &result.Nodes[index]
		if node.ErrorCode == "duplicate_logical_path" {
			duplicate = node
		}
		if node.DisplayName == "hidden.txt" {
			payload = node
		}
	}
	if duplicate == nil ||
		duplicate.ExtractionStatus != StatusInvalidPath ||
		!strings.Contains(duplicate.LogicalPath, "__duplicate_entry_") ||
		payload == nil ||
		payload.ParentLocalID == 0 {
		t.Fatalf("duplicate=%+v payload=%+v nodes=%+v", duplicate, payload, result.Nodes)
	}
	var metadata map[string]any
	if err := json.Unmarshal(duplicate.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["archive"] != arProfileGeneric ||
		metadata["duplicate_logical_path"] != "/dup.zip" {
		t.Fatalf("duplicate metadata = %+v", metadata)
	}
}

func TestARNearMaxDuplicateMovesToSafeAncestorAndRecurses(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("visible"),
	}})
	inner := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "dup.zip/", body: []byte("first")},
		{rawName: "dup.zip/", body: nested},
	})
	containerPath := nearMaxArchivePath("c")
	prefix := "/" + containerPath
	outer := zipFixture(t, []zipEntry{{
		name:  containerPath,
		body:  inner,
		store: true,
	}})

	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, prefix)
	duplicate := findNodeWithCode(
		t,
		result.Nodes,
		"duplicate_logical_path",
	)
	parent := nodeWithLocalID(
		t,
		result.Nodes,
		duplicate.ParentLocalID,
	)
	payload := findNode(
		t,
		result.Nodes,
		duplicate.LogicalPath+"/payload.txt",
	)
	var metadata map[string]any
	if err := json.Unmarshal(duplicate.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if !result.Partial ||
		result.LimitCode != "" ||
		container.Format != arProfileGeneric ||
		duplicate.ParentLocalID == container.LocalID ||
		len(duplicate.LogicalPath) > maxLogicalPathBytes ||
		duplicate.Depth != parent.Depth+1 ||
		!strings.HasPrefix(duplicate.LogicalPath, parent.LogicalPath+"/") ||
		payload.ParentLocalID != duplicate.LocalID ||
		payload.Depth != duplicate.Depth+1 ||
		payload.ExtractionStatus != StatusExtracted ||
		metadata["duplicate_logical_path"] != prefix+"/dup.zip" {
		t.Fatalf(
			"result=%+v container=%+v duplicate=%+v parent=%+v payload=%+v metadata=%+v",
			result,
			container,
			duplicate,
			parent,
			payload,
			metadata,
		)
	}
}

func TestARQuarantineNameCollisionsDoNotHideNestedPayloads(t *testing.T) {
	nestedZIP := zipFixture(t, []zipEntry{{
		name: "extended-hidden.txt",
		body: []byte("visible"),
	}})
	nestedTAR := arTARFixture(t, "duplicate-hidden.txt", []byte("visible"))
	tests := []struct {
		name        string
		entries     []arFixtureEntry
		kind        string
		payloadName string
	}{
		{
			name: "extended",
			entries: []arFixtureEntry{
				arBSDEntry("hidden.zip", nestedZIP),
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: arTARFixture(t, "control", []byte("ok"))},
				{rawName: "data.tar/", body: arTARFixture(t, "data", []byte("ok"))},
			},
			kind:        "deb_extended",
			payloadName: "extended-hidden.txt",
		},
		{
			name: "required duplicate",
			entries: []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: arTARFixture(t, "control", []byte("ok"))},
				{rawName: "data.tar/", body: arTARFixture(t, "data", []byte("ok"))},
				{rawName: "data.tar/", body: nestedTAR},
			},
			kind:        "deb_duplicate",
			payloadName: "duplicate-hidden.txt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := runARExtractWithStateSetup(
				t,
				context.Background(),
				arArchiveFixture(t, test.entries),
				arProfileDeb,
				generousLimits(),
				func(state *operationState) {
					for id := 1; id <= 20; id++ {
						base := fmt.Sprintf(
							"/__%s_member_%d",
							test.kind,
							id,
						)
						state.paths[base] = struct{}{}
						state.paths[base+"_1"] = struct{}{}
					}
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			var payload *Node
			for index := range result.Nodes {
				node := &result.Nodes[index]
				if node.DisplayName == test.payloadName {
					payload = node
					break
				}
			}
			if !result.Partial ||
				payload == nil ||
				!strings.Contains(payload.LogicalPath, "_2/") {
				t.Fatalf("result=%+v payload=%+v", result, payload)
			}
		})
	}
}

func TestARMalformedNamesAreLocalAndSiblingSurvives(t *testing.T) {
	longName := bytes.Repeat([]byte{'a'}, maxARMemberNameBytes+1)
	data := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "//", body: []byte("valid-name.txt/\n")},
		{rawName: "/999", body: []byte("bad-offset")},
		arBSDEntry(string(longName), []byte("too-long")),
		{rawName: "../escape/", body: []byte("escape")},
		{rawName: "safe.txt/", body: []byte("safe")},
	})

	result := runARExtract(t, data, arProfileGeneric, generousLimits())
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial ||
		safe.ExtractionStatus != StatusExtracted ||
		countNodesWithCode(result.Nodes, "ar_gnu_name_offset_invalid") != 1 ||
		countNodesWithCode(result.Nodes, "ar_member_name_too_long") != 1 ||
		countNodesWithCode(result.Nodes, "invalid_archive_path") != 1 {
		t.Fatalf("result=%+v safe=%+v", result, safe)
	}
	assertCleanWorkDirectory(t)
}

func TestAROverlongBSDNameBodyRecursesFromQuarantine(t *testing.T) {
	overlongName := strings.Repeat("n", maxARMemberNameBytes+1)
	tests := []struct {
		name        string
		body        []byte
		format      string
		payloadName string
	}{
		{
			name: "zip",
			body: zipFixture(t, []zipEntry{{
				name: "zip-hidden.txt",
				body: []byte("visible"),
			}}),
			format:      "zip",
			payloadName: "zip-hidden.txt",
		},
		{
			name:        "tar",
			body:        arTARFixture(t, "tar-hidden.txt", []byte("visible")),
			format:      "tar",
			payloadName: "tar-hidden.txt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runARExtract(
				t,
				arArchiveFixture(t, []arFixtureEntry{
					arBSDEntry(overlongName, test.body),
				}),
				arProfileGeneric,
				generousLimits(),
			)
			invalid := findNodeWithCode(
				t,
				result.Nodes,
				"ar_member_name_too_long",
			)
			payload := findNode(
				t,
				result.Nodes,
				invalid.LogicalPath+"/"+test.payloadName,
			)
			var metadata map[string]any
			if err := json.Unmarshal(invalid.MetadataJSON, &metadata); err != nil {
				t.Fatal(err)
			}
			if !result.Partial ||
				result.LimitCode != "" ||
				invalid.ExtractionStatus != StatusCorrupt ||
				invalid.Format != test.format ||
				invalid.SizeBytes != int64(len(test.body)) ||
				payload.ParentLocalID != invalid.LocalID ||
				payload.ExtractionStatus != StatusExtracted ||
				metadata["declared_bytes"] != float64(len(test.body)) ||
				metadata["header_bytes"] !=
					float64(len(overlongName)+len(test.body)) {
				t.Fatalf(
					"result=%+v invalid=%+v payload=%+v metadata=%+v",
					result,
					invalid,
					payload,
					metadata,
				)
			}
		})
	}
}

func TestResolveARMemberRejectsInvalidBSDNameBounds(t *testing.T) {
	body := []byte("raw")
	tests := []struct {
		name    string
		rawName string
	}{
		{name: "truncated name", rawName: "#1/4"},
		{
			name:    "numeric overflow",
			rawName: "#1/" + strings.Repeat("9", 32),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := resolveARMember(
				context.Background(),
				bytes.NewReader(body),
				int64(len(body)),
				arMemberHeader{
					rawName: test.rawName,
					size:    int64(len(body)),
				},
				0,
				int64(len(body)),
				nil,
			)
			if resolved.nameError == nil ||
				resolved.nameErrorCode != "ar_bsd_name_invalid" ||
				resolved.nameEncoding != arMemberNameEncodingBSD ||
				resolved.dataOffset != 0 ||
				resolved.dataSize != int64(len(body)) {
				t.Fatalf("resolved member = %+v", resolved)
			}
		})
	}
}

func TestARInvalidGNUNameBodyRecursesFromNearMaxQuarantine(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "hidden.txt",
		body: []byte("visible"),
	}})
	inner := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "//", body: []byte("valid-name.txt/\n")},
		{rawName: "/999", body: nested},
	})
	containerPath := nearMaxArchivePath("c")
	prefix := "/" + containerPath
	outer := zipFixture(t, []zipEntry{{
		name:  containerPath,
		body:  inner,
		store: true,
	}})

	result := runExtract(t, outer, "zip", generousLimits())
	container := findNode(t, result.Nodes, prefix)
	invalid := findNodeWithCode(
		t,
		result.Nodes,
		"ar_gnu_name_offset_invalid",
	)
	parent := nodeWithLocalID(t, result.Nodes, invalid.ParentLocalID)
	payload := findNode(
		t,
		result.Nodes,
		invalid.LogicalPath+"/hidden.txt",
	)
	var metadata map[string]any
	if err := json.Unmarshal(invalid.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if !result.Partial ||
		result.LimitCode != "" ||
		container.Format != arProfileGeneric ||
		invalid.ExtractionStatus != StatusCorrupt ||
		invalid.Format != "zip" ||
		invalid.ParentLocalID == container.LocalID ||
		len(invalid.LogicalPath) > maxLogicalPathBytes ||
		invalid.Depth != parent.Depth+1 ||
		!strings.HasPrefix(invalid.LogicalPath, parent.LogicalPath+"/") ||
		payload.ParentLocalID != invalid.LocalID ||
		payload.Depth != invalid.Depth+1 ||
		payload.ExtractionStatus != StatusExtracted ||
		metadata["archive"] != arProfileGeneric ||
		metadata["raw_name"] != "/999" ||
		metadata["archive_container_path"] != prefix {
		t.Fatalf(
			"result=%+v container=%+v invalid=%+v parent=%+v payload=%+v metadata=%+v",
			result,
			container,
			invalid,
			parent,
			payload,
			metadata,
		)
	}
}

func TestResolveGNUARNameUsesBoundedSearchWindow(t *testing.T) {
	table := bytes.Repeat([]byte{'a'}, int(maxARStringTableBytes))
	copy(table[len(table)-2:], "/\n")

	window := boundedGNUARNameSearchWindow(table)
	wantWindowBytes := maxARMemberNameBytes + len("/\n")
	if len(window) != wantWindowBytes {
		t.Fatalf(
			"search window bytes = %d, want %d",
			len(window),
			wantWindowBytes,
		)
	}
	if _, err := resolveGNUARName(table, 0); err == nil ||
		!errors.Is(err, errInvalidARArchive) ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("overlong GNU name error = %v", err)
	}

	maximumName := bytes.Repeat([]byte{'m'}, maxARMemberNameBytes)
	maximumTable := append(append([]byte(nil), maximumName...), '/', '\n')
	got, err := resolveGNUARName(maximumTable, 0)
	if err != nil || got != string(maximumName) {
		t.Fatalf("maximum GNU name = %q, %v", got, err)
	}

	if _, err := resolveGNUARName([]byte("unterminated"), 0); err == nil ||
		!strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("unterminated GNU name error = %v", err)
	}

	boundaryTable := []byte("first/\nsecond/\n")
	if _, err := resolveGNUARName(boundaryTable, 1); err == nil ||
		!strings.Contains(err.Error(), "outside an entry boundary") {
		t.Fatalf("GNU boundary error = %v", err)
	}
	got, err = resolveGNUARName(boundaryTable, int64(len("first/\n")))
	if err != nil || got != "second" {
		t.Fatalf("boundary GNU name = %q, %v", got, err)
	}
}

func TestARStructuralCorruptionIsDiagnosed(t *testing.T) {
	valid := arArchiveFixture(t, []arFixtureEntry{{
		rawName: "file/",
		body:    []byte("x"),
	}})
	badSize := append([]byte(nil), valid...)
	copy(badSize[arGlobalHeaderSize+48:arGlobalHeaderSize+58], "not-a-size")
	truncatedBody := arArchiveWithDeclaredMember(
		t,
		"file/",
		10,
		[]byte("x"),
		false,
	)
	badPadding := append([]byte(nil), valid...)
	badPadding[len(badPadding)-1] = 0

	for _, test := range []struct {
		name string
		data []byte
		code string
	}{
		{
			name: "global-magic",
			data: []byte("not-ar!!"),
			code: "ar_archive_corrupt",
		},
		{
			name: "truncated-header",
			data: append(append([]byte(nil), arGlobalMagic...), 'x'),
			code: "ar_header_corrupt",
		},
		{name: "invalid-size", data: badSize, code: "ar_header_corrupt"},
		{
			name: "truncated-body",
			data: truncatedBody,
			code: "ar_member_truncated",
		},
		{
			name: "invalid-padding",
			data: badPadding,
			code: "ar_member_truncated",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := runARExtract(
				t,
				test.data,
				arProfileGeneric,
				generousLimits(),
			)
			if !result.Partial ||
				countNodesWithCode(result.Nodes, test.code) != 1 {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestARLimitsAndCancellation(t *testing.T) {
	t.Run("expanded-bytes", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxExpandedBytes = 10
		data := arArchiveFixture(t, []arFixtureEntry{{
			rawName: "large/",
			body:    bytes.Repeat([]byte{'x'}, 128),
		}})
		result := runARExtract(t, data, arProfileGeneric, limits)
		node := findNode(t, result.Nodes, "/large")
		if !result.Partial ||
			result.LimitCode != LimitMaxExpandedBytes ||
			node.SizeBytes != 10 ||
			node.ExtractionStatus != StatusLimitExceeded {
			t.Fatalf("result=%+v node=%+v", result, node)
		}
	})

	t.Run("string-table-memory", func(t *testing.T) {
		data := arArchiveFixture(t, []arFixtureEntry{{
			rawName: "//",
			body:    bytes.Repeat([]byte{'a'}, int(maxARStringTableBytes)+1),
		}})
		result := runARExtract(t, data, arProfileGeneric, generousLimits())
		if !result.Partial ||
			result.LimitCode != LimitMaxArchiveMetadata ||
			result.parserDecoderMemoryUsed != 0 ||
			len(result.Nodes) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("node-count", func(t *testing.T) {
		limits := generousLimits()
		limits.MaxNodes = 1
		data := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "one/", body: []byte("1")},
			{rawName: "two/", body: []byte("2")},
		})
		result := runARExtract(t, data, arProfileGeneric, limits)
		if !result.Partial ||
			result.LimitCode != LimitMaxNodes ||
			len(result.Nodes) != 1 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := runARExtractWithContext(
			t,
			ctx,
			arArchiveFixture(t, []arFixtureEntry{{
				rawName: "file/",
				body:    []byte("content"),
			}}),
			arProfileGeneric,
			generousLimits(),
		)
		if !errors.Is(err, context.Canceled) ||
			!result.Partial ||
			result.LimitCode != LimitContextCancelled ||
			len(result.Nodes) != 0 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
	})
}

func TestDEBRecursesGZIPXZAndZSTDWithExtensions(t *testing.T) {
	for _, codec := range []string{"gzip", "xz", "zstd"} {
		t.Run(codec, func(t *testing.T) {
			suffix, compress := arStreamCodec(t, codec)
			control := compress(arTARFixture(t, "control.txt", []byte("control")))
			dataPayload := compress(arTARFixture(t, "payload.txt", []byte("data")))
			deb := arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.17\nFeature: enabled\n")},
				{rawName: "_before/", body: []byte("extension")},
				{rawName: "control.tar" + suffix + "/", body: control},
				{rawName: "_between/", body: []byte("extension")},
				{rawName: "data.tar" + suffix + "/", body: dataPayload},
				{rawName: "notes/", body: []byte("kept")},
			})

			result := runARExtract(t, deb, arProfileDeb, generousLimits())
			controlPath := "/control.tar" + suffix + "/content/control.txt"
			dataPath := "/data.tar" + suffix + "/content/payload.txt"
			if result.Partial ||
				findNode(t, result.Nodes, controlPath).ExtractionStatus !=
					StatusExtracted ||
				findNode(t, result.Nodes, dataPath).ExtractionStatus !=
					StatusExtracted ||
				findNode(t, result.Nodes, "/notes").ExtractionStatus !=
					StatusExtracted {
				t.Fatalf("result = %+v", result)
			}
			version := findNode(t, result.Nodes, "/debian-binary")
			var metadata map[string]any
			if err := json.Unmarshal(version.MetadataJSON, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["deb_expected_version"] != "2.<numeric-minor>" {
				t.Fatalf("version metadata = %+v", metadata)
			}
			assertCleanWorkDirectory(t)
		})
	}
}

func TestDEBStructuralDiagnosticsDoNotHidePayloads(t *testing.T) {
	tarBody := arTARFixture(t, "payload.txt", []byte("visible"))

	t.Run("unsupported-version", func(t *testing.T) {
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("3.0\n")},
			{rawName: "control.tar/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		version := findNode(t, result.Nodes, "/debian-binary")
		payload := findNode(t, result.Nodes, "/data.tar/payload.txt")
		if !result.Partial ||
			version.ErrorCode != "deb_version_unsupported" ||
			payload.ExtractionStatus != StatusExtracted {
			t.Fatalf(
				"result=%+v version=%+v payload=%+v",
				result,
				version,
				payload,
			)
		}
	})

	t.Run("order-duplicate-missing", func(t *testing.T) {
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "data.tar/", body: tarBody},
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "debian-binary/", body: []byte("2.1\n")},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		if !result.Partial ||
			countNodesWithCode(result.Nodes, "deb_member_order_invalid") != 2 ||
			countNodesWithCode(result.Nodes, "deb_duplicate_member") != 1 ||
			countNodesWithCode(result.Nodes, "deb_missing_member") != 1 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("gnu-name-profile-is-rejected", func(t *testing.T) {
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "//", body: []byte("extra.tar/\n")},
			{rawName: "/0", body: tarBody},
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "control.tar/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		if !result.Partial ||
			countNodesWithCode(
				result.Nodes,
				"deb_extended_name_not_allowed",
			) != 2 ||
			findNode(t, result.Nodes, "/data.tar/payload.txt").
				ExtractionStatus != StatusExtracted {
			t.Fatalf("result = %+v", result)
		}
		foundExtendedPayload := false
		for _, node := range result.Nodes {
			if node.DisplayName == "payload.txt" &&
				bytes.Contains(
					[]byte(node.LogicalPath),
					[]byte("__deb_extended_"),
				) {
				foundExtendedPayload = true
			}
		}
		if !foundExtendedPayload {
			t.Fatalf("extended member payload was hidden: %+v", result.Nodes)
		}
	})

	t.Run("duplicate-data-is-still-scanned", func(t *testing.T) {
		duplicate := arTARFixture(
			t,
			"duplicate.txt",
			[]byte("still-visible"),
		)
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "control.tar/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
			{rawName: "data.tar/", body: duplicate},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		if !result.Partial ||
			countNodesWithCode(result.Nodes, "deb_duplicate_member") != 1 {
			t.Fatalf("result = %+v", result)
		}
		foundDuplicatePayload := false
		for _, node := range result.Nodes {
			if node.DisplayName == "duplicate.txt" {
				foundDuplicatePayload = true
			}
		}
		if !foundDuplicatePayload {
			t.Fatalf("duplicate payload was hidden: %+v", result.Nodes)
		}
	})

	t.Run("compressed-payload-must-contain-tar", func(t *testing.T) {
		_, compress := arStreamCodec(t, "gzip")
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "control.tar.gz/", body: compress([]byte("not tar"))},
			{rawName: "data.tar/", body: tarBody},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		control := findNode(t, result.Nodes, "/control.tar.gz")
		if !result.Partial ||
			control.ErrorCode != "deb_payload_not_tar" {
			t.Fatalf("result=%+v control=%+v", result, control)
		}
	})

	t.Run("control-bzip2-is-not-a-valid-role", func(t *testing.T) {
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("2.0\n")},
			{rawName: "control.tar.bz2/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		if !result.Partial ||
			countNodesWithCode(result.Nodes, "deb_unexpected_member") != 1 ||
			countNodesWithCode(result.Nodes, "deb_member_order_invalid") != 1 ||
			countNodesWithCode(result.Nodes, "deb_missing_member") != 1 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("invalid-version-extension", func(t *testing.T) {
		deb := arArchiveFixture(t, []arFixtureEntry{
			{rawName: "debian-binary/", body: []byte("2.0\nbad\x00line\n")},
			{rawName: "control.tar/", body: tarBody},
			{rawName: "data.tar/", body: tarBody},
		})
		result := runARExtract(t, deb, arProfileDeb, generousLimits())
		version := findNode(t, result.Nodes, "/debian-binary")
		if !result.Partial || version.ErrorCode != "deb_version_invalid" {
			t.Fatalf("result=%+v version=%+v", result, version)
		}
	})
}

func TestDEBNonRequiredDuplicatesRemainVisible(t *testing.T) {
	featureZIP := zipFixture(t, []zipEntry{{
		name: "feature-hidden.txt",
		body: []byte("visible"),
	}})
	trailingZIP := zipFixture(t, []zipEntry{{
		name: "trailing-hidden.txt",
		body: []byte("visible"),
	}})
	tarBody := arTARFixture(t, "payload.txt", []byte("visible"))
	deb := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "debian-binary/", body: []byte("2.0\n")},
		{rawName: "_feature/", body: []byte("first")},
		{rawName: "_feature/", body: featureZIP},
		{rawName: "control.tar/", body: tarBody},
		{rawName: "data.tar/", body: tarBody},
		{rawName: "notes/", body: []byte("first")},
		{rawName: "notes/", body: trailingZIP},
	})

	result := runARExtract(t, deb, arProfileDeb, generousLimits())
	if !result.Partial ||
		countNodesWithCode(result.Nodes, "duplicate_logical_path") != 2 {
		t.Fatalf("result = %+v", result)
	}
	for _, name := range []string{
		"feature-hidden.txt",
		"trailing-hidden.txt",
	} {
		found := false
		for _, node := range result.Nodes {
			if node.DisplayName == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s was hidden: %+v", name, result.Nodes)
		}
	}
}

func TestDEBVersionDiagnosticsDoNotHideNestedArchives(t *testing.T) {
	smallZIP := zipFixture(t, []zipEntry{{
		name: "small-hidden.txt",
		body: []byte("visible"),
	}})
	oversizeZIP := zipFixture(t, []zipEntry{{
		name:  "oversize-hidden.txt",
		body:  bytes.Repeat([]byte{0xa5}, 5000),
		store: true,
	}})
	tarBody := arTARFixture(t, "payload.txt", []byte("visible"))

	tests := []struct {
		name        string
		entries     []arFixtureEntry
		code        string
		payloadName string
	}{
		{
			name: "invalid",
			entries: []arFixtureEntry{
				{rawName: "debian-binary/", body: smallZIP},
				{rawName: "control.tar/", body: tarBody},
				{rawName: "data.tar/", body: tarBody},
			},
			code:        "deb_version_invalid",
			payloadName: "small-hidden.txt",
		},
		{
			name: "duplicate",
			entries: []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "debian-binary/", body: smallZIP},
				{rawName: "control.tar/", body: tarBody},
				{rawName: "data.tar/", body: tarBody},
			},
			code:        "deb_duplicate_member",
			payloadName: "small-hidden.txt",
		},
		{
			name: "oversize",
			entries: []arFixtureEntry{
				{rawName: "debian-binary/", body: oversizeZIP},
				{rawName: "control.tar/", body: tarBody},
				{rawName: "data.tar/", body: tarBody},
			},
			code:        "deb_version_invalid",
			payloadName: "oversize-hidden.txt",
		},
		{
			name: "extended",
			entries: []arFixtureEntry{
				arBSDEntry("debian-binary", smallZIP),
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: tarBody},
				{rawName: "data.tar/", body: tarBody},
			},
			code:        "deb_extended_name_not_allowed",
			payloadName: "small-hidden.txt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runARExtract(
				t,
				arArchiveFixture(t, test.entries),
				arProfileDeb,
				generousLimits(),
			)
			if !result.Partial ||
				countNodesWithCode(result.Nodes, test.code) == 0 {
				t.Fatalf("result = %+v", result)
			}
			found := false
			for _, node := range result.Nodes {
				if node.DisplayName == test.payloadName {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("version payload was hidden: %+v", result.Nodes)
			}
		})
	}
}

func TestDEBExtensionBeforeVersionIsDiagnosedButScanned(t *testing.T) {
	earlyZIP := zipFixture(t, []zipEntry{{
		name: "early-hidden.txt",
		body: []byte("visible"),
	}})
	tarBody := arTARFixture(t, "payload.txt", []byte("visible"))
	deb := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "_early/", body: earlyZIP},
		{rawName: "debian-binary/", body: []byte("2.0\n")},
		{rawName: "control.tar/", body: tarBody},
		{rawName: "data.tar/", body: tarBody},
	})
	result := runARExtract(t, deb, arProfileDeb, generousLimits())
	if !result.Partial ||
		countNodesWithCode(result.Nodes, "deb_unexpected_member") != 1 ||
		findNode(t, result.Nodes, "/_early/early-hidden.txt").
			ExtractionStatus != StatusExtracted {
		t.Fatalf("result = %+v", result)
	}
}

func TestDEBDataLZMAUsesValidatedMemberFraming(t *testing.T) {
	var encoded bytes.Buffer
	writer, err := lzmalib.NewWriter(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(
		arTARFixture(t, "payload.txt", []byte("lzma")),
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	deb := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "debian-binary/", body: []byte("2.0\n")},
		{rawName: "control.tar/", body: arTARFixture(t, "control", []byte("ok"))},
		{rawName: "data.tar.lzma/", body: encoded.Bytes()},
	})
	result := runARExtract(t, deb, arProfileDeb, generousLimits())
	node := findNode(t, result.Nodes, "/data.tar.lzma")
	payload := findNode(
		t,
		result.Nodes,
		"/data.tar.lzma/content/payload.txt",
	)
	if result.Partial ||
		node.Format != "lzma" ||
		node.MIMEType != "application/x-lzma" ||
		payload.ExtractionStatus != StatusExtracted {
		t.Fatalf(
			"result=%+v node=%+v payload=%+v",
			result,
			node,
			payload,
		)
	}
}

func TestDEBDataLZMASemanticsDoNotOverrideDetectedArchives(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		format      string
		payloadPath string
	}{
		{
			name: "zip",
			body: zipFixture(t, []zipEntry{{
				name: "zip-hidden.txt",
				body: []byte("visible"),
			}}),
			format:      "zip",
			payloadPath: "/data.tar.lzma/zip-hidden.txt",
		},
		{
			name:        "tar",
			body:        arTARFixture(t, "tar-hidden.txt", []byte("visible")),
			format:      "tar",
			payloadPath: "/data.tar.lzma/tar-hidden.txt",
		},
	}
	control := arTARFixture(t, "control", []byte("ok"))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deb := arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: control},
				{rawName: "data.tar.lzma/", body: test.body},
			})
			result := runARExtract(
				t,
				deb,
				arProfileDeb,
				generousLimits(),
			)
			outer := findNode(t, result.Nodes, "/data.tar.lzma")
			payload := findNode(t, result.Nodes, test.payloadPath)
			if !result.Partial ||
				outer.Format != test.format ||
				outer.ErrorCode != "deb_payload_format_mismatch" ||
				payload.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v outer=%+v payload=%+v",
					result,
					outer,
					payload,
				)
			}
		})
	}
}

func TestDEBAnomalousLZMAMembersKeepDetectedFormat(t *testing.T) {
	disguisedZIP := zipFixture(t, []zipEntry{{
		name: "anomaly-hidden.txt",
		body: []byte("visible"),
	}})
	control := arTARFixture(t, "control", []byte("ok"))
	canonicalData := arLZMACompress(
		t,
		arTARFixture(t, "canonical.txt", []byte("ok")),
	)
	tests := []struct {
		name    string
		member  arFixtureEntry
		code    string
		payload string
	}{
		{
			name: "duplicate",
			member: arFixtureEntry{
				rawName: "data.tar.lzma/",
				body:    disguisedZIP,
			},
			code:    "deb_duplicate_member",
			payload: "anomaly-hidden.txt",
		},
		{
			name:    "extended",
			member:  arBSDEntry("data.tar.lzma", disguisedZIP),
			code:    "deb_extended_name_not_allowed",
			payload: "anomaly-hidden.txt",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deb := arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: control},
				{rawName: "data.tar.lzma/", body: canonicalData},
				test.member,
			})
			result := runARExtract(
				t,
				deb,
				arProfileDeb,
				generousLimits(),
			)
			var anomalous *Node
			payloadVisible := false
			for index := range result.Nodes {
				node := &result.Nodes[index]
				if node.ErrorCode == test.code {
					anomalous = node
				}
				if node.DisplayName == test.payload {
					payloadVisible = true
				}
			}
			if !result.Partial ||
				anomalous == nil ||
				anomalous.Format != "zip" ||
				!payloadVisible {
				t.Fatalf(
					"result=%+v anomalous=%+v",
					result,
					anomalous,
				)
			}
		})
	}
}

func TestDEBAnomalousUnknownLZMAMembersUseExactNameFallback(t *testing.T) {
	control := arTARFixture(t, "control", []byte("ok"))
	canonicalData := arLZMACompress(
		t,
		arTARFixture(t, "canonical.txt", []byte("ok")),
	)
	anomalousData := arLZMACompress(
		t,
		arTARFixture(t, "anomaly-hidden.txt", []byte("visible")),
	)
	tests := []struct {
		name   string
		member arFixtureEntry
		code   string
	}{
		{
			name: "duplicate",
			member: arFixtureEntry{
				rawName: "data.tar.lzma/",
				body:    anomalousData,
			},
			code: "deb_duplicate_member",
		},
		{
			name:   "extended",
			member: arBSDEntry("data.tar.lzma", anomalousData),
			code:   "deb_extended_name_not_allowed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deb := arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: control},
				{rawName: "data.tar.lzma/", body: canonicalData},
				test.member,
			})
			result := runARExtract(
				t,
				deb,
				arProfileDeb,
				generousLimits(),
			)
			anomalous := findNodeWithCode(t, result.Nodes, test.code)
			payload := findNode(
				t,
				result.Nodes,
				anomalous.LogicalPath+"/content/anomaly-hidden.txt",
			)
			if !result.Partial ||
				result.LimitCode != "" ||
				anomalous.ExtractionStatus != StatusCorrupt ||
				anomalous.Format != "lzma" ||
				anomalous.MIMEType != "application/x-lzma" ||
				payload.ParentLocalID == 0 ||
				payload.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v anomalous=%+v payload=%+v",
					result,
					anomalous,
					payload,
				)
			}
		})
	}
}

func TestDEBRawLZMAFallbackRequiresExactTrustedUnknownMember(t *testing.T) {
	canonical := arResolvedMember{
		name:         "data.tar.lzma",
		nameEncoding: arMemberNameEncodingSysV,
	}
	clean := debMemberObservation{role: debRoleData}
	tests := []struct {
		name     string
		member   arResolvedMember
		observe  debMemberObservation
		profile  string
		detected string
		want     bool
	}{
		{
			name:     "unknown canonical",
			member:   canonical,
			observe:  clean,
			profile:  "data.tar.lzma",
			detected: "unknown",
			want:     true,
		},
		{
			name:    "empty format canonical",
			member:  canonical,
			observe: clean,
			profile: "data.tar.lzma",
			want:    true,
		},
		{
			name:     "strong content detection",
			member:   canonical,
			observe:  clean,
			profile:  "data.tar.lzma",
			detected: "zip",
		},
		{
			name:   "duplicate observation",
			member: canonical,
			observe: debMemberObservation{
				role: debRoleData,
				code: "deb_duplicate_member",
			},
			profile:  "data.tar.lzma",
			detected: "unknown",
		},
		{
			name: "exact duplicate anomaly",
			member: arResolvedMember{
				name:         "data.tar.lzma",
				originalName: "data.tar.lzma",
				nameEncoding: arMemberNameEncodingSysV,
			},
			observe: debMemberObservation{
				role: debRoleData,
				code: "deb_duplicate_member",
			},
			profile:  "data.tar.lzma",
			detected: "unknown",
			want:     true,
		},
		{
			name: "extended name",
			member: arResolvedMember{
				name:         "data.tar.lzma",
				nameEncoding: arMemberNameEncodingBSD,
			},
			observe:  clean,
			profile:  "data.tar.lzma",
			detected: "unknown",
		},
		{
			name: "exact extended anomaly",
			member: arResolvedMember{
				name:         "data.tar.lzma",
				originalName: "data.tar.lzma",
				nameEncoding: arMemberNameEncodingBSD,
			},
			observe: debMemberObservation{
				role: debRoleData,
				code: "deb_extended_name_not_allowed",
			},
			profile:  "data.tar.lzma",
			detected: "unknown",
			want:     true,
		},
		{
			name: "remapped member",
			member: arResolvedMember{
				name:         "__deb_duplicate_member_1",
				originalName: "data.tar.lzma",
				nameEncoding: arMemberNameEncodingSysV,
			},
			observe:  clean,
			profile:  "data.tar.lzma",
			detected: "unknown",
			want:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := shouldUseDEBRawLZMA(
				test.member,
				test.observe,
				test.profile,
				test.detected,
			); got != test.want {
				t.Fatalf("fallback = %t, want %t", got, test.want)
			}
		})
	}
}

func TestDEBDataBZIP2RecursesToTAR(t *testing.T) {
	encoded, err := hex.DecodeString(
		"425a68393141592653595d9713e4000035db90ca8040037184004074205e5" +
			"00400004820005434a69a6206984d193daa0924d4d01a06868059467f91a" +
			"c4112a46b631bdeb10c26a109300f9c04a6f3644037aa3737b1242ca7b23" +
			"02ca587e5e088a27e2ee48a70a120bb2e27c8",
	)
	if err != nil {
		t.Fatal(err)
	}
	deb := arArchiveFixture(t, []arFixtureEntry{
		{rawName: "debian-binary/", body: []byte("2.0\n")},
		{rawName: "control.tar/", body: arTARFixture(t, "control", []byte("ok"))},
		{rawName: "data.tar.bz2/", body: encoded},
	})
	result := runARExtract(t, deb, arProfileDeb, generousLimits())
	payload := findNode(
		t,
		result.Nodes,
		"/data.tar.bz2/content/bzip.txt",
	)
	if result.Partial || payload.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
}

func TestDEBV7AndEmptyTARPayloads(t *testing.T) {
	v7 := arV7TARFixture(t, "v7-hidden.txt", []byte("visible"))
	empty := make([]byte, 1024)
	_, gzipCompress := arStreamCodec(t, "gzip")
	_, xzCompress := arStreamCodec(t, "xz")
	_, zstdCompress := arStreamCodec(t, "zstd")
	bzipEmpty, err := hex.DecodeString(
		"425a683931415926535974f5adf70000044000c0000008200030802a6945ac" +
			"38bb9229c28483a7ad6fb8",
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		member      string
		body        []byte
		tarPath     string
		payloadPath string
	}{
		{
			name:        "raw V7",
			member:      "data.tar/",
			body:        v7,
			payloadPath: "/data.tar/v7-hidden.txt",
		},
		{
			name:    "raw empty",
			member:  "data.tar/",
			body:    empty,
			tarPath: "/data.tar",
		},
		{
			name:        "gzip V7",
			member:      "data.tar.gz/",
			body:        gzipCompress(v7),
			payloadPath: "/data.tar.gz/content/v7-hidden.txt",
		},
		{
			name:    "xz empty",
			member:  "data.tar.xz/",
			body:    xzCompress(empty),
			tarPath: "/data.tar.xz/content",
		},
		{
			name:        "zstd V7",
			member:      "data.tar.zst/",
			body:        zstdCompress(v7),
			payloadPath: "/data.tar.zst/content/v7-hidden.txt",
		},
		{
			name:    "bzip2 empty",
			member:  "data.tar.bz2/",
			body:    bzipEmpty,
			tarPath: "/data.tar.bz2/content",
		},
		{
			name:        "lzma V7",
			member:      "data.tar.lzma/",
			body:        arLZMACompress(t, v7),
			payloadPath: "/data.tar.lzma/content/v7-hidden.txt",
		},
	}
	control := arV7TARFixture(t, "control", []byte("ok"))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deb := arArchiveFixture(t, []arFixtureEntry{
				{rawName: "debian-binary/", body: []byte("2.0\n")},
				{rawName: "control.tar/", body: control},
				{rawName: test.member, body: test.body},
			})
			result := runARExtract(
				t,
				deb,
				arProfileDeb,
				generousLimits(),
			)
			if result.Partial {
				t.Fatalf("result = %+v", result)
			}
			if test.payloadPath != "" {
				if node := findNode(
					t,
					result.Nodes,
					test.payloadPath,
				); node.ExtractionStatus != StatusExtracted {
					t.Fatalf("payload = %+v", node)
				}
			} else if node := findNode(
				t,
				result.Nodes,
				test.tarPath,
			); node.Format != "tar" {
				t.Fatalf("empty tar node = %+v", node)
			}
		})
	}
}

func TestDEBLargeExtensionSetDetectsAndRecursesLZMAV7(t *testing.T) {
	v7 := arV7TARFixture(t, "large-hidden.txt", []byte("visible"))
	entries := make([]arFixtureEntry, 0, 4100)
	entries = append(entries, arFixtureEntry{
		rawName: "debian-binary/",
		body:    []byte("2.0\n"),
	})
	for index := 0; index < 4097; index++ {
		entries = append(entries, arFixtureEntry{
			rawName: fmt.Sprintf("_f%05d/", index),
		})
	}
	entries = append(entries,
		arFixtureEntry{
			rawName: "control.tar/",
			body:    arV7TARFixture(t, "control", []byte("ok")),
		},
		arFixtureEntry{
			rawName: "data.tar.lzma/",
			body:    arLZMACompress(t, v7),
		},
	)
	deb := arArchiveFixture(t, entries)
	detected, err := (filetype.Detector{}).Detect(
		bytes.NewReader(deb),
		int64(len(deb)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if detected.Format != "deb" ||
		detected.Metadata["entries"] != 4100 {
		t.Fatalf("detection = %+v", detected)
	}

	limits := generousLimits()
	limits.MaxNodes = 10_000
	result := runExtract(t, deb, detected.Format, limits)
	payload := findNode(
		t,
		result.Nodes,
		"/data.tar.lzma/content/large-hidden.txt",
	)
	if result.Partial || payload.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v payload=%+v", result, payload)
	}
}

func TestDEBRawPayloadAcceptsTARStructuralFamily(t *testing.T) {
	for _, format := range []string{"tar", "docker-tar", "oci-tar"} {
		t.Run(format, func(t *testing.T) {
			code, message := validateDEBMaterializedMember(
				context.Background(),
				bytes.NewReader(nil),
				arResolvedMember{name: "data.tar"},
				&Node{Format: format},
				debMemberObservation{role: debRoleData},
				"data.tar",
			)
			if code != "" || message != "" {
				t.Fatalf("code=%q message=%q", code, message)
			}
		})
	}
}

type arFixtureEntry struct {
	rawName string
	body    []byte
}

func arBSDEntry(name string, body []byte) arFixtureEntry {
	encodedBody := make([]byte, 0, len(name)+len(body))
	encodedBody = append(encodedBody, name...)
	encodedBody = append(encodedBody, body...)
	return arFixtureEntry{
		rawName: fmt.Sprintf("#1/%d", len(name)),
		body:    encodedBody,
	}
}

func arArchiveFixture(t *testing.T, entries []arFixtureEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(arGlobalMagic)
	for _, entry := range entries {
		appendARFixtureMember(
			t,
			&output,
			entry.rawName,
			int64(len(entry.body)),
			entry.body,
			true,
		)
	}
	return output.Bytes()
}

func arArchiveWithDeclaredMember(
	t *testing.T,
	rawName string,
	declaredSize int64,
	body []byte,
	padding bool,
) []byte {
	t.Helper()
	var output bytes.Buffer
	output.Write(arGlobalMagic)
	appendARFixtureMember(
		t,
		&output,
		rawName,
		declaredSize,
		body,
		padding,
	)
	return output.Bytes()
}

func appendARFixtureMember(
	t *testing.T,
	output *bytes.Buffer,
	rawName string,
	declaredSize int64,
	body []byte,
	padding bool,
) {
	t.Helper()
	if len(rawName) > 16 {
		t.Fatalf("raw ar name %q exceeds 16 bytes", rawName)
	}
	header := fmt.Sprintf(
		"%-16s%-12d%-6d%-6d%-8o%-10d`\n",
		rawName,
		0,
		0,
		0,
		0o644,
		declaredSize,
	)
	if len(header) != int(arMemberHeaderSize) {
		t.Fatalf("ar fixture header is %d bytes", len(header))
	}
	output.WriteString(header)
	output.Write(body)
	if padding && declaredSize%2 != 0 {
		output.WriteByte('\n')
	}
}

func arTARFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func arV7TARFixture(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	if name == "" || len(name) > 100 {
		t.Fatalf("invalid V7 fixture name %q", name)
	}
	var output bytes.Buffer
	header := make([]byte, 512)
	copy(header[:100], name)
	for _, field := range []struct {
		bytes []byte
		value int64
	}{
		{bytes: header[100:108], value: 0o600},
		{bytes: header[108:116], value: 0},
		{bytes: header[116:124], value: 0},
		{bytes: header[124:136], value: int64(len(body))},
		{bytes: header[136:148], value: 0},
	} {
		encoded := fmt.Sprintf(
			"%0*o",
			len(field.bytes)-1,
			field.value,
		)
		copy(field.bytes, encoded)
		field.bytes[len(field.bytes)-1] = 0
	}
	header[156] = tar.TypeReg
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	checksum := int64(0)
	for _, value := range header {
		checksum += int64(value)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	output.Write(header)
	output.Write(body)
	if remainder := len(body) % 512; remainder != 0 {
		output.Write(make([]byte, 512-remainder))
	}
	output.Write(make([]byte, 1024))
	return output.Bytes()
}

func arLZMACompress(t *testing.T, input []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := lzmalib.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func arStreamCodec(
	t *testing.T,
	codec string,
) (string, func([]byte) []byte) {
	t.Helper()
	switch codec {
	case "gzip":
		return ".gz", func(input []byte) []byte {
			var output bytes.Buffer
			writer := gzip.NewWriter(&output)
			if _, err := writer.Write(input); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			return output.Bytes()
		}
	case "xz":
		return ".xz", func(input []byte) []byte {
			var output bytes.Buffer
			writer, err := xzlib.NewWriter(&output)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(input); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			return output.Bytes()
		}
	case "zstd":
		return ".zst", func(input []byte) []byte {
			writer, err := zstd.NewWriter(
				nil,
				zstd.WithEncoderConcurrency(1),
			)
			if err != nil {
				t.Fatal(err)
			}
			encoded := writer.EncodeAll(input, nil)
			writer.Close()
			return encoded
		}
	default:
		t.Fatalf("unknown fixture codec %q", codec)
		return "", nil
	}
}

func runARExtract(
	t *testing.T,
	data []byte,
	profile string,
	limits Limits,
) Result {
	t.Helper()
	result, err := runARExtractWithContext(
		t,
		context.Background(),
		data,
		profile,
		limits,
	)
	if err != nil {
		t.Fatalf("ar extraction error = %v", err)
	}
	return result
}

func runARExtractWithContext(
	t *testing.T,
	ctx context.Context,
	data []byte,
	profile string,
	limits Limits,
) (Result, error) {
	t.Helper()
	return runARExtractWithStateSetup(
		t,
		ctx,
		data,
		profile,
		limits,
		nil,
	)
}

func runARExtractWithStateSetup(
	t *testing.T,
	ctx context.Context,
	data []byte,
	profile string,
	limits Limits,
	setup func(*operationState),
) (Result, error) {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	workDir := t.TempDir()
	lastWorkDirectory = workDir
	engine := NewEngine(filetype.Detector{}, limits)
	state := operationState{
		engine:      engine,
		ctx:         ctx,
		workDir:     workDir,
		rootSize:    int64(len(data)),
		nextID:      1,
		paths:       make(map[string]struct{}),
		nodeIndex:   make(map[int]int),
		directories: make(map[string]int),
		memory: parserDecoderMemory{
			limit: maxTaskParserDecoderMemoryBytes,
		},
	}
	if setup != nil {
		setup(&state)
	}
	budget := containerBudget{sourceSize: int64(len(data))}
	switch profile {
	case arProfileGeneric:
		err = state.extractAR(
			source,
			int64(len(data)),
			0,
			"",
			0,
			&budget,
		)
	case arProfileDeb:
		err = state.extractDEB(
			source,
			int64(len(data)),
			0,
			"",
			0,
			&budget,
		)
	default:
		t.Fatalf("unknown ar profile %q", profile)
	}
	if err != nil {
		var limit *limitError
		switch {
		case errors.As(err, &limit):
			state.markLimit(limit.code)
			err = nil
		case errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			state.markLimit(LimitContextCancelled)
		}
	}
	result := state.result()
	assertNodeGraph(t, result.Nodes)
	return result, err
}

func countNodesWithCode(nodes []Node, code string) int {
	count := 0
	for _, node := range nodes {
		if node.ErrorCode == code {
			count++
		}
	}
	return count
}
