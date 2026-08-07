package extract

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"binaryscan/internal/filetype"
)

func TestExtractCPIONewcCRCAndODC(t *testing.T) {
	for _, encoding := range []string{"newc", "crc", "odc"} {
		t.Run(encoding, func(t *testing.T) {
			data := cpioArchiveFixture(t, encoding, []cpioFixtureEntry{
				{
					name:  "directory/",
					mode:  cpioModeDir | 0o755,
					nlink: 2,
				},
				{
					name: "directory/payload.txt",
					mode: cpioModeRegular | 0o600,
					body: []byte("payload"),
				},
				{
					name: "odd",
					mode: cpioModeRegular | 0o600,
					body: []byte("x"),
				},
			}, true)
			result, err := runCPIOExtract(
				t,
				context.Background(),
				data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			directory := findNode(t, result.Nodes, "/directory")
			payload := findNode(t, result.Nodes, "/directory/payload.txt")
			odd := findNode(t, result.Nodes, "/odd")
			if result.Partial ||
				directory.NodeType != NodeTypeDirectory ||
				payload.ExtractionStatus != StatusExtracted ||
				payload.SizeBytes != int64(len("payload")) ||
				odd.ExtractionStatus != StatusExtracted {
				t.Fatalf(
					"result=%+v directory=%+v payload=%+v odd=%+v",
					result,
					directory,
					payload,
					odd,
				)
			}
		})
	}
}

func TestExtractCPIORecursesIntoDetectedArchive(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("nested"),
	}})
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "inner.zip",
		mode: cpioModeRegular | 0o600,
		body: nested,
	}}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	container := findNode(t, result.Nodes, "/inner.zip")
	child := findNode(t, result.Nodes, "/inner.zip/payload.txt")
	if result.Partial ||
		container.Format != "zip" ||
		child.ParentLocalID != container.LocalID ||
		child.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v container=%+v child=%+v", result, container, child)
	}
}

func TestExtractCPIODataBearingHardlinkIsScannedWithoutCreatingLink(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("nested-hardlink"),
	}})
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
		{
			name:  "data-member.zip",
			mode:  cpioModeRegular | 0o600,
			nlink: 2,
			inode: 77,
			body:  nested,
		},
		{
			name:  "alias.zip",
			mode:  cpioModeRegular | 0o600,
			nlink: 2,
			inode: 77,
		},
	}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	dataMember := findNode(t, result.Nodes, "/data-member.zip")
	child := findNode(t, result.Nodes, "/data-member.zip/payload.txt")
	alias := findNode(t, result.Nodes, "/alias.zip")
	if result.Partial ||
		dataMember.NodeType != NodeTypeFile ||
		dataMember.Format != "zip" ||
		child.ParentLocalID != dataMember.LocalID ||
		alias.NodeType != NodeTypeHardlink ||
		alias.ExtractionStatus != StatusRecorded {
		t.Fatalf(
			"result=%+v data=%+v child=%+v alias=%+v",
			result,
			dataMember,
			child,
			alias,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(dataMember.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["hardlink_data_member"] != true {
		t.Fatalf("data member metadata = %v", metadata)
	}
}

func TestExtractCPIORejectsUnsafePathsAndContinues(t *testing.T) {
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
		{name: "../escape", mode: cpioModeRegular | 0o600, body: []byte("x")},
		{name: "/absolute", mode: cpioModeRegular | 0o600, body: []byte("x")},
		{name: `back\slash`, mode: cpioModeRegular | 0o600, body: []byte("x")},
		{name: "safe.txt", mode: cpioModeRegular | 0o600, body: []byte("safe")},
	}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	invalid := 0
	for _, node := range result.Nodes {
		if node.ExtractionStatus == StatusInvalidPath {
			invalid++
		}
	}
	safe := findNode(t, result.Nodes, "/safe.txt")
	if !result.Partial || invalid != 3 ||
		safe.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v invalid=%d safe=%+v", result, invalid, safe)
	}
}

func TestExtractCPIOCRCMismatchDoesNotRecurse(t *testing.T) {
	nested := zipFixture(t, []zipEntry{{
		name: "payload.txt",
		body: []byte("must-not-appear"),
	}})
	badChecksum := cpioByteSum(nested) + 1
	data := cpioArchiveFixture(t, "crc", []cpioFixtureEntry{{
		name:             "bad.zip",
		mode:             cpioModeRegular | 0o600,
		body:             nested,
		checksumOverride: &badChecksum,
	}}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	node := findNode(t, result.Nodes, "/bad.zip")
	if !result.Partial ||
		node.ExtractionStatus != StatusCorrupt ||
		node.ErrorCode != "cpio_crc_mismatch" ||
		node.SHA256 != "" ||
		len(result.Nodes) != 1 {
		t.Fatalf("result=%+v node=%+v", result, node)
	}
}

func TestExtractCPIOSymlinkHardlinkAndSpecialNodesAreRecorded(t *testing.T) {
	data := cpioArchiveFixture(t, "crc", []cpioFixtureEntry{
		{
			name: "link",
			mode: cpioModeSymlink | 0o777,
			body: []byte("target/path"),
		},
		{
			name:  "hard",
			mode:  cpioModeRegular | 0o600,
			nlink: 2,
			inode: 42,
		},
		{name: "device", mode: cpioModeChar | 0o600},
		{name: "pipe", mode: cpioModeFIFO | 0o600},
		{name: "socket", mode: cpioModeSocket | 0o600},
	}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	link := findNode(t, result.Nodes, "/link")
	hard := findNode(t, result.Nodes, "/hard")
	device := findNode(t, result.Nodes, "/device")
	pipe := findNode(t, result.Nodes, "/pipe")
	socket := findNode(t, result.Nodes, "/socket")
	if result.Partial ||
		link.NodeType != NodeTypeSymlink ||
		link.ExtractionStatus != StatusRecorded ||
		hard.NodeType != NodeTypeHardlink ||
		hard.ExtractionStatus != StatusRecorded ||
		device.NodeType != NodeTypeSpecial ||
		pipe.NodeType != NodeTypeSpecial ||
		socket.NodeType != NodeTypeSpecial {
		t.Fatalf(
			"result=%+v link=%+v hard=%+v device=%+v pipe=%+v socket=%+v",
			result,
			link,
			hard,
			device,
			pipe,
			socket,
		)
	}
	var metadata map[string]any
	if err := json.Unmarshal(link.MetadataJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["link_target"] != "target/path" {
		t.Fatalf("symlink metadata = %v", metadata)
	}
}

func TestExtractCPIOLocalSemanticErrorsDoNotHideSiblings(t *testing.T) {
	tests := []struct {
		name      string
		encoding  string
		bad       cpioFixtureEntry
		mutate    func([]byte)
		errorCode string
	}{
		{
			name: "zero-link-count",
			bad: cpioFixtureEntry{
				name: "bad-nlink",
				mode: cpioModeRegular | 0o600,
				body: []byte("ignored"),
			},
			mutate: func(data []byte) {
				copy(data[38:46], "00000000")
			},
			errorCode: "cpio_header_corrupt",
		},
		{
			name: "invalid-mode",
			bad: cpioFixtureEntry{
				name: "bad-mode",
				mode: 0030000 | 0o600,
				body: []byte("ignored"),
			},
			errorCode: "cpio_mode_invalid",
		},
		{
			name: "special-node-with-body",
			bad: cpioFixtureEntry{
				name: "bad-device",
				mode: cpioModeChar | 0o600,
				body: []byte("ignored"),
			},
			errorCode: "cpio_special_size_invalid",
		},
		{
			name:     "crc-invalid-mode",
			encoding: "crc",
			bad: cpioFixtureEntry{
				name: "bad-crc-mode",
				mode: 0030000 | 0o600,
				body: []byte("ignored"),
			},
			errorCode: "cpio_mode_invalid",
		},
		{
			name:     "binary-special-with-odd-body-padding",
			encoding: "binary-le",
			bad: cpioFixtureEntry{
				name: "bad-binary-device",
				mode: cpioModeChar | 0o600,
				body: []byte("x"),
			},
			errorCode: "cpio_special_size_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoding := test.encoding
			if encoding == "" {
				encoding = "newc"
			}
			data := cpioArchiveFixture(t, encoding, []cpioFixtureEntry{
				test.bad,
				{
					name: "safe.txt",
					mode: cpioModeRegular | 0o600,
					body: []byte("safe"),
				},
			}, true)
			if test.mutate != nil {
				test.mutate(data)
			}
			result, err := runCPIOExtract(
				t,
				context.Background(),
				data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			safe := findNode(t, result.Nodes, "/safe.txt")
			if !result.Partial ||
				safe.ExtractionStatus != StatusExtracted ||
				safe.SizeBytes != int64(len("safe")) ||
				len(result.Nodes) != 2 ||
				result.Nodes[0].ErrorCode != test.errorCode ||
				result.Nodes[0].ExtractionStatus != StatusCorrupt {
				t.Fatalf(
					"result=%+v safe=%+v",
					result,
					safe,
				)
			}
		})
	}
}

func TestExtractCPIOBinaryEndiannessAndTwoByteAlignment(t *testing.T) {
	for _, encoding := range []string{"binary-le", "binary-be"} {
		t.Run(encoding, func(t *testing.T) {
			data := cpioArchiveFixture(t, encoding, []cpioFixtureEntry{
				{
					name: "odd",
					mode: cpioModeRegular | 0o600,
					body: []byte("x"),
				},
				{
					name:  "device",
					mode:  cpioModeChar | 0o600,
					nlink: 1,
				},
			}, true)
			result, err := runCPIOExtract(
				t,
				context.Background(),
				data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			odd := findNode(t, result.Nodes, "/odd")
			device := findNode(t, result.Nodes, "/device")
			if result.Partial ||
				odd.ExtractionStatus != StatusExtracted ||
				odd.SizeBytes != 1 ||
				device.NodeType != NodeTypeSpecial ||
				device.ExtractionStatus != StatusRecorded {
				t.Fatalf(
					"result=%+v odd=%+v device=%+v",
					result,
					odd,
					device,
				)
			}
		})
	}
}

func TestExtractCPIOBinaryRejectsNonZeroTwoBytePadding(t *testing.T) {
	data := cpioArchiveFixture(t, "binary-le", []cpioFixtureEntry{{
		name: "odd",
		mode: cpioModeRegular | 0o600,
		body: []byte("x"),
	}}, true)
	// Header 26 + "odd\x00" 4 + one data byte, followed by one pad byte.
	data[31] = 1
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || !hasCPIOErrorNode(result.Nodes) {
		t.Fatalf("result = %+v", result)
	}
}

func TestExtractCPIOCorruptionIsRetainedWithoutPanic(t *testing.T) {
	valid := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "file",
		mode: cpioModeRegular | 0o600,
		body: []byte("data"),
	}}, true)
	badNumber := append([]byte(nil), valid...)
	badNumber[10] = 'g'
	badPadding := append([]byte(nil), valid...)
	// Header 110 + "file\x00" 5 + one byte of name padding + four data bytes.
	badPadding[115] = 1
	missingTrailer := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "file",
		mode: cpioModeRegular | 0o600,
		body: []byte("data"),
	}}, false)
	trailingGarbage := append(append([]byte(nil), valid...), 1)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated", data: valid[:len(valid)-5]},
		{name: "bad numeric field", data: badNumber},
		{name: "non-zero alignment", data: badPadding},
		{name: "missing trailer", data: missingTrailer},
		{name: "trailing garbage", data: trailingGarbage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := runCPIOExtract(
				t,
				context.Background(),
				test.data,
				generousLimits(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Partial || !hasCPIOErrorNode(result.Nodes) {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestExtractCPIONewcRequiresZeroChecksumField(t *testing.T) {
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "file",
		mode: cpioModeRegular | 0o600,
		body: []byte("data"),
	}}, true)
	copy(data[102:110], "00000001")
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || !hasCPIOErrorNode(result.Nodes) {
		t.Fatalf("result = %+v", result)
	}
}

func TestExtractCPIOLimitsNameSymlinkAndHeaderCount(t *testing.T) {
	t.Run("name", func(t *testing.T) {
		data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
			name: strings.Repeat("n", maxLogicalPathBytes+1),
			mode: cpioModeRegular | 0o600,
		}}, true)
		result, err := runCPIOExtract(
			t,
			context.Background(),
			data,
			generousLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Partial ||
			result.LimitCode != LimitMaxArchiveMetadata ||
			len(result.Nodes) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("symlink target", func(t *testing.T) {
		data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
			{
				name: "link",
				mode: cpioModeSymlink | 0o777,
				body: bytes.Repeat(
					[]byte("x"),
					maxLogicalPathBytes+1,
				),
			},
			{
				name: "safe.txt",
				mode: cpioModeRegular | 0o600,
				body: []byte("safe"),
			},
		}, true)
		result, err := runCPIOExtract(
			t,
			context.Background(),
			data,
			generousLimits(),
		)
		if err != nil {
			t.Fatal(err)
		}
		node := findNode(t, result.Nodes, "/link")
		safe := findNode(t, result.Nodes, "/safe.txt")
		if !result.Partial ||
			result.LimitCode != LimitMaxArchiveMetadata ||
			node.ExtractionStatus != StatusLimitExceeded ||
			node.ErrorCode != LimitMaxArchiveMetadata ||
			safe.ExtractionStatus != StatusExtracted {
			t.Fatalf(
				"result=%+v node=%+v safe=%+v",
				result,
				node,
				safe,
			)
		}
	})

	t.Run("headers", func(t *testing.T) {
		data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
			{name: "one", mode: cpioModeRegular | 0o600},
			{name: "two", mode: cpioModeRegular | 0o600},
			{name: "three", mode: cpioModeRegular | 0o600},
		}, true)
		limits := generousLimits()
		limits.MaxNodes = 2
		result, err := runCPIOExtract(
			t,
			context.Background(),
			data,
			limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Partial ||
			result.LimitCode != LimitMaxNodes ||
			len(result.Nodes) != 2 {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestExtractCPIOSymlinkJSONBudgetRetainsSafeSibling(t *testing.T) {
	const symlinkCount = 1_600
	target := bytes.Repeat([]byte{0x01}, maxLogicalPathBytes)
	entries := make([]cpioFixtureEntry, 0, symlinkCount+1)
	for index := 0; index < symlinkCount; index++ {
		entries = append(entries, cpioFixtureEntry{
			name: fmt.Sprintf("link-%04d", index),
			mode: cpioModeSymlink | 0o777,
			body: target,
		})
	}
	entries = append(entries, cpioFixtureEntry{
		name: "safe.txt",
		mode: cpioModeRegular | 0o600,
		body: []byte("safe"),
	})
	data := cpioArchiveFixture(t, "newc", entries, true)
	limits := generousLimits()
	limits.MaxNodes = symlinkCount + 10
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		limits,
	)
	if err != nil {
		t.Fatal(err)
	}

	safe := findNode(t, result.Nodes, "/safe.txt")
	var retainedJSON int64
	limited := 0
	for _, node := range result.Nodes {
		if node.NodeType != NodeTypeSymlink {
			continue
		}
		retainedJSON += int64(len(node.MetadataJSON))
		if node.ExtractionStatus == StatusLimitExceeded {
			limited++
			if node.ErrorCode != LimitMaxArchiveMetadata ||
				string(node.MetadataJSON) != "{}" {
				t.Fatalf("symlink limit node = %+v", node)
			}
			continue
		}
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		limited == 0 ||
		retainedJSON > maxCPIORetainedSymlinkMetadataBytes ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != int64(len("safe")) {
		t.Fatalf(
			"result=%+v limited=%d retained=%d safe=%+v",
			result,
			limited,
			retainedJSON,
			safe,
		)
	}
}

func TestExtractCPIOGlobalSymlinkJSONBudgetAcrossNestedSiblings(
	t *testing.T,
) {
	const linksPerArchive = 800
	target := bytes.Repeat([]byte{0x01}, maxLogicalPathBytes)
	makeInner := func(includeSafe bool) []byte {
		entries := make([]cpioFixtureEntry, 0, linksPerArchive+1)
		for index := 0; index < linksPerArchive; index++ {
			entries = append(entries, cpioFixtureEntry{
				name: fmt.Sprintf("link-%04d", index),
				mode: cpioModeSymlink | 0o777,
				body: target,
			})
		}
		if includeSafe {
			entries = append(entries, cpioFixtureEntry{
				name: "safe.txt",
				mode: cpioModeRegular | 0o600,
				body: []byte("safe"),
			})
		}
		return cpioArchiveFixture(t, "newc", entries, true)
	}
	outer := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
		{
			name: "first.cpio",
			mode: cpioModeRegular | 0o600,
			body: makeInner(false),
		},
		{
			name: "second.cpio",
			mode: cpioModeRegular | 0o600,
			body: makeInner(true),
		},
	}, true)
	limits := generousLimits()
	limits.MaxNodes = linksPerArchive*2 + 20
	result, err := runCPIOExtract(
		t,
		context.Background(),
		outer,
		limits,
	)
	if err != nil {
		t.Fatal(err)
	}

	safe := findNode(
		t,
		result.Nodes,
		"/second.cpio/safe.txt",
	)
	var retainedJSON int64
	firstLimited := 0
	secondLimited := 0
	for _, node := range result.Nodes {
		if node.NodeType != NodeTypeSymlink {
			continue
		}
		retainedJSON += int64(len(node.MetadataJSON))
		if node.ExtractionStatus != StatusLimitExceeded {
			continue
		}
		switch {
		case strings.HasPrefix(node.LogicalPath, "/first.cpio/"):
			firstLimited++
		case strings.HasPrefix(node.LogicalPath, "/second.cpio/"):
			secondLimited++
		}
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		firstLimited != 0 ||
		secondLimited == 0 ||
		retainedJSON > maxCPIORetainedSymlinkMetadataBytes ||
		safe.ExtractionStatus != StatusExtracted ||
		safe.SizeBytes != int64(len("safe")) {
		t.Fatalf(
			"result=%+v first_limited=%d second_limited=%d retained=%d safe=%+v",
			result,
			firstLimited,
			secondLimited,
			retainedJSON,
			safe,
		)
	}
}

func TestAppendCPIOSymlinkLimitDropsExistingMetadata(t *testing.T) {
	engine := NewEngine(filetype.Detector{}, generousLimits())
	state := operationState{
		engine:      engine,
		nextID:      1,
		paths:       make(map[string]struct{}),
		nodeIndex:   make(map[int]int),
		directories: make(map[string]int),
	}
	node := Node{
		LogicalPath:  "/link",
		MetadataJSON: json.RawMessage(`{"link_target":"attacker-controlled"}`),
	}

	if err := state.appendCPIOSymlinkLimit(node, "metadata limit"); err != nil {
		t.Fatal(err)
	}
	if len(state.nodes) != 1 ||
		string(state.nodes[0].MetadataJSON) != "{}" ||
		state.retainedCPIOSymlinkMetadataBytes !=
			cpioEmptyMetadataJSONBytes {
		t.Fatalf(
			"nodes=%+v retained=%d",
			state.nodes,
			state.retainedCPIOSymlinkMetadataBytes,
		)
	}
}

func TestCPIOSymlinkJSONEstimateCoversWorstEscaping(t *testing.T) {
	target := strings.Repeat("\x01", maxLogicalPathBytes)
	header := cpioHeader{
		encoding:  cpioMagicNewc,
		inode:     math.MaxUint64,
		mode:      cpioModeSymlink | 0o777,
		uid:       math.MaxUint64,
		gid:       math.MaxUint64,
		nlink:     math.MaxUint64,
		mtime:     math.MaxUint64,
		fileSize:  uint64(len(target)),
		devMajor:  math.MaxUint64,
		devMinor:  math.MaxUint64,
		rdevMajor: math.MaxUint64,
		rdevMinor: math.MaxUint64,
		checksum:  math.MaxUint32,
	}
	collisionText := strings.Repeat("\x02", maxLogicalPathBytes)
	location := entryLocation{collision: &namespaceCollision{
		archivePath:          collisionText,
		containerPath:        collisionText,
		duplicateLogicalPath: collisionText,
		collisionPath:        collisionText,
	}}
	metadata := cpioMetadata(header)
	metadata["link_target"] = target
	metadata["link_target_truncated"] = false
	node := Node{}
	state := operationState{}
	state.applyNamespaceCollision(location, &node, metadata)
	if node.MetadataJSON == nil {
		node.MetadataJSON = metadataJSON(metadata)
	}
	estimated := estimateCPIOSymlinkJSONBytes(header, location)
	if int64(len(node.MetadataJSON)) > estimated {
		t.Fatalf(
			"escaped JSON bytes = %d, estimate = %d",
			len(node.MetadataJSON),
			estimated,
		)
	}
}

func TestExtractCPIOCancellationPropagates(t *testing.T) {
	data := cpioArchiveFixture(t, "crc", []cpioFixtureEntry{{
		name: "large",
		mode: cpioModeRegular | 0o600,
		body: bytes.Repeat([]byte("x"), 1<<20),
	}}, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runCPIOExtract(t, ctx, data, generousLimits())
	if !errors.Is(err, context.Canceled) ||
		!result.Partial ||
		result.LimitCode != LimitContextCancelled {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestExtractCPIOMixedEncodingIsRejected(t *testing.T) {
	newc := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "first.txt",
		mode: cpioModeRegular | 0o600,
		body: []byte("first"),
	}}, false)
	odc := cpioArchiveFixture(t, "odc", []cpioFixtureEntry{{
		name: "second.txt",
		mode: cpioModeRegular | 0o600,
		body: []byte("second"),
	}}, true)
	data := append(newc, odc...)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	first := findNode(t, result.Nodes, "/first.txt")
	if !result.Partial ||
		first.ExtractionStatus != StatusExtracted ||
		len(result.Nodes) != 2 ||
		result.Nodes[1].ErrorCode != "cpio_mixed_encoding" {
		t.Fatalf("result=%+v first=%+v", result, first)
	}
}

func TestExtractCPIORootDirectoryIsIgnoredAndDotPathsAreNormalized(t *testing.T) {
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
		{name: ".", mode: cpioModeDir | 0o755, nlink: 2},
		{
			name: "./safe.txt",
			mode: cpioModeRegular | 0o600,
			body: []byte("safe"),
		},
		{
			name: "./nested/child.txt",
			mode: cpioModeRegular | 0o600,
			body: []byte("child"),
		},
	}, true)
	result, err := runCPIOExtract(
		t,
		context.Background(),
		data,
		generousLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	safe := findNode(t, result.Nodes, "/safe.txt")
	child := findNode(t, result.Nodes, "/nested/child.txt")
	if result.Partial ||
		len(result.Nodes) != 3 ||
		safe.ExtractionStatus != StatusExtracted ||
		child.ExtractionStatus != StatusExtracted {
		t.Fatalf("result=%+v safe=%+v child=%+v", result, safe, child)
	}
}

func TestExtractCPIOCumulativeMetadataLimit(t *testing.T) {
	longRootName := strings.Repeat(
		"./",
		maxLogicalPathBytes/2,
	)
	record := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name:  longRootName,
		mode:  cpioModeDir | 0o755,
		nlink: 2,
	}}, false)
	if int64(len(record)) <= 0 ||
		int64(len(record)) > maxCPIONameBytes+cpioNewcHeaderBytes+3 {
		t.Fatalf("metadata record length = %d", len(record))
	}
	recordCount := int(maxCPIOMetadataBytes/int64(len(record))) + 2
	if recordCount >= defaultMaxNodes {
		t.Fatalf("metadata fixture needs %d records", recordCount)
	}

	sourcePath := filepath.Join(t.TempDir(), "metadata-limit.cpio")
	output, err := os.OpenFile(
		sourcePath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	buffered := bufio.NewWriterSize(output, 256<<10)
	for range recordCount {
		if _, err := buffered.Write(record); err != nil {
			_ = output.Close()
			t.Fatal(err)
		}
	}
	if err := buffered.Flush(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}

	limits := generousLimits()
	limits.MaxNodes = defaultMaxNodes
	result, err := runCPIOExtractPath(
		t,
		context.Background(),
		sourcePath,
		limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestExtractCPIOExpandedAndDepthLimitsCleanWorkFiles(t *testing.T) {
	t.Run("expanded midway", func(t *testing.T) {
		data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{
			{
				name: "first.txt",
				mode: cpioModeRegular | 0o600,
				body: []byte("first"),
			},
			{
				name: "limited.bin",
				mode: cpioModeRegular | 0o600,
				body: bytes.Repeat([]byte("x"), 128),
			},
			{
				name: "unreached.txt",
				mode: cpioModeRegular | 0o600,
				body: []byte("unreached"),
			},
		}, true)
		limits := generousLimits()
		limits.MaxExpandedBytes = 17
		result, err := runCPIOExtract(
			t,
			context.Background(),
			data,
			limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		first := findNode(t, result.Nodes, "/first.txt")
		limited := findNode(t, result.Nodes, "/limited.bin")
		if !result.Partial ||
			result.LimitCode != LimitMaxExpandedBytes ||
			result.ExpandedBytes != 17 ||
			first.ExtractionStatus != StatusExtracted ||
			limited.ExtractionStatus != StatusLimitExceeded ||
			limited.SizeBytes != 12 {
			t.Fatalf(
				"result=%+v first=%+v limited=%+v",
				result,
				first,
				limited,
			)
		}
	})

	t.Run("nested depth", func(t *testing.T) {
		nested := zipFixture(t, []zipEntry{{
			name: "payload.txt",
			body: []byte("nested"),
		}})
		data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
			name: "inner.zip",
			mode: cpioModeRegular | 0o600,
			body: nested,
		}}, true)
		limits := generousLimits()
		limits.MaxDepth = 1
		result, err := runCPIOExtract(
			t,
			context.Background(),
			data,
			limits,
		)
		if err != nil {
			t.Fatal(err)
		}
		container := findNode(t, result.Nodes, "/inner.zip")
		if !result.Partial ||
			result.LimitCode != LimitMaxDepth ||
			container.ExtractionStatus != StatusDepthLimited ||
			len(result.Nodes) != 1 {
			t.Fatalf("result=%+v container=%+v", result, container)
		}
	})
}

func TestCPIOParserCancellationDuringHeaderRead(t *testing.T) {
	data := cpioArchiveFixture(t, "newc", []cpioFixtureEntry{{
		name: "file",
		mode: cpioModeRegular | 0o600,
		body: []byte("content"),
	}}, true)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterReaderAt{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 2,
	}
	parser := cpioParser{
		ctx:    ctx,
		source: reader,
		size:   int64(len(data)),
	}
	_, err := parser.nextHeader()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("nextHeader() error = %v", err)
	}
}

type cpioFixtureEntry struct {
	name             string
	mode             uint64
	uid              uint64
	gid              uint64
	nlink            uint64
	inode            uint64
	mtime            uint64
	devMajor         uint64
	devMinor         uint64
	rdevMajor        uint64
	rdevMinor        uint64
	body             []byte
	checksumOverride *uint32
}

func cpioArchiveFixture(
	t *testing.T,
	encoding string,
	entries []cpioFixtureEntry,
	trailer bool,
) []byte {
	t.Helper()
	var output bytes.Buffer
	nextInode := uint64(1)
	for _, entry := range entries {
		if entry.inode == 0 {
			entry.inode = nextInode
		}
		nextInode++
		if entry.nlink == 0 {
			entry.nlink = 1
		}
		writeCPIOFixtureEntry(t, &output, encoding, entry)
	}
	if trailer {
		writeCPIOFixtureEntry(t, &output, encoding, cpioFixtureEntry{
			name:  "TRAILER!!!",
			inode: nextInode,
			nlink: 1,
		})
	}
	return append([]byte(nil), output.Bytes()...)
}

func writeCPIOFixtureEntry(
	t *testing.T,
	output *bytes.Buffer,
	encoding string,
	entry cpioFixtureEntry,
) {
	t.Helper()
	nameSize := uint64(len(entry.name) + 1)
	checksum := cpioByteSum(entry.body)
	if entry.checksumOverride != nil {
		checksum = *entry.checksumOverride
	}
	switch encoding {
	case "newc", "crc":
		magic := cpioMagicNewc
		if encoding == "crc" {
			magic = cpioMagicCRC
		} else {
			checksum = 0
		}
		header := fmt.Sprintf(
			"%s%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			magic,
			entry.inode,
			entry.mode,
			entry.uid,
			entry.gid,
			entry.nlink,
			entry.mtime,
			len(entry.body),
			entry.devMajor,
			entry.devMinor,
			entry.rdevMajor,
			entry.rdevMinor,
			nameSize,
			checksum,
		)
		if len(header) != int(cpioNewcHeaderBytes) {
			t.Fatalf("newc header length = %d", len(header))
		}
		output.WriteString(header)
		output.WriteString(entry.name)
		output.WriteByte(0)
		writeCPIOFixturePadding(output, int(cpioNewcAlignment))
		output.Write(entry.body)
		writeCPIOFixturePadding(output, int(cpioNewcAlignment))
	case "odc":
		header := fmt.Sprintf(
			"%s%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
			cpioMagicODC,
			entry.devMinor,
			entry.inode,
			entry.mode,
			entry.uid,
			entry.gid,
			entry.nlink,
			entry.rdevMinor,
			entry.mtime,
			nameSize,
			len(entry.body),
		)
		if len(header) != int(cpioODCHeaderBytes) {
			t.Fatalf("odc header length = %d", len(header))
		}
		output.WriteString(header)
		output.WriteString(entry.name)
		output.WriteByte(0)
		// POSIX odc is entirely unpadded, unlike the binary format.
		output.Write(entry.body)
	case "binary-le", "binary-be":
		var order binary.ByteOrder = binary.LittleEndian
		if encoding == "binary-be" {
			order = binary.BigEndian
		}
		if entry.inode > math.MaxUint16 ||
			entry.mode > math.MaxUint16 ||
			entry.uid > math.MaxUint16 ||
			entry.gid > math.MaxUint16 ||
			entry.nlink > math.MaxUint16 ||
			entry.devMinor > math.MaxUint16 ||
			entry.rdevMinor > math.MaxUint16 ||
			nameSize > math.MaxUint16 ||
			len(entry.body) > math.MaxInt32 {
			t.Fatal("binary fixture field overflow")
		}
		var raw [cpioBinaryHeaderBytes]byte
		fields := [...]uint16{
			0x71c7,
			uint16(entry.devMinor),
			uint16(entry.inode),
			uint16(entry.mode),
			uint16(entry.uid),
			uint16(entry.gid),
			uint16(entry.nlink),
			uint16(entry.rdevMinor),
			uint16(entry.mtime >> 16),
			uint16(entry.mtime),
			uint16(nameSize),
			uint16(uint32(len(entry.body)) >> 16),
			uint16(len(entry.body)),
		}
		for index, field := range fields {
			order.PutUint16(raw[index*2:(index+1)*2], field)
		}
		output.Write(raw[:])
		output.WriteString(entry.name)
		output.WriteByte(0)
		writeCPIOFixturePadding(output, int(cpioBinaryAlignment))
		output.Write(entry.body)
		writeCPIOFixturePadding(output, int(cpioBinaryAlignment))
	default:
		t.Fatalf("unknown CPIO fixture encoding %q", encoding)
	}
}

func writeCPIOFixturePadding(output *bytes.Buffer, alignment int) {
	for output.Len()%alignment != 0 {
		output.WriteByte(0)
	}
}

func cpioByteSum(data []byte) uint32 {
	var checksum uint32
	for _, current := range data {
		checksum += uint32(current)
	}
	return checksum
}

func hasCPIOErrorNode(nodes []Node) bool {
	for _, node := range nodes {
		if node.ErrorCode == "cpio_archive_corrupt" {
			return true
		}
	}
	return false
}

func runCPIOExtract(
	t *testing.T,
	ctx context.Context,
	data []byte,
	limits Limits,
) (Result, error) {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), "input.cpio")
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return runCPIOExtractPath(t, ctx, sourcePath, limits)
}

func runCPIOExtractPath(
	t *testing.T,
	ctx context.Context,
	sourcePath string,
	limits Limits,
) (Result, error) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	engine := NewEngine(filetype.Detector{}, limits)
	state := operationState{
		engine:      engine,
		ctx:         ctx,
		workDir:     workDir,
		rootSize:    info.Size(),
		nextID:      1,
		paths:       make(map[string]struct{}),
		nodeIndex:   make(map[int]int),
		directories: make(map[string]int),
		memory: parserDecoderMemory{
			limit: engine.parserDecoderMemoryLimit,
		},
	}
	container := containerBudget{sourceSize: info.Size()}
	extractErr := state.extractCPIO(
		source,
		info.Size(),
		0,
		"",
		0,
		&container,
	)
	if extractErr != nil {
		var limit *limitError
		switch {
		case errors.As(extractErr, &limit):
			state.markLimit(limit.code)
		case errors.Is(extractErr, context.Canceled),
			errors.Is(extractErr, context.DeadlineExceeded):
			state.markLimit(LimitContextCancelled)
		default:
			return state.result(), extractErr
		}
	}
	result := state.result()
	assertNodeGraph(t, result.Nodes)
	workEntries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(workEntries) != 0 {
		t.Fatalf("work directory is not clean: %v", workEntries)
	}
	if errors.Is(extractErr, context.Canceled) ||
		errors.Is(extractErr, context.DeadlineExceeded) {
		return result, extractErr
	}
	return result, nil
}
