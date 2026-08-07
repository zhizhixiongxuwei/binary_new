package extract

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"binaryscan/internal/filetype"
	"binaryscan/internal/imageextract"
)

func TestExtractRecursesArchiveImageArchiveWithSharedTree(t *testing.T) {
	innerArchive := storedZIP(t, "payload.txt", []byte("nested payload"))
	image := extractISOFixture(t, "INNER.ZIP;1", innerArchive)
	outerArchive := storedZIP(t, "disk.iso", image)

	result := extractBytesForImageTest(t, outerArchive, "zip", Limits{})
	if result.Partial || result.LimitCode != "" {
		t.Fatalf("recursive extraction result = %#v", result)
	}
	imageNode := findNode(t, result.Nodes, "/disk.iso")
	innerNode := findNode(t, result.Nodes, "/disk.iso/INNER.ZIP")
	payload := findNode(
		t,
		result.Nodes,
		"/disk.iso/INNER.ZIP/payload.txt",
	)
	if imageNode.Format != "iso9660" || innerNode.Format != "zip" ||
		payload.SizeBytes != int64(len("nested payload")) {
		t.Fatalf(
			"recursive nodes = image:%#v inner:%#v payload:%#v",
			imageNode,
			innerNode,
			payload,
		)
	}
	wantHash := sha256.Sum256([]byte("nested payload"))
	if payload.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("payload SHA-256 = %q", payload.SHA256)
	}
	assertNodeGraph(t, result.Nodes)
}

func TestExtractDiskPartitionsAt512And4096ByteSectors(t *testing.T) {
	for _, sectorSize := range []int64{512, 4096} {
		t.Run(strconv.FormatInt(sectorSize, 10), func(t *testing.T) {
			image := extractISOFixture(t, "HELLO.TXT;1", []byte("hello"))
			disk := diskWithPayload(t, sectorSize, image)
			result := extractBytesForImageTest(t, disk, "mbr-img", Limits{})
			if result.Partial {
				t.Fatalf("disk result = %#v", result)
			}
			partition := findNode(t, result.Nodes, "/partition-001")
			file := findNode(
				t,
				result.Nodes,
				"/partition-001/HELLO.TXT",
			)
			if partition.NodeType != NodeTypeDirectory ||
				partition.Format != "iso9660" || file.SizeBytes != 5 {
				t.Fatalf("partition nodes = (%#v, %#v)", partition, file)
			}
			assertNodeGraph(t, result.Nodes)
		})
	}
}

func TestExtractDiskRetainsSafePartitionWhenTableIsPartial(t *testing.T) {
	disk := make([]byte, 128*512)
	disk[510], disk[511] = 0x55, 0xaa
	writeExtractMBRPartition(disk[446:462], 0x83, 8, 40)
	writeExtractMBRPartition(disk[462:478], 0x07, 16, 40)

	result := extractBytesForImageTest(t, disk, "mbr-img", Limits{})
	if !result.Partial {
		t.Fatalf("overlapping table was not partial: %#v", result)
	}
	partition := findNode(t, result.Nodes, "/partition-001")
	if partition.NodeType != NodeTypeDirectory {
		t.Fatalf("retained partition = %#v", partition)
	}
	corruptNodes := 0
	for _, node := range result.Nodes {
		if node.ErrorCode == "image_corrupt" {
			corruptNodes++
		}
	}
	if corruptNodes != 1 {
		t.Fatalf("image_corrupt nodes = %d; nodes = %#v", corruptNodes, result.Nodes)
	}
}

func TestExtractISORetainsValidatedFileBeforeCorruptSibling(t *testing.T) {
	image := extractISOFixture(t, "HELLO.TXT;1", []byte("hello"))
	root := image[20*2048 : 21*2048]
	position := 0
	for position < len(root) && root[position] != 0 {
		position += int(root[position])
	}
	copy(
		root[position:],
		extractISORecord(33, 2048, 0x02, []byte("BAD")),
	)
	result := extractBytesForImageTest(t, image, "iso9660", Limits{})
	if !result.Partial {
		t.Fatalf("corrupt ISO result = %#v", result)
	}
	file := findNode(t, result.Nodes, "/HELLO.TXT")
	if file.SizeBytes != 5 || file.SHA256 == "" {
		t.Fatalf("retained ISO file = %#v", file)
	}
	corrupt := 0
	for _, node := range result.Nodes {
		if node.ErrorCode == "image_corrupt" {
			corrupt++
		}
	}
	if corrupt != 1 {
		t.Fatalf("corrupt marker count = %d; nodes = %#v", corrupt, result.Nodes)
	}
}

func TestExtractDiskDoesNotRouteArchivePayloadThroughImageEngine(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload := compressed.Bytes()
	disk := diskWithPayload(t, 512, payload)
	result := extractBytesForImageTest(t, disk, "mbr-img", Limits{})
	if !result.Partial {
		t.Fatalf("archive partition should be explicitly unsupported: %#v", result)
	}
	partition := findNode(t, result.Nodes, "/partition-001")
	if partition.Format != "gzip" ||
		partition.ErrorCode != "unsupported_partition_payload" ||
		partition.ExtractionStatus != StatusUnsupported {
		t.Fatalf("archive partition = %#v", partition)
	}
	for _, node := range result.Nodes {
		if node.ErrorCode == "image_corrupt" {
			t.Fatalf("archive payload was incorrectly routed as an image: %#v", result.Nodes)
		}
	}
}

func TestExtractImageRecursionSharesGlobalNodeLimit(t *testing.T) {
	innerArchive := storedZIP(t, "payload.txt", []byte("payload"))
	image := extractISOFixture(t, "INNER.ZIP;1", innerArchive)
	outerArchive := storedZIP(t, "disk.iso", image)
	result := extractBytesForImageTest(t, outerArchive, "zip", Limits{
		MaxNodes: 2,
	})
	if !result.Partial || result.LimitCode != LimitMaxNodes ||
		len(result.Nodes) != 2 {
		t.Fatalf("node-limited result = %#v", result)
	}
}

func TestExtractImagePreservesNonFileAndPartitionErrors(t *testing.T) {
	workDir := t.TempDir()
	sourcePath := filepath.Join(workDir, "sample.bin")
	if err := os.WriteFile(sourcePath, make([]byte, 16), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	registry := imageextract.NewRegistry()
	if err := registry.Register("raw-img", imageextract.ExtractorFunc(func(
		_ context.Context,
		_ imageextract.Request,
		sink imageextract.Sink,
	) error {
		if err := sink.AddPartition(imageextract.Partition{
			ID: "p1", Index: 1, StartOffsetBytes: 0, SizeBytes: 8,
			Status:    imageextract.StatusCorrupt,
			ErrorCode: "bad_partition", ErrorMessage: "partition is corrupt",
		}); err != nil {
			return err
		}
		if err := sink.AddEntry(imageextract.Entry{
			ID: 1, LogicalPath: "/dir", Kind: imageextract.EntryDirectory,
			Depth: 1, Status: imageextract.StatusCorrupt,
			ErrorCode: "bad_directory", ErrorMessage: "directory is corrupt",
		}); err != nil {
			return err
		}
		return sink.AddEntry(imageextract.Entry{
			ID: 2, LogicalPath: "/link", Kind: imageextract.EntrySymlink,
			Depth: 1, LinkTarget: "target",
			Status:    imageextract.StatusUnsupported,
			ErrorCode: "bad_link", ErrorMessage: "link is unsupported",
		})
	})); err != nil {
		t.Fatal(err)
	}
	imageEngine, err := imageextract.NewEngine(registry, imageextract.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(filetype.Detector{}, Limits{})
	engine.imageEngine = imageEngine
	result, err := engine.Extract(
		context.Background(), source, "raw-img", workDir,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial {
		t.Fatalf("image errors did not produce a partial result: %#v", result)
	}
	for logical, code := range map[string]string{
		"/partition-001": "bad_partition",
		"/dir":           "bad_directory",
		"/link":          "bad_link",
	} {
		if node := findNode(t, result.Nodes, logical); node.ErrorCode != code {
			t.Fatalf("node %s = %#v", logical, node)
		}
	}
}

func extractBytesForImageTest(
	t *testing.T,
	content []byte,
	format string,
	limits Limits,
) Result {
	t.Helper()
	workDir := t.TempDir()
	sourcePath := filepath.Join(workDir, "sample.bin")
	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	engine := NewEngine(filetype.Detector{}, limits)
	result, err := engine.Extract(
		context.Background(),
		source,
		format,
		workDir,
	)
	if err != nil {
		t.Fatalf("Extract() error = %v; result = %#v", err, result)
	}
	return result
}

func storedZIP(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(0o600)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func diskWithPayload(t *testing.T, sectorSize int64, payload []byte) []byte {
	t.Helper()
	const startLBA = uint32(8)
	sectors := uint32((int64(len(payload)) + sectorSize - 1) / sectorSize)
	disk := make([]byte, int64(startLBA+sectors+1)*sectorSize)
	disk[510], disk[511] = 0x55, 0xaa
	writeExtractMBRPartition(disk[446:462], 0x83, startLBA, sectors)
	copy(disk[int64(startLBA)*sectorSize:], payload)
	return disk
}

func writeExtractMBRPartition(
	target []byte,
	kind byte,
	start uint32,
	sectors uint32,
) {
	target[4] = kind
	binary.LittleEndian.PutUint32(target[8:12], start)
	binary.LittleEndian.PutUint32(target[12:16], sectors)
}

func extractISOFixture(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	if len(content) > 2048 {
		t.Fatalf("ISO fixture content is too large: %d", len(content))
	}
	const sectors = uint32(32)
	image := make([]byte, int(sectors)*2048)
	primary := image[16*2048 : 17*2048]
	primary[0] = 1
	copy(primary[1:6], "CD001")
	primary[6] = 1
	for index := 40; index < 72; index++ {
		primary[index] = ' '
	}
	copy(primary[40:72], "EXTRACT")
	putExtractBoth32(primary[80:88], sectors)
	putExtractBoth16(primary[120:124], 1)
	putExtractBoth16(primary[124:128], 1)
	putExtractBoth16(primary[128:132], 2048)
	putExtractBoth32(primary[132:140], 10)
	copy(primary[156:], extractISORecord(20, 2048, 0x02, []byte{0}))

	terminator := image[17*2048 : 18*2048]
	terminator[0] = 255
	copy(terminator[1:6], "CD001")
	terminator[6] = 1

	root := image[20*2048 : 21*2048]
	position := 0
	for _, record := range [][]byte{
		extractISORecord(20, 2048, 0x02, []byte{0}),
		extractISORecord(20, 2048, 0x02, []byte{1}),
		extractISORecord(21, uint32(len(content)), 0, []byte(name)),
	} {
		copy(root[position:], record)
		position += len(record)
	}
	copy(image[21*2048:], content)
	return image
}

func extractISORecord(
	lba uint32,
	size uint32,
	flags byte,
	identifier []byte,
) []byte {
	length := 33 + len(identifier)
	if len(identifier)%2 == 0 {
		length++
	}
	record := make([]byte, length)
	record[0] = byte(length)
	putExtractBoth32(record[2:10], lba)
	putExtractBoth32(record[10:18], size)
	record[25] = flags
	putExtractBoth16(record[28:32], 1)
	record[32] = byte(len(identifier))
	copy(record[33:], identifier)
	return record
}

func putExtractBoth16(target []byte, value uint16) {
	binary.LittleEndian.PutUint16(target[:2], value)
	binary.BigEndian.PutUint16(target[2:4], value)
}

func putExtractBoth32(target []byte, value uint32) {
	binary.LittleEndian.PutUint32(target[:4], value)
	binary.BigEndian.PutUint32(target[4:8], value)
}
