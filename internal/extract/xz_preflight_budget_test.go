package extract

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"

	xzlib "github.com/ulikunitz/xz"
)

func TestXZPreflightAcceptsRealEmptyBlocksAndReportsCost(t *testing.T) {
	const blockCount = 16
	data := xzEmptyBlocksFixture(t, blockCount, 0)

	info, err := preflightXZ(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatalf("preflightXZ() error = %v", err)
	}
	if info.BlockCount != blockCount ||
		info.MaxDictionaryBytes != 4<<10 ||
		info.TotalDecoderAllocationBytes != blockCount*(4<<10) {
		t.Fatalf("preflight info = %+v", info)
	}

	reader, err := (xzlib.ReaderConfig{
		DictCap:      0,
		SingleStream: true,
	}).NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader() error = %v", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("decoded %d bytes from empty Blocks", len(decoded))
	}
}

func TestXZPreflightCumulativeDictionaryBudgetBoundary(t *testing.T) {
	const dictionaryProperty = byte(28) // 64 MiB
	data := xzEmptyBlocksFixture(t, 4, dictionaryProperty)

	info, err := preflightXZ(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatalf("preflightXZ() boundary error = %v", err)
	}
	if info.BlockCount != 4 ||
		info.MaxDictionaryBytes != int64(maxStreamDecoderMemoryBytes) ||
		info.TotalDecoderAllocationBytes !=
			maxXZTotalDecoderAllocationBytes {
		t.Fatalf("preflight boundary info = %+v", info)
	}

	over := xzEmptyBlocksFixture(t, 5, dictionaryProperty)
	_, err = preflightXZ(
		context.Background(),
		bytes.NewReader(over),
		int64(len(over)),
	)
	var limit *limitError
	if !errors.As(err, &limit) ||
		limit.code != LimitMaxDecoderMemory {
		t.Fatalf("preflight over-budget error = %v", err)
	}
	result := runExtract(t, over, "xz", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxDecoderMemory ||
		len(result.Nodes) != 0 {
		t.Fatalf("over-budget extraction result = %+v", result)
	}
}

func TestXZPreflightBlockMetadataBoundary(t *testing.T) {
	data := xzEmptyBlocksFixture(t, int(maxXZBlocks), 0)
	info, err := preflightXZ(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatalf("preflightXZ() block boundary error = %v", err)
	}
	if info.BlockCount != maxXZBlocks {
		t.Fatalf("block count = %d", info.BlockCount)
	}

	over := xzEmptyBlocksFixture(t, int(maxXZBlocks)+1, 0)
	_, err = preflightXZ(
		context.Background(),
		bytes.NewReader(over),
		int64(len(over)),
	)
	var limit *limitError
	if !errors.As(err, &limit) ||
		limit.code != LimitMaxArchiveMetadata {
		t.Fatalf("preflight block-limit error = %v", err)
	}
	result := runExtract(t, over, "xz", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("block-limit extraction result = %+v", result)
	}
}

func TestXZPreflightCancellationWhileWalkingEmptyBlocks(t *testing.T) {
	data := xzEmptyBlocksFixture(t, int(maxXZBlocks), 0)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterReaderAt{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 100,
	}
	_, err := preflightXZ(ctx, reader, int64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("preflight cancellation error = %v", err)
	}
}

func TestXZPreflightCumulativeChunkBudgetBoundary(t *testing.T) {
	half := int(maxXZChunksPerStream / 2)
	data := xzChunkedBlocksFixture(t, []int{half, half})
	info, err := preflightXZ(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatalf("preflightXZ() chunk boundary error = %v", err)
	}
	if info.BlockCount != 2 ||
		info.ChunkCount != maxXZChunksPerStream {
		t.Fatalf("chunk boundary info = %+v", info)
	}
	result := runExtract(t, data, "xz", generousLimits())
	node := findNode(t, result.Nodes, "/content")
	if result.Partial ||
		node.ExtractionStatus != StatusExtracted ||
		node.SizeBytes != int64(maxXZChunksPerStream) {
		t.Fatalf("chunk boundary result=%+v node=%+v", result, node)
	}

	over := xzChunkedBlocksFixture(t, []int{half, half + 1})
	_, err = preflightXZ(
		context.Background(),
		bytes.NewReader(over),
		int64(len(over)),
	)
	var limit *limitError
	if !errors.As(err, &limit) ||
		limit.code != LimitMaxArchiveMetadata {
		t.Fatalf("preflight chunk-limit error = %v", err)
	}
	result = runExtract(t, over, "xz", generousLimits())
	if !result.Partial ||
		result.LimitCode != LimitMaxArchiveMetadata ||
		len(result.Nodes) != 0 {
		t.Fatalf("chunk-limit extraction result = %+v", result)
	}
}

func TestXZPreflightCancellationWhileWalkingChunks(t *testing.T) {
	data := xzChunkedBlocksFixture(t, []int{1_024})
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancelAfterReaderAt{
		reader:      bytes.NewReader(data),
		cancel:      cancel,
		cancelAfter: 100,
	}
	_, err := preflightXZ(ctx, reader, int64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("chunk preflight cancellation error = %v", err)
	}
}

func xzEmptyBlocksFixture(
	t *testing.T,
	blockCount int,
	dictionaryProperty byte,
) []byte {
	t.Helper()
	if blockCount < 1 {
		t.Fatal("XZ fixture requires at least one Block")
	}
	dictionarySize, err := xzDictionarySize(dictionaryProperty)
	if err != nil {
		t.Fatal(err)
	}
	if dictionarySize > maxStreamDecoderMemoryBytes {
		t.Fatal("XZ fixture dictionary exceeds the supported Block limit")
	}
	var template bytes.Buffer
	writer, err := (xzlib.WriterConfig{
		DictCap: 4 << 10,
	}).NewWriter(&template)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	source := setXZDictionaryProperty(
		t,
		template.Bytes(),
		dictionaryProperty,
	)
	checkSize, ok := xzCheckSize(source[7])
	if !ok {
		t.Fatal("XZ fixture uses an unsupported check")
	}
	blockOffset := int64(xzStreamHeaderLength)
	headerLength := int64(int(source[blockOffset])+1) * 4
	compressedSize, _, err := scanXZLZMA2(
		context.Background(),
		bytes.NewReader(source),
		int64(len(source)),
		blockOffset+headerLength,
		maxXZChunksPerStream,
	)
	if err != nil {
		t.Fatal(err)
	}
	paddingSize := (4 - compressedSize%4) % 4
	blockEnd := blockOffset + headerLength + compressedSize +
		paddingSize + int64(checkSize)
	if blockEnd >= int64(len(source)) {
		t.Fatal("XZ fixture has no Index")
	}
	block := append([]byte(nil), source[blockOffset:blockEnd]...)
	unpaddedSize := uint64(headerLength + compressedSize + int64(checkSize))

	var output bytes.Buffer
	output.Write(source[:xzStreamHeaderLength])
	for count := 0; count < blockCount; count++ {
		output.Write(block)
	}

	var index bytes.Buffer
	index.WriteByte(0)
	writeXZFixtureVLI(&index, uint64(blockCount))
	for count := 0; count < blockCount; count++ {
		writeXZFixtureVLI(&index, unpaddedSize)
		writeXZFixtureVLI(&index, 0)
	}
	for index.Len()%4 != 0 {
		index.WriteByte(0)
	}
	indexCRC := crc32.ChecksumIEEE(index.Bytes())
	if err := binary.Write(&index, binary.LittleEndian, indexCRC); err != nil {
		t.Fatal(err)
	}
	output.Write(index.Bytes())

	var footer [12]byte
	binary.LittleEndian.PutUint32(
		footer[4:8],
		uint32(index.Len()/4-1),
	)
	footer[8] = source[6]
	footer[9] = source[7]
	footer[10] = 'Y'
	footer[11] = 'Z'
	binary.LittleEndian.PutUint32(
		footer[0:4],
		crc32.ChecksumIEEE(footer[4:10]),
	)
	output.Write(footer[:])
	return output.Bytes()
}

func xzChunkedBlocksFixture(t *testing.T, chunksPerBlock []int) []byte {
	t.Helper()
	if len(chunksPerBlock) < 1 {
		t.Fatal("XZ fixture requires at least one Block")
	}
	var template bytes.Buffer
	writer, err := (xzlib.WriterConfig{
		DictCap:    4 << 10,
		NoCheckSum: true,
	}).NewWriter(&template)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	source := template.Bytes()
	blockOffset := int64(xzStreamHeaderLength)
	headerLength := int64(int(source[blockOffset])+1) * 4
	headerEnd := blockOffset + headerLength
	if headerLength < 8 || headerEnd >= int64(len(source)) {
		t.Fatal("XZ fixture has an invalid Block header")
	}
	blockHeader := source[blockOffset:headerEnd]

	type indexRecord struct {
		unpaddedSize     uint64
		uncompressedSize uint64
	}
	records := make([]indexRecord, 0, len(chunksPerBlock))
	var output bytes.Buffer
	output.Write(source[:xzStreamHeaderLength])
	for blockIndex, chunkCount := range chunksPerBlock {
		if chunkCount < 0 {
			t.Fatalf("Block %d has a negative chunk count", blockIndex)
		}
		output.Write(blockHeader)
		compressedSize := int64(1)
		for chunkIndex := 0; chunkIndex < chunkCount; chunkIndex++ {
			control := byte(2)
			if chunkIndex == 0 {
				control = 1
			}
			output.Write([]byte{
				control,
				0,
				0,
				byte(chunkIndex),
			})
			compressedSize += 4
		}
		output.WriteByte(0)
		for padding := (4 - compressedSize%4) % 4; padding > 0; padding-- {
			output.WriteByte(0)
		}
		records = append(records, indexRecord{
			unpaddedSize:     uint64(headerLength + compressedSize),
			uncompressedSize: uint64(chunkCount),
		})
	}

	var index bytes.Buffer
	index.WriteByte(0)
	writeXZFixtureVLI(&index, uint64(len(records)))
	for _, record := range records {
		writeXZFixtureVLI(&index, record.unpaddedSize)
		writeXZFixtureVLI(&index, record.uncompressedSize)
	}
	for index.Len()%4 != 0 {
		index.WriteByte(0)
	}
	indexCRC := crc32.ChecksumIEEE(index.Bytes())
	if err := binary.Write(&index, binary.LittleEndian, indexCRC); err != nil {
		t.Fatal(err)
	}
	output.Write(index.Bytes())

	var footer [12]byte
	binary.LittleEndian.PutUint32(
		footer[4:8],
		uint32(index.Len()/4-1),
	)
	footer[8] = source[6]
	footer[9] = source[7]
	footer[10] = 'Y'
	footer[11] = 'Z'
	binary.LittleEndian.PutUint32(
		footer[0:4],
		crc32.ChecksumIEEE(footer[4:10]),
	)
	output.Write(footer[:])
	return output.Bytes()
}

func writeXZFixtureVLI(output *bytes.Buffer, value uint64) {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(encoded[:], value)
	output.Write(encoded[:length])
}
