package rpm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseValidRPMWrapper(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("cpio-payload"),
		nil,
		[]parserHeaderEntry{
			{tag: tagArchitecture, value: "x86_64"},
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "zstd"},
			{tag: tagPayloadFlags, value: "19"},
		},
	)
	parsed, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MajorVersion != 3 ||
		parsed.MinorVersion != 0 ||
		parsed.PackageType != 0 ||
		parsed.ArchitectureCode != 1 ||
		parsed.Architecture != "x86_64" ||
		parsed.FormatVersion != 3 ||
		parsed.PayloadFormat != "cpio" ||
		parsed.PayloadCompressor != "zstd" ||
		parsed.PayloadFlags != "19" ||
		parsed.Signature.Offset != 96 ||
		parsed.Signature.IndexCount != 0 ||
		parsed.MainHeader.IndexCount != 4 ||
		parsed.PayloadBytes != int64(len("cpio-payload")) ||
		!bytes.Equal(data[parsed.PayloadOffset:], []byte("cpio-payload")) {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestParseRPMFormatTag(t *testing.T) {
	fixture := func() []byte {
		data := parserRPMFixture(
			t,
			[]byte("07070X00000000"),
			nil,
			[]parserHeaderEntry{
				{tag: tagPayloadFormat, value: "cpio"},
				{tag: tagPayloadCompressor, value: "none"},
				{
					tag:          tagRPMFormat,
					valueType:    headerTypeInt32,
					integerValue: 6,
				},
			},
		)
		data[4] = 4
		return data
	}

	data := fixture()
	parsed, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.FormatVersion != 6 {
		t.Fatalf("FormatVersion = %d, want 6", parsed.FormatVersion)
	}

	const mainOffset = 112
	const rpmFormatIndex = mainOffset + 16 + 2*16
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "wrong-type",
			mutate: func(data []byte) {
				binary.BigEndian.PutUint32(
					data[rpmFormatIndex+4:rpmFormatIndex+8],
					headerTypeBin,
				)
			},
		},
		{
			name: "wrong-count",
			mutate: func(data []byte) {
				binary.BigEndian.PutUint32(
					data[rpmFormatIndex+12:rpmFormatIndex+16],
					2,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := fixture()
			test.mutate(data)
			_, err := Parse(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
			)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
}

func TestParseInfersV4FromHeaderImmutable(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("payload"),
		nil,
		[]parserHeaderEntry{
			{
				tag:       tagHeaderImmutable,
				valueType: headerTypeBin,
				rawValue:  make([]byte, 16),
			},
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "none"},
		},
	)
	parsed, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.FormatVersion != 4 {
		t.Fatalf("FormatVersion = %d, want 4", parsed.FormatVersion)
	}
}

func TestParseTreatsLegacyLeadFieldsAsUntrustedObservations(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("payload"),
		nil,
		[]parserHeaderEntry{
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "none"},
		},
	)
	data[4] = 0xff
	data[5] = 0xfe
	binary.BigEndian.PutUint16(data[6:8], 0xfdfc)
	binary.BigEndian.PutUint16(data[8:10], 0xfbfa)
	for index := 10; index < 76; index++ {
		data[index] = 'x'
	}
	binary.BigEndian.PutUint16(data[78:80], 0xf9f8)
	for index := 80; index < 96; index++ {
		data[index] = byte(index)
	}

	parsed, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MajorVersion != 0xff ||
		parsed.MinorVersion != 0xfe ||
		parsed.PackageType != 0xfdfc ||
		parsed.ArchitectureCode != 0xfbfa {
		t.Fatalf("legacy lead observations = %+v", parsed)
	}
}

func TestParseAcceptsSignaturePaddingOnlyWhenZero(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("payload"),
		[]byte{0x7f},
		[]parserHeaderEntry{
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "none"},
		},
	)
	if _, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	); err != nil {
		t.Fatal(err)
	}

	data[113] = 1
	_, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsMalformedLeadAndHeaderBounds(t *testing.T) {
	valid := parserRPMFixture(
		t,
		[]byte("payload"),
		nil,
		[]parserHeaderEntry{
			{tag: tagArchitecture, value: "x86_64"},
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "none"},
			{tag: tagPayloadFlags, value: "9"},
		},
	)
	const mainOffset = 112
	const firstIndex = mainOffset + 16
	tests := []struct {
		name   string
		mutate func([]byte) []byte
		target error
	}{
		{
			name: "bad-magic",
			mutate: func(data []byte) []byte {
				data[0] = 0
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "bad-signature-magic",
			mutate: func(data []byte) []byte {
				data[96] = 0
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "signature-entry-limit",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(data[104:108], 100_001)
				return data
			},
			target: ErrMetadataLimit,
		},
		{
			name: "signature-data-out-of-range",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(data[108:112], 4096)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "bad-main-magic",
			mutate: func(data []byte) []byte {
				data[mainOffset] = 0
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "negative-value-offset",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[firstIndex+8:firstIndex+12],
					0xffffffff,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "value-extends-beyond-data",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[firstIndex+4:firstIndex+8],
					headerTypeBin,
				)
				binary.BigEndian.PutUint32(
					data[firstIndex+12:firstIndex+16],
					0xffffffff,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "misaligned-integer",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[firstIndex+4:firstIndex+8],
					headerTypeInt32,
				)
				binary.BigEndian.PutUint32(
					data[firstIndex+8:firstIndex+12],
					1,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "unknown-value-type",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[firstIndex+4:firstIndex+8],
					99,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "unordered-tags",
			mutate: func(data []byte) []byte {
				secondIndex := firstIndex + 16
				binary.BigEndian.PutUint32(
					data[secondIndex:secondIndex+4],
					tagArchitecture,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "payload-tag-wrong-type",
			mutate: func(data []byte) []byte {
				binary.BigEndian.PutUint32(
					data[firstIndex+4:firstIndex+8],
					headerTypeBin,
				)
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "unterminated-final-string",
			mutate: func(data []byte) []byte {
				mainDataBytes := binary.BigEndian.Uint32(
					data[mainOffset+12 : mainOffset+16],
				)
				mainEnd := mainOffset + 16 + 4*16 +
					int(mainDataBytes)
				data[mainEnd-1] = 'x'
				return data
			},
			target: ErrInvalid,
		},
		{
			name: "empty-payload",
			mutate: func(data []byte) []byte {
				mainDataBytes := binary.BigEndian.Uint32(
					data[mainOffset+12 : mainOffset+16],
				)
				mainEnd := mainOffset + 16 + 4*16 +
					int(mainDataBytes)
				return data[:mainEnd]
			},
			target: ErrInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := test.mutate(append([]byte(nil), valid...))
			_, err := Parse(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
			)
			if !errors.Is(err, test.target) {
				t.Fatalf("Parse() error = %v, want %v", err, test.target)
			}
		})
	}
}

func TestParseRejectsOversizedTargetString(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("payload"),
		nil,
		[]parserHeaderEntry{
			{tag: tagPayloadFormat, value: strings.Repeat("x", 65)},
			{tag: tagPayloadCompressor, value: "none"},
		},
	)
	_, err := Parse(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
	)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseCancellationAndReaderFailure(t *testing.T) {
	data := parserRPMFixture(
		t,
		[]byte("payload"),
		nil,
		[]parserHeaderEntry{
			{tag: tagPayloadFormat, value: "cpio"},
			{tag: tagPayloadCompressor, value: "none"},
		},
	)
	t.Run("cancelled-before-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Parse(ctx, bytes.NewReader(data), int64(len(data)))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
	t.Run("cancelled-during-header-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &parserCancelingReaderAt{
			reader:      bytes.NewReader(data),
			cancel:      cancel,
			cancelAfter: 4,
		}
		_, err := Parse(ctx, reader, int64(len(data)))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
	t.Run("reader-failure", func(t *testing.T) {
		expected := errors.New("reader failed")
		reader := parserFailingReaderAt{
			data:   data,
			offset: 96,
			err:    expected,
		}
		_, err := Parse(
			context.Background(),
			reader,
			int64(len(data)),
		)
		if !errors.Is(err, expected) {
			t.Fatalf("Parse() error = %v", err)
		}
	})
}

type parserHeaderEntry struct {
	tag          uint32
	valueType    uint32
	value        string
	integerValue uint32
	rawValue     []byte
}

func parserRPMFixture(
	t *testing.T,
	payload []byte,
	signatureData []byte,
	entries []parserHeaderEntry,
) []byte {
	t.Helper()
	lead := make([]byte, leadBytes)
	copy(lead[:4], rpmMagic)
	lead[4] = 3
	binary.BigEndian.PutUint16(lead[8:10], 1)
	copy(lead[10:76], "fixture-1.0-1")
	binary.BigEndian.PutUint16(lead[76:78], 1)
	binary.BigEndian.PutUint16(lead[78:80], 5)

	signature := parserHeaderFixture(t, nil, signatureData)
	main := parserHeaderFixture(t, entries, nil)
	output := append([]byte(nil), lead...)
	output = append(output, signature...)
	for len(output)%8 != 0 {
		output = append(output, 0)
	}
	output = append(output, main...)
	output = append(output, payload...)
	return output
}

func parserHeaderFixture(
	t *testing.T,
	entries []parserHeaderEntry,
	extraData []byte,
) []byte {
	t.Helper()
	var index bytes.Buffer
	var data bytes.Buffer
	for _, entry := range entries {
		valueType := entry.valueType
		if valueType == 0 {
			valueType = headerTypeString
		}
		if valueType == headerTypeInt32 {
			for data.Len()%4 != 0 {
				data.WriteByte(0)
			}
		}
		var encoded [16]byte
		binary.BigEndian.PutUint32(encoded[0:4], entry.tag)
		binary.BigEndian.PutUint32(encoded[4:8], valueType)
		binary.BigEndian.PutUint32(
			encoded[8:12],
			uint32(data.Len()),
		)
		count := uint32(1)
		if valueType == headerTypeBin {
			count = uint32(len(entry.rawValue))
		}
		binary.BigEndian.PutUint32(encoded[12:16], count)
		index.Write(encoded[:])
		switch valueType {
		case headerTypeString:
			data.WriteString(entry.value)
			data.WriteByte(0)
		case headerTypeInt32:
			var encodedValue [4]byte
			binary.BigEndian.PutUint32(
				encodedValue[:],
				entry.integerValue,
			)
			data.Write(encodedValue[:])
		case headerTypeBin:
			data.Write(entry.rawValue)
		default:
			t.Fatalf("unsupported fixture value type %d", valueType)
		}
	}
	data.Write(extraData)
	var intro [16]byte
	copy(intro[:8], headerMagic)
	binary.BigEndian.PutUint32(intro[8:12], uint32(len(entries)))
	binary.BigEndian.PutUint32(intro[12:16], uint32(data.Len()))
	output := append([]byte(nil), intro[:]...)
	output = append(output, index.Bytes()...)
	output = append(output, data.Bytes()...)
	return output
}

type parserFailingReaderAt struct {
	data   []byte
	offset int64
	err    error
}

func (reader parserFailingReaderAt) ReadAt(
	buffer []byte,
	offset int64,
) (int, error) {
	if offset >= reader.offset {
		return 0, reader.err
	}
	return bytes.NewReader(reader.data).ReadAt(buffer, offset)
}

var _ io.ReaderAt = parserFailingReaderAt{}

type parserCancelingReaderAt struct {
	reader      io.ReaderAt
	cancel      context.CancelFunc
	cancelAfter int
	reads       int
}

func (reader *parserCancelingReaderAt) ReadAt(
	buffer []byte,
	offset int64,
) (int, error) {
	count, err := reader.reader.ReadAt(buffer, offset)
	reader.reads++
	if reader.reads == reader.cancelAfter {
		reader.cancel()
	}
	return count, err
}

var _ io.ReaderAt = (*parserCancelingReaderAt)(nil)
