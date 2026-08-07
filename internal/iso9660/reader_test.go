package iso9660

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"unicode/utf16"
)

const fixtureSectors = 48

type fixtureOptions struct {
	multiExtent bool
	rockRidge   bool
	joliet      bool
}

func TestOpenIndexesAndCopiesRecursiveISO9660(t *testing.T) {
	image := buildFixture(t, fixtureOptions{})
	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if reader.Volume() != (Volume{
		Identifier:       "BINARYSCAN",
		LogicalBlockSize: 2048,
	}) {
		t.Fatalf("Volume() = %#v", reader.Volume())
	}
	entries := reader.Entries()
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	if !reflect.DeepEqual(paths, []string{
		"README.TXT", "SUBDIR", "SUBDIR/INNER.BIN",
	}) {
		t.Fatalf("entry paths = %#v", paths)
	}
	if entries[0].Type != TypeFile || entries[0].Size != 5 ||
		entries[1].Type != TypeDirectory || entries[2].Size != 4 {
		t.Fatalf("entries = %#v", entries)
	}

	var output bytes.Buffer
	copied, err := reader.CopyFile(context.Background(), "README.TXT", &output)
	if err != nil || copied != 5 || output.String() != "hello" {
		t.Fatalf("CopyFile() = (%d, %q, %v)", copied, output.String(), err)
	}
	if _, err := reader.CopyFile(
		context.Background(),
		"SUBDIR",
		io.Discard,
	); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory CopyFile error = %v", err)
	}
	if _, err := reader.CopyFile(
		context.Background(),
		"missing",
		io.Discard,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CopyFile error = %v", err)
	}
	if _, ok := reader.Lookup("SUBDIR/../README.TXT"); ok {
		t.Fatal("Lookup accepted a non-normalized path")
	}

	copyOfEntries := reader.Entries()
	copyOfEntries[0].Path = "mutated"
	if current, _ := reader.Lookup("README.TXT"); current.Path != "README.TXT" {
		t.Fatal("Entries exposed mutable Reader state")
	}
}

func TestOpenJoinsMultiExtentFileWithoutReadingPastSegments(t *testing.T) {
	image := buildFixture(t, fixtureOptions{multiExtent: true})
	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := reader.Lookup("BIG.BIN")
	if !ok || entry.Size != 6 || entry.ExtentCount != 2 {
		t.Fatalf("multi-extent entry = (%#v, %v)", entry, ok)
	}
	extents, err := reader.Extents("BIG.BIN")
	if err != nil || !reflect.DeepEqual(extents, []Extent{
		{OffsetBytes: 22 * 2048, SizeBytes: 3},
		{OffsetBytes: 23 * 2048, SizeBytes: 3},
	}) {
		t.Fatalf("Extents() = (%#v, %v)", extents, err)
	}
	extents[0].OffsetBytes = 0
	again, err := reader.Extents("BIG.BIN")
	if err != nil || again[0].OffsetBytes != 22*2048 {
		t.Fatalf("Extents exposed mutable Reader state: (%#v, %v)", again, err)
	}
	var output bytes.Buffer
	if copied, err := reader.CopyFile(
		context.Background(),
		"BIG.BIN",
		&output,
	); err != nil || copied != 6 || output.String() != "abcdef" {
		t.Fatalf("CopyFile() = (%d, %q, %v)", copied, output.String(), err)
	}
}

func TestOpenWalksMultiExtentDirectory(t *testing.T) {
	image := buildFixture(t, fixtureOptions{})
	root := image[20*2048 : 21*2048]
	clear(root)
	writeDirectory(t, root,
		directoryRecord(20, 2048, 0x02, []byte{0}, nil),
		directoryRecord(20, 2048, 0x02, []byte{1}, nil),
		directoryRecord(22, 5, 0, []byte("README.TXT;1"), nil),
		directoryRecord(21, 2048, 0x82, []byte("SUBDIR"), nil),
		directoryRecord(24, 2048, 0x02, []byte("SUBDIR"), nil),
	)
	subdirectory := image[21*2048 : 22*2048]
	clear(subdirectory)
	writeDirectory(t, subdirectory,
		directoryRecord(21, 2048, 0x82, []byte{0}, nil),
		directoryRecord(24, 2048, 0x02, []byte{0}, nil),
		directoryRecord(20, 2048, 0x02, []byte{1}, nil),
		directoryRecord(23, 4, 0, []byte("INNER.BIN;1"), nil),
	)

	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	directory, ok := reader.Lookup("SUBDIR")
	if !ok || directory.Type != TypeDirectory || directory.Size != 4096 ||
		directory.ExtentCount != 2 {
		t.Fatalf("multi-extent directory = (%#v, %v)", directory, ok)
	}
	if nested, ok := reader.Lookup("SUBDIR/INNER.BIN"); !ok || nested.Size != 4 {
		t.Fatalf("nested entry = (%#v, %v)", nested, ok)
	}
}

func TestOpenPrefersJolietAndDecodesUTF16BE(t *testing.T) {
	image := buildFixture(t, fixtureOptions{joliet: true})
	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reader.Volume().Joliet || reader.Volume().RockRidge ||
		reader.Volume().Identifier != "离线镜像" {
		t.Fatalf("Joliet volume = %#v", reader.Volume())
	}
	entry, ok := reader.Lookup("资料.txt")
	if !ok || entry.Type != TypeFile {
		t.Fatalf("Joliet entry = (%#v, %v)", entry, ok)
	}
	var output bytes.Buffer
	if _, err := reader.CopyFile(
		context.Background(),
		"资料.txt",
		&output,
	); err != nil || output.String() != "joliet" {
		t.Fatalf("Joliet CopyFile = (%q, %v)", output.String(), err)
	}
}

func TestOpenUsesInlineRockRidgeNameModeAndRecordsSymlink(t *testing.T) {
	image := buildFixture(t, fixtureOptions{rockRidge: true, joliet: true})
	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reader.Volume().RockRidge || reader.Volume().Joliet {
		t.Fatalf("Rock Ridge did not take precedence: %#v", reader.Volume())
	}
	entry, ok := reader.Lookup("safe-name.txt")
	if !ok || entry.Type != TypeFile || entry.Mode != 0o100640 ||
		entry.UID != 1000 || entry.GID != 1001 {
		t.Fatalf("Rock Ridge file = (%#v, %v)", entry, ok)
	}
	link, ok := reader.Lookup("latest")
	if !ok || link.Type != TypeSymlink || link.Mode != 0o120777 ||
		link.SymlinkTarget != "../safe-name.txt" {
		t.Fatalf("Rock Ridge link = (%#v, %v)", link, ok)
	}
	nested, ok := reader.Lookup("目录/子文件.bin")
	if !ok || nested.Type != TypeFile || nested.Size != 2 {
		t.Fatalf("recursive Rock Ridge file = (%#v, %v)", nested, ok)
	}
	var nestedOutput bytes.Buffer
	if _, err := reader.CopyFile(
		context.Background(),
		"目录/子文件.bin",
		&nestedOutput,
	); err != nil || !bytes.Equal(nestedOutput.Bytes(), []byte{0xca, 0xfe}) {
		t.Fatalf("recursive Rock Ridge CopyFile = (%x, %v)", nestedOutput.Bytes(), err)
	}
	if _, err := reader.CopyFile(
		context.Background(),
		"latest",
		io.Discard,
	); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("symlink CopyFile error = %v", err)
	}
}

func TestOpenRejectsCorruptExtentsCyclesAndRecords(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, []byte)
	}{
		{
			name: "extent outside volume",
			mutate: func(t *testing.T, image []byte) {
				t.Helper()
				record := findRootRecord(t, image, []byte("README.TXT;1"))
				putBoth32(record[2:10], fixtureSectors+1)
			},
		},
		{
			name: "directory cycle",
			mutate: func(t *testing.T, image []byte) {
				t.Helper()
				record := findRootRecord(t, image, []byte("SUBDIR"))
				putBoth32(record[2:10], 20)
			},
		},
		{
			name: "disagreeing endian extent",
			mutate: func(t *testing.T, image []byte) {
				t.Helper()
				record := findRootRecord(t, image, []byte("README.TXT;1"))
				binary.BigEndian.PutUint32(record[6:10], 99)
			},
		},
		{
			name: "nonzero directory padding",
			mutate: func(t *testing.T, image []byte) {
				t.Helper()
				root := image[20*2048 : 21*2048]
				position := directoryRecordsEnd(root)
				root[position+7] = 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := buildFixture(t, fixtureOptions{})
			test.mutate(t, image)
			_, err := Open(
				context.Background(),
				bytes.NewReader(image),
				int64(len(image)),
				Limits{},
			)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open() error = %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestOpenReturnsValidatedPrefixOnLocalCorruptionAndLimit(t *testing.T) {
	t.Run("cyclic later directory", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{})
		record := findRootRecord(t, image, []byte("SUBDIR"))
		putBoth32(record[2:10], 20)
		reader, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) || reader == nil {
			t.Fatalf("Open() = (%#v, %v), want partial reader", reader, err)
		}
		entries := reader.Entries()
		if len(entries) != 1 || entries[0].Path != "README.TXT" {
			t.Fatalf("validated prefix = %#v", entries)
		}
		var output bytes.Buffer
		if _, err := reader.CopyFile(
			context.Background(), "README.TXT", &output,
		); err != nil || output.String() != "hello" {
			t.Fatalf("CopyFile(valid prefix) = (%q, %v)", output.String(), err)
		}
	})

	t.Run("node plus one", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{})
		reader, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{MaxNodes: 1},
		)
		var limit *LimitError
		if !errors.As(err, &limit) || limit.Limit != LimitNodes || reader == nil {
			t.Fatalf("Open() = (%#v, %v), want partial node limit", reader, err)
		}
		entries := reader.Entries()
		if len(entries) != 1 || entries[0].Path != "README.TXT" {
			t.Fatalf("limit prefix = %#v", entries)
		}
	})
}

func TestOpenRejectsUnterminatedMultiExtentAndUnsafeRockRidgeName(t *testing.T) {
	t.Run("unterminated multi extent", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{multiExtent: true})
		record := findRootRecord(t, image, []byte("BIG.BIN;1"))
		secondOffset := int(record[0])
		second := record[secondOffset:]
		second[25] |= 0x80
		_, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open() error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("unsafe Rock Ridge name", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{rockRidge: true})
		record := findRootRecord(t, image, []byte("LONGNA~1.TXT;1"))
		systemUse := recordSystemUse(t, record)
		firstNM := bytes.Index(systemUse, []byte("NM"))
		if firstNM < 0 {
			t.Fatal("NM fixture entry not found")
		}
		copy(systemUse[firstNM+5:], []byte("../x-"))
		_, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open() error = %v, want ErrCorrupt", err)
		}
	})
}

func TestOpenRejectsMalformedJolietAndRockRidgeMetadata(t *testing.T) {
	t.Run("invalid Joliet surrogate", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{joliet: true})
		root := image[30*2048 : 31*2048]
		offset := int(root[0])
		offset += int(root[offset])
		record := root[offset:]
		if record[32] < 4 {
			t.Fatal("Joliet fixture identifier is unexpectedly short")
		}
		binary.BigEndian.PutUint16(record[33:35], 0xd800)
		binary.BigEndian.PutUint16(record[35:37], 'x')
		_, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open() error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("PX byte order mismatch", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{rockRidge: true})
		record := findRootRecord(t, image, []byte("LONGNA~1.TXT;1"))
		systemUse := recordSystemUse(t, record)
		px := bytes.Index(systemUse, []byte("PX"))
		if px < 0 {
			t.Fatal("PX fixture entry not found")
		}
		binary.BigEndian.PutUint32(systemUse[px+8:px+12], 0)
		_, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open() error = %v, want ErrCorrupt", err)
		}
	})

	t.Run("unsafe SL component", func(t *testing.T) {
		image := buildFixture(t, fixtureOptions{rockRidge: true})
		record := findRootRecord(t, image, []byte("LINK.;1"))
		systemUse := recordSystemUse(t, record)
		sl := bytes.Index(systemUse, []byte("SL"))
		if sl < 0 || sl+10 > len(systemUse) {
			t.Fatal("SL fixture entry not found")
		}
		systemUse[sl+9] = '/'
		_, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{},
		)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open() error = %v, want ErrCorrupt", err)
		}
	})
}

func TestOpenEnforcesEveryResourceLimit(t *testing.T) {
	image := buildFixture(t, fixtureOptions{})
	tests := []struct {
		name   string
		limits Limits
		want   Limit
	}{
		{name: "nodes", limits: Limits{MaxNodes: 1}, want: LimitNodes},
		{name: "depth", limits: Limits{MaxDepth: 1}, want: LimitDepth},
		{name: "extents", limits: Limits{MaxExtents: 3}, want: LimitExtents},
		{name: "bytes", limits: Limits{MaxBytes: 2048}, want: LimitBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Open(
				context.Background(),
				bytes.NewReader(image),
				int64(len(image)),
				test.limits,
			)
			var limitError *LimitError
			if !errors.As(err, &limitError) || limitError.Limit != test.want ||
				!errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("Open() error = %v, want %s LimitError", err, test.want)
			}
		})
	}
}

func TestOpenAndCopyHonorCancellation(t *testing.T) {
	image := buildFixture(t, fixtureOptions{})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Open(
		cancelled,
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Open error = %v", err)
	}

	reader, err := Open(
		context.Background(),
		bytes.NewReader(image),
		int64(len(image)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.CopyFile(
		cancelled,
		"README.TXT",
		io.Discard,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CopyFile error = %v", err)
	}
}

func TestOpenValidatesArgumentsAndLimits(t *testing.T) {
	image := buildFixture(t, fixtureOptions{})
	for _, test := range []struct {
		ctx    context.Context
		source io.ReaderAt
		size   int64
		limits Limits
	}{
		{size: int64(len(image))},
		{source: bytes.NewReader(image), size: int64(len(image))},
		{ctx: context.Background(), source: bytes.NewReader(image), size: -1},
		{ctx: context.Background(), source: bytes.NewReader(image), size: int64(len(image)), limits: Limits{MaxDepth: 65}},
		{ctx: context.Background(), source: bytes.NewReader(image), size: int64(len(image)), limits: Limits{MaxBytes: hardMaxBytes + 1}},
	} {
		if _, err := Open(
			test.ctx,
			test.source,
			test.size,
			test.limits,
		); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("Open(%#v) error = %v", test, err)
		}
	}
}

func FuzzOpenKeepsEveryExposedExtentInsideTheImage(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildFixture(f, fixtureOptions{}))
	f.Add(buildFixture(f, fixtureOptions{multiExtent: true}))
	f.Fuzz(func(t *testing.T, image []byte) {
		reader, err := Open(
			context.Background(),
			bytes.NewReader(image),
			int64(len(image)),
			Limits{
				MaxNodes: 64, MaxDepth: 4, MaxExtents: 256,
				MaxBytes: 1024 * 1024,
			},
		)
		if err != nil {
			return
		}
		entries := reader.Entries()
		if len(entries) > 64 {
			t.Fatalf("node limit bypassed: %d", len(entries))
		}
		for _, entry := range entries {
			extents, err := reader.Extents(entry.Path)
			if err != nil {
				t.Fatal(err)
			}
			var logicalSize int64
			for _, item := range extents {
				if item.OffsetBytes < 0 || item.SizeBytes < 0 ||
					item.OffsetBytes > int64(len(image))-item.SizeBytes {
					t.Fatalf("out-of-image extent exposed: %#v", item)
				}
				logicalSize += item.SizeBytes
			}
			if logicalSize != entry.Size {
				t.Fatalf("extent bytes = %d, entry size = %d", logicalSize, entry.Size)
			}
			if entry.Type == TypeFile {
				copied, err := reader.CopyFile(
					context.Background(),
					entry.Path,
					io.Discard,
				)
				if err != nil || copied != entry.Size {
					t.Fatalf("CopyFile() = (%d, %v), size=%d", copied, err, entry.Size)
				}
			}
		}
	})
}

func buildFixture(t testing.TB, options fixtureOptions) []byte {
	t.Helper()
	image := make([]byte, fixtureSectors*2048)
	writeVolumeDescriptor(t, image[16*2048:17*2048], 1, 20, "BINARYSCAN", nil)
	descriptorEnd := 17

	if options.joliet {
		writeVolumeDescriptor(
			t,
			image[17*2048:18*2048],
			2,
			30,
			"离线镜像",
			[]byte{'%', '/', 'E'},
		)
		jolietRoot := image[30*2048 : 31*2048]
		writeDirectory(t, jolietRoot,
			directoryRecord(30, 2048, 0x02, []byte{0}, nil),
			directoryRecord(30, 2048, 0x02, []byte{1}, nil),
			directoryRecord(31, 6, 0, encodeUTF16BE("资料.txt;1"), nil),
		)
		copy(image[31*2048:], []byte("joliet"))
		descriptorEnd = 18
	}
	writeTerminator(image[descriptorEnd*2048 : (descriptorEnd+1)*2048])

	root := image[20*2048 : 21*2048]
	rootSystemUse := []byte(nil)
	if options.rockRidge {
		rootSystemUse = append(suspSP(0), suspPX(0o040555, 0, 0)...)
	}
	dot := directoryRecord(20, 2048, 0x02, []byte{0}, rootSystemUse)
	dotdot := directoryRecord(20, 2048, 0x02, []byte{1}, nil)

	if options.multiExtent {
		writeDirectory(t, root,
			dot,
			dotdot,
			directoryRecord(22, 3, 0x80, []byte("BIG.BIN;1"), nil),
			directoryRecord(23, 3, 0, []byte("BIG.BIN;1"), nil),
		)
		copy(image[22*2048:], []byte("abc"))
		copy(image[23*2048:], []byte("def"))
		return image
	}

	if options.rockRidge {
		fileSUSP := append([]byte{}, suspNM(true, "safe-")...)
		fileSUSP = append(fileSUSP, suspNM(false, "name.txt")...)
		fileSUSP = append(fileSUSP, suspPX(0o100640, 1000, 1001)...)
		linkSUSP := append([]byte{}, suspNM(false, "latest")...)
		linkSUSP = append(linkSUSP, suspPX(0o120777, 1000, 1001)...)
		linkSUSP = append(linkSUSP, suspSLParentAndName("safe-name.txt")...)
		directorySUSP := append([]byte{}, suspNM(false, "目录")...)
		directorySUSP = append(directorySUSP, suspPX(0o040750, 1000, 1001)...)
		writeDirectory(t, root,
			dot,
			dotdot,
			directoryRecord(22, 5, 0, []byte("LONGNA~1.TXT;1"), fileSUSP),
			directoryRecord(0, 0, 0, []byte("LINK.;1"), linkSUSP),
			directoryRecord(21, 2048, 0x02, []byte("DIR0001"), directorySUSP),
		)
		nestedSUSP := append([]byte{}, suspNM(false, "子文件.bin")...)
		nestedSUSP = append(nestedSUSP, suspPX(0o100600, 1000, 1001)...)
		writeDirectory(t, image[21*2048:22*2048],
			directoryRecord(21, 2048, 0x02, []byte{0}, nil),
			directoryRecord(20, 2048, 0x02, []byte{1}, nil),
			directoryRecord(23, 2, 0, []byte("NEST.TXT;1"), nestedSUSP),
		)
		copy(image[22*2048:], []byte("hello"))
		copy(image[23*2048:], []byte{0xca, 0xfe})
		return image
	}

	writeDirectory(t, root,
		dot,
		dotdot,
		directoryRecord(22, 5, 0, []byte("README.TXT;1"), nil),
		directoryRecord(21, 2048, 0x02, []byte("SUBDIR"), nil),
	)
	subdirectory := image[21*2048 : 22*2048]
	writeDirectory(t, subdirectory,
		directoryRecord(21, 2048, 0x02, []byte{0}, nil),
		directoryRecord(20, 2048, 0x02, []byte{1}, nil),
		directoryRecord(23, 4, 0, []byte("INNER.BIN;1"), nil),
	)
	copy(image[22*2048:], []byte("hello"))
	copy(image[23*2048:], []byte{0xde, 0xad, 0xbe, 0xef})
	return image
}

func writeVolumeDescriptor(
	t testing.TB,
	destination []byte,
	descriptorType byte,
	rootLBA uint32,
	identifier string,
	escape []byte,
) {
	t.Helper()
	destination[0] = descriptorType
	copy(destination[1:6], "CD001")
	destination[6] = 1
	putBoth32(destination[80:88], fixtureSectors)
	putBoth16(destination[120:124], 1)
	putBoth16(destination[124:128], 1)
	putBoth16(destination[128:132], 2048)
	putBoth32(destination[132:140], 10)
	if descriptorType == 2 {
		copy(destination[88:120], escape)
		encoded := encodeUTF16BE(identifier)
		if len(encoded) > 32 {
			t.Fatalf("Joliet volume identifier is too long: %q", identifier)
		}
		for offset := 40; offset < 72; offset += 2 {
			destination[offset+1] = ' '
		}
		copy(destination[40:72], encoded)
	} else {
		for index := 40; index < 72; index++ {
			destination[index] = ' '
		}
		copy(destination[40:72], identifier)
	}
	root := directoryRecord(rootLBA, 2048, 0x02, []byte{0}, nil)
	copy(destination[156:], root)
}

func writeTerminator(destination []byte) {
	destination[0] = 255
	copy(destination[1:6], "CD001")
	destination[6] = 1
}

func directoryRecord(
	lba uint32,
	size uint32,
	flags byte,
	identifier []byte,
	systemUse []byte,
) []byte {
	length := 33 + len(identifier) + len(systemUse)
	if len(identifier)%2 == 0 {
		length++
	}
	if length > 255 {
		panic("fixture directory record exceeds one-byte length")
	}
	record := make([]byte, length)
	record[0] = byte(length)
	putBoth32(record[2:10], lba)
	putBoth32(record[10:18], size)
	record[25] = flags
	putBoth16(record[28:32], 1)
	record[32] = byte(len(identifier))
	copy(record[33:], identifier)
	systemUseOffset := 33 + len(identifier)
	if len(identifier)%2 == 0 {
		systemUseOffset++
	}
	copy(record[systemUseOffset:], systemUse)
	return record
}

func writeDirectory(t testing.TB, destination []byte, records ...[]byte) {
	t.Helper()
	offset := 0
	for _, record := range records {
		if offset+len(record) > len(destination) {
			t.Fatal("fixture directory records exceed one sector")
		}
		copy(destination[offset:], record)
		offset += len(record)
	}
}

func findRootRecord(t *testing.T, image []byte, identifier []byte) []byte {
	t.Helper()
	root := image[20*2048 : 21*2048]
	for offset := 0; offset < len(root) && root[offset] != 0; {
		length := int(root[offset])
		if length < 34 || offset+length > len(root) {
			t.Fatal("invalid fixture record while searching")
		}
		record := root[offset : offset+length]
		nameLength := int(record[32])
		if bytes.Equal(record[33:33+nameLength], identifier) {
			return root[offset:]
		}
		offset += length
	}
	t.Fatalf("fixture record %q was not found", identifier)
	return nil
}

func directoryRecordsEnd(directory []byte) int {
	offset := 0
	for offset < len(directory) && directory[offset] != 0 {
		offset += int(directory[offset])
	}
	return offset
}

func recordSystemUse(t *testing.T, record []byte) []byte {
	t.Helper()
	length := int(record[0])
	if length > len(record) || length < 34 {
		t.Fatal("invalid fixture record")
	}
	nameLength := int(record[32])
	offset := 33 + nameLength
	if nameLength%2 == 0 {
		offset++
	}
	return record[offset:length]
}

func suspSP(skip byte) []byte {
	return []byte{'S', 'P', 7, 1, 0xbe, 0xef, skip}
}

func suspNM(continuing bool, name string) []byte {
	flags := byte(0)
	if continuing {
		flags = nmContinue
	}
	entry := []byte{'N', 'M', byte(5 + len(name)), 1, flags}
	return append(entry, []byte(name)...)
}

func suspPX(mode uint32, uid uint32, gid uint32) []byte {
	entry := make([]byte, 36)
	copy(entry, "PX")
	entry[2] = byte(len(entry))
	entry[3] = 1
	putBoth32(entry[4:12], mode)
	putBoth32(entry[12:20], 1)
	putBoth32(entry[20:28], uid)
	putBoth32(entry[28:36], gid)
	return entry
}

func suspSLParentAndName(name string) []byte {
	entry := []byte{'S', 'L', 0, 1, 0}
	entry = append(entry, slComponentParent, 0)
	entry = append(entry, 0, byte(len(name)))
	entry = append(entry, []byte(name)...)
	entry[2] = byte(len(entry))
	return entry
}

func encodeUTF16BE(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.BigEndian.PutUint16(encoded[index*2:index*2+2], unit)
	}
	return encoded
}

func putBoth16(destination []byte, value uint16) {
	if len(destination) != 4 {
		panic(fmt.Sprintf("putBoth16 destination length = %d", len(destination)))
	}
	binary.LittleEndian.PutUint16(destination[:2], value)
	binary.BigEndian.PutUint16(destination[2:], value)
}

func putBoth32(destination []byte, value uint32) {
	if len(destination) != 8 {
		panic(fmt.Sprintf("putBoth32 destination length = %d", len(destination)))
	}
	binary.LittleEndian.PutUint32(destination[:4], value)
	binary.BigEndian.PutUint32(destination[4:], value)
}
