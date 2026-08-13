package trivy

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ext4Fixture builds a minimal ext4 filesystem header the filetype detector
// recognizes: the superblock lives at offset 1024 with magic 0xEF53.
func ext4Fixture() []byte {
	data := make([]byte, 4096)
	sb := data[1024 : 1024+1024]
	binary.LittleEndian.PutUint32(sb[0:4], 1)          // inodes
	binary.LittleEndian.PutUint32(sb[4:8], 100)        // blocks
	binary.LittleEndian.PutUint32(sb[0x18:0x1c], 2)    // log block size (4096)
	binary.LittleEndian.PutUint16(sb[0x38:0x3a], 0xef53) // magic
	binary.LittleEndian.PutUint16(sb[0x58:0x5a], 256)  // inode size
	binary.LittleEndian.PutUint32(sb[0x60:0x64], 0x40|0x80) // incompatible: extents, flex_bg
	return data
}

func TestVerifyVMImageAcceptsExtFilesystemAndPartitionedImages(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name    string
		content []byte
	}{
		{name: "ext4 filesystem", content: ext4Fixture()},
		{name: "gpt partitioned image", content: gptImageFixture(512)},
		{name: "mbr partitioned image", content: mbrImageFixture()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name+".img")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := VerifyVMImage(path)
			if err != nil {
				t.Fatal(err)
			}
			if source.Kind() != SourceVMImage {
				t.Fatalf("source = %+v", source)
			}
			canonical, canonicalErr := filepath.EvalSymlinks(path)
			if canonicalErr != nil || source.Path() != canonical {
				t.Fatalf("source path = %q, want %q", source.Path(), canonical)
			}
			if err := verifySourceAgain(source); err != nil {
				t.Fatalf("verifySourceAgain: %v", err)
			}
		})
	}
}

func TestVerifyVMImageRejectsNonImageContent(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "empty file", content: nil},
		{name: "plain text", content: []byte("hello world, this is not a disk image at all")},
		{name: "iso9660", content: isoImageFixture()},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(directory, test.name+".bin")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyVMImage(path); err == nil {
				t.Fatalf("VerifyVMImage(%q) accepted non-image content", path)
			}
		})
	}
}

func TestVerifyVMImageRejectsDirectoriesAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	if _, err := VerifyVMImage(directory); err == nil {
		t.Fatal("VerifyVMImage accepted a directory")
	}
	target := filepath.Join(directory, "target.img")
	if err := os.WriteFile(target, ext4Fixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.img")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVMImage(link); err == nil {
		t.Fatal("VerifyVMImage accepted a symlink")
	}
	if _, err := VerifyVMImage(filepath.Join(directory, "missing.img")); err == nil {
		t.Fatal("VerifyVMImage accepted a missing path")
	}
}

// gptImageFixture mirrors the filetype package GPT fixture: protective MBR,
// one protective partition entry, and a GPT header at the sector boundary.
func gptImageFixture(sectorSize int) []byte {
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

// mbrImageFixture mirrors the filetype package MBR fixture: boot signature,
// one Linux partition entry, no GPT marker.
func mbrImageFixture() []byte {
	const totalSectors = 100
	data := make([]byte, totalSectors*512)
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[4] = 0x83
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	binary.LittleEndian.PutUint32(entry[12:16], totalSectors-1)
	return data
}

// isoImageFixture builds a minimal ISO 9660 primary volume descriptor so the
// filetype detector classifies the content as an optical image instead of a
// VM disk image.
func isoImageFixture() []byte {
	data := make([]byte, 2048*20)
	descriptor := data[2048*16 : 2048*17]
	descriptor[0] = 1
	copy(descriptor[1:6], "CD001")
	descriptor[6] = 1
	return data
}

func TestVMImageArgumentsUseVMSubcommandWithoutInputFlag(t *testing.T) {
	adapter := &Adapter{
		executable: "/usr/local/bin/trivy",
	}
	source := VerifiedSource{
		path: "/inputs/vm-image.img",
		kind: SourceVMImage,
	}
	arguments := adapter.arguments(source, "/work/trivy-result.json")
	if len(arguments) == 0 {
		t.Fatal("vm arguments are empty")
	}
	if arguments[0] != "vm" || arguments[1] != "/inputs/vm-image.img" {
		t.Fatalf("vm arguments = %v", arguments)
	}
	for _, argument := range arguments {
		if argument == "--input" {
			t.Fatalf("vm subcommand must not use --input: %v", arguments)
		}
	}
	joined := strings.Join(arguments, "\x00")
	for _, required := range []string{
		"--offline-scan", "--skip-db-update", "--skip-java-db-update",
		"--scanners", "vuln", "--format", "json",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("vm arguments missing %q: %v", required, arguments)
		}
	}
}
