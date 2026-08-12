package inputcategory

import "testing"

func TestForFormatMatchesFrozenContract(t *testing.T) {
	tests := map[Category][]string{
		Binary: {
			"pe32", "pe32+", "elf32", "elf64", "macho-thin", "macho-fat",
			"java-class", "jar", "war", "ear", "dex", "apk", "pyc",
		},
		Archive: {
			"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd",
			"cab", "cpio", "ar", "deb", "rpm",
		},
		Container: {"docker-tar", "oci-tar"},
	}
	for expected, formats := range tests {
		for _, format := range formats {
			actual, ok := ForFormat(format)
			if !ok || actual != expected {
				t.Errorf("ForFormat(%q) = %q, %t; want %q, true", format, actual, ok, expected)
			}
		}
	}
	for _, format := range []string{
		"unknown", "ext2", "ext3", "ext4", "squashfs", "iso9660", "udf",
		"mbr-img", "gpt-img", "JAR", "",
	} {
		if category, ok := ForFormat(format); ok {
			t.Errorf("ForFormat(%q) = %q, true; want unsupported", format, category)
		}
	}
}

func TestParseAcceptsOnlyCanonicalCategory(t *testing.T) {
	for _, value := range []Category{Binary, Archive, Container} {
		parsed, ok := Parse(string(value))
		if !ok || parsed != value {
			t.Fatalf("Parse(%q) = %q, %t", value, parsed, ok)
		}
	}
	for _, value := range []string{"", "Binary", "image", " binary"} {
		if parsed, ok := Parse(value); ok {
			t.Errorf("Parse(%q) = %q, true; want invalid", value, parsed)
		}
	}
}
