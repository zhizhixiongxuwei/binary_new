package archivesandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSevenZipListingAcceptsFrozenSevenZipAndCABShapes(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		listing string
		path    string
		size    int64
	}{
		{
			name: "7z", format: "7z", path: "bin/tool", size: 5,
			listing: "Path = bin/tool\r\nSize = 5\r\nPacked Size = 9\r\n" +
				"Modified = 2026-08-12 01:13:46\r\nAttributes = A -rw-r--r--\r\n" +
				"CRC = 3610A686\r\nEncrypted = -\r\nMethod = LZMA2:12\r\nBlock = 0\r\n\r\n",
		},
		{
			name: "cab", format: "cab", path: "payload.txt", size: 5,
			listing: "Path = payload.txt\nSize = 5\nModified = 1980-01-01 00:00:00\n" +
				"Attributes = A\nMethod = None\nBlock = 0\n\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries, err := parseSevenZipListing(test.listing, Request{
				Format: test.format, MaxEntries: 20,
				MaxEntryBytes: 1 << 20, MaxExpandedBytes: 2 << 20,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].path != test.path ||
				entries[0].size != test.size || entries[0].directory {
				t.Fatalf("entries = %#v", entries)
			}
		})
	}
}

func TestParseSevenZipListingRejectsUnsafeAmbiguousMembers(t *testing.T) {
	request := Request{
		Format: "7z", MaxEntries: 20,
		MaxEntryBytes: 1 << 20, MaxExpandedBytes: 2 << 20,
	}
	base := "Size = 1\nPacked Size = 1\nModified = 2026-08-12 00:00:00\n" +
		"Attributes = A -rw-r--r--\nCRC = 0\nEncrypted = -\nMethod = Copy\nBlock = 0\n\n"
	for _, listing := range []string{
		"Path = ../escape\n" + base,
		"Path = link\n" + strings.Replace(base, "A -rw-r--r--", "A lrwxrwxrwx", 1),
		"Path = duplicate\n" + base + "Path = duplicate\n" + base,
		"Path = encrypted\n" + strings.Replace(base, "Encrypted = -", "Encrypted = +", 1),
		"Path = a\n\nSize = 1\n",
	} {
		if entries, err := parseSevenZipListing(listing, request); err == nil {
			t.Fatalf("parseSevenZipListing() accepted %#v: %#v", listing, entries)
		}
	}
}

func TestValidatePreflightOutputRequiresExactFileAndSizeSet(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "bin", "tool"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	manifest := []preflightEntry{{path: "bin/tool", size: 4}}
	if err := validatePreflightOutput(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePreflightOutput(root, manifest); err == nil {
		t.Fatal("validatePreflightOutput() accepted an unlisted extracted file")
	}
}
