// Package inputcategory owns the stable mapping between content-derived file
// formats and the task input categories exposed by the API.
package inputcategory

type Category string

const (
	Binary    Category = "binary"
	Archive   Category = "archive"
	Container Category = "container"
)

var formatCategories = map[string]Category{
	"pe32": Binary, "pe32+": Binary,
	"elf32": Binary, "elf64": Binary,
	"macho-thin": Binary, "macho-fat": Binary,
	"java-class": Binary, "jar": Binary, "war": Binary, "ear": Binary,
	"dex": Binary, "apk": Binary, "pyc": Binary,

	"zip": Archive, "7z": Archive, "rar": Archive, "tar": Archive,
	"gzip": Archive, "bzip2": Archive, "xz": Archive, "zstd": Archive,
	"cab": Archive, "cpio": Archive, "ar": Archive, "deb": Archive,
	"rpm": Archive,

	// ISO 9660 disc images are unpacked one level like any other archive.
	"iso9660": Archive,

	"docker-tar": Container, "oci-tar": Container,

	// Disk and filesystem images are scanned by Trivy's vm subcommand through
	// the same container image-scan task pipeline. raw-img is intentionally
	// absent: the detector never produces it.
	"ext2": Container, "ext3": Container, "ext4": Container,
	"mbr-img": Container, "gpt-img": Container,
}

func Parse(value string) (Category, bool) {
	category := Category(value)
	switch category {
	case Binary, Archive, Container:
		return category, true
	default:
		return "", false
	}
}

// ForFormat returns the supported task input category for a detector format.
// Formats intentionally excluded from the v1 input contract return false.
func ForFormat(format string) (Category, bool) {
	category, ok := formatCategories[format]
	return category, ok
}

func (category Category) Valid() bool {
	_, ok := Parse(string(category))
	return ok
}
