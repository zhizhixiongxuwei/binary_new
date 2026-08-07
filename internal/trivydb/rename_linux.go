//go:build linux

package trivydb

import (
	"errors"

	"golang.org/x/sys/unix"
)

var errRenameDestinationExists = errors.New("rename destination exists")

func renameDirectoryNoReplaceAt(parentFD int, source, destination string) error {
	err := unix.Renameat2(
		parentFD,
		source,
		parentFD,
		destination,
		unix.RENAME_NOREPLACE,
	)
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
		return errRenameDestinationExists
	}
	return err
}
