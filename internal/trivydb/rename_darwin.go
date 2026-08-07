//go:build darwin

package trivydb

import (
	"errors"

	"golang.org/x/sys/unix"
)

var errRenameDestinationExists = errors.New("rename destination exists")

func renameDirectoryNoReplaceAt(parentFD int, source, destination string) error {
	err := unix.RenameatxNp(
		parentFD,
		source,
		parentFD,
		destination,
		unix.RENAME_EXCL,
	)
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.ENOTEMPTY) {
		return errRenameDestinationExists
	}
	return err
}
