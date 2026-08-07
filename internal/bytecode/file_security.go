package bytecode

import (
	"io/fs"
	"os"
	"syscall"
)

func fileDeviceAndLinks(info fs.FileInfo) (uint64, uint64, bool) {
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(metadata.Dev), uint64(metadata.Nlink), true
}

// trustedEntry rejects mount crossings for every entry and hard-linked regular
// files. Directory link counts are intentionally not constrained because a
// normal directory's count reflects its children.
func trustedEntry(info fs.FileInfo, trustedDevice uint64) bool {
	device, links, ok := fileDeviceAndLinks(info)
	if !ok {
		return false
	}
	return trustedMetadata(info.Mode(), device, links, trustedDevice)
}

func trustedMetadata(
	mode fs.FileMode,
	device uint64,
	links uint64,
	trustedDevice uint64,
) bool {
	if device != trustedDevice {
		return false
	}
	return !mode.IsRegular() || links == 1
}

func trustedRootDevice(info fs.FileInfo) (uint64, bool) {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, false
	}
	device, _, ok := fileDeviceAndLinks(info)
	return device, ok
}
