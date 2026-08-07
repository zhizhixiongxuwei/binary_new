package trivydb

import "golang.org/x/sys/unix"

func identityFromStat(value *unix.Stat_t) fileIdentity {
	return fileIdentity{
		device: uint64(value.Dev),
		inode:  uint64(value.Ino),
		mode:   uint32(value.Mode),
	}
}
