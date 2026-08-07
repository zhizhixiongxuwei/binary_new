//go:build linux

package archivesandbox

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func cgroupPeerSnapshot() map[int]struct{} {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil
	}
	identity := unifiedCgroupIdentity(string(self))
	if identity == "" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	peers := make(map[int]struct{})
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cgroup"))
		if err == nil && unifiedCgroupIdentity(string(raw)) == identity {
			peers[pid] = struct{}{}
		}
	}
	return peers
}

func killNewCgroupPeers(baseline map[int]struct{}) bool {
	if len(baseline) == 0 {
		return false
	}
	current := cgroupPeerSnapshot()
	self := os.Getpid()
	escaped := false
	for pid := range current {
		if pid == self {
			continue
		}
		if _, existed := baseline[pid]; existed {
			continue
		}
		escaped = true
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	return escaped
}

func unifiedCgroupIdentity(value string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, "0::/") || line == "0::/" {
			return line
		}
	}
	return ""
}
