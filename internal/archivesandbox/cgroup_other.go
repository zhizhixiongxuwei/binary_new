//go:build !linux

package archivesandbox

func cgroupPeerSnapshot() map[int]struct{} {
	return nil
}

func killNewCgroupPeers(map[int]struct{}) bool {
	return false
}
