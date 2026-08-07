package bytecode

import (
	"io/fs"
	"testing"
)

func TestTrustedEntryRejectsDeviceCrossingAndHardLinks(t *testing.T) {
	tests := []struct {
		name          string
		mode          fs.FileMode
		device        uint64
		links         uint64
		trustedDevice uint64
		want          bool
	}{
		{"regular", 0, 7, 1, 7, true},
		{"hard link", 0, 7, 2, 7, false},
		{"file mount crossing", 0, 8, 1, 7, false},
		{"directory links allowed", fs.ModeDir, 7, 5, 7, true},
		{"directory mount crossing", fs.ModeDir, 8, 5, 7, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := trustedMetadata(
				test.mode, test.device, test.links, test.trustedDevice,
			); got != test.want {
				t.Fatalf("trustedMetadata() = %v, want %v", got, test.want)
			}
		})
	}
}
