package systemstatus

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureStorageProbeUsesConfiguredCanonicalDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	usage, err := (SecureStorageProbe{}).Probe(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if usage.TotalBytes == 0 || usage.FreeBytes > usage.TotalBytes ||
		usage.UsedBytes != usage.TotalBytes-usage.FreeBytes ||
		!usage.DeviceKnown {
		t.Fatalf("disk usage = %#v", usage)
	}
}

func TestSecureStorageProbeRejectsNonCanonicalAndSymlinkRoots(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{
		"/",
		target + "/../target",
		link,
	} {
		t.Run(root, func(t *testing.T) {
			if _, err := (SecureStorageProbe{}).Probe(
				context.Background(),
				root,
			); err == nil {
				t.Fatalf("Probe(%q) error = nil", root)
			}
		})
	}
}

func TestSecureStorageProbeHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (SecureStorageProbe{}).Probe(ctx, "/private/tmp"); err == nil {
		t.Fatal("Probe() error = nil")
	}
}

func TestCheckedMultiplyRejectsOverflow(t *testing.T) {
	if _, ok := checkedMultiply(math.MaxUint64, 2); ok {
		t.Fatal("checkedMultiply() accepted overflow")
	}
	if value, ok := checkedMultiply(8, 16); !ok || value != 128 {
		t.Fatalf("checkedMultiply() = %d, %v", value, ok)
	}
}
