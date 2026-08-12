package archiveimport

import "testing"

func TestDecodeLimitsSnapshotKeepsV1DepthForLegacyRows(t *testing.T) {
	limits, err := decodeLimitsSnapshot([]byte(`{
        "max_upload_bytes":2147483648,
        "max_expanded_bytes":10737418240,
        "max_archive_ratio":50,
        "max_entries":20000,
        "max_entry_bytes":2147483648
    }`))
	if err != nil {
		t.Fatalf("decodeLimitsSnapshot() error = %v", err)
	}
	if limits.MaxDepth != DefaultMaxDepth {
		t.Fatalf("MaxDepth = %d, want %d", limits.MaxDepth, DefaultMaxDepth)
	}
}

func TestDecodeLimitsSnapshotRejectsDepthBeyondContract(t *testing.T) {
	_, err := decodeLimitsSnapshot([]byte(`{
        "max_upload_bytes":2147483648,
        "max_expanded_bytes":10737418240,
        "max_archive_ratio":50,
        "max_entries":20000,
        "max_entry_bytes":2147483648,
        "max_depth":11
    }`))
	if err == nil {
		t.Fatal("decodeLimitsSnapshot() error = nil, want invalid depth")
	}
}
