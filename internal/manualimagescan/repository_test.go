package manualimagescan

import (
	"database/sql"
	"testing"
)

func TestEligibleManualImageTargetAcceptsRootAndSkippedNestedImages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		parentID   sql.NullInt64
		nodeType   string
		format     sql.NullString
		extraction string
		errorCode  sql.NullString
		want       bool
	}{
		{
			name:     "root OCI image",
			parentID: sql.NullInt64{}, nodeType: "file",
			format:     sql.NullString{String: "oci-tar", Valid: true},
			extraction: "indexed", want: true,
		},
		{
			name:     "skipped nested Docker image",
			parentID: sql.NullInt64{Int64: 7, Valid: true}, nodeType: "file",
			format:     sql.NullString{String: "docker-tar", Valid: true},
			extraction: "limit_reached",
			errorCode:  sql.NullString{String: "max_auto_container_images", Valid: true},
			want:       true,
		},
		{
			name:     "ordinary nested image",
			parentID: sql.NullInt64{Int64: 7, Valid: true}, nodeType: "file",
			format:     sql.NullString{String: "oci-tar", Valid: true},
			extraction: "extracted", want: false,
		},
		{
			name:     "root generic tar",
			parentID: sql.NullInt64{}, nodeType: "file",
			format:     sql.NullString{String: "tar", Valid: true},
			extraction: "indexed", want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := eligibleManualImageTarget(
				test.parentID,
				test.nodeType,
				test.format,
				test.extraction,
				test.errorCode,
			); got != test.want {
				t.Fatalf("eligibleManualImageTarget() = %t, want %t", got, test.want)
			}
		})
	}
}
