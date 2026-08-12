package main

import (
	"errors"
	"testing"

	"binaryscan/internal/archiveimport"
	"binaryscan/internal/upload"
)

func TestAPIRejectsUnknownCommandBeforeLoadingConfiguration(t *testing.T) {
	if err := run([]string{"unknown"}); err == nil {
		t.Fatal("run() error = nil, want invalid command error")
	}
}

func TestMapArchiveImportUploadError(t *testing.T) {
	tests := []struct {
		name string
		got  error
		want error
	}{
		{name: "nil", got: mapArchiveImportUploadError(nil)},
		{
			name: "conflict", got: mapArchiveImportUploadError(archiveimport.ErrConflict),
			want: upload.ErrInvalidState,
		},
		{
			name: "forbidden", got: mapArchiveImportUploadError(archiveimport.ErrForbidden),
			want: upload.ErrForbidden,
		},
		{
			name: "not found", got: mapArchiveImportUploadError(archiveimport.ErrNotFound),
			want: upload.ErrNotFound,
		},
		{
			name: "invalid", got: mapArchiveImportUploadError(archiveimport.ErrInvalidInput),
			want: upload.ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !errors.Is(test.got, test.want) ||
				(test.want == nil && test.got != nil) {
				t.Fatalf("mapped error = %v, want %v", test.got, test.want)
			}
		})
	}
}
