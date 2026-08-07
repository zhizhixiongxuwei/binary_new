package orphanreaper

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	DefaultGracePeriod  = 24 * time.Hour
	MaxSweepBatch       = 1000
	maxDirectoryEntries = 100_000
)

var (
	canonicalSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	canonicalUUID   = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	canonicalObjectID = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
	)
	ErrUnsafeInventory = errors.New("unsafe orphan inventory")
)

type BlobCandidate struct {
	SHA256     string
	StorageKey string
	SizeBytes  int64
	ModifiedAt time.Time
	fileInfo   fs.FileInfo
}

type UploadCandidate struct {
	ID         string
	ModifiedAt time.Time
	fileInfo   fs.FileInfo
}

type StoredFileKind string

const (
	StoredFileReport    StoredFileKind = "report"
	StoredFileArtifact  StoredFileKind = "artifact"
	StoredFileDecompile StoredFileKind = "decompile"
)

var storedFileNamespaces = []struct {
	Kind      StoredFileKind
	Directory string
}{
	{Kind: StoredFileReport, Directory: "reports"},
	{Kind: StoredFileArtifact, Directory: "artifacts"},
	{Kind: StoredFileDecompile, Directory: "decompile"},
}

type StoredFileCandidate struct {
	Kind       StoredFileKind
	StorageKey string
	SHA256     string
	SizeBytes  int64
	ModifiedAt time.Time
	fileInfo   fs.FileInfo
}

type BlobReferenceCandidate struct {
	ID uint64
}

type BlobReferenceResult struct {
	Drifted       bool
	Corrected     bool
	PreviousCount uint64
	ActualCount   uint64
	PreviousState string
	CurrentState  string
}

type Diagnostic struct {
	Kind string
	Name string
	Err  error
}

type Report struct {
	BlobFilesScanned        int
	UploadDirsScanned       int
	StoredFilesScanned      int
	BlobReferencesScanned   int
	ReferencedBlobs         int
	ReferencedUploads       int
	ReferencedStoredFiles   int
	DriftedBlobReferences   int
	CorrectedBlobReferences int
	OrphanBlobs             int
	OrphanUploads           int
	OrphanStoredFiles       int
	RemovedBlobs            int
	RemovedUploads          int
	RemovedStoredFiles      int
	RecheckProtected        int
	DeferredYoungBlobs      int
	DeferredYoungUpload     int
	DeferredYoungStored     int
	Skipped                 int
	Failures                int
	DryRun                  bool
	Diagnostics             []Diagnostic
}

func (r *Report) addDiagnostic(kind string, name string, err error) {
	r.Skipped++
	r.Failures++
	r.Diagnostics = append(r.Diagnostics, Diagnostic{
		Kind: kind,
		Name: name,
		Err:  err,
	})
}

func validStoredFileCandidate(candidate StoredFileCandidate) bool {
	if candidate.SizeBytes < 0 || !canonicalSHA256.MatchString(candidate.SHA256) ||
		strings.Contains(candidate.StorageKey, `\`) ||
		path.Clean(candidate.StorageKey) != candidate.StorageKey {
		return false
	}
	for _, namespace := range storedFileNamespaces {
		if candidate.Kind == namespace.Kind {
			return strings.HasPrefix(
				candidate.StorageKey,
				namespace.Directory+"/",
			) && len(candidate.StorageKey) > len(namespace.Directory)+1
		}
	}
	return false
}
