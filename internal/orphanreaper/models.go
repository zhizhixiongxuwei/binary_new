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
	canonicalStagingNonce = regexp.MustCompile(`^[0-9a-f]{24}$`)
	ErrUnsafeInventory    = errors.New("unsafe orphan inventory")
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

type SourceProjectCandidate struct {
	ID         string
	StorageKey string
	ModifiedAt time.Time
	fileInfo   fs.FileInfo
}

type PendingSourceProject struct {
	ID            string
	TaskID        string
	LayoutVersion string
}

type SourceProjectCleanupTarget struct {
	ProjectID       string
	TaskID          string
	LayoutVersion   string
	LegacyResultIDs []string
}

type StoredFileKind string

const (
	StoredFileReport        StoredFileKind = "report"
	StoredFileReportStaging StoredFileKind = "report-staging"
	StoredFileArtifact      StoredFileKind = "artifact"
	StoredFileDecompile     StoredFileKind = "decompile"
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
	BlobFilesScanned           int
	UploadDirsScanned          int
	SourceProjectDirsScanned   int
	StoredFilesScanned         int
	BlobReferencesScanned      int
	ReferencedBlobs            int
	ReferencedUploads          int
	ReferencedSourceProjects   int
	ReferencedStoredFiles      int
	DriftedBlobReferences      int
	CorrectedBlobReferences    int
	OrphanBlobs                int
	OrphanUploads              int
	OrphanSourceProjects       int
	OrphanStoredFiles          int
	RemovedBlobs               int
	RemovedUploads             int
	RemovedSourceProjects      int
	RemovedStoredFiles         int
	PendingSourceProjects      int
	CompletedSourceProjects    int
	RecheckProtected           int
	DeferredYoungBlobs         int
	DeferredYoungUpload        int
	DeferredYoungSourceProject int
	DeferredYoungStored        int
	Skipped                    int
	Failures                   int
	DryRun                     bool
	Diagnostics                []Diagnostic
}

func validSourceProjectCandidate(candidate SourceProjectCandidate) bool {
	return canonicalObjectID.MatchString(candidate.ID) &&
		candidate.StorageKey == path.Join("source-projects", candidate.ID)
}

func validPendingSourceProject(candidate PendingSourceProject) bool {
	if !canonicalObjectID.MatchString(candidate.ID) ||
		!canonicalObjectID.MatchString(candidate.TaskID) {
		return false
	}
	return candidate.LayoutVersion == "project-v1" ||
		candidate.LayoutVersion == "legacy-v1"
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
	if candidate.Kind == StoredFileReportStaging {
		_, _, valid := reportStagingIdentity(candidate.StorageKey)
		return valid
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

func reportStagingIdentity(storageKey string) (string, string, bool) {
	components := strings.Split(storageKey, "/")
	if len(components) != 3 || components[0] != "reports" ||
		!canonicalObjectID.MatchString(components[1]) {
		return "", "", false
	}
	name := components[2]
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".staging") {
		return "", "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".staging")
	separator := strings.LastIndexByte(body, '.')
	if separator < 0 {
		return "", "", false
	}
	reportID := body[:separator]
	nonce := body[separator+1:]
	if !canonicalObjectID.MatchString(reportID) ||
		!canonicalStagingNonce.MatchString(nonce) {
		return "", "", false
	}
	return components[1], reportID, true
}
