package orphanreaper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ownershipMarkerName = ".binaryscan-owned"

var errStoredInventoryBatchFull = errors.New("stored-file inventory batch is full")

type inventory struct {
	repositoryPath      string
	repositoryInfo      fs.FileInfo
	uploadsPath         string
	uploadsInfo         fs.FileInfo
	blobPrefix          int
	blobCursor          string
	uploadCursor        string
	sourceProjectCursor string
	storedKind          int
	storedCursor        string
}

func (i *inventory) nextSourceProjects(
	ctx context.Context,
	limit int,
	cutoff time.Time,
) ([]SourceProjectCandidate, int, []Diagnostic, error) {
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return nil, 0, nil, err
	}
	defer root.Close()
	projects, err := openChildDirectory(root, "source-projects")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil, nil
	}
	if err != nil {
		return nil, 0, nil, fmt.Errorf("open source project inventory: %w", err)
	}
	defer projects.Close()
	entries, err := fs.ReadDir(projects.FS(), ".")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("list source project inventory: %w", err)
	}
	if len(entries) > maxDirectoryEntries {
		return nil, 0, nil, fmt.Errorf(
			"%w: source project root exceeds the entry limit", ErrUnsafeInventory,
		)
	}
	if len(entries) == 0 {
		i.sourceProjectCursor = ""
		return nil, 0, nil, nil
	}
	start := sort.Search(len(entries), func(index int) bool {
		return entries[index].Name() > i.sourceProjectCursor
	})
	if start == len(entries) {
		start = 0
	}
	count := limit
	if count > len(entries) {
		count = len(entries)
	}
	result := make([]SourceProjectCandidate, 0, count)
	diagnostics := make([]Diagnostic, 0)
	deferred := 0
	for offset := 0; offset < count; offset++ {
		if err := ctx.Err(); err != nil {
			return result, deferred, diagnostics, err
		}
		entry := entries[(start+offset)%len(entries)]
		name := entry.Name()
		i.sourceProjectCursor = name
		if name == ownershipMarkerName {
			continue
		}
		if !canonicalObjectID.MatchString(name) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "source-project", Name: name,
				Err: fmt.Errorf(
					"%w: non-canonical source project directory", ErrUnsafeInventory,
				),
			})
			continue
		}
		info, statErr := projects.Lstat(name)
		if statErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "source-project", Name: name, Err: statErr,
			})
			continue
		}
		if !realDirectory(info) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "source-project", Name: name,
				Err: fmt.Errorf(
					"%w: source project candidate is not a real directory",
					ErrUnsafeInventory,
				),
			})
			continue
		}
		if info.ModTime().After(cutoff) {
			deferred++
			continue
		}
		result = append(result, SourceProjectCandidate{
			ID: name, StorageKey: path.Join("source-projects", name),
			ModifiedAt: info.ModTime().UTC(), fileInfo: info,
		})
	}
	return result, deferred, diagnostics, nil
}

func newInventory(repositoryPath string, uploadsPath string) (*inventory, error) {
	repositoryInfo, err := snapshotRoot(repositoryPath, "repository")
	if err != nil {
		return nil, err
	}
	uploadsInfo, err := snapshotRoot(uploadsPath, "upload")
	if err != nil {
		return nil, err
	}
	return &inventory{
		repositoryPath: repositoryPath,
		repositoryInfo: repositoryInfo,
		uploadsPath:    uploadsPath,
		uploadsInfo:    uploadsInfo,
	}, nil
}

func snapshotRoot(path string, kind string) (fs.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		path == string(filepath.Separator) {
		return nil, fmt.Errorf("%s root must be a canonical absolute path below /", kind)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s root: %w", kind, err)
	}
	if !realDirectory(info) {
		return nil, fmt.Errorf("%w: %s root is not a real directory", ErrUnsafeInventory, kind)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open %s root: %w", kind, err)
	}
	opened, statErr := root.Stat(".")
	closeErr := root.Close()
	if statErr != nil || !realDirectory(opened) || !os.SameFile(info, opened) {
		return nil, errors.Join(
			statErr,
			fmt.Errorf("%w: %s root changed while opening", ErrUnsafeInventory, kind),
			closeErr,
		)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s root: %w", kind, closeErr)
	}
	return opened, nil
}

func reopenRoot(path string, expected fs.FileInfo, kind string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reinspect %s root: %w", kind, err)
	}
	if !realDirectory(info) || !os.SameFile(expected, info) {
		return nil, fmt.Errorf("%w: %s root was replaced", ErrUnsafeInventory, kind)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("reopen %s root: %w", kind, err)
	}
	opened, err := root.Stat(".")
	if err != nil || !realDirectory(opened) || !os.SameFile(expected, opened) {
		_ = root.Close()
		return nil, errors.Join(
			err,
			fmt.Errorf("%w: opened %s root was replaced", ErrUnsafeInventory, kind),
		)
	}
	return root, nil
}

func openChildDirectory(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !realDirectory(info) {
		return nil, fmt.Errorf("%w: %q is not a real directory", ErrUnsafeInventory, name)
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Stat(".")
	if err != nil || !realDirectory(opened) || !os.SameFile(info, opened) {
		_ = child.Close()
		return nil, errors.Join(
			err,
			fmt.Errorf("%w: directory %q changed while opening", ErrUnsafeInventory, name),
		)
	}
	return child, nil
}

func (i *inventory) nextBlobs(
	ctx context.Context,
	limit int,
	cutoff time.Time,
) ([]BlobCandidate, int, []Diagnostic, error) {
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return nil, 0, nil, err
	}
	defer root.Close()
	blobs, err := openChildDirectory(root, "blobs")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil, nil
	}
	if err != nil {
		return nil, 0, nil, fmt.Errorf("open blob inventory: %w", err)
	}
	defer blobs.Close()
	shaRoot, err := openChildDirectory(blobs, "sha256")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil, nil
	}
	if err != nil {
		return nil, 0, nil, fmt.Errorf("open SHA-256 inventory: %w", err)
	}
	defer shaRoot.Close()

	result := make([]BlobCandidate, 0, limit)
	diagnostics := make([]Diagnostic, 0)
	deferred := 0
	examined := 0
	for checkedPrefixes := 0; checkedPrefixes < 256 && examined < limit; checkedPrefixes++ {
		if err := ctx.Err(); err != nil {
			return result, deferred, diagnostics, err
		}
		prefix := fmt.Sprintf("%02x", i.blobPrefix)
		prefixRoot, openErr := openChildDirectory(shaRoot, prefix)
		if errors.Is(openErr, fs.ErrNotExist) {
			i.advanceBlobPrefix()
			continue
		}
		if openErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "blob-prefix", Name: prefix, Err: openErr,
			})
			i.advanceBlobPrefix()
			examined++
			continue
		}
		entries, readErr := fs.ReadDir(prefixRoot.FS(), ".")
		if readErr != nil {
			_ = prefixRoot.Close()
			return result, deferred, diagnostics, fmt.Errorf(
				"list blob prefix %s: %w", prefix, readErr,
			)
		}
		if len(entries) > maxDirectoryEntries {
			_ = prefixRoot.Close()
			return result, deferred, diagnostics, fmt.Errorf(
				"%w: blob prefix %s exceeds the entry limit", ErrUnsafeInventory, prefix,
			)
		}
		start := sort.Search(len(entries), func(index int) bool {
			return entries[index].Name() > i.blobCursor
		})
		for index := start; index < len(entries) && examined < limit; index++ {
			if err := ctx.Err(); err != nil {
				_ = prefixRoot.Close()
				return result, deferred, diagnostics, err
			}
			name := entries[index].Name()
			i.blobCursor = name
			examined++
			if !canonicalSHA256.MatchString(name) || !strings.HasPrefix(name, prefix) {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: "blob", Name: prefix + "/" + name,
					Err: fmt.Errorf("%w: non-canonical blob name", ErrUnsafeInventory),
				})
				continue
			}
			info, statErr := prefixRoot.Lstat(name)
			if statErr != nil {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: "blob", Name: name, Err: statErr,
				})
				continue
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: "blob", Name: name,
					Err: fmt.Errorf("%w: blob candidate is not a regular file", ErrUnsafeInventory),
				})
				continue
			}
			if info.ModTime().After(cutoff) {
				deferred++
				continue
			}
			result = append(result, BlobCandidate{
				SHA256:     name,
				StorageKey: filepath.ToSlash(filepath.Join("blobs", "sha256", prefix, name)),
				SizeBytes:  info.Size(), ModifiedAt: info.ModTime().UTC(), fileInfo: info,
			})
		}
		closeErr := prefixRoot.Close()
		if closeErr != nil {
			return result, deferred, diagnostics, fmt.Errorf(
				"close blob prefix %s: %w", prefix, closeErr,
			)
		}
		if start >= len(entries) || i.blobCursor == entries[len(entries)-1].Name() {
			i.advanceBlobPrefix()
		}
	}
	return result, deferred, diagnostics, nil
}

func (i *inventory) advanceBlobPrefix() {
	i.blobPrefix = (i.blobPrefix + 1) % 256
	i.blobCursor = ""
}

func (i *inventory) nextUploads(
	ctx context.Context,
	limit int,
	cutoff time.Time,
) ([]UploadCandidate, int, []Diagnostic, error) {
	root, err := reopenRoot(i.uploadsPath, i.uploadsInfo, "upload")
	if err != nil {
		return nil, 0, nil, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, 0, nil, fmt.Errorf("list upload inventory: %w", err)
	}
	filtered := entries[:0]
	for _, entry := range entries {
		if entry.Name() != ownershipMarkerName {
			filtered = append(filtered, entry)
		}
	}
	entries = filtered
	if len(entries) > maxDirectoryEntries {
		return nil, 0, nil, fmt.Errorf(
			"%w: upload root exceeds the entry limit", ErrUnsafeInventory,
		)
	}
	if len(entries) == 0 {
		i.uploadCursor = ""
		return nil, 0, nil, nil
	}
	start := sort.Search(len(entries), func(index int) bool {
		return entries[index].Name() > i.uploadCursor
	})
	if start == len(entries) {
		start = 0
	}
	count := limit
	if count > len(entries) {
		count = len(entries)
	}
	result := make([]UploadCandidate, 0, count)
	diagnostics := make([]Diagnostic, 0)
	deferred := 0
	for offset := 0; offset < count; offset++ {
		if err := ctx.Err(); err != nil {
			return result, deferred, diagnostics, err
		}
		entry := entries[(start+offset)%len(entries)]
		name := entry.Name()
		i.uploadCursor = name
		if !canonicalUUID.MatchString(name) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "upload", Name: name,
				Err: fmt.Errorf("%w: non-canonical upload directory", ErrUnsafeInventory),
			})
			continue
		}
		info, statErr := root.Lstat(name)
		if statErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "upload", Name: name, Err: statErr,
			})
			continue
		}
		if !realDirectory(info) {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: "upload", Name: name,
				Err: fmt.Errorf("%w: upload candidate is not a real directory", ErrUnsafeInventory),
			})
			continue
		}
		if info.ModTime().After(cutoff) {
			deferred++
			continue
		}
		result = append(result, UploadCandidate{
			ID: name, ModifiedAt: info.ModTime().UTC(), fileInfo: info,
		})
	}
	return result, deferred, diagnostics, nil
}

func (i *inventory) nextStoredFiles(
	ctx context.Context,
	limit int,
	cutoff time.Time,
) ([]StoredFileCandidate, int, []Diagnostic, error) {
	result := make([]StoredFileCandidate, 0, limit)
	diagnostics := make([]Diagnostic, 0)
	deferred := 0
	examined := 0
	for checked := 0; checked < len(storedFileNamespaces) && examined < limit; {
		namespace := storedFileNamespaces[i.storedKind]
		candidates, namespaceDeferred, namespaceDiagnostics, nextCursor,
			namespaceExamined, exhausted, err := i.scanStoredNamespace(
			ctx, namespace, limit-examined, cutoff, i.storedCursor,
		)
		result = append(result, candidates...)
		deferred += namespaceDeferred
		diagnostics = append(diagnostics, namespaceDiagnostics...)
		examined += namespaceExamined
		i.storedCursor = nextCursor
		if err != nil {
			return result, deferred, diagnostics, err
		}
		if !exhausted {
			break
		}
		i.storedKind = (i.storedKind + 1) % len(storedFileNamespaces)
		i.storedCursor = ""
		checked++
	}
	return result, deferred, diagnostics, nil
}

func (i *inventory) scanStoredNamespace(
	ctx context.Context,
	namespace struct {
		Kind      StoredFileKind
		Directory string
	},
	limit int,
	cutoff time.Time,
	cursor string,
) (
	[]StoredFileCandidate,
	int,
	[]Diagnostic,
	string,
	int,
	bool,
	error,
) {
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return nil, 0, nil, cursor, 0, false, err
	}
	defer root.Close()
	namespaceRoot, err := openChildDirectory(root, namespace.Directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil, cursor, 0, true, nil
	}
	if err != nil {
		return nil, 0, nil, cursor, 0, false, fmt.Errorf(
			"open %s inventory: %w", namespace.Directory, err,
		)
	}
	defer namespaceRoot.Close()

	candidates := make([]StoredFileCandidate, 0, limit)
	diagnostics := make([]Diagnostic, 0)
	deferred := 0
	examined := 0
	nextCursor := cursor
	walkErr := fs.WalkDir(namespaceRoot.FS(), ".", func(
		relative string,
		entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if entry.Name() == ownershipMarkerName {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			info, statErr := namespaceRoot.Lstat(relative)
			if statErr != nil {
				return statErr
			}
			if !realDirectory(info) {
				diagnostics = append(diagnostics, Diagnostic{
					Kind: string(namespace.Kind), Name: relative,
					Err: fmt.Errorf("%w: stored-file directory is unsafe", ErrUnsafeInventory),
				})
				return fs.SkipDir
			}
			return nil
		}
		if relative <= cursor {
			return nil
		}
		if examined >= limit {
			return errStoredInventoryBatchFull
		}
		nextCursor = relative
		examined++
		info, statErr := namespaceRoot.Lstat(relative)
		if statErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: string(namespace.Kind), Name: relative, Err: statErr,
			})
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: string(namespace.Kind), Name: relative,
				Err: fmt.Errorf("%w: stored-file candidate is not a regular file", ErrUnsafeInventory),
			})
			return nil
		}
		if info.ModTime().After(cutoff) {
			deferred++
			return nil
		}
		digest, hashErr := hashStoredFile(ctx, namespaceRoot, relative, info)
		if hashErr != nil {
			diagnostics = append(diagnostics, Diagnostic{
				Kind: string(namespace.Kind), Name: relative, Err: hashErr,
			})
			return nil
		}
		storageKey := path.Join(namespace.Directory, relative)
		kind := namespace.Kind
		if namespace.Kind == StoredFileReport {
			if _, _, staging := reportStagingIdentity(storageKey); staging {
				kind = StoredFileReportStaging
			}
		}
		candidates = append(candidates, StoredFileCandidate{
			Kind: kind, StorageKey: storageKey, SHA256: digest,
			SizeBytes: info.Size(), ModifiedAt: info.ModTime().UTC(), fileInfo: info,
		})
		return nil
	})
	if errors.Is(walkErr, errStoredInventoryBatchFull) {
		return candidates, deferred, diagnostics, nextCursor,
			limit, false, nil
	}
	if walkErr != nil {
		return candidates, deferred, diagnostics, nextCursor,
			examined, false, fmt.Errorf(
				"walk %s inventory: %w", namespace.Directory, walkErr,
			)
	}
	return candidates, deferred, diagnostics, nextCursor, examined, true, nil
}

func hashStoredFile(
	ctx context.Context,
	root *os.Root,
	name string,
	expected fs.FileInfo,
) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", fmt.Errorf("open stored-file candidate: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect opened stored-file candidate: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) ||
		opened.Size() != expected.Size() {
		return "", fmt.Errorf("%w: stored-file candidate changed while opening", ErrUnsafeInventory)
	}
	hasher := sha256.New()
	buffer := make([]byte, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			_, _ = hasher.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("hash stored-file candidate: %w", readErr)
		}
		if read == 0 {
			return "", errors.New("hash stored-file candidate made no progress")
		}
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return "", errors.Join(
			err,
			fmt.Errorf("%w: stored-file candidate changed while hashing", ErrUnsafeInventory),
		)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (i *inventory) revalidateBlob(candidate BlobCandidate) error {
	if candidate.fileInfo == nil {
		return fmt.Errorf("%w: blob inventory identity is missing", ErrUnsafeInventory)
	}
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return err
	}
	defer root.Close()
	blobs, err := openChildDirectory(root, "blobs")
	if err != nil {
		return fmt.Errorf("reopen blob inventory: %w", err)
	}
	defer blobs.Close()
	shaRoot, err := openChildDirectory(blobs, "sha256")
	if err != nil {
		return fmt.Errorf("reopen SHA-256 inventory: %w", err)
	}
	defer shaRoot.Close()
	prefixRoot, err := openChildDirectory(shaRoot, candidate.SHA256[:2])
	if err != nil {
		return fmt.Errorf("reopen blob prefix: %w", err)
	}
	defer prefixRoot.Close()
	current, err := prefixRoot.Lstat(candidate.SHA256)
	if err != nil {
		return fmt.Errorf("reinspect blob candidate: %w", err)
	}
	if !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		current.Size() != candidate.SizeBytes ||
		!os.SameFile(candidate.fileInfo, current) {
		return fmt.Errorf("%w: blob candidate changed before deletion", ErrUnsafeInventory)
	}
	return nil
}

func (i *inventory) revalidateUpload(candidate UploadCandidate) error {
	if candidate.fileInfo == nil {
		return fmt.Errorf("%w: upload inventory identity is missing", ErrUnsafeInventory)
	}
	root, err := reopenRoot(i.uploadsPath, i.uploadsInfo, "upload")
	if err != nil {
		return err
	}
	defer root.Close()
	current, err := root.Lstat(candidate.ID)
	if err != nil {
		return fmt.Errorf("reinspect upload candidate: %w", err)
	}
	if !realDirectory(current) || !os.SameFile(candidate.fileInfo, current) {
		return fmt.Errorf("%w: upload candidate changed before deletion", ErrUnsafeInventory)
	}
	return nil
}

func (i *inventory) revalidateSourceProject(
	candidate SourceProjectCandidate,
) error {
	if candidate.fileInfo == nil || !validSourceProjectCandidate(candidate) {
		return fmt.Errorf(
			"%w: source project inventory identity is missing", ErrUnsafeInventory,
		)
	}
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return err
	}
	defer root.Close()
	projects, err := openChildDirectory(root, "source-projects")
	if err != nil {
		return fmt.Errorf("reopen source project inventory: %w", err)
	}
	defer projects.Close()
	current, err := projects.Lstat(candidate.ID)
	if err != nil {
		return fmt.Errorf("reinspect source project candidate: %w", err)
	}
	if !realDirectory(current) || !os.SameFile(candidate.fileInfo, current) {
		return fmt.Errorf(
			"%w: source project candidate changed before deletion",
			ErrUnsafeInventory,
		)
	}
	return nil
}

func (i *inventory) deleteReportStaging(
	ctx context.Context,
	candidate StoredFileCandidate,
) (bool, error) {
	taskID, _, valid := reportStagingIdentity(candidate.StorageKey)
	if !valid || candidate.Kind != StoredFileReportStaging || candidate.fileInfo == nil {
		return false, fmt.Errorf(
			"%w: report staging inventory identity is missing", ErrUnsafeInventory,
		)
	}
	root, err := reopenRoot(i.repositoryPath, i.repositoryInfo, "repository")
	if err != nil {
		return false, err
	}
	defer root.Close()
	reports, err := openChildDirectory(root, "reports")
	if err != nil {
		return false, fmt.Errorf("reopen report staging inventory: %w", err)
	}
	defer reports.Close()
	taskReports, err := openChildDirectory(reports, taskID)
	if err != nil {
		return false, fmt.Errorf("reopen report staging task directory: %w", err)
	}
	defer taskReports.Close()

	name := path.Base(candidate.StorageKey)
	current, err := taskReports.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reinspect report staging candidate: %w", err)
	}
	if !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 ||
		current.Size() != candidate.SizeBytes ||
		!os.SameFile(candidate.fileInfo, current) {
		return false, fmt.Errorf(
			"%w: report staging candidate changed before deletion", ErrUnsafeInventory,
		)
	}
	digest, err := hashStoredFile(ctx, taskReports, name, current)
	if err != nil {
		return false, err
	}
	if digest != candidate.SHA256 {
		return false, fmt.Errorf(
			"%w: report staging content changed before deletion", ErrUnsafeInventory,
		)
	}
	latest, err := taskReports.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reinspect hashed report staging candidate: %w", err)
	}
	if !latest.Mode().IsRegular() || latest.Mode()&os.ModeSymlink != 0 ||
		latest.Size() != current.Size() || !os.SameFile(current, latest) {
		return false, fmt.Errorf(
			"%w: report staging candidate changed before removal", ErrUnsafeInventory,
		)
	}
	if err := taskReports.Remove(name); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("remove report staging candidate: %w", err)
	}
	return true, nil
}

func realDirectory(info fs.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
