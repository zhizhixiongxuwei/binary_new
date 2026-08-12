package decompile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"binaryscan/internal/taskcleanup"

	"golang.org/x/sys/unix"
)

const maxProjectStorageKeyBytes = 1024

// PublishedSourceProject is the immutable filesystem identity promoted with a
// completed analyzer run. Public API models live separately so storage keys
// never cross the HTTP boundary.
type PublishedSourceProject struct {
	ID                  string
	LayoutVersion       string
	SourceKind          string
	Language            string
	RootStorageKey      string
	CanonicalStorageKey string
	CanonicalSHA256     string
	CanonicalSizeBytes  uint64
	ManifestStorageKey  string
	ManifestSHA256      string
	ManifestSizeBytes   uint64
	SourceFileCount     int
	SymbolCount         int
	SourceSizeBytes     uint64
}

const (
	sourceProjectLayoutV1     = "project-v1"
	sourceProjectRootName     = "source-projects"
	sourceProjectManifestName = "manifest.json"
)

func sourceProjectRoot(runID string) string {
	return sourceProjectRootName + "/" + runID
}

func validPublishedSourceProject(
	runID string,
	project PublishedSourceProject,
	resultCount int,
) bool {
	root := sourceProjectRoot(runID)
	if !uuidPattern.MatchString(runID) || project.ID != runID ||
		project.LayoutVersion != sourceProjectLayoutV1 ||
		project.SourceKind == "" || len(project.SourceKind) > 32 ||
		project.Language == "" || len(project.Language) > 32 ||
		project.RootStorageKey != root ||
		project.ManifestStorageKey != path.Join(root, sourceProjectManifestName) ||
		!safeProjectStorageKey(project.ManifestStorageKey, root) ||
		!sha256Pattern.MatchString(project.ManifestSHA256) ||
		project.ManifestSizeBytes == 0 || project.SourceFileCount <= 0 ||
		project.SymbolCount != resultCount || resultCount <= 0 ||
		project.SourceSizeBytes == 0 {
		return false
	}
	hasCanonical := project.CanonicalStorageKey != "" ||
		project.CanonicalSHA256 != "" || project.CanonicalSizeBytes != 0
	if !hasCanonical {
		return project.CanonicalStorageKey == "" &&
			project.CanonicalSHA256 == "" && project.CanonicalSizeBytes == 0
	}
	return safeProjectStorageKey(project.CanonicalStorageKey, root) &&
		sha256Pattern.MatchString(project.CanonicalSHA256) &&
		project.CanonicalSizeBytes > 0
}

func validOptionalPublishedSourceProject(
	runID string,
	project PublishedSourceProject,
	results []BytecodePublishedResult,
) bool {
	hasStoredSource := false
	for _, result := range results {
		if result.StorageKey != "" {
			hasStoredSource = true
			break
		}
	}
	if !hasStoredSource {
		return project == (PublishedSourceProject{})
	}
	return validPublishedSourceProject(runID, project, len(results))
}

func safeProjectStorageKey(key string, root string) bool {
	return key != "" && len(key) <= maxProjectStorageKeyBytes &&
		!path.IsAbs(key) && path.Clean(key) == key &&
		!strings.Contains(key, `\`) && strings.HasPrefix(key, root+"/")
}

const maxSourceProjectPublicationDepth = 32

type sourceProjectPublication struct {
	repositoryRoot   string
	runID            string
	rootFD           int
	projectsFD       int
	projectFD        int
	rootIdentity     unix.Stat_t
	projectsIdentity unix.Stat_t
	projectIdentity  unix.Stat_t

	mu          sync.Mutex
	directories map[string]unix.Stat_t
	files       map[string]sourceProjectPublishedFile
	active      map[*sourceProjectPublicationFile]struct{}
	finalized   bool
	closed      bool
}

type sourceProjectPublishedFile struct {
	identity unix.Stat_t
	sha256   string
}

type sourceProjectPublicationFile struct {
	publication *sourceProjectPublication
	file        *os.File
	parentFD    int
	relative    string
	name        string
	hasher      hash.Hash
	closed      bool
}

func newSourceProjectPublication(
	repositoryRoot string,
	runID string,
) (_ *sourceProjectPublication, returnErr error) {
	if !uuidPattern.MatchString(runID) || !filepath.IsAbs(repositoryRoot) ||
		filepath.Clean(repositoryRoot) != repositoryRoot ||
		repositoryRoot == string(filepath.Separator) {
		return nil, errors.New("source project publication identity is invalid")
	}
	publication := &sourceProjectPublication{
		repositoryRoot: repositoryRoot,
		runID:          runID,
		rootFD:         -1,
		projectsFD:     -1,
		projectFD:      -1,
		directories:    make(map[string]unix.Stat_t),
		files:          make(map[string]sourceProjectPublishedFile),
		active:         make(map[*sourceProjectPublicationFile]struct{}),
	}
	projectCreated := false
	defer func() {
		if returnErr != nil {
			_ = publication.Close()
			if projectCreated {
				cleanupSourceProject(repositoryRoot, runID)
			}
		}
	}()

	var repositoryIdentity unix.Stat_t
	if err := unix.Lstat(repositoryRoot, &repositoryIdentity); err != nil ||
		repositoryIdentity.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.Join(
			err, errors.New("source project repository root is not a real directory"),
		)
	}
	rootFD, err := unix.Open(
		repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open source project repository root: %w", err)
	}
	publication.rootFD = rootFD
	if err := unix.Fstat(rootFD, &publication.rootIdentity); err != nil ||
		!sameSourceProjectDirectory(repositoryIdentity, publication.rootIdentity) {
		return nil, errors.Join(
			err, errors.New("source project repository root changed while opening"),
		)
	}

	projectsFD, projectsIdentity, created, err := openOrCreateProjectDirectory(
		rootFD, sourceProjectRootName, true,
	)
	if err != nil {
		return nil, fmt.Errorf("open source projects directory: %w", err)
	}
	publication.projectsFD = projectsFD
	publication.projectsIdentity = projectsIdentity
	if created {
		if err := syncSourceProjectDirectory(rootFD); err != nil {
			return nil, fmt.Errorf("sync source projects parent: %w", err)
		}
	}

	projectFD, projectIdentity, created, err := openOrCreateProjectDirectory(
		projectsFD, runID, false,
	)
	projectCreated = created
	if err != nil {
		return nil, fmt.Errorf("create source project directory: %w", err)
	}
	publication.projectFD = projectFD
	publication.projectIdentity = projectIdentity
	publication.directories[""] = projectIdentity
	if err := syncSourceProjectDirectory(projectsFD); err != nil {
		return nil, fmt.Errorf("sync source project parent: %w", err)
	}
	return publication, nil
}

func openOrCreateProjectDirectory(
	parentFD int,
	name string,
	allowExisting bool,
) (int, unix.Stat_t, bool, error) {
	created := false
	if err := unix.Mkdirat(parentFD, name, 0o700); err == nil {
		created = true
	} else if !allowExisting || !errors.Is(err, unix.EEXIST) {
		return -1, unix.Stat_t{}, false, err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return -1, unix.Stat_t{}, created, errors.Join(
			err, errors.New("source project path is not a real directory"),
		)
	}
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return -1, unix.Stat_t{}, created, err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil ||
		!sameSourceProjectDirectory(named, opened) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, created, errors.Join(
			err, errors.New("source project directory changed while opening"),
		)
	}
	return fd, opened, created, nil
}

func (publication *sourceProjectPublication) MkdirAll(relative string) error {
	if relative == "" || relative == "." {
		return nil
	}
	components, err := sourceProjectRelativeComponents(publication.runID, relative)
	if err != nil {
		return err
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.closed || publication.finalized {
		return errors.New("source project publication is closed")
	}
	currentFD, err := duplicateProjectDirectory(publication.projectFD)
	if err != nil {
		return err
	}
	defer func() {
		if currentFD >= 0 {
			_ = unix.Close(currentFD)
		}
	}()
	currentPath := ""
	for _, component := range components {
		currentPath = path.Join(currentPath, component)
		expected, known := publication.directories[currentPath]
		created := false
		if err := unix.Mkdirat(currentFD, component, 0o700); err == nil {
			created = true
		} else if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("create source project directory: %w", err)
		} else if !known {
			return errors.New("unexpected source project directory already exists")
		}
		var named unix.Stat_t
		if err := unix.Fstatat(
			currentFD, component, &named, unix.AT_SYMLINK_NOFOLLOW,
		); err != nil || named.Mode&unix.S_IFMT != unix.S_IFDIR {
			return errors.Join(
				err, errors.New("source project path is not a real directory"),
			)
		}
		nextFD, err := unix.Openat(
			currentFD, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return fmt.Errorf("open source project directory: %w", err)
		}
		var opened unix.Stat_t
		if err := unix.Fstat(nextFD, &opened); err != nil ||
			!sameSourceProjectDirectory(named, opened) ||
			(known && !sameSourceProjectDirectory(expected, opened)) {
			_ = unix.Close(nextFD)
			return errors.Join(
				err, errors.New("source project directory identity changed"),
			)
		}
		if created {
			if err := syncSourceProjectDirectory(currentFD); err != nil {
				_ = unix.Close(nextFD)
				return fmt.Errorf("sync source project directory parent: %w", err)
			}
			publication.directories[currentPath] = opened
		}
		closingFD := currentFD
		currentFD = -1
		if err := unix.Close(closingFD); err != nil {
			_ = unix.Close(nextFD)
			return err
		}
		currentFD = nextFD
	}
	return nil
}

func (publication *sourceProjectPublication) CreateFile(
	relative string,
) (*sourceProjectPublicationFile, error) {
	components, err := sourceProjectRelativeComponents(publication.runID, relative)
	if err != nil {
		return nil, err
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.closed || publication.finalized {
		return nil, errors.New("source project publication is closed")
	}
	if _, exists := publication.files[relative]; exists {
		return nil, errors.New("source project file already published")
	}
	parentFD, err := publication.openTrackedDirectoryLocked(components[:len(components)-1])
	if err != nil {
		return nil, err
	}
	name := components[len(components)-1]
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		_ = unix.Close(parentFD)
		return nil, fmt.Errorf("create source project file: %w", err)
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Close(parentFD)
		return nil, errors.New("wrap source project file descriptor")
	}
	value := &sourceProjectPublicationFile{
		publication: publication,
		file:        file,
		parentFD:    parentFD,
		relative:    relative,
		name:        name,
		hasher:      sha256.New(),
	}
	publication.active[value] = struct{}{}
	return value, nil
}

func (publication *sourceProjectPublication) openTrackedDirectoryLocked(
	components []string,
) (int, error) {
	currentFD, err := duplicateProjectDirectory(publication.projectFD)
	if err != nil {
		return -1, err
	}
	currentPath := ""
	for _, component := range components {
		currentPath = path.Join(currentPath, component)
		expected, found := publication.directories[currentPath]
		if !found {
			_ = unix.Close(currentFD)
			return -1, errors.New("source project parent directory was not created")
		}
		nextFD, err := unix.Openat(
			currentFD, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(currentFD)
		if err != nil {
			return -1, fmt.Errorf("open source project parent: %w", err)
		}
		var opened unix.Stat_t
		if err := unix.Fstat(nextFD, &opened); err != nil ||
			!sameSourceProjectDirectory(expected, opened) {
			_ = unix.Close(nextFD)
			return -1, errors.Join(
				err, errors.New("source project parent directory was replaced"),
			)
		}
		currentFD = nextFD
	}
	return currentFD, nil
}

func (file *sourceProjectPublicationFile) Write(value []byte) (int, error) {
	if file == nil || file.closed || file.file == nil {
		return 0, os.ErrClosed
	}
	written, err := file.file.Write(value)
	if written > 0 {
		_, _ = file.hasher.Write(value[:written])
	}
	if err == nil && written != len(value) {
		err = io.ErrShortWrite
	}
	return written, err
}

func (file *sourceProjectPublicationFile) Commit() error {
	if file == nil || file.file == nil || file.closed {
		return os.ErrClosed
	}
	if err := file.file.Sync(); err != nil {
		return err
	}
	var opened unix.Stat_t
	if err := unix.Fstat(int(file.file.Fd()), &opened); err != nil ||
		opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Nlink != 1 ||
		opened.Mode&0o077 != 0 {
		return errors.Join(
			err, errors.New("published source project file identity is invalid"),
		)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(
		file.parentFD, file.name, &named, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil || !sameSourceProjectFile(opened, named) {
		return errors.Join(
			err, errors.New("published source project file was replaced"),
		)
	}
	if err := file.file.Close(); err != nil {
		file.file = nil
		return err
	}
	file.file = nil
	if err := syncSourceProjectDirectory(file.parentFD); err != nil {
		return err
	}
	if err := unix.Close(file.parentFD); err != nil {
		file.parentFD = -1
		return err
	}
	file.parentFD = -1
	file.closed = true
	file.publication.mu.Lock()
	defer file.publication.mu.Unlock()
	delete(file.publication.active, file)
	file.publication.files[file.relative] = sourceProjectPublishedFile{
		identity: opened,
		sha256:   hex.EncodeToString(file.hasher.Sum(nil)),
	}
	return nil
}

func (file *sourceProjectPublicationFile) Close() error {
	if file == nil || file.closed {
		return nil
	}
	file.closed = true
	var result error
	if file.file != nil {
		result = errors.Join(result, file.file.Close())
		file.file = nil
	}
	if file.parentFD >= 0 {
		result = errors.Join(result, unix.Close(file.parentFD))
		file.parentFD = -1
	}
	if file.publication != nil {
		file.publication.mu.Lock()
		delete(file.publication.active, file)
		file.publication.mu.Unlock()
	}
	return result
}

func (publication *sourceProjectPublication) Finalize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.closed {
		return errors.New("source project publication is closed")
	}
	if publication.finalized {
		return nil
	}
	if len(publication.active) != 0 || len(publication.files) == 0 {
		return errors.New("source project publication has uncommitted files")
	}
	fileNames := make([]string, 0, len(publication.files))
	for relative := range publication.files {
		fileNames = append(fileNames, relative)
	}
	sort.Strings(fileNames)
	for _, relative := range fileNames {
		if err := publication.verifyFileLocked(
			ctx, relative, publication.files[relative],
		); err != nil {
			return err
		}
	}
	directoryNames := make([]string, 0, len(publication.directories))
	for relative := range publication.directories {
		directoryNames = append(directoryNames, relative)
	}
	sort.Slice(directoryNames, func(left, right int) bool {
		leftDepth := sourceProjectPathDepth(directoryNames[left])
		rightDepth := sourceProjectPathDepth(directoryNames[right])
		if leftDepth != rightDepth {
			return leftDepth > rightDepth
		}
		return directoryNames[left] < directoryNames[right]
	})
	for _, relative := range directoryNames {
		if err := publication.verifyAndSyncDirectoryLocked(relative); err != nil {
			return err
		}
	}
	if err := syncSourceProjectDirectory(publication.projectsFD); err != nil {
		return fmt.Errorf("sync source projects directory: %w", err)
	}
	if err := syncSourceProjectDirectory(publication.rootFD); err != nil {
		return fmt.Errorf("sync source project repository root: %w", err)
	}
	if err := publication.verifyNamedChainLocked(); err != nil {
		return err
	}
	publication.finalized = true
	return nil
}

func (publication *sourceProjectPublication) verifyFileLocked(
	ctx context.Context,
	relative string,
	expected sourceProjectPublishedFile,
) error {
	components := strings.Split(relative, "/")
	parentFD, err := publication.openTrackedDirectoryLocked(
		components[:len(components)-1],
	)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	name := components[len(components)-1]
	var named unix.Stat_t
	if err := unix.Fstatat(
		parentFD, name, &named, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil || !sameSourceProjectFile(expected.identity, named) {
		return errors.Join(
			err, errors.New("published source project file changed before commit"),
		)
	}
	fd, err := unix.Openat(
		parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return fmt.Errorf("reopen published source project file: %w", err)
	}
	opened := os.NewFile(uintptr(fd), relative)
	if opened == nil {
		_ = unix.Close(fd)
		return errors.New("wrap published source project file descriptor")
	}
	defer opened.Close()
	var openedIdentity unix.Stat_t
	if err := unix.Fstat(fd, &openedIdentity); err != nil ||
		!sameSourceProjectFile(expected.identity, openedIdentity) {
		return errors.Join(
			err, errors.New("published source project file identity changed"),
		)
	}
	hasher := sha256.New()
	written, err := io.Copy(
		hasher,
		io.LimitReader(
			&contextReader{ctx: ctx, reader: opened},
			expected.identity.Size+1,
		),
	)
	if err != nil || written != expected.identity.Size ||
		hex.EncodeToString(hasher.Sum(nil)) != expected.sha256 {
		return errors.Join(
			err, errors.New("published source project file content changed"),
		)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		!sameSourceProjectFile(expected.identity, after) {
		return errors.Join(
			err, errors.New("published source project file changed while verifying"),
		)
	}
	return nil
}

func (publication *sourceProjectPublication) verifyAndSyncDirectoryLocked(
	relative string,
) error {
	components := []string{}
	if relative != "" {
		components = strings.Split(relative, "/")
	}
	fd, err := publication.openTrackedDirectoryLocked(components)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil ||
		!sameSourceProjectDirectory(publication.directories[relative], opened) {
		return errors.Join(
			err, errors.New("source project directory changed before commit"),
		)
	}
	if err := syncSourceProjectDirectory(fd); err != nil {
		return fmt.Errorf("sync source project directory: %w", err)
	}
	return nil
}

func (publication *sourceProjectPublication) verifyNamedChainLocked() error {
	var namedRoot unix.Stat_t
	if err := unix.Lstat(publication.repositoryRoot, &namedRoot); err != nil ||
		!sameSourceProjectDirectory(publication.rootIdentity, namedRoot) {
		return errors.Join(
			err, errors.New("source project repository root was replaced"),
		)
	}
	rootFD, err := unix.Open(
		publication.repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("reopen source project repository root: %w", err)
	}
	defer unix.Close(rootFD)
	var openedRoot unix.Stat_t
	if err := unix.Fstat(rootFD, &openedRoot); err != nil ||
		!sameSourceProjectDirectory(publication.rootIdentity, openedRoot) {
		return errors.Join(
			err, errors.New("source project repository root identity changed"),
		)
	}
	projectsFD, err := unix.Openat(
		rootFD, sourceProjectRootName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("reopen source projects directory: %w", err)
	}
	defer unix.Close(projectsFD)
	var projectsIdentity unix.Stat_t
	if err := unix.Fstat(projectsFD, &projectsIdentity); err != nil ||
		!sameSourceProjectDirectory(publication.projectsIdentity, projectsIdentity) {
		return errors.Join(
			err, errors.New("source projects directory was replaced"),
		)
	}
	projectFD, err := unix.Openat(
		projectsFD, publication.runID,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("reopen source project directory: %w", err)
	}
	defer unix.Close(projectFD)
	var projectIdentity unix.Stat_t
	if err := unix.Fstat(projectFD, &projectIdentity); err != nil ||
		!sameSourceProjectDirectory(publication.projectIdentity, projectIdentity) {
		return errors.Join(
			err, errors.New("source project directory was replaced"),
		)
	}
	if err := syncSourceProjectDirectory(projectFD); err != nil {
		return err
	}
	if err := syncSourceProjectDirectory(projectsFD); err != nil {
		return err
	}
	return syncSourceProjectDirectory(rootFD)
}

func (publication *sourceProjectPublication) Close() error {
	if publication == nil {
		return nil
	}
	publication.mu.Lock()
	if publication.closed {
		publication.mu.Unlock()
		return nil
	}
	publication.closed = true
	active := make([]*sourceProjectPublicationFile, 0, len(publication.active))
	for file := range publication.active {
		active = append(active, file)
	}
	publication.mu.Unlock()
	var result error
	for _, file := range active {
		result = errors.Join(result, file.Close())
	}
	publication.mu.Lock()
	defer publication.mu.Unlock()
	for _, fd := range []*int{
		&publication.projectFD, &publication.projectsFD, &publication.rootFD,
	} {
		if *fd >= 0 {
			result = errors.Join(result, unix.Close(*fd))
			*fd = -1
		}
	}
	return result
}

func duplicateProjectDirectory(fd int) (int, error) {
	duplicate, err := unix.Openat(
		fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return -1, fmt.Errorf("duplicate source project directory: %w", err)
	}
	return duplicate, nil
}

func sourceProjectRelativeComponents(runID string, relative string) ([]string, error) {
	if relative == "" || path.IsAbs(relative) || path.Clean(relative) != relative ||
		strings.Contains(relative, `\`) || strings.ContainsRune(relative, 0) ||
		len(sourceProjectRoot(runID))+1+len(relative) > maxProjectStorageKeyBytes {
		return nil, errors.New("source project relative path is invalid")
	}
	components := strings.Split(relative, "/")
	if len(components) > maxSourceProjectPublicationDepth {
		return nil, errors.New("source project relative path is too deep")
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			len(component) > 255 {
			return nil, errors.New("source project path component is invalid")
		}
	}
	return components, nil
}

func sameSourceProjectDirectory(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode == right.Mode && left.Mode&unix.S_IFMT == unix.S_IFDIR &&
		right.Mode&unix.S_IFMT == unix.S_IFDIR
}

func sameSourceProjectFile(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode == right.Mode && left.Size == right.Size &&
		left.Nlink == 1 && right.Nlink == 1 &&
		left.Mode&unix.S_IFMT == unix.S_IFREG &&
		right.Mode&unix.S_IFMT == unix.S_IFREG
}

func sourceProjectPathDepth(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, "/") + 1
}

func syncSourceProjectDirectory(fd int) error {
	err := unix.Fsync(fd)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	return err
}

func cleanupSourceProject(repositoryRoot string, runID string) {
	deleter, err := taskcleanup.NewRepositoryFileDeleter(repositoryRoot)
	if err != nil {
		return
	}
	_ = deleter.DeleteScope(context.Background(), taskcleanup.Scope{
		Kind: taskcleanup.FileSourceProject, TaskID: runID, RecordID: runID,
	})
}
