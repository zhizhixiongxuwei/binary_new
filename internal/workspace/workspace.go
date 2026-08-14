package workspace

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	markerVersion         = 1
	markerFileName        = ".binaryscan-workspace.json"
	pendingMarkerFileName = ".binaryscan-workspace.json.pending"
	maxMarkerBytes        = 4096
	randomNameBytes       = 16
)

var (
	ErrInvalidIdentity = errors.New("invalid workspace identity")
	ErrUnsafeWorkspace = errors.New("unsafe workspace")
	ErrInvalidMarker   = errors.New("invalid workspace marker")

	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	workspaceNamePattern = regexp.MustCompile(
		`^scan-` +
			`[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}-` +
			`[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}-` +
			`[1-9][0-9]*-[1-9][0-9]*-(scan|trivy|image|decompile|c_analysis|java_analysis|python_analysis)-[a-f0-9]{32}$`,
	)
)

// Identity binds a workspace to one fenced job attempt.
type Identity struct {
	JobID         string `json:"job_id"`
	TaskID        string `json:"task_id"`
	TaskAttemptID uint64 `json:"task_attempt_id"`
	FencingToken  uint64 `json:"fencing_token"`
	Kind          string `json:"kind"`
}

func (i Identity) Validate() error {
	if !uuidPattern.MatchString(i.JobID) ||
		!uuidPattern.MatchString(i.TaskID) ||
		i.TaskAttemptID == 0 ||
		i.FencingToken == 0 ||
		(i.Kind != "scan" && i.Kind != "trivy" &&
			i.Kind != "image" && i.Kind != "decompile" &&
			i.Kind != "c_analysis" && i.Kind != "java_analysis" &&
			i.Kind != "python_analysis") {
		return ErrInvalidIdentity
	}
	return nil
}

type marker struct {
	Version int `json:"version"`
	Identity
}

// Directory is a private worker workspace anchored to an opened root.
type Directory struct {
	mu            sync.Mutex
	root          *os.Root
	name          string
	path          string
	directoryInfo fs.FileInfo
	closed        bool
}

// Create creates a random 0700 worker directory with an exact 0600 identity
// marker. The returned Directory owns an open descriptor for the work root.
func Create(rootPath string, identity Identity) (*Directory, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	cleanRoot := filepath.Clean(rootPath)
	root, _, err := openVerifiedRoot(cleanRoot)
	if err != nil {
		return nil, err
	}

	name, directoryInfo, err := createDirectory(root, identity)
	if err != nil {
		var cleanupErr error
		if name != "" && directoryInfo != nil {
			cleanupErr = removeRootedTree(root, name, directoryInfo)
		}
		return nil, errors.Join(
			err,
			wrapOptional(cleanupErr, "remove incomplete workspace"),
			root.Close(),
		)
	}
	if err := writeMarker(root, name, identity, directoryInfo); err != nil {
		cleanupErr := removeRootedTree(root, name, directoryInfo)
		return nil, errors.Join(
			err,
			wrapOptional(cleanupErr, "remove incomplete workspace"),
			root.Close(),
		)
	}
	return &Directory{
		root: root, name: name,
		path: filepath.Join(cleanRoot, name), directoryInfo: directoryInfo,
	}, nil
}

func (d *Directory) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// Cleanup removes only the original direct child of the anchored task-work
// root. A replaced path is left untouched and reported.
func (d *Directory) Cleanup() error {
	if d == nil {
		return errors.New("cleanup nil workspace")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true

	info, err := d.root.Lstat(d.name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return errors.Join(
			fmt.Errorf(
				"%w: workspace disappeared before cleanup",
				ErrUnsafeWorkspace,
			),
			d.root.Close(),
		)
	case err != nil:
		return errors.Join(
			fmt.Errorf("inspect workspace before cleanup: %w", err),
			d.root.Close(),
		)
	case !realDirectory(info) || !os.SameFile(d.directoryInfo, info):
		return errors.Join(
			fmt.Errorf("%w: workspace path was replaced", ErrUnsafeWorkspace),
			d.root.Close(),
		)
	}
	opened, err := d.root.OpenRoot(d.name)
	if err != nil {
		return errors.Join(
			fmt.Errorf("open workspace before cleanup: %w", err),
			d.root.Close(),
		)
	}
	openedInfo, statErr := opened.Stat(".")
	closeErr := opened.Close()
	if statErr != nil || !realDirectory(openedInfo) ||
		!os.SameFile(info, openedInfo) {
		return errors.Join(
			wrapOptional(statErr, "inspect opened workspace before cleanup"),
			fmt.Errorf("%w: workspace changed before cleanup", ErrUnsafeWorkspace),
			closeErr,
			d.root.Close(),
		)
	}
	if closeErr != nil {
		return errors.Join(
			fmt.Errorf("close inspected workspace: %w", closeErr),
			d.root.Close(),
		)
	}
	if err := removeRootedTree(
		d.root,
		d.name,
		d.directoryInfo,
	); err != nil {
		return errors.Join(
			fmt.Errorf("remove workspace: %w", err),
			d.root.Close(),
		)
	}
	if _, err := d.root.Lstat(d.name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			err = errors.New("workspace still exists")
		}
		return errors.Join(
			fmt.Errorf("verify workspace cleanup: %w", err),
			d.root.Close(),
		)
	}
	return d.root.Close()
}

func createDirectory(
	root *os.Root,
	identity Identity,
) (name string, directoryInfo fs.FileInfo, returnErr error) {
	parent, err := root.Open(".")
	if err != nil {
		return "", nil, fmt.Errorf(
			"open workspace root for directory creation: %w",
			err,
		)
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapOptional(parent.Close(), "close workspace creation root"),
		)
	}()

	prefix := directoryPrefix(identity)
	for attempt := 0; attempt < 10; attempt++ {
		random := make([]byte, randomNameBytes)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return "", nil, fmt.Errorf("generate workspace name: %w", err)
		}
		candidateName := prefix + hex.EncodeToString(random)
		if err := root.Mkdir(candidateName, 0o700); errors.Is(err, fs.ErrExist) {
			continue
		} else if err != nil {
			return "", nil, fmt.Errorf("create workspace directory: %w", err)
		}
		name = candidateName
		info, err := root.Lstat(name)
		if err != nil {
			return name, nil, fmt.Errorf("inspect workspace directory: %w", err)
		}
		if !nonSymlinkDirectory(info) {
			return name, info, fmt.Errorf(
				"%w: new workspace path is not a real directory",
				ErrUnsafeWorkspace,
			)
		}
		preparedInfo, err := prepareCreatedDirectory(parent, name, info)
		if err != nil {
			return name, info, err
		}
		return name, preparedInfo, nil
	}
	return "", nil, errors.New("allocate unique workspace name")
}

func prepareCreatedDirectory(
	parent *os.File,
	name string,
	expected fs.FileInfo,
) (directoryInfo fs.FileInfo, returnErr error) {
	opened, err := openDirectoryAt(parent, name)
	if err != nil {
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf(
				"%w: created workspace path was replaced",
				ErrUnsafeWorkspace,
			)
		}
		return nil, fmt.Errorf("open created workspace directory: %w", err)
	}
	defer func() {
		returnErr = errors.Join(
			returnErr,
			wrapOptional(opened.Close(), "close created workspace directory"),
		)
	}()

	beforeChmod, err := opened.Stat()
	if err != nil || !nonSymlinkDirectory(beforeChmod) ||
		expected == nil || !os.SameFile(expected, beforeChmod) {
		return nil, errors.Join(
			wrapOptional(err, "inspect created workspace before chmod"),
			fmt.Errorf(
				"%w: created workspace changed before chmod",
				ErrUnsafeWorkspace,
			),
		)
	}
	if err := unix.Fchmod(int(opened.Fd()), 0o700); err != nil {
		return nil, fmt.Errorf("chmod created workspace directory: %w", err)
	}
	afterChmod, err := opened.Stat()
	if err != nil || !realDirectory(afterChmod) ||
		!os.SameFile(expected, afterChmod) ||
		!os.SameFile(beforeChmod, afterChmod) {
		return nil, errors.Join(
			wrapOptional(err, "inspect created workspace after chmod"),
			fmt.Errorf(
				"%w: created workspace changed during chmod",
				ErrUnsafeWorkspace,
			),
		)
	}
	return afterChmod, nil
}

func writeMarker(
	root *os.Root,
	name string,
	identity Identity,
	expectedDirectory fs.FileInfo,
) (returnErr error) {
	workRoot, err := root.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("open workspace for marker: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, workRoot.Close())
	}()
	directory, err := workRoot.Open(".")
	if err != nil {
		return fmt.Errorf("open workspace directory for marker publish: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, directory.Close())
	}()
	directoryInfo, err := directory.Stat()
	if err != nil || !realDirectory(directoryInfo) ||
		!os.SameFile(expectedDirectory, directoryInfo) {
		return errors.Join(
			wrapOptional(err, "inspect workspace marker publish directory"),
			fmt.Errorf("%w: marker publish directory changed", ErrUnsafeWorkspace),
		)
	}
	content, err := canonicalMarker(identity)
	if err != nil {
		return err
	}
	file, err := workRoot.OpenFile(
		pendingMarkerFileName,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create workspace marker: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set workspace marker permissions: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return fmt.Errorf("write workspace marker: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync workspace marker: %w", err)
	}
	pendingInfo, err := file.Stat()
	if err != nil || !exactMarkerFile(pendingInfo) {
		_ = file.Close()
		return errors.Join(
			wrapOptional(err, "inspect pending workspace marker"),
			fmt.Errorf("%w: pending workspace marker changed", ErrUnsafeWorkspace),
		)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close workspace marker: %w", err)
	}
	if err := unix.Renameat(
		int(directory.Fd()),
		pendingMarkerFileName,
		int(directory.Fd()),
		markerFileName,
	); err != nil {
		return fmt.Errorf("publish workspace marker: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync published workspace marker directory: %w", err)
	}
	info, err := workRoot.Lstat(markerFileName)
	if err != nil {
		return fmt.Errorf("inspect workspace marker: %w", err)
	}
	if !exactMarkerFile(info) || !os.SameFile(pendingInfo, info) {
		return fmt.Errorf(
			"%w: published workspace marker changed",
			ErrUnsafeWorkspace,
		)
	}
	return nil
}

func canonicalMarker(identity Identity) ([]byte, error) {
	content, err := json.Marshal(marker{
		Version:  markerVersion,
		Identity: identity,
	})
	if err != nil {
		return nil, fmt.Errorf("encode workspace marker: %w", err)
	}
	return append(content, '\n'), nil
}

func directoryPrefix(identity Identity) string {
	return fmt.Sprintf(
		"scan-%s-%s-%d-%d-%s-",
		identity.JobID,
		identity.TaskID,
		identity.TaskAttemptID,
		identity.FencingToken,
		identity.Kind,
	)
}

func openVerifiedRoot(rootPath string) (*os.Root, fs.FileInfo, error) {
	if !filepath.IsAbs(rootPath) ||
		rootPath == string(filepath.Separator) {
		return nil, nil, errors.New(
			"workspace root must be an absolute non-root path",
		)
	}
	info, err := os.Lstat(rootPath)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect workspace root: %w", err)
	}
	if !nonSymlinkDirectory(info) {
		return nil, nil, errors.New("workspace root is not a real directory")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open workspace root: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, fmt.Errorf("inspect opened workspace root: %w", err)
	}
	if !nonSymlinkDirectory(openedInfo) || !os.SameFile(info, openedInfo) {
		_ = root.Close()
		return nil, nil, fmt.Errorf(
			"%w: workspace root changed while opening",
			ErrUnsafeWorkspace,
		)
	}
	return root, openedInfo, nil
}

func realDirectory(info fs.FileInfo) bool {
	return nonSymlinkDirectory(info) &&
		info.Mode().Perm() == 0o700 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func nonSymlinkDirectory(info fs.FileInfo) bool {
	return info != nil && info.IsDir() &&
		info.Mode()&os.ModeSymlink == 0
}

func exactMarkerFile(info fs.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == 0o600 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Size() > 0 && info.Size() <= maxMarkerBytes
}

func wrapOptional(err error, operation string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func markerMatches(content []byte, identity Identity) bool {
	expected, err := canonicalMarker(identity)
	return err == nil && bytes.Equal(content, expected)
}

func safeWorkspaceName(name string) bool {
	return workspaceNamePattern.MatchString(name) &&
		!strings.ContainsAny(name, `/\`)
}

func identityFromWorkspaceName(name string) (Identity, bool) {
	if !safeWorkspaceName(name) {
		return Identity{}, false
	}
	parts := strings.Split(name, "-")
	if len(parts) != 15 {
		return Identity{}, false
	}
	taskAttemptID, err := strconv.ParseUint(parts[11], 10, 64)
	if err != nil {
		return Identity{}, false
	}
	fencingToken, err := strconv.ParseUint(parts[12], 10, 64)
	if err != nil {
		return Identity{}, false
	}
	identity := Identity{
		JobID:         strings.Join(parts[1:6], "-"),
		TaskID:        strings.Join(parts[6:11], "-"),
		TaskAttemptID: taskAttemptID,
		FencingToken:  fencingToken,
		Kind:          parts[13],
	}
	if err := identity.Validate(); err != nil {
		return Identity{}, false
	}
	return identity, true
}
