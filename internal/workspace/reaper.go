package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	maxSweepBatch       = 1000
	ownershipMarkerName = ".binaryscan-owned"
	archiveImportRoot   = "archive-imports"
	ownershipMarkerSize = 37
	ownershipMarkerMode = 0o640
)

type LeaseChecker interface {
	WorkspaceLeaseActive(context.Context, Identity) (bool, error)
}

type Diagnostic struct {
	Name string
	Err  error
}

type SweepReport struct {
	Scanned     int
	Removed     int
	Active      int
	Skipped     int
	Diagnostics []Diagnostic
}

// Reaper conservatively removes only marked workspaces whose exact fenced
// lease is no longer active.
type Reaper struct {
	rootPath string
	rootInfo fs.FileInfo
	checker  LeaseChecker
	mu       sync.Mutex
	cursor   string
}

func NewReaper(rootPath string, checker LeaseChecker) (*Reaper, error) {
	if checker == nil {
		return nil, errors.New("workspace lease checker is required")
	}
	cleanRoot := filepath.Clean(rootPath)
	root, rootInfo, err := openVerifiedRoot(cleanRoot)
	if err != nil {
		return nil, err
	}
	if err := root.Close(); err != nil {
		return nil, fmt.Errorf("close verified workspace root: %w", err)
	}
	return &Reaper{
		rootPath: cleanRoot,
		rootInfo: rootInfo,
		checker:  checker,
	}, nil
}

func (r *Reaper) Sweep(
	ctx context.Context,
	limit int,
) (report SweepReport, returnErr error) {
	if limit < 1 || limit > maxSweepBatch {
		return SweepReport{}, errors.New(
			"workspace sweep limit must be between 1 and 1000",
		)
	}
	if err := ctx.Err(); err != nil {
		return SweepReport{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	root, rootInfo, err := openVerifiedRoot(r.rootPath)
	if err != nil {
		return SweepReport{}, err
	}
	if !os.SameFile(r.rootInfo, rootInfo) {
		return SweepReport{}, errors.Join(
			fmt.Errorf(
				"%w: workspace root was replaced",
				ErrUnsafeWorkspace,
			),
			root.Close(),
		)
	}
	defer func() {
		returnErr = errors.Join(returnErr, root.Close())
	}()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return SweepReport{}, fmt.Errorf("list workspace root: %w", err)
	}
	entries = filterTrustedRootMetadata(root, entries)
	selected := r.nextEntries(entries, limit)
	for _, entry := range selected {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.Scanned++
		r.cursor = entry.Name()
		candidate, err := inspectCandidate(root, entry.Name())
		if err != nil {
			report.addDiagnostic(entry.Name(), err)
			continue
		}
		active, err := r.checker.WorkspaceLeaseActive(ctx, candidate.identity)
		if err != nil {
			report.addDiagnostic(
				entry.Name(),
				fmt.Errorf("query workspace lease: %w", err),
			)
			continue
		}
		if active {
			report.Active++
			continue
		}
		rechecked, err := inspectCandidate(root, entry.Name())
		if err != nil {
			report.addDiagnostic(
				entry.Name(),
				fmt.Errorf("revalidate inactive workspace: %w", err),
			)
			continue
		}
		if rechecked.identity != candidate.identity ||
			!os.SameFile(candidate.directoryInfo, rechecked.directoryInfo) ||
			rechecked.markerPresent != candidate.markerPresent ||
			(candidate.markerPresent &&
				!os.SameFile(candidate.markerInfo, rechecked.markerInfo)) {
			report.addDiagnostic(
				entry.Name(),
				fmt.Errorf(
					"%w: workspace changed before removal",
					ErrUnsafeWorkspace,
				),
			)
			continue
		}
		if err := removeRootedTree(
			root,
			entry.Name(),
			rechecked.directoryInfo,
		); err != nil {
			report.addDiagnostic(
				entry.Name(),
				fmt.Errorf("remove inactive workspace: %w", err),
			)
			continue
		}
		if _, err := root.Lstat(entry.Name()); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = errors.New("workspace still exists")
			}
			report.addDiagnostic(
				entry.Name(),
				fmt.Errorf("verify inactive workspace removal: %w", err),
			)
			continue
		}
		report.Removed++
	}
	return report, nil
}

func (r *Reaper) nextEntries(entries []fs.DirEntry, limit int) []fs.DirEntry {
	if len(entries) == 0 {
		r.cursor = ""
		return nil
	}
	start := sort.Search(len(entries), func(index int) bool {
		return entries[index].Name() > r.cursor
	})
	if start == len(entries) {
		start = 0
	}
	count := limit
	if count > len(entries) {
		count = len(entries)
	}
	selected := make([]fs.DirEntry, 0, count)
	for index := 0; index < count; index++ {
		selected = append(selected, entries[(start+index)%len(entries)])
	}
	return selected
}

func (r *SweepReport) addDiagnostic(name string, err error) {
	r.Skipped++
	r.Diagnostics = append(r.Diagnostics, Diagnostic{Name: name, Err: err})
}

type inspectedCandidate struct {
	identity      Identity
	directoryInfo fs.FileInfo
	markerInfo    fs.FileInfo
	markerPresent bool
}

func inspectCandidate(
	root *os.Root,
	name string,
) (candidate inspectedCandidate, returnErr error) {
	if name == ownershipMarkerName {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: ownership marker is not a regular 0640 UUID-sized file",
			ErrInvalidMarker,
		)
	}
	nameIdentity, ok := identityFromWorkspaceName(name)
	if !ok {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: unrecognized workspace directory name",
			ErrInvalidMarker,
		)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return inspectedCandidate{}, fmt.Errorf(
			"inspect workspace candidate: %w", err,
		)
	}
	if !realDirectory(info) {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: candidate is not a 0700 real directory",
			ErrUnsafeWorkspace,
		)
	}
	workRoot, err := root.OpenRoot(name)
	if err != nil {
		return inspectedCandidate{}, fmt.Errorf(
			"open workspace candidate: %w", err,
		)
	}
	defer func() {
		returnErr = errors.Join(returnErr, workRoot.Close())
	}()
	openedInfo, err := workRoot.Stat(".")
	if err != nil || !realDirectory(openedInfo) ||
		!os.SameFile(info, openedInfo) {
		return inspectedCandidate{}, errors.Join(
			wrapOptional(err, "inspect opened workspace candidate"),
			fmt.Errorf(
				"%w: candidate changed while opening",
				ErrUnsafeWorkspace,
			),
		)
	}
	markerInfo, err := workRoot.Lstat(markerFileName)
	if errors.Is(err, fs.ErrNotExist) {
		// Creation publishes the marker by atomic rename. A missing marker is
		// therefore an interrupted create or RemoveAll, never a partial marker.
		// The strictly parsed directory name remains sufficient to perform the
		// exact fenced-lease check, while malformed existing markers stay
		// fail-closed below.
		return inspectedCandidate{
			identity: nameIdentity, directoryInfo: openedInfo,
		}, nil
	}
	if err != nil {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: inspect marker: %v", ErrInvalidMarker, err,
		)
	}
	if !exactMarkerFile(markerInfo) {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: marker is not a 0600 regular file",
			ErrInvalidMarker,
		)
	}
	file, err := workRoot.Open(markerFileName)
	if err != nil {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: open marker: %v", ErrInvalidMarker, err,
		)
	}
	openedMarkerInfo, statErr := file.Stat()
	if statErr != nil || !exactMarkerFile(openedMarkerInfo) ||
		!os.SameFile(markerInfo, openedMarkerInfo) {
		_ = file.Close()
		return inspectedCandidate{}, errors.Join(
			wrapOptional(statErr, "inspect opened workspace marker"),
			fmt.Errorf(
				"%w: marker changed while opening",
				ErrInvalidMarker,
			),
		)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxMarkerBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return inspectedCandidate{}, errors.Join(
			wrapOptional(readErr, "read workspace marker"),
			wrapOptional(closeErr, "close workspace marker"),
		)
	}
	if len(content) > maxMarkerBytes {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: marker exceeds size limit", ErrInvalidMarker,
		)
	}
	decoded, err := decodeMarker(content)
	if err != nil {
		return inspectedCandidate{}, err
	}
	if !markerMatches(content, decoded.Identity) ||
		decoded.Identity != nameIdentity {
		return inspectedCandidate{}, fmt.Errorf(
			"%w: marker does not match directory name",
			ErrInvalidMarker,
		)
	}
	return inspectedCandidate{
		identity: decoded.Identity, directoryInfo: openedInfo,
		markerInfo: openedMarkerInfo, markerPresent: true,
	}, nil
}

func filterTrustedRootMetadata(
	root *os.Root,
	entries []fs.DirEntry,
) []fs.DirEntry {
	filtered := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		// Archive imports use their own UUID/fence hierarchy and lifecycle
		// cleanup below the shared task-work root. It is not a queue workspace
		// and must never be interpreted (or removed) by this reaper.
		if entry.Name() == archiveImportRoot {
			info, err := root.Lstat(entry.Name())
			if err == nil && realDirectory(info) {
				continue
			}
		}
		if entry.Name() == ownershipMarkerName {
			info, err := root.Lstat(entry.Name())
			if err == nil && exactOwnershipMarker(info) {
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func exactOwnershipMarker(info fs.FileInfo) bool {
	return info != nil &&
		info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == ownershipMarkerMode &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Size() == ownershipMarkerSize
}

func decodeMarker(content []byte) (marker, error) {
	var decoded marker
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return marker{}, fmt.Errorf(
			"%w: decode marker: %v", ErrInvalidMarker, err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return marker{}, fmt.Errorf(
			"%w: marker has trailing data", ErrInvalidMarker,
		)
	}
	if decoded.Version != markerVersion {
		return marker{}, fmt.Errorf(
			"%w: unsupported marker version", ErrInvalidMarker,
		)
	}
	if err := decoded.Identity.Validate(); err != nil {
		return marker{}, fmt.Errorf("%w: %v", ErrInvalidMarker, err)
	}
	return decoded, nil
}
