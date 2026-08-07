package extract

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxLogicalPathBytes = 2048
	maxPathPartBytes    = 255
)

var (
	errInvalidArchivePath = errors.New("invalid archive path")
	errArchiveRootEntry   = errors.New("archive root entry")
)

func ensureWorkDirectory(workDir string) error {
	if workDir == "" {
		return errors.New("extract: empty work directory")
	}
	if !filepath.IsAbs(workDir) {
		return errors.New("extract: work directory must be absolute")
	}
	info, err := os.Lstat(workDir)
	if err != nil {
		return fmt.Errorf("extract: stat work directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("extract: work path is not a real directory")
	}
	return nil
}

func logicalPath(prefix, archivePath string, directory bool) (string, string, error) {
	relative, err := validateArchivePath(archivePath, directory)
	if err != nil {
		return "", "", err
	}
	logical := "/" + relative
	if prefix != "" {
		logical = prefix + "/" + relative
	}
	if len(logical) > maxLogicalPathBytes || path.Clean(logical) != logical ||
		logical == "/" || !strings.HasPrefix(logical, "/") {
		return "", "", errInvalidArchivePath
	}
	return logical, path.Base(relative), nil
}

func validateArchivePath(value string, directory bool) (string, error) {
	if len(value) > maxLogicalPathBytes {
		return "", errInvalidArchivePath
	}
	if directory {
		value = strings.TrimSuffix(value, "/")
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	if value == "." || value == "" {
		if directory {
			return "", errArchiveRootEntry
		}
		return "", errInvalidArchivePath
	}
	if !utf8.ValidString(value) || strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") {
		return "", errInvalidArchivePath
	}
	for _, current := range value {
		if current == 0 || unicode.IsControl(current) {
			return "", errInvalidArchivePath
		}
	}
	parts := strings.Split(value, "/")
	for index, part := range parts {
		if part == "" || part == "." || part == ".." ||
			len(part) > maxPathPartBytes {
			return "", errInvalidArchivePath
		}
		if index == 0 && len(part) >= 2 &&
			((part[0] >= 'a' && part[0] <= 'z') ||
				(part[0] >= 'A' && part[0] <= 'Z')) &&
			part[1] == ':' {
			return "", errInvalidArchivePath
		}
	}
	if path.Clean(value) != value {
		return "", errInvalidArchivePath
	}
	return value, nil
}

func (state *operationState) appendRejectedPath(
	rawPath string,
	parentID int,
	prefix string,
	_ int,
) error {
	boundedRaw := boundedText(rawPath, maxLogicalPathBytes)
	location, locationErr := state.uniqueQuarantineLocation(
		parentID,
		"rejected",
	)
	if locationErr != nil {
		return locationErr
	}
	state.reserveLogicalPath(location.logical)
	metadata := map[string]any{
		"archive_path":           boundedRaw,
		"archive_path_truncated": boundedRaw != rawPath,
	}
	if prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	_, err := state.appendNode(Node{
		ParentLocalID:          location.parentID,
		SourceContainerLocalID: parentID,
		LogicalPath:            location.logical,
		DisplayName:            "rejected-entry",
		ArchiveNameID:          archiveNameID(rawPath),
		NodeType:               NodeTypeSpecial,
		Depth:                  location.depth,
		ExtractionStatus:       StatusInvalidPath,
		MetadataJSON:           metadataJSON(metadata),
		ErrorCode:              "invalid_archive_path",
		ErrorMessage:           "archive entry path was rejected",
	})
	state.partial = true
	return err
}

type entryLocation struct {
	logical                string
	display                string
	parentID               int
	depth                  int
	directoryNode          int
	collision              *namespaceCollision
	archiveNameID          string
	sourceContainerLocalID int
}

type namespaceCollision struct {
	archivePath          string
	containerPath        string
	duplicateLogicalPath string
	collisionPath        string
	reason               string
	errorCode            string
}

type quarantineLocation struct {
	logical  string
	parentID int
	depth    int
}

func (state *operationState) prepareEntry(
	prefix string,
	archivePath string,
	directory bool,
	containerParentID int,
	containerParentDepth int,
) (entryLocation, bool, error) {
	return state.prepareEntryWithMode(
		prefix,
		archivePath,
		directory,
		containerParentID,
		containerParentDepth,
		false,
	)
}

func (state *operationState) prepareEntryWithNameSuffix(
	prefix string,
	archivePath string,
	directory bool,
	containerParentID int,
	containerParentDepth int,
) (entryLocation, bool, error) {
	return state.prepareEntryWithMode(
		prefix,
		archivePath,
		directory,
		containerParentID,
		containerParentDepth,
		true,
	)
}

func (state *operationState) prepareEntryWithMode(
	prefix string,
	archivePath string,
	directory bool,
	containerParentID int,
	containerParentDepth int,
	suffixNameCollision bool,
) (
	location entryLocation,
	prepared bool,
	returnErr error,
) {
	identity := archiveNameID(archivePath)
	defer func() {
		location.archiveNameID = identity
		location.sourceContainerLocalID = containerParentID
	}()
	relative, err := validateArchivePath(archivePath, directory)
	if errors.Is(err, errArchiveRootEntry) {
		return entryLocation{}, false, nil
	}
	if err != nil {
		return state.prepareInvalidArchivePathEntry(
			prefix,
			archivePath,
			"unsafe_archive_path",
			directory,
			containerParentID,
		)
	}
	relative = norm.NFC.String(relative)
	if _, err := validateArchivePath(relative, directory); err != nil {
		return state.prepareInvalidArchivePathEntry(
			prefix,
			archivePath,
			"normalized_archive_path_invalid",
			directory,
			containerParentID,
		)
	}
	originalLogical, display, err := logicalPath(prefix, relative, directory)
	if err != nil {
		return state.prepareInvalidArchivePathEntry(
			prefix,
			archivePath,
			"logical_path_overflow",
			directory,
			containerParentID,
		)
	}
	parts := strings.Split(relative, "/")
	directoryParts := parts[:len(parts)-1]
	if directory {
		directoryParts = parts
	}
	parentID := containerParentID
	parentDepth := containerParentDepth
	currentPrefix := prefix
	directoryIndex := -1
	for _, part := range directoryParts {
		logical := "/" + part
		if currentPrefix != "" {
			logical = currentPrefix + "/" + part
		}
		if len(logical) > maxLogicalPathBytes || path.Clean(logical) != logical {
			return entryLocation{}, false, errInvalidArchivePath
		}
		if state.logicalPathReserved(logical) {
			return state.prepareNamespaceCollisionEntry(
				prefix,
				archivePath,
				originalLogical,
				logical,
				display,
				directory,
				containerParentID,
				containerParentDepth,
			)
		}
		if existingID, found := state.directories[logical]; found {
			existing := state.nodeByLocalID(existingID)
			if existing == nil {
				return entryLocation{}, false, errors.New("extract: directory index is inconsistent")
			}
			parentID = existingID
			parentDepth = existing.Depth
			currentPrefix = logical
			directoryIndex = state.nodeIndex[existingID]
			continue
		}
		if _, occupied := state.paths[logical]; occupied {
			return state.prepareNamespaceCollisionEntry(
				prefix,
				archivePath,
				originalLogical,
				logical,
				display,
				directory,
				containerParentID,
				containerParentDepth,
			)
		}
		if parentDepth >= state.engine.limits.MaxDepth {
			state.markDepthLimit(parentID)
			return entryLocation{}, false, nil
		}
		index, appendErr := state.appendNode(Node{
			ParentLocalID:          parentID,
			SourceContainerLocalID: containerParentID,
			LogicalPath:            logical,
			DisplayName:            part,
			NodeType:               NodeTypeDirectory,
			Depth:                  parentDepth + 1,
			ExtractionStatus:       StatusRecorded,
			MetadataJSON: metadataJSON(map[string]any{
				"synthetic": true,
			}),
		})
		if appendErr != nil {
			return entryLocation{}, false, appendErr
		}
		parentID = state.nodes[index].LocalID
		parentDepth = state.nodes[index].Depth
		currentPrefix = logical
		directoryIndex = index
	}
	if directory {
		return entryLocation{
			logical:       currentPrefix,
			display:       parts[len(parts)-1],
			parentID:      parentID,
			depth:         parentDepth,
			directoryNode: directoryIndex,
		}, true, nil
	}
	if parentDepth >= state.engine.limits.MaxDepth {
		state.markDepthLimit(parentID)
		return entryLocation{}, false, nil
	}
	logical := "/" + parts[len(parts)-1]
	if currentPrefix != "" {
		logical = currentPrefix + "/" + parts[len(parts)-1]
	}
	if len(logical) > maxLogicalPathBytes || path.Clean(logical) != logical {
		return entryLocation{}, false, errInvalidArchivePath
	}
	if state.logicalPathReserved(logical) {
		return state.prepareNamespaceCollisionEntry(
			prefix,
			archivePath,
			originalLogical,
			logical,
			display,
			false,
			containerParentID,
			containerParentDepth,
		)
	}
	if _, occupied := state.paths[logical]; occupied &&
		suffixNameCollision &&
		len(logical)+1+maxPathPartBytes <= maxLogicalPathBytes {
		collision, collisionPrepared, collisionErr :=
			state.prepareArchiveNameCollisionEntry(
				prefix,
				archivePath,
				originalLogical,
				logical,
				parts[len(parts)-1],
				parentID,
				parentDepth+1,
			)
		if collisionErr == nil {
			return collision, collisionPrepared, nil
		}
		if !errors.Is(collisionErr, errInvalidArchivePath) {
			return entryLocation{}, false, collisionErr
		}
	}
	return entryLocation{
		logical:       logical,
		display:       parts[len(parts)-1],
		parentID:      parentID,
		depth:         parentDepth + 1,
		directoryNode: -1,
	}, true, nil
}

func (state *operationState) prepareArchiveNameCollisionEntry(
	prefix string,
	archivePath string,
	duplicateLogicalPath string,
	collisionPath string,
	display string,
	parentID int,
	depth int,
) (entryLocation, bool, error) {
	parentPath := path.Dir(collisionPath)
	if parentPath == "/" {
		parentPath = ""
	}
	digest := sha256.Sum256([]byte(archivePath))
	stem := hex.EncodeToString(digest[:4])
	var (
		logical string
		name    string
	)
	for occurrence := 1; ; occurrence++ {
		suffix := "~" + stem
		if occurrence > 1 {
			suffix += fmt.Sprintf("-%d", occurrence)
		}
		available := maxPathPartBytes
		if parentPath != "" {
			pathAvailable := maxLogicalPathBytes - len(parentPath) - 1
			if pathAvailable < available {
				available = pathAvailable
			}
		} else if maxLogicalPathBytes-1 < available {
			available = maxLogicalPathBytes - 1
		}
		if available <= len(suffix) {
			return entryLocation{}, false, errInvalidArchivePath
		}
		name = truncateUTF8Bytes(display, available-len(suffix)) + suffix
		if name == suffix || len(name) > maxPathPartBytes {
			return entryLocation{}, false, errInvalidArchivePath
		}
		logical = "/" + name
		if parentPath != "" {
			logical = parentPath + "/" + name
		}
		if _, exists := state.paths[logical]; exists {
			continue
		}
		if state.logicalPathReserved(logical) {
			continue
		}
		break
	}
	errorCode := "duplicate_archive_name"
	reason := "duplicate_archive_name"
	if previous := state.archiveNames[collisionPath]; previous != "" &&
		previous != archiveNameID(archivePath) {
		errorCode = "unicode_normalization_collision"
		reason = "unicode_normalization_collision"
	}
	return entryLocation{
		logical:       logical,
		display:       name,
		parentID:      parentID,
		depth:         depth,
		directoryNode: -1,
		collision: &namespaceCollision{
			archivePath:          archivePath,
			containerPath:        prefix,
			duplicateLogicalPath: duplicateLogicalPath,
			collisionPath:        collisionPath,
			reason:               reason,
			errorCode:            errorCode,
		},
	}, true, nil
}

func (state *operationState) prepareNamespaceCollisionEntry(
	prefix string,
	archivePath string,
	duplicateLogicalPath string,
	collisionPath string,
	display string,
	directory bool,
	containerParentID int,
	_ int,
) (entryLocation, bool, error) {
	quarantine, err := state.uniqueQuarantineLocation(
		containerParentID,
		"namespace_collision",
	)
	if err != nil {
		return entryLocation{}, false, err
	}
	state.reserveLogicalPath(quarantine.logical)
	location := entryLocation{
		logical:       quarantine.logical,
		display:       display,
		parentID:      quarantine.parentID,
		depth:         quarantine.depth,
		directoryNode: -1,
		collision: &namespaceCollision{
			archivePath:          archivePath,
			containerPath:        prefix,
			duplicateLogicalPath: duplicateLogicalPath,
			collisionPath:        collisionPath,
		},
	}
	if !directory {
		return location, true, nil
	}

	index, err := state.appendNode(Node{
		ParentLocalID:          quarantine.parentID,
		SourceContainerLocalID: containerParentID,
		LogicalPath:            quarantine.logical,
		DisplayName:            display,
		NodeType:               NodeTypeDirectory,
		Depth:                  quarantine.depth,
		ExtractionStatus:       StatusRecorded,
		MetadataJSON: metadataJSON(map[string]any{
			"synthetic": true,
		}),
	})
	if err != nil {
		return entryLocation{}, false, err
	}
	location.directoryNode = index
	return location, true, nil
}

func (state *operationState) prepareInvalidArchivePathEntry(
	prefix string,
	archivePath string,
	reason string,
	directory bool,
	containerParentID int,
) (entryLocation, bool, error) {
	quarantine, err := state.uniqueQuarantineLocation(
		containerParentID,
		"rejected",
	)
	if err != nil {
		return entryLocation{}, false, err
	}
	state.reserveLogicalPath(quarantine.logical)
	location := entryLocation{
		logical:       quarantine.logical,
		display:       path.Base(quarantine.logical),
		parentID:      quarantine.parentID,
		depth:         quarantine.depth,
		directoryNode: -1,
		collision: &namespaceCollision{
			archivePath:   archivePath,
			containerPath: prefix,
			reason:        reason,
			errorCode:     "invalid_archive_path",
		},
	}
	if !directory {
		return location, true, nil
	}

	index, err := state.appendNode(Node{
		ParentLocalID:          quarantine.parentID,
		SourceContainerLocalID: containerParentID,
		LogicalPath:            quarantine.logical,
		DisplayName:            path.Base(quarantine.logical),
		NodeType:               NodeTypeDirectory,
		Depth:                  quarantine.depth,
		ExtractionStatus:       StatusRecorded,
		MetadataJSON: metadataJSON(map[string]any{
			"synthetic": true,
		}),
	})
	if err != nil {
		return entryLocation{}, false, err
	}
	location.directoryNode = index
	return location, true, nil
}

func (state *operationState) applyNamespaceCollision(
	location entryLocation,
	node *Node,
	metadata map[string]any,
) {
	node.ArchiveNameID = location.archiveNameID
	node.SourceContainerLocalID = location.sourceContainerLocalID
	if location.collision == nil {
		return
	}
	archivePath := boundedText(
		location.collision.archivePath,
		maxLogicalPathBytes,
	)
	metadata["archive_path"] = archivePath
	metadata["archive_path_truncated"] =
		archivePath != location.collision.archivePath
	if location.collision.containerPath != "" {
		metadata["archive_container_path"] =
			location.collision.containerPath
	}
	if location.collision.duplicateLogicalPath != "" {
		metadata["duplicate_logical_path"] =
			location.collision.duplicateLogicalPath
	}
	if location.collision.collisionPath != "" {
		metadata["namespace_collision_path"] =
			location.collision.collisionPath
	}
	if location.collision.reason != "" {
		metadata["reason"] = location.collision.reason
	}
	node.MetadataJSON = metadataJSON(metadata)
	state.partial = true
	if node.ErrorCode != "" {
		return
	}
	node.ExtractionStatus = StatusInvalidPath
	if location.collision.errorCode != "" {
		node.ErrorCode = location.collision.errorCode
		node.ErrorMessage =
			"archive entry path was safely remapped"
		return
	}
	node.ErrorCode = "namespace_collision"
	node.ErrorMessage =
		"archive entry namespace collision was safely remapped"
}

func archiveNameID(value string) string {
	raw := []byte(value)
	if len(raw) <= maxLogicalPathBytes {
		return "b64:" + base64.StdEncoding.EncodeToString(raw)
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func truncateUTF8Bytes(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	if len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value
}

func (state *operationState) uniqueQuarantineLocation(
	startParentID int,
	kind string,
) (quarantineLocation, error) {
	parentID := startParentID
	for {
		prefix, parentDepth, nextParentID, err :=
			state.quarantineParent(parentID)
		if err != nil {
			return quarantineLocation{}, err
		}
		if parentDepth < state.engine.limits.MaxDepth {
			for suffix := 0; ; suffix++ {
				name, nameErr := quarantineName(
					kind,
					state.nextID,
					suffix,
				)
				if nameErr != nil {
					break
				}
				logical := "/" + name
				if prefix != "" {
					logical = prefix + "/" + name
				}
				if len(logical) > maxLogicalPathBytes {
					break
				}
				if path.Clean(logical) != logical {
					return quarantineLocation{}, errInvalidArchivePath
				}
				if _, exists := state.paths[logical]; exists {
					continue
				}
				if state.logicalPathReserved(logical) {
					continue
				}
				return quarantineLocation{
					logical:  logical,
					parentID: parentID,
					depth:    parentDepth + 1,
				}, nil
			}
		}
		if parentID == 0 {
			return quarantineLocation{}, errInvalidArchivePath
		}
		parentID = nextParentID
	}
}

func (state *operationState) quarantineParent(
	parentID int,
) (prefix string, depth int, nextParentID int, err error) {
	if parentID == 0 {
		return "", 0, 0, nil
	}
	parent := state.nodeByLocalID(parentID)
	if parent == nil {
		return "", 0, 0, errors.New(
			"extract: quarantine parent index is inconsistent",
		)
	}
	return parent.LogicalPath, parent.Depth, parent.ParentLocalID, nil
}

func quarantineName(
	kind string,
	localID int,
	suffix int,
) (string, error) {
	var stem string
	switch kind {
	case "duplicate":
		stem = "__duplicate_entry_"
	case "namespace_collision":
		stem = "__namespace_collision_entry_"
	case "rejected":
		stem = "__rejected_entry_"
	case "corrupt":
		stem = "__corrupt_entry_"
	case "unsupported":
		stem = "__unsupported_entry_"
	case "ar_diagnostic":
		stem = "__ar_diagnostic_"
	case "deb_extended":
		stem = "__deb_extended_member_"
	case "deb_duplicate":
		stem = "__deb_duplicate_member_"
	default:
		return "", errInvalidArchivePath
	}
	name := fmt.Sprintf("%s%d", stem, localID)
	if suffix > 0 {
		name = fmt.Sprintf("%s_%d", name, suffix)
	}
	if len(name) > maxPathPartBytes {
		return "", errInvalidArchivePath
	}
	return name, nil
}

func (state *operationState) reserveLogicalPath(logical string) {
	if state.reservedPaths == nil {
		state.reservedPaths = make(map[string]struct{})
	}
	state.reservedPaths[logical] = struct{}{}
}

func (state *operationState) logicalPathReserved(logical string) bool {
	_, reserved := state.reservedPaths[logical]
	return reserved
}

func (state *operationState) markDepthLimit(parentID int) {
	state.markLimit(LimitMaxDepth)
	if parent := state.nodeByLocalID(parentID); parent != nil {
		parent.ExtractionStatus = StatusDepthLimited
		parent.ErrorCode = LimitMaxDepth
		parent.ErrorMessage = "child path exceeds configured depth limit"
	}
}

func boundedText(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	if maximum <= 0 || len(value) <= maximum {
		return value
	}
	value = value[:maximum]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value
}

func pathDirectory(logical string) string {
	directory := path.Dir(logical)
	if directory == "." || !strings.HasPrefix(directory, "/") {
		return "/"
	}
	return directory
}
