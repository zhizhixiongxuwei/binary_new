package extract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	arGlobalHeaderSize       = int64(8)
	arMemberHeaderSize       = int64(60)
	maxARMembers             = uint64(100_000)
	maxARMemberHeadersBytes  = int64(maxARMembers) * arMemberHeaderSize
	maxARStringTableBytes    = int64(16 << 20)
	maxARMemberNameBytes     = maxLogicalPathBytes
	maxDEBVersionBytes       = int64(4 << 10)
	arReadChunkBytes         = 32 << 10
	arProfileGeneric         = "ar"
	arProfileDeb             = "deb"
	arMemberNameEncodingSysV = "sysv"
	arMemberNameEncodingGNU  = "gnu"
	arMemberNameEncodingBSD  = "bsd"
)

var (
	arGlobalMagic       = []byte("!<arch>\n")
	errInvalidARArchive = errors.New("invalid ar archive")
)

type arMemberHeader struct {
	rawName   string
	timestamp uint64
	uid       uint64
	gid       uint64
	mode      uint64
	size      int64
}

type arResolvedMember struct {
	name          string
	originalName  string
	nameEncoding  string
	dataOffset    int64
	dataSize      int64
	symbolTable   bool
	quarantine    *quarantineLocation
	nameErrorCode string
	nameError     error
}

type debMemberRole string

const (
	debRoleNone    debMemberRole = ""
	debRoleVersion debMemberRole = "debian-binary"
	debRoleControl debMemberRole = "control"
	debRoleData    debMemberRole = "data"
)

type debProfileState struct {
	requiredRoleCount int
	canonicalVersion  bool
	seen              map[debMemberRole]int
}

type debMemberObservation struct {
	role    debMemberRole
	code    string
	message string
}

func (state *operationState) extractAR(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	return state.extractARProfile(
		source,
		sourceSize,
		parentID,
		prefix,
		parentDepth,
		budget,
		arProfileGeneric,
	)
}

func (state *operationState) extractDEB(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
) error {
	return state.extractARProfile(
		source,
		sourceSize,
		parentID,
		prefix,
		parentDepth,
		budget,
		arProfileDeb,
	)
}

func (state *operationState) extractARProfile(
	source *os.File,
	sourceSize int64,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
	profile string,
) error {
	if source == nil || sourceSize < arGlobalHeaderSize {
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			profile+"_archive_corrupt",
			errInvalidARArchive,
		)
	}
	var magic [arGlobalHeaderSize]byte
	if err := readARAt(
		state.ctx,
		source,
		sourceSize,
		magic[:],
		0,
	); err != nil || !bytes.Equal(magic[:], arGlobalMagic) {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err == nil {
			err = fmt.Errorf("%w: invalid global magic", errInvalidARArchive)
		}
		return state.appendCorruptArchiveNode(
			parentID,
			prefix,
			parentDepth+1,
			profile+"_archive_corrupt",
			err,
		)
	}

	var stringTable []byte
	releaseStringTable := func() {}
	defer func() {
		releaseStringTable()
	}()
	var debState *debProfileState
	if profile == arProfileDeb {
		debState = &debProfileState{
			seen: make(map[debMemberRole]int, 3),
		}
	}

	offset := arGlobalHeaderSize
	var memberCount uint64
	var headerBytes int64
	for offset < sourceSize {
		if err := state.ctx.Err(); err != nil {
			return err
		}
		if state.stopped {
			return &limitError{code: state.limitCode, global: true}
		}
		if memberCount >= maxARMembers ||
			headerBytes > maxARMemberHeadersBytes-arMemberHeaderSize {
			limit := &limitError{code: LimitMaxArchiveMetadata}
			state.markLimit(limit.code)
			return limit
		}
		if sourceSize-offset < arMemberHeaderSize {
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				profile+"_header_corrupt",
				fmt.Errorf("%w: truncated member header", errInvalidARArchive),
			)
		}

		var encodedHeader [arMemberHeaderSize]byte
		if err := readARAt(
			state.ctx,
			source,
			sourceSize,
			encodedHeader[:],
			offset,
		); err != nil {
			return err
		}
		memberCount++
		headerBytes += arMemberHeaderSize
		header, err := parseARMemberHeader(encodedHeader[:])
		if err != nil {
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				profile+"_header_corrupt",
				err,
			)
		}

		bodyOffset := offset + arMemberHeaderSize
		bodyEnd, nextOffset, err := validateARMemberRange(
			state.ctx,
			source,
			sourceSize,
			bodyOffset,
			header.size,
		)
		if err != nil {
			if errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return state.appendCorruptArchiveNode(
				parentID,
				prefix,
				parentDepth+1,
				profile+"_member_truncated",
				err,
			)
		}

		switch header.rawName {
		case "//":
			if profile == arProfileDeb {
				if err := state.appendARDiagnostic(
					parentID,
					prefix,
					parentDepth+1,
					StatusCorrupt,
					"deb_extended_name_not_allowed",
					"DEB permits only common ar member names",
					map[string]any{"archive": profile, "encoding": "gnu"},
				); err != nil {
					return err
				}
			}
			if stringTable != nil {
				if err := state.appendARDiagnostic(
					parentID,
					prefix,
					parentDepth+1,
					StatusCorrupt,
					"ar_duplicate_string_table",
					"duplicate GNU ar string table was ignored",
					map[string]any{"archive": profile},
				); err != nil {
					return err
				}
				offset = nextOffset
				continue
			}
			if header.size > maxARStringTableBytes {
				limit := &limitError{code: LimitMaxArchiveMetadata}
				state.markLimit(limit.code)
				return limit
			}
			release, memoryLimit := state.memory.acquire(
				header.size,
				LimitMaxArchiveMetadata,
			)
			if memoryLimit != nil {
				state.markLimit(memoryLimit.code)
				return memoryLimit
			}
			table := make([]byte, int(header.size))
			if err := readARAt(
				state.ctx,
				source,
				sourceSize,
				table,
				bodyOffset,
			); err != nil {
				release()
				return err
			}
			stringTable = table
			releaseStringTable = release
			offset = nextOffset
			continue
		}

		resolved := resolveARMember(
			state.ctx,
			source,
			sourceSize,
			header,
			bodyOffset,
			bodyEnd,
			stringTable,
		)
		if errors.Is(resolved.nameError, context.Canceled) ||
			errors.Is(resolved.nameError, context.DeadlineExceeded) {
			return resolved.nameError
		}
		if profile == arProfileDeb && resolved.symbolTable {
			if err := state.appendARDiagnostic(
				parentID,
				prefix,
				parentDepth+1,
				StatusCorrupt,
				"deb_unexpected_member",
				"DEB does not permit ar symbol-table pseudo-members",
				map[string]any{
					"archive":       profile,
					"pseudo_member": "symbol_table",
				},
			); err != nil {
				return err
			}
			offset = nextOffset
			continue
		}
		if resolved.nameError != nil {
			quarantine, err := state.uniqueQuarantineLocation(
				parentID,
				"ar_diagnostic",
			)
			if err != nil {
				return err
			}
			state.reserveLogicalPath(quarantine.logical)
			resolved.quarantine = &quarantine
			if err := state.extractARMember(
				source,
				header,
				resolved,
				parentID,
				prefix,
				parentDepth,
				budget,
				profile,
				debMemberObservation{},
			); err != nil {
				return err
			}
			offset = nextOffset
			continue
		}
		if resolved.symbolTable {
			if err := state.appendARDiagnostic(
				parentID,
				prefix,
				parentDepth+1,
				StatusRecorded,
				"ar_symbol_table_skipped",
				"ar symbol table pseudo-member was not extracted",
				map[string]any{
					"archive":        profile,
					"declared_bytes": resolved.dataSize,
					"pseudo_member":  "symbol_table",
				},
			); err != nil {
				return err
			}
			offset = nextOffset
			continue
		}

		observation := debMemberObservation{}
		if debState != nil {
			if resolved.nameEncoding != arMemberNameEncodingSysV {
				observation = debMemberObservation{
					role:    classifyDEBMember(resolved.name),
					code:    "deb_extended_name_not_allowed",
					message: "DEB permits only common ar member names",
				}
				resolved.originalName = resolved.name
				quarantine, err := state.uniqueQuarantineLocation(
					parentID,
					"deb_extended",
				)
				if err != nil {
					return err
				}
				state.reserveLogicalPath(quarantine.logical)
				resolved.quarantine = &quarantine
			} else {
				observation = debState.observe(resolved.name)
			}
			if observation.code == "deb_duplicate_member" {
				resolved.originalName = resolved.name
				quarantine, err := state.uniqueQuarantineLocation(
					parentID,
					"deb_duplicate",
				)
				if err != nil {
					return err
				}
				state.reserveLogicalPath(quarantine.logical)
				resolved.quarantine = &quarantine
			}
		}
		if err := state.extractARMember(
			source,
			header,
			resolved,
			parentID,
			prefix,
			parentDepth,
			budget,
			profile,
			observation,
		); err != nil {
			return err
		}
		offset = nextOffset
	}

	if err := state.ctx.Err(); err != nil {
		return err
	}
	if debState != nil {
		return state.appendMissingDEBMembers(
			debState,
			parentID,
			prefix,
			parentDepth+1,
		)
	}
	return nil
}

func (state *operationState) extractARMember(
	source *os.File,
	header arMemberHeader,
	member arResolvedMember,
	parentID int,
	prefix string,
	parentDepth int,
	budget *containerBudget,
	profile string,
	observation debMemberObservation,
) error {
	var (
		location entryLocation
		prepared bool
		pathErr  error
	)
	if member.quarantine != nil {
		location = entryLocation{
			logical:       member.quarantine.logical,
			display:       path.Base(member.quarantine.logical),
			parentID:      member.quarantine.parentID,
			depth:         member.quarantine.depth,
			directoryNode: -1,
		}
		prepared = true
	} else {
		location, prepared, pathErr = state.prepareEntry(
			prefix,
			member.name,
			false,
			parentID,
			parentDepth,
		)
	}
	if pathErr != nil {
		return state.appendRejectedPath(
			member.name,
			parentID,
			prefix,
			parentDepth+1,
		)
	}
	if !prepared {
		return nil
	}
	metadata := map[string]any{
		"archive":          profile,
		"declared_bytes":   member.dataSize,
		"header_bytes":     header.size,
		"mode":             header.mode,
		"uid":              header.uid,
		"gid":              header.gid,
		"modified_unix":    header.timestamp,
		"ar_name_encoding": member.nameEncoding,
	}
	if member.originalName != "" {
		metadata["archive_member_name"] = member.originalName
	}
	if member.nameError != nil {
		metadata["raw_name"] = boundedText(header.rawName, 128)
	}
	if member.quarantine != nil && prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	profileMemberName := member.name
	if member.originalName != "" {
		profileMemberName = member.originalName
	}
	if observation.role != debRoleNone {
		metadata["deb_member_role"] = observation.role
	}
	switch observation.role {
	case debRoleVersion:
		metadata["deb_expected_version"] = "2.<numeric-minor>"
		metadata["deb_version_max_bytes"] = maxDEBVersionBytes
	case debRoleControl, debRoleData:
		metadata["deb_expected_format"] = expectedDEBMemberFormat(
			profileMemberName,
		)
	}
	materializedNode := Node{
		ParentLocalID: location.parentID,
		LogicalPath:   location.logical,
		DisplayName:   location.display,
		NodeType:      NodeTypeFile,
		Depth:         location.depth,
		SizeBytes:     safeSignedSize(member.dataSize),
	}
	if member.nameError != nil {
		materializedNode.ExtractionStatus = StatusCorrupt
		materializedNode.ErrorCode = member.nameErrorCode
		materializedNode.ErrorMessage = member.nameError.Error()
		state.partial = true
	}
	state.applyNamespaceCollision(
		location,
		&materializedNode,
		metadata,
	)
	nodeLocalID := state.nextID
	materialized, limit, err := state.materializeRegular(
		contextAwareReader{
			ctx: state.ctx,
			reader: io.NewSectionReader(
				source,
				member.dataOffset,
				member.dataSize,
			),
		},
		materializedNode,
		metadata,
		budget,
	)
	if materialized == nil {
		if err != nil {
			return err
		}
		if limit != nil {
			return limit
		}
		return nil
	}

	node := state.nodeByLocalID(nodeLocalID)
	if node == nil {
		materialized.close()
		return errors.New("extract: ar member node disappeared")
	}
	if profile == arProfileDeb {
		if err := state.ctx.Err(); err != nil {
			materialized.close()
			return err
		}
		if shouldUseDEBRawLZMA(
			member,
			observation,
			profileMemberName,
			node.Format,
		) {
			// Raw LZMA has no reliable universal magic. An exact parsed DEB
			// member name provides fallback framing, but never overrides a
			// stronger content-based identification.
			node.Format = "lzma"
			node.MIMEType = "application/x-lzma"
		}
		code, message := validateDEBMaterializedMember(
			state.ctx,
			source,
			member,
			node,
			observation,
			profileMemberName,
		)
		if err := state.ctx.Err(); err != nil {
			materialized.close()
			return err
		}
		if code != "" && node.ErrorCode == "" {
			node.ExtractionStatus = StatusCorrupt
			node.ErrorCode = code
			node.ErrorMessage = message
			state.partial = true
		}
		if observation.role == debRoleVersion && code == "" {
			materialized.close()
			return nil
		}
	}
	defer materialized.close()
	nestedLimit, err := state.expandMaterializedRegular(materialized)
	if err != nil {
		return err
	}
	if nestedLimit != nil {
		return nestedLimit
	}
	if profile == arProfileDeb &&
		(observation.role == debRoleControl ||
			observation.role == debRoleData) {
		outer := state.nodeByLocalID(nodeLocalID)
		if outer == nil {
			return errors.New("extract: DEB payload node disappeared")
		}
		switch outer.ExtractionStatus {
		case StatusLimitExceeded,
			StatusCancelled,
			StatusDepthLimited,
			StatusUnsupported:
			return nil
		}
		if !state.debPayloadContainsTAR(*outer) &&
			outer.ErrorCode == "" {
			outer.ExtractionStatus = StatusCorrupt
			outer.ErrorCode = "deb_payload_not_tar"
			outer.ErrorMessage = "DEB control/data payload did not decode to a tar archive"
			state.partial = true
		}
	}
	return nil
}

func (state *operationState) debPayloadContainsTAR(outer Node) bool {
	if isTARFamilyFormat(outer.Format) {
		return true
	}
	for _, candidate := range state.nodes {
		if candidate.ParentLocalID == outer.LocalID &&
			isTARFamilyFormat(candidate.Format) {
			return true
		}
	}
	return false
}

func isTARFamilyFormat(format string) bool {
	switch format {
	case "tar", "docker-tar", "oci-tar":
		return true
	default:
		return false
	}
}

func parseARMemberHeader(encoded []byte) (arMemberHeader, error) {
	if len(encoded) != int(arMemberHeaderSize) ||
		!bytes.Equal(encoded[58:60], []byte{'`', '\n'}) {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member header trailer",
			errInvalidARArchive,
		)
	}
	header := arMemberHeader{
		rawName: strings.TrimRight(string(encoded[0:16]), " "),
	}
	if header.rawName == "" {
		return arMemberHeader{}, fmt.Errorf(
			"%w: empty member name",
			errInvalidARArchive,
		)
	}
	var err error
	if header.timestamp, err = parseARUint(encoded[16:28], 10, false); err != nil {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member timestamp: %v",
			errInvalidARArchive,
			err,
		)
	}
	if header.uid, err = parseARUint(encoded[28:34], 10, false); err != nil {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member uid: %v",
			errInvalidARArchive,
			err,
		)
	}
	if header.gid, err = parseARUint(encoded[34:40], 10, false); err != nil {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member gid: %v",
			errInvalidARArchive,
			err,
		)
	}
	if header.mode, err = parseARUint(encoded[40:48], 8, false); err != nil {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member mode: %v",
			errInvalidARArchive,
			err,
		)
	}
	size, err := parseARUint(encoded[48:58], 10, true)
	if err != nil || size > math.MaxInt64 {
		return arMemberHeader{}, fmt.Errorf(
			"%w: invalid member size",
			errInvalidARArchive,
		)
	}
	header.size = int64(size)
	return header, nil
}

func parseARUint(field []byte, base int, required bool) (uint64, error) {
	value := strings.TrimSpace(string(field))
	if value == "" {
		if required {
			return 0, errors.New("empty numeric field")
		}
		return 0, nil
	}
	for _, current := range value {
		valid := current >= '0' && current <= '9'
		if base == 8 {
			valid = current >= '0' && current <= '7'
		}
		if !valid {
			return 0, errors.New("non-digit in numeric field")
		}
	}
	return strconv.ParseUint(value, base, 64)
}

func validateARMemberRange(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	bodyOffset int64,
	bodySize int64,
) (bodyEnd int64, nextOffset int64, err error) {
	if bodyOffset < 0 || bodySize < 0 ||
		bodyOffset > sourceSize || bodySize > sourceSize-bodyOffset {
		return 0, 0, fmt.Errorf(
			"%w: member body exceeds archive",
			errInvalidARArchive,
		)
	}
	bodyEnd = bodyOffset + bodySize
	nextOffset = bodyEnd
	if bodySize%2 == 0 {
		return bodyEnd, nextOffset, nil
	}
	var padding [1]byte
	if err := readARAt(
		ctx,
		source,
		sourceSize,
		padding[:],
		bodyEnd,
	); err != nil {
		return 0, 0, fmt.Errorf(
			"%w: missing member alignment byte",
			errInvalidARArchive,
		)
	}
	if padding[0] != '\n' {
		return 0, 0, fmt.Errorf(
			"%w: invalid member alignment byte",
			errInvalidARArchive,
		)
	}
	return bodyEnd, bodyEnd + 1, nil
}

func resolveARMember(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	header arMemberHeader,
	bodyOffset int64,
	bodyEnd int64,
	stringTable []byte,
) arResolvedMember {
	resolved := arResolvedMember{
		dataOffset:   bodyOffset,
		dataSize:     header.size,
		nameEncoding: arMemberNameEncodingSysV,
	}
	rawName := header.rawName
	switch {
	case isARSymbolName(rawName):
		resolved.name = rawName
		resolved.symbolTable = true
		return resolved
	case strings.HasPrefix(rawName, "#1/"):
		resolved.nameEncoding = arMemberNameEncodingBSD
		length, err := parseARNameLength(rawName[3:])
		if err != nil || length > header.size {
			resolved.nameErrorCode = "ar_bsd_name_invalid"
			resolved.nameError = fmt.Errorf(
				"%w: invalid BSD extended name length",
				errInvalidARArchive,
			)
			return resolved
		}
		resolved.dataOffset = bodyOffset + length
		resolved.dataSize = header.size - length
		if length > maxARMemberNameBytes {
			resolved.nameErrorCode = "ar_member_name_too_long"
			resolved.nameError = fmt.Errorf(
				"%w: BSD extended member name exceeds %d bytes",
				errInvalidARArchive,
				maxARMemberNameBytes,
			)
			return resolved
		}
		encodedName := make([]byte, int(length))
		if err := readARAt(
			ctx,
			source,
			sourceSize,
			encodedName,
			bodyOffset,
		); err != nil {
			resolved.nameErrorCode = "ar_bsd_name_invalid"
			resolved.nameError = err
			return resolved
		}
		resolved.name = string(encodedName)
	case strings.HasPrefix(rawName, "/"):
		resolved.nameEncoding = arMemberNameEncodingGNU
		if stringTable == nil {
			resolved.nameErrorCode = "ar_gnu_string_table_missing"
			resolved.nameError = fmt.Errorf(
				"%w: GNU name offset appears before a string table",
				errInvalidARArchive,
			)
			return resolved
		}
		offset, err := parseARNameLength(rawName[1:])
		if err != nil {
			resolved.nameErrorCode = "ar_gnu_name_offset_invalid"
			resolved.nameError = fmt.Errorf(
				"%w: invalid GNU name offset",
				errInvalidARArchive,
			)
			return resolved
		}
		name, err := resolveGNUARName(stringTable, offset)
		if err != nil {
			resolved.nameErrorCode = "ar_gnu_name_offset_invalid"
			resolved.nameError = err
			return resolved
		}
		resolved.name = name
	default:
		resolved.name = strings.TrimSuffix(rawName, "/")
	}
	if resolved.name == "" {
		resolved.nameErrorCode = "ar_member_name_invalid"
		resolved.nameError = fmt.Errorf(
			"%w: empty resolved member name",
			errInvalidARArchive,
		)
		return resolved
	}
	if len(resolved.name) > maxARMemberNameBytes {
		resolved.nameErrorCode = "ar_member_name_too_long"
		resolved.nameError = fmt.Errorf(
			"%w: member name exceeds %d bytes",
			errInvalidARArchive,
			maxARMemberNameBytes,
		)
		return resolved
	}
	if isARSymbolName(resolved.name) {
		resolved.symbolTable = true
	}
	return resolved
}

func parseARNameLength(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("empty ar name length")
	}
	for _, current := range value {
		if current < '0' || current > '9' {
			return 0, errors.New("invalid ar name length")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, err
	}
	return int64(parsed), nil
}

func resolveGNUARName(table []byte, offset int64) (string, error) {
	if offset < 0 || offset >= int64(len(table)) ||
		(offset > 0 && table[offset-1] != '\n') {
		return "", fmt.Errorf(
			"%w: GNU name offset is outside an entry boundary",
			errInvalidARArchive,
		)
	}
	tail := table[offset:]
	searchWindow := boundedGNUARNameSearchWindow(tail)
	terminator := bytes.Index(searchWindow, []byte{'/', '\n'})
	if terminator < 0 {
		if len(searchWindow) < len(tail) {
			return "", fmt.Errorf(
				"%w: GNU member name exceeds %d bytes",
				errInvalidARArchive,
				maxARMemberNameBytes,
			)
		}
		return "", fmt.Errorf(
			"%w: unterminated GNU string-table name",
			errInvalidARArchive,
		)
	}
	if terminator > maxARMemberNameBytes {
		return "", fmt.Errorf(
			"%w: GNU member name exceeds %d bytes",
			errInvalidARArchive,
			maxARMemberNameBytes,
		)
	}
	if terminator == 0 {
		return "", fmt.Errorf(
			"%w: empty GNU string-table name",
			errInvalidARArchive,
		)
	}
	return string(tail[:terminator]), nil
}

func boundedGNUARNameSearchWindow(tail []byte) []byte {
	const maxSearchBytes = maxARMemberNameBytes + len("/\n")
	if len(tail) > maxSearchBytes {
		return tail[:maxSearchBytes]
	}
	return tail
}

func isARSymbolName(name string) bool {
	switch strings.TrimSuffix(name, "/") {
	case "", "__.SYMDEF", "__.SYMDEF SORTED", "/SYM64":
		return name == "/" ||
			name == "/SYM64/" ||
			strings.HasPrefix(name, "__.SYMDEF")
	default:
		return false
	}
}

func (state *debProfileState) observe(name string) debMemberObservation {
	role := classifyDEBMember(name)
	observation := debMemberObservation{role: role}
	if strings.HasPrefix(name, "_") {
		if !state.canonicalVersion {
			observation.code = "deb_unexpected_member"
			observation.message =
				"DEB extension member appears before canonical debian-binary"
		}
		return observation
	}
	if role != debRoleNone {
		position := state.requiredRoleCount
		state.requiredRoleCount++
		state.seen[role]++
		if role == debRoleVersion &&
			position == 0 &&
			state.seen[role] == 1 {
			state.canonicalVersion = true
		}
		if state.seen[role] > 1 {
			observation.code = "deb_duplicate_member"
			observation.message = "duplicate required DEB member"
			return observation
		}
		if debRoleIndex(role) != position {
			observation.code = "deb_member_order_invalid"
			observation.message = "required DEB member is out of order"
		}
		return observation
	}
	if state.requiredRoleCount < 3 {
		expected := []debMemberRole{
			debRoleVersion,
			debRoleControl,
			debRoleData,
		}
		observation.code = "deb_unexpected_member"
		observation.message = fmt.Sprintf(
			"unexpected DEB member before required %s member",
			expected[state.requiredRoleCount],
		)
	}
	return observation
}

func classifyDEBMember(name string) debMemberRole {
	switch {
	case name == "debian-binary":
		return debRoleVersion
	case isDEBTARMember(name, "control"):
		return debRoleControl
	case isDEBTARMember(name, "data"):
		return debRoleData
	default:
		return debRoleNone
	}
}

func isDEBTARMember(name string, role string) bool {
	base := role + ".tar"
	if role == "control" {
		switch name {
		case base, base + ".gz", base + ".xz", base + ".zst":
			return true
		default:
			return false
		}
	}
	switch name {
	case base,
		base + ".gz",
		base + ".xz",
		base + ".zst",
		base + ".bz2",
		base + ".lzma":
		return true
	default:
		return false
	}
}

func debRoleIndex(role debMemberRole) int {
	switch role {
	case debRoleVersion:
		return 0
	case debRoleControl:
		return 1
	case debRoleData:
		return 2
	default:
		return -1
	}
}

func validateDEBMaterializedMember(
	ctx context.Context,
	source io.ReaderAt,
	member arResolvedMember,
	node *Node,
	observation debMemberObservation,
	profileMemberName string,
) (string, string) {
	if observation.code != "" {
		return observation.code, observation.message
	}
	switch observation.role {
	case debRoleVersion:
		if member.dataSize < 4 || member.dataSize > maxDEBVersionBytes {
			return "deb_version_invalid",
				"debian-binary must be at most 4096 bytes and start with a 2.<numeric-minor> line"
		}
		version := make([]byte, int(member.dataSize))
		if err := readARAt(
			ctx,
			source,
			member.dataOffset+member.dataSize,
			version,
			member.dataOffset,
		); err != nil {
			return "deb_version_invalid",
				"debian-binary version could not be read"
		}
		firstLineEnd := bytes.IndexByte(version, '\n')
		if firstLineEnd < 0 {
			return "deb_version_invalid",
				"debian-binary must start with a newline-terminated version"
		}
		firstLine := version[:firstLineEnd]
		dot := bytes.IndexByte(firstLine, '.')
		if dot <= 0 {
			return "deb_version_invalid",
				"debian-binary version must be major.minor"
		}
		if !bytes.Equal(firstLine[:dot], []byte("2")) {
			return "deb_version_unsupported",
				"only DEB major version 2 is supported"
		}
		minor := firstLine[dot+1:]
		if len(minor) == 0 || !allDecimalDigits(minor) {
			return "deb_version_invalid",
				"DEB minor version must contain only decimal digits"
		}
		extensions := version[firstLineEnd+1:]
		if len(extensions) > 0 &&
			(extensions[len(extensions)-1] != '\n' ||
				!validDEBVersionExtensions(extensions)) {
			return "deb_version_invalid",
				"DEB version extensions must be bounded printable lines"
		}
	case debRoleControl, debRoleData:
		want := expectedDEBMemberFormat(profileMemberName)
		formatMatches := node.Format == want
		if want == "tar" {
			formatMatches = isTARFamilyFormat(node.Format)
		}
		if !formatMatches {
			return "deb_payload_format_mismatch",
				fmt.Sprintf(
					"%s content format is %q, expected %q",
					observation.role,
					node.Format,
					want,
				)
		}
	}
	return "", ""
}

func shouldUseDEBRawLZMA(
	member arResolvedMember,
	observation debMemberObservation,
	profileMemberName string,
	detectedFormat string,
) bool {
	if detectedFormat != "" && detectedFormat != "unknown" {
		return false
	}
	const expectedName = "data.tar.lzma"
	parsedName := member.name
	if member.originalName != "" {
		parsedName = member.originalName
	}
	if observation.role != debRoleData ||
		parsedName != expectedName ||
		profileMemberName != expectedName {
		return false
	}
	switch observation.code {
	case "":
		return member.nameEncoding == arMemberNameEncodingSysV
	case "deb_duplicate_member":
		return member.nameEncoding == arMemberNameEncodingSysV &&
			member.originalName == expectedName
	case "deb_extended_name_not_allowed":
		return (member.nameEncoding == arMemberNameEncodingGNU ||
			member.nameEncoding == arMemberNameEncodingBSD) &&
			member.originalName == expectedName
	default:
		return false
	}
}

func allDecimalDigits(value []byte) bool {
	for _, current := range value {
		if current < '0' || current > '9' {
			return false
		}
	}
	return true
}

func validDEBVersionExtensions(value []byte) bool {
	for _, current := range value {
		if current == '\n' || current == '\t' {
			continue
		}
		if current < 0x20 || current > 0x7e {
			return false
		}
	}
	return true
}

func expectedDEBMemberFormat(name string) string {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return "gzip"
	case strings.HasSuffix(name, ".tar.xz"):
		return "xz"
	case strings.HasSuffix(name, ".tar.zst"):
		return "zstd"
	case strings.HasSuffix(name, ".tar.bz2"):
		return "bzip2"
	case strings.HasSuffix(name, ".tar.lzma"):
		return "lzma"
	default:
		return "tar"
	}
}

func (state *operationState) appendMissingDEBMembers(
	profile *debProfileState,
	parentID int,
	prefix string,
	depth int,
) error {
	for _, role := range []debMemberRole{
		debRoleVersion,
		debRoleControl,
		debRoleData,
	} {
		if profile.seen[role] > 0 {
			continue
		}
		if err := state.appendARDiagnostic(
			parentID,
			prefix,
			depth,
			StatusCorrupt,
			"deb_missing_member",
			"required DEB member is missing: "+string(role),
			map[string]any{
				"archive":         arProfileDeb,
				"expected_member": role,
			},
		); err != nil {
			return err
		}
	}
	return nil
}

func (state *operationState) appendARDiagnostic(
	parentID int,
	prefix string,
	_ int,
	status string,
	code string,
	message string,
	metadata map[string]any,
) error {
	location, locationErr := state.uniqueQuarantineLocation(
		parentID,
		"ar_diagnostic",
	)
	if locationErr != nil {
		return locationErr
	}
	state.reserveLogicalPath(location.logical)
	if prefix != "" {
		metadata["archive_container_path"] = prefix
	}
	_, err := state.appendNode(Node{
		ParentLocalID:          location.parentID,
		SourceContainerLocalID: parentID,
		LogicalPath:            location.logical,
		DisplayName:            path.Base(location.logical),
		NodeType:               NodeTypeSpecial,
		Depth:                  location.depth,
		ExtractionStatus:       status,
		MetadataJSON:           metadataJSON(metadata),
		ErrorCode:              code,
		ErrorMessage:           message,
	})
	if status == StatusCorrupt {
		state.partial = true
	}
	return err
}

func readARAt(
	ctx context.Context,
	reader io.ReaderAt,
	size int64,
	buffer []byte,
	offset int64,
) error {
	if ctx == nil {
		return errors.New("extract: nil ar read context")
	}
	if reader == nil || offset < 0 || size < 0 || offset > size ||
		int64(len(buffer)) > size-offset {
		return fmt.Errorf("%w: read outside source range", errInvalidARArchive)
	}
	for len(buffer) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := len(buffer)
		if length > arReadChunkBytes {
			length = arReadChunkBytes
		}
		count, err := reader.ReadAt(buffer[:length], offset)
		if count != length {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
		if err != nil {
			return err
		}
		buffer = buffer[length:]
		offset += int64(length)
	}
	return ctx.Err()
}
