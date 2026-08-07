package iso9660

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type selectedVolume struct {
	info        Volume
	blockSize   int64
	volumeBytes int64
	root        rawRecord
	jolietLevel int
	suspSkip    int
}

type imageParser struct {
	ctx    context.Context
	source io.ReaderAt
	size   int64
	limits Limits
	volume selectedVolume

	nodes      int
	extents    int
	bytes      int64
	entries    []Entry
	byPath     map[string]indexedEntry
	dirSeen    map[string]string
	activeDirs [][]extent
}

type rawRecord struct {
	identifier []byte
	flags      byte
	extent     extent
	systemUse  []byte
	dataLength int64
}

type recordGroup struct {
	records []rawRecord
	extents []extent
	size    int64
}

type rockRidge struct {
	name          string
	hasName       bool
	mode          uint32
	uid           uint32
	gid           uint32
	hasPX         bool
	symlinkTarget string
	hasSL         bool
}

func (p *imageParser) selectVolume() (selectedVolume, error) {
	var primary *selectedVolume
	var joliet *selectedVolume
	terminated := false
	sector := make([]byte, descriptorSectorSize)
	for index := int64(0); index < maxDescriptors; index++ {
		offset := (descriptorStartLBA + index) * descriptorSectorSize
		if offset > p.size-descriptorSectorSize {
			return selectedVolume{}, fmt.Errorf(
				"%w: volume descriptor chain is truncated",
				ErrInvalidFormat,
			)
		}
		if err := readAtFull(p.ctx, p.source, p.size, sector, offset); err != nil {
			return selectedVolume{}, err
		}
		if !bytes.Equal(sector[1:6], []byte("CD001")) {
			return selectedVolume{}, fmt.Errorf(
				"%w: bad volume descriptor signature at sector %d",
				ErrInvalidFormat,
				descriptorStartLBA+index,
			)
		}
		switch sector[0] {
		case 1:
			if sector[6] != 1 {
				return selectedVolume{}, fmt.Errorf("%w: unsupported primary descriptor version", ErrInvalidFormat)
			}
			if primary != nil {
				return selectedVolume{}, fmt.Errorf("%w: duplicate primary volume descriptor", ErrCorrupt)
			}
			value, err := p.parseVolumeDescriptor(sector, 0)
			if err != nil {
				return selectedVolume{}, err
			}
			primary = &value
		case 2:
			// ISO 9660:1999 enhanced descriptors use version 2. They are
			// outside this reader's namespace contract and can be skipped while
			// retaining a valid version-1 primary descriptor.
			if sector[6] != 1 {
				continue
			}
			level := jolietLevel(sector[88:120])
			if level == 0 {
				continue
			}
			value, err := p.parseVolumeDescriptor(sector, level)
			if err != nil {
				return selectedVolume{}, err
			}
			if joliet == nil || level > joliet.jolietLevel {
				joliet = &value
			}
		case 255:
			if sector[6] != 1 {
				return selectedVolume{}, fmt.Errorf("%w: invalid descriptor terminator version", ErrCorrupt)
			}
			terminated = true
		}
		if terminated {
			break
		}
	}
	if !terminated {
		return selectedVolume{}, fmt.Errorf("%w: descriptor terminator was not found", ErrCorrupt)
	}
	if primary == nil {
		return selectedVolume{}, fmt.Errorf("%w: primary volume descriptor was not found", ErrInvalidFormat)
	}

	rockRidge, skip, err := p.detectRockRidge(*primary)
	if err != nil {
		return selectedVolume{}, err
	}
	if rockRidge {
		primary.info.RockRidge = true
		primary.suspSkip = skip
		return *primary, nil
	}
	if joliet != nil {
		return *joliet, nil
	}
	return *primary, nil
}

func (p *imageParser) parseVolumeDescriptor(
	descriptor []byte,
	joliet int,
) (selectedVolume, error) {
	volumeBlocks, err := bothEndian32(descriptor[80:88])
	if err != nil || volumeBlocks == 0 {
		return selectedVolume{}, fmt.Errorf("%w: invalid volume space size", ErrCorrupt)
	}
	blockSize, err := bothEndian16(descriptor[128:132])
	if err != nil || blockSize < 512 || blockSize > 32*1024 ||
		blockSize&(blockSize-1) != 0 {
		return selectedVolume{}, fmt.Errorf("%w: invalid logical block size", ErrCorrupt)
	}
	volumeBytes, ok := checkedMultiply(int64(volumeBlocks), int64(blockSize))
	if !ok || volumeBytes > p.size {
		return selectedVolume{}, fmt.Errorf("%w: declared volume exceeds the image", ErrCorrupt)
	}
	rootLength := int(descriptor[156])
	if rootLength < 34 || 156+rootLength > len(descriptor) {
		return selectedVolume{}, fmt.Errorf("%w: invalid root directory record", ErrCorrupt)
	}
	volume := selectedVolume{
		blockSize:   int64(blockSize),
		volumeBytes: volumeBytes,
		jolietLevel: joliet,
		info: Volume{
			LogicalBlockSize: uint32(blockSize),
			Joliet:           joliet > 0,
		},
	}
	volume.root, err = parseRawRecord(
		descriptor[156:156+rootLength],
		volume.blockSize,
		volume.volumeBytes,
		p.size,
	)
	if err != nil {
		return selectedVolume{}, fmt.Errorf("root directory: %w", err)
	}
	if volume.root.flags&0x02 == 0 || volume.root.flags&0x80 != 0 ||
		len(volume.root.identifier) != 1 ||
		volume.root.identifier[0] != 0 || volume.root.dataLength == 0 {
		return selectedVolume{}, fmt.Errorf("%w: root record is not a directory", ErrCorrupt)
	}
	if joliet > 0 {
		volume.info.Identifier, err = decodeUTF16BE(descriptor[40:72], true)
	} else {
		volume.info.Identifier, err = decodeASCIIIdentifier(descriptor[40:72], true)
	}
	if err != nil {
		return selectedVolume{}, fmt.Errorf("volume identifier: %w", err)
	}
	return volume, nil
}

func (p *imageParser) detectRockRidge(
	volume selectedVolume,
) (bool, int, error) {
	if volume.root.dataLength < 34 {
		return false, 0, fmt.Errorf("%w: root directory is too short", ErrCorrupt)
	}
	length := []byte{0}
	if err := readExtentsAt(
		p.ctx,
		p.source,
		p.size,
		[]extent{volume.root.extent},
		length,
		0,
	); err != nil {
		return false, 0, err
	}
	if length[0] < 34 || int64(length[0]) > volume.root.dataLength {
		return false, 0, fmt.Errorf("%w: invalid root dot record", ErrCorrupt)
	}
	recordBytes := make([]byte, int(length[0]))
	if err := readExtentsAt(
		p.ctx,
		p.source,
		p.size,
		[]extent{volume.root.extent},
		recordBytes,
		0,
	); err != nil {
		return false, 0, err
	}
	record, err := parseRawRecord(
		recordBytes,
		volume.blockSize,
		volume.volumeBytes,
		p.size,
	)
	if err != nil {
		return false, 0, fmt.Errorf("root dot record: %w", err)
	}
	if len(record.identifier) != 1 || record.identifier[0] != 0 {
		return false, 0, fmt.Errorf("%w: root directory does not begin with dot", ErrCorrupt)
	}
	for skip := 0; skip+7 <= len(record.systemUse) && skip <= 32; skip++ {
		candidate := record.systemUse[skip:]
		if !bytes.Equal(candidate[:2], []byte("SP")) {
			continue
		}
		if candidate[2] != 7 || candidate[3] != 1 ||
			candidate[4] != 0xbe || candidate[5] != 0xef ||
			int(candidate[6]) != skip {
			return false, 0, fmt.Errorf("%w: invalid SUSP SP entry", ErrCorrupt)
		}
		rockRidge, err := hasRockRidgeIndicator(record.systemUse[skip:])
		if err != nil {
			return false, 0, err
		}
		return rockRidge, skip, nil
	}
	return false, 0, nil
}

func hasRockRidgeIndicator(data []byte) (bool, error) {
	for len(data) > 0 {
		if data[0] == 0 {
			if !allZero(data) {
				return false, fmt.Errorf("%w: invalid root SUSP padding", ErrCorrupt)
			}
			return false, nil
		}
		if len(data) < 4 {
			return false, fmt.Errorf("%w: truncated root SUSP entry", ErrCorrupt)
		}
		length := int(data[2])
		if length < 4 || length > len(data) {
			return false, fmt.Errorf("%w: invalid root SUSP entry length", ErrCorrupt)
		}
		entry := data[:length]
		switch string(entry[:2]) {
		case "RR", "PX", "NM", "SL":
			if entry[3] != 1 {
				return false, fmt.Errorf("%w: invalid Rock Ridge indicator", ErrCorrupt)
			}
			return true, nil
		case "ER":
			if length < 8 {
				return false, fmt.Errorf("%w: invalid SUSP ER entry", ErrCorrupt)
			}
			identifierLength := int(entry[4])
			descriptorLength := int(entry[5])
			sourceLength := int(entry[6])
			if 8+identifierLength+descriptorLength+sourceLength > length {
				return false, fmt.Errorf("%w: truncated SUSP ER entry", ErrCorrupt)
			}
			identifier := string(entry[8 : 8+identifierLength])
			if strings.Contains(identifier, "RRIP") ||
				strings.Contains(identifier, "IEEE_P1282") {
				return true, nil
			}
		case "ST":
			if length != 4 || entry[3] != 1 {
				return false, fmt.Errorf("%w: invalid root SUSP terminator", ErrCorrupt)
			}
			return false, nil
		}
		data = data[length:]
	}
	return false, nil
}

func (p *imageParser) walkRoot() error {
	if err := p.consumeExtent(); err != nil {
		return err
	}
	if err := p.consumeBytes(p.volume.root.dataLength); err != nil {
		return err
	}
	rootExtents := []extent{p.volume.root.extent}
	p.dirSeen[extentIdentity(rootExtents)] = "."
	p.activeDirs = append(p.activeDirs, rootExtents)
	err := p.walkDirectory(
		"",
		rootExtents,
		p.volume.root.dataLength,
		0,
		rootExtents,
	)
	p.activeDirs = p.activeDirs[:len(p.activeDirs)-1]
	return err
}

func (p *imageParser) walkDirectory(
	parent string,
	extents []extent,
	size int64,
	depth int,
	parentExtents []extent,
) error {
	var offset int64
	dotRecords := 0
	for offset < size {
		group, next, found, err := p.nextRecordGroup(extents, size, offset)
		if err != nil {
			return err
		}
		offset = next
		if !found {
			break
		}
		first := group.records[0]
		if isDotIdentifier(first.identifier) {
			dotRecords++
			if first.flags&0x02 == 0 || dotRecords > 2 {
				return fmt.Errorf("%w: invalid dot directory record", ErrCorrupt)
			}
			expected := extents
			if first.identifier[0] == 1 {
				if dotRecords != 2 {
					return fmt.Errorf("%w: parent record precedes current record", ErrCorrupt)
				}
				expected = parentExtents
			} else if dotRecords != 1 {
				return fmt.Errorf("%w: duplicate current directory record", ErrCorrupt)
			}
			if group.size != extentSize(expected) ||
				!equalExtents(group.extents, expected) {
				return fmt.Errorf("%w: dot record extent mismatch", ErrCorrupt)
			}
			continue
		}
		if dotRecords != 2 {
			return fmt.Errorf("%w: directory is missing dot records", ErrCorrupt)
		}
		entryDepth := depth + 1
		if entryDepth > p.limits.MaxDepth {
			return &LimitError{Limit: LimitDepth, Max: int64(p.limits.MaxDepth)}
		}
		name, metadata, err := p.recordNameAndMetadata(first)
		if err != nil {
			return err
		}
		if err := validatePathComponent(name); err != nil {
			return err
		}
		entryPath := name
		if parent != "" {
			entryPath = path.Join(parent, name)
		}
		if len(entryPath) > maxPathBytes {
			return fmt.Errorf("%w: path exceeds %d bytes", ErrCorrupt, maxPathBytes)
		}
		if _, exists := p.byPath[entryPath]; exists {
			return fmt.Errorf("%w: duplicate path %q", ErrCorrupt, entryPath)
		}
		entryType, mode, err := classifyRecord(first, metadata)
		if err != nil {
			return err
		}
		directoryIdentity := ""
		if entryType == TypeDirectory {
			if group.size == 0 {
				return fmt.Errorf("%w: directory %q has no data", ErrCorrupt, entryPath)
			}
			directoryIdentity = extentIdentity(group.extents)
			if prior, exists := p.dirSeen[directoryIdentity]; exists {
				return fmt.Errorf(
					"%w: directory %q reuses directory extent from %q",
					ErrCorrupt,
					entryPath,
					prior,
				)
			}
			for _, ancestor := range p.activeDirs {
				if extentsOverlap(group.extents, ancestor) {
					return fmt.Errorf(
						"%w: directory %q overlaps an ancestor",
						ErrCorrupt,
						entryPath,
					)
				}
			}
		}
		if err := p.consumeNode(); err != nil {
			return err
		}
		if err := p.consumeBytes(group.size); err != nil {
			return err
		}
		entry := Entry{
			Path:          entryPath,
			Name:          name,
			Type:          entryType,
			Size:          group.size,
			Mode:          mode,
			UID:           metadata.uid,
			GID:           metadata.gid,
			SymlinkTarget: metadata.symlinkTarget,
			ExtentCount:   len(group.extents),
		}
		p.entries = append(p.entries, entry)
		p.byPath[entryPath] = indexedEntry{
			entry: entry, extents: append([]extent(nil), group.extents...),
		}
		if entryType != TypeDirectory {
			continue
		}
		p.dirSeen[directoryIdentity] = entryPath
		p.activeDirs = append(p.activeDirs, group.extents)
		err = p.walkDirectory(
			entryPath,
			group.extents,
			group.size,
			entryDepth,
			extents,
		)
		p.activeDirs = p.activeDirs[:len(p.activeDirs)-1]
		if err != nil {
			return err
		}
	}
	if dotRecords != 2 {
		return fmt.Errorf("%w: directory is missing dot records", ErrCorrupt)
	}
	return nil
}

func (p *imageParser) nextRecordGroup(
	extents []extent,
	size int64,
	offset int64,
) (recordGroup, int64, bool, error) {
	first, next, found, err := p.nextRawRecord(extents, size, offset)
	if err != nil || !found {
		return recordGroup{}, next, found, err
	}
	group := recordGroup{
		records: []rawRecord{first},
		extents: []extent{first.extent},
		size:    first.dataLength,
	}
	current := first
	for current.flags&0x80 != 0 {
		var continuation rawRecord
		continuation, next, found, err = p.nextRawRecord(extents, size, next)
		if err != nil {
			return recordGroup{}, next, false, err
		}
		if !found {
			return recordGroup{}, next, false, fmt.Errorf("%w: unterminated multi-extent record", ErrCorrupt)
		}
		if !bytes.Equal(continuation.identifier, first.identifier) ||
			continuation.flags&^byte(0x80) != first.flags&^byte(0x80) {
			return recordGroup{}, next, false, fmt.Errorf("%w: inconsistent multi-extent record", ErrCorrupt)
		}
		combined, ok := checkedAdd(group.size, continuation.dataLength)
		if !ok {
			return recordGroup{}, next, false, fmt.Errorf("%w: multi-extent size overflow", ErrCorrupt)
		}
		group.size = combined
		group.records = append(group.records, continuation)
		group.extents = append(group.extents, continuation.extent)
		current = continuation
	}
	return group, next, true, nil
}

func (p *imageParser) nextRawRecord(
	extents []extent,
	size int64,
	offset int64,
) (rawRecord, int64, bool, error) {
	for offset < size {
		length := []byte{0}
		if err := readExtentsAt(
			p.ctx,
			p.source,
			p.size,
			extents,
			length,
			offset,
		); err != nil {
			return rawRecord{}, offset, false, err
		}
		if length[0] == 0 {
			next := ((offset / p.volume.blockSize) + 1) * p.volume.blockSize
			if next > size {
				next = size
			}
			paddingLength := next - offset
			if paddingLength > 0 {
				padding := make([]byte, int(paddingLength))
				if err := readExtentsAt(
					p.ctx,
					p.source,
					p.size,
					extents,
					padding,
					offset,
				); err != nil {
					return rawRecord{}, offset, false, err
				}
				if !allZero(padding) {
					return rawRecord{}, offset, false, fmt.Errorf("%w: nonzero directory padding", ErrCorrupt)
				}
			}
			offset = next
			continue
		}
		recordLength := int64(length[0])
		if recordLength < 34 || recordLength > size-offset ||
			offset%p.volume.blockSize+recordLength > p.volume.blockSize {
			return rawRecord{}, offset, false, fmt.Errorf("%w: invalid directory record length", ErrCorrupt)
		}
		recordBytes := make([]byte, int(recordLength))
		if err := readExtentsAt(
			p.ctx,
			p.source,
			p.size,
			extents,
			recordBytes,
			offset,
		); err != nil {
			return rawRecord{}, offset, false, err
		}
		if err := p.consumeExtent(); err != nil {
			return rawRecord{}, offset, false, err
		}
		record, err := parseRawRecord(
			recordBytes,
			p.volume.blockSize,
			p.volume.volumeBytes,
			p.size,
		)
		if err != nil {
			return rawRecord{}, offset, false, err
		}
		return record, offset + recordLength, true, nil
	}
	return rawRecord{}, offset, false, nil
}

func (p *imageParser) recordNameAndMetadata(
	record rawRecord,
) (string, rockRidge, error) {
	var metadata rockRidge
	var err error
	if p.volume.info.RockRidge {
		metadata, err = parseRockRidge(record.systemUse, p.volume.suspSkip)
		if err != nil {
			return "", rockRidge{}, err
		}
		if metadata.hasName {
			return metadata.name, metadata, nil
		}
	}
	var name string
	if p.volume.info.Joliet {
		name, err = decodeUTF16BE(record.identifier, false)
	} else {
		name, err = decodeASCIIIdentifier(record.identifier, false)
	}
	if err != nil {
		return "", rockRidge{}, err
	}
	return stripISOFileVersion(name), metadata, nil
}

func classifyRecord(record rawRecord, metadata rockRidge) (EntryType, uint32, error) {
	directory := record.flags&0x02 != 0
	mode := uint32(0)
	if directory {
		mode = 0o040555
	} else {
		mode = 0o100444
	}
	if metadata.hasPX {
		mode = metadata.mode
		switch mode & 0o170000 {
		case 0o040000:
			if !directory {
				return "", 0, fmt.Errorf("%w: PX directory conflicts with ISO flags", ErrCorrupt)
			}
			return TypeDirectory, mode, nil
		case 0o100000:
			if directory {
				return "", 0, fmt.Errorf("%w: PX regular file conflicts with ISO flags", ErrCorrupt)
			}
			if metadata.hasSL {
				return "", 0, fmt.Errorf("%w: regular file has an SL record", ErrCorrupt)
			}
			return TypeFile, mode, nil
		case 0o120000:
			if directory || !metadata.hasSL {
				return "", 0, fmt.Errorf("%w: invalid Rock Ridge symlink", ErrCorrupt)
			}
			return TypeSymlink, mode, nil
		default:
			if directory || metadata.hasSL {
				return "", 0, fmt.Errorf("%w: invalid Rock Ridge special file", ErrCorrupt)
			}
			return TypeSpecial, mode, nil
		}
	}
	if metadata.hasSL {
		if directory {
			return "", 0, fmt.Errorf("%w: directory has an SL record", ErrCorrupt)
		}
		return TypeSymlink, 0o120777, nil
	}
	if directory {
		return TypeDirectory, mode, nil
	}
	return TypeFile, mode, nil
}

func (p *imageParser) consumeNode() error {
	if p.nodes >= p.limits.MaxNodes {
		return &LimitError{Limit: LimitNodes, Max: int64(p.limits.MaxNodes)}
	}
	p.nodes++
	return nil
}

func (p *imageParser) consumeExtent() error {
	if p.extents >= p.limits.MaxExtents {
		return &LimitError{Limit: LimitExtents, Max: int64(p.limits.MaxExtents)}
	}
	p.extents++
	return nil
}

func (p *imageParser) consumeBytes(value int64) error {
	next, ok := checkedAdd(p.bytes, value)
	if !ok || next > p.limits.MaxBytes {
		return &LimitError{Limit: LimitBytes, Max: p.limits.MaxBytes}
	}
	p.bytes = next
	return nil
}

func parseRawRecord(
	record []byte,
	blockSize int64,
	volumeBytes int64,
	sourceBytes int64,
) (rawRecord, error) {
	if len(record) < 34 || int(record[0]) != len(record) {
		return rawRecord{}, fmt.Errorf("%w: truncated directory record", ErrCorrupt)
	}
	location, err := bothEndian32(record[2:10])
	if err != nil {
		return rawRecord{}, fmt.Errorf("%w: extent location byte orders disagree", ErrCorrupt)
	}
	dataLength, err := bothEndian32(record[10:18])
	if err != nil {
		return rawRecord{}, fmt.Errorf("%w: extent length byte orders disagree", ErrCorrupt)
	}
	if _, err := bothEndian16(record[28:32]); err != nil {
		return rawRecord{}, fmt.Errorf("%w: volume sequence byte orders disagree", ErrCorrupt)
	}
	if record[26] != 0 || record[27] != 0 {
		return rawRecord{}, fmt.Errorf("%w: interleaved files are not supported", ErrCorrupt)
	}
	nameLength := int(record[32])
	if nameLength == 0 || 33+nameLength > len(record) {
		return rawRecord{}, fmt.Errorf("%w: invalid file identifier length", ErrCorrupt)
	}
	systemUseOffset := 33 + nameLength
	if nameLength%2 == 0 {
		systemUseOffset++
	}
	if systemUseOffset > len(record) {
		return rawRecord{}, fmt.Errorf("%w: missing file identifier padding", ErrCorrupt)
	}
	extendedBlocks := int64(record[1])
	dataBlock, ok := checkedAdd(int64(location), extendedBlocks)
	if !ok {
		return rawRecord{}, fmt.Errorf("%w: extended attribute location overflow", ErrCorrupt)
	}
	offset, ok := checkedMultiply(dataBlock, blockSize)
	if !ok {
		return rawRecord{}, fmt.Errorf("%w: extent offset overflow", ErrCorrupt)
	}
	end, ok := checkedAdd(offset, int64(dataLength))
	if !ok || end > volumeBytes || end > sourceBytes {
		return rawRecord{}, fmt.Errorf("%w: extent is outside the declared volume", ErrCorrupt)
	}
	return rawRecord{
		identifier: append([]byte(nil), record[33:33+nameLength]...),
		flags:      record[25],
		extent:     extent{offset: offset, length: int64(dataLength)},
		systemUse:  append([]byte(nil), record[systemUseOffset:]...),
		dataLength: int64(dataLength),
	}, nil
}

func readExtentsAt(
	ctx context.Context,
	source io.ReaderAt,
	sourceSize int64,
	extents []extent,
	destination []byte,
	offset int64,
) error {
	if offset < 0 {
		return fmt.Errorf("%w: negative logical extent offset", ErrCorrupt)
	}
	remainingOffset := offset
	remaining := destination
	for _, item := range extents {
		if remainingOffset >= item.length {
			remainingOffset -= item.length
			continue
		}
		available := item.length - remainingOffset
		chunk := int64(len(remaining))
		if available < chunk {
			chunk = available
		}
		if chunk > 0 {
			if err := readAtFull(
				ctx,
				source,
				sourceSize,
				remaining[:int(chunk)],
				item.offset+remainingOffset,
			); err != nil {
				return err
			}
			remaining = remaining[int(chunk):]
		}
		remainingOffset = 0
		if len(remaining) == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: logical read exceeds extent list", ErrCorrupt)
}

func bothEndian16(value []byte) (uint16, error) {
	if len(value) != 4 {
		return 0, ErrCorrupt
	}
	little := binary.LittleEndian.Uint16(value[:2])
	big := binary.BigEndian.Uint16(value[2:])
	if little != big {
		return 0, ErrCorrupt
	}
	return little, nil
}

func bothEndian32(value []byte) (uint32, error) {
	if len(value) != 8 {
		return 0, ErrCorrupt
	}
	little := binary.LittleEndian.Uint32(value[:4])
	big := binary.BigEndian.Uint32(value[4:])
	if little != big {
		return 0, ErrCorrupt
	}
	return little, nil
}

func jolietLevel(escape []byte) int {
	if len(escape) < 3 || escape[0] != '%' || escape[1] != '/' {
		return 0
	}
	switch escape[2] {
	case '@':
		return 1
	case 'C':
		return 2
	case 'E':
		return 3
	default:
		return 0
	}
}

func decodeASCIIIdentifier(value []byte, trimPadding bool) (string, error) {
	if trimPadding {
		value = bytes.TrimRight(value, " \x00")
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", fmt.Errorf("%w: non-ASCII identifier", ErrCorrupt)
		}
	}
	return string(value), nil
}

func decodeUTF16BE(value []byte, trimPadding bool) (string, error) {
	if len(value)%2 != 0 {
		return "", fmt.Errorf("%w: odd-length Joliet identifier", ErrCorrupt)
	}
	units := make([]uint16, 0, len(value)/2)
	for index := 0; index < len(value); index += 2 {
		unit := binary.BigEndian.Uint16(value[index : index+2])
		if trimPadding && (unit == 0 || unit == 0x20) {
			allPadding := true
			for tail := index; tail < len(value); tail += 2 {
				candidate := binary.BigEndian.Uint16(value[tail : tail+2])
				if candidate != 0 && candidate != 0x20 {
					allPadding = false
					break
				}
			}
			if allPadding {
				break
			}
		}
		if 0xd800 <= unit && unit <= 0xdbff {
			if index+4 > len(value) {
				return "", fmt.Errorf("%w: truncated Joliet surrogate", ErrCorrupt)
			}
			next := binary.BigEndian.Uint16(value[index+2 : index+4])
			if next < 0xdc00 || next > 0xdfff {
				return "", fmt.Errorf("%w: invalid Joliet surrogate", ErrCorrupt)
			}
			units = append(units, unit, next)
			index += 2
			continue
		}
		if 0xdc00 <= unit && unit <= 0xdfff {
			return "", fmt.Errorf("%w: unexpected Joliet low surrogate", ErrCorrupt)
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units)), nil
}

func stripISOFileVersion(name string) string {
	semicolon := strings.LastIndexByte(name, ';')
	if semicolon >= 0 && semicolon+1 < len(name) {
		version := name[semicolon+1:]
		numeric := true
		for _, character := range version {
			if character < '0' || character > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			name = name[:semicolon]
		}
	}
	return strings.TrimSuffix(name, ".")
}

func validatePathComponent(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 ||
		!utf8.ValidString(name) || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%w: unsafe path component %q", ErrCorrupt, name)
	}
	for _, character := range name {
		if character == utf8.RuneError || character == 0 || unicode.IsControl(character) {
			return fmt.Errorf("%w: unsafe path component %q", ErrCorrupt, name)
		}
	}
	return nil
}

func isDotIdentifier(identifier []byte) bool {
	return len(identifier) == 1 && (identifier[0] == 0 || identifier[0] == 1)
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func extentsOverlap(left []extent, right []extent) bool {
	for _, first := range left {
		firstEnd := first.offset + first.length
		for _, second := range right {
			secondEnd := second.offset + second.length
			if first.length > 0 && second.length > 0 &&
				first.offset < secondEnd && second.offset < firstEnd {
				return true
			}
		}
	}
	return false
}

func equalExtents(left []extent, right []extent) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func extentSize(items []extent) int64 {
	var size int64
	for _, item := range items {
		size += item.length
	}
	return size
}
