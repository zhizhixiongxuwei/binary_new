package iso9660

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	nmContinue = byte(0x01)
	slContinue = byte(0x01)

	slComponentContinue = byte(0x01)
	slComponentCurrent  = byte(0x02)
	slComponentParent   = byte(0x04)
	slComponentRoot     = byte(0x08)

	maxSymlinkTargetBytes = 4096
)

type symlinkState struct {
	seen       bool
	continuing bool
	absolute   bool
	components []string
	fragment   []byte
}

func parseRockRidge(systemUse []byte, skip int) (rockRidge, error) {
	var result rockRidge
	if len(systemUse) == 0 || len(systemUse) <= skip {
		return result, nil
	}
	if skip < 0 || skip > 32 {
		return result, fmt.Errorf("%w: invalid SUSP skip", ErrCorrupt)
	}
	data := systemUse[skip:]
	var name bytes.Buffer
	nameSeen := false
	nameContinuing := false
	link := symlinkState{}

	for len(data) > 0 {
		if data[0] == 0 {
			if !allZero(data) {
				return rockRidge{}, fmt.Errorf("%w: invalid SUSP padding", ErrCorrupt)
			}
			break
		}
		if len(data) < 4 {
			return rockRidge{}, fmt.Errorf("%w: truncated SUSP entry", ErrCorrupt)
		}
		entryLength := int(data[2])
		if entryLength < 4 || entryLength > len(data) {
			return rockRidge{}, fmt.Errorf("%w: invalid SUSP entry length", ErrCorrupt)
		}
		entry := data[:entryLength]
		signature := string(entry[:2])
		if entry[3] != 1 {
			switch signature {
			case "NM", "PX", "SL", "CE", "SP", "ST":
				return rockRidge{}, fmt.Errorf("%w: unsupported SUSP entry version", ErrCorrupt)
			}
		}
		switch signature {
		case "ST":
			if entryLength != 4 {
				return rockRidge{}, fmt.Errorf("%w: invalid SUSP terminator", ErrCorrupt)
			}
			data = nil
			continue
		case "SP":
			if entryLength != 7 || entry[4] != 0xbe || entry[5] != 0xef {
				return rockRidge{}, fmt.Errorf("%w: invalid SUSP SP entry", ErrCorrupt)
			}
		case "CE":
			// Continuation areas are deliberately not followed. Structural
			// validation still prevents a malformed CE from being mistaken for
			// inline data; inline NM/PX/SL remain fully supported.
			if entryLength != 28 {
				return rockRidge{}, fmt.Errorf("%w: invalid SUSP continuation entry", ErrCorrupt)
			}
			for offset := 4; offset < 28; offset += 8 {
				if _, err := bothEndian32(entry[offset : offset+8]); err != nil {
					return rockRidge{}, fmt.Errorf("%w: invalid SUSP continuation address", ErrCorrupt)
				}
			}
		case "NM":
			if entryLength < 5 || entry[4]&^nmContinue != 0 ||
				(nameSeen && !nameContinuing) {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge NM entry", ErrCorrupt)
			}
			nameSeen = true
			if name.Len()+len(entry[5:]) > 255 {
				return rockRidge{}, fmt.Errorf("%w: Rock Ridge name is too long", ErrCorrupt)
			}
			_, _ = name.Write(entry[5:])
			nameContinuing = entry[4]&nmContinue != 0
		case "PX":
			if result.hasPX || entryLength < 36 {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge PX entry", ErrCorrupt)
			}
			mode, err := bothEndian32(entry[4:12])
			if err != nil {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge PX mode", ErrCorrupt)
			}
			if _, err := bothEndian32(entry[12:20]); err != nil {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge PX link count", ErrCorrupt)
			}
			uid, err := bothEndian32(entry[20:28])
			if err != nil {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge PX uid", ErrCorrupt)
			}
			gid, err := bothEndian32(entry[28:36])
			if err != nil {
				return rockRidge{}, fmt.Errorf("%w: invalid Rock Ridge PX gid", ErrCorrupt)
			}
			result.mode = mode
			result.uid = uid
			result.gid = gid
			result.hasPX = true
		case "SL":
			if err := link.consume(entry); err != nil {
				return rockRidge{}, err
			}
		}
		data = data[entryLength:]
	}
	if nameContinuing {
		return rockRidge{}, fmt.Errorf("%w: unterminated Rock Ridge NM name", ErrCorrupt)
	}
	if nameSeen {
		result.name = name.String()
		if err := validatePathComponent(result.name); err != nil {
			return rockRidge{}, err
		}
		result.hasName = true
	}
	if link.continuing || len(link.fragment) != 0 {
		return rockRidge{}, fmt.Errorf("%w: unterminated Rock Ridge SL target", ErrCorrupt)
	}
	if link.seen {
		if link.absolute {
			result.symlinkTarget = "/" + strings.Join(link.components, "/")
		} else {
			result.symlinkTarget = strings.Join(link.components, "/")
		}
		if result.symlinkTarget == "" {
			return rockRidge{}, fmt.Errorf("%w: empty Rock Ridge SL target", ErrCorrupt)
		}
		if len(result.symlinkTarget) > maxSymlinkTargetBytes {
			return rockRidge{}, fmt.Errorf("%w: Rock Ridge SL target is too long", ErrCorrupt)
		}
		result.hasSL = true
	}
	return result, nil
}

func (state *symlinkState) consume(entry []byte) error {
	if len(entry) < 5 || entry[4]&^slContinue != 0 ||
		(state.seen && !state.continuing) {
		return fmt.Errorf("%w: invalid Rock Ridge SL entry", ErrCorrupt)
	}
	state.seen = true
	components := entry[5:]
	for len(components) > 0 {
		if len(components) < 2 {
			return fmt.Errorf("%w: truncated Rock Ridge SL component", ErrCorrupt)
		}
		flags := components[0]
		length := int(components[1])
		if length > len(components)-2 {
			return fmt.Errorf("%w: invalid Rock Ridge SL component length", ErrCorrupt)
		}
		value := components[2 : 2+length]
		components = components[2+length:]
		special := flags &^ slComponentContinue
		if special != 0 {
			if flags&slComponentContinue != 0 || length != 0 ||
				special != slComponentCurrent &&
					special != slComponentParent &&
					special != slComponentRoot {
				return fmt.Errorf("%w: unsupported Rock Ridge SL component", ErrCorrupt)
			}
			if len(state.fragment) != 0 {
				return fmt.Errorf("%w: special SL component interrupts a fragment", ErrCorrupt)
			}
			switch special {
			case slComponentCurrent:
				state.components = append(state.components, ".")
			case slComponentParent:
				state.components = append(state.components, "..")
			case slComponentRoot:
				if state.absolute || len(state.components) != 0 {
					return fmt.Errorf("%w: misplaced Rock Ridge SL root", ErrCorrupt)
				}
				state.absolute = true
			}
			continue
		}
		state.fragment = append(state.fragment, value...)
		if len(state.fragment) > maxSymlinkTargetBytes {
			return fmt.Errorf("%w: Rock Ridge SL target is too long", ErrCorrupt)
		}
		if flags&slComponentContinue != 0 {
			continue
		}
		part := string(state.fragment)
		if err := validateLinkComponent(part); err != nil {
			return err
		}
		state.components = append(state.components, part)
		state.fragment = state.fragment[:0]
	}
	state.continuing = entry[4]&slContinue != 0
	return nil
}

func validateLinkComponent(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "/\\") {
		return fmt.Errorf("%w: unsafe Rock Ridge SL component", ErrCorrupt)
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 || unicode.IsControl(character) {
			return fmt.Errorf("%w: unsafe Rock Ridge SL component", ErrCorrupt)
		}
	}
	return nil
}
