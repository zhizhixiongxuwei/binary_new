package filetype

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

const maxDebianVersionBytes = int64(4 << 10)

func detectAR(reader *boundedReader) (Result, bool, error) {
	magic, ok, err := reader.readAt(0, 8)
	if err != nil || !ok || !bytes.Equal(magic, []byte("!<arch>\n")) {
		return Result{}, false, err
	}
	offset := int64(8)
	entries := 0
	hasDebianVersion := false
	debianVersion := ""
	hasControl := false
	hasData := false
	debianOrderValid := true
	for entries < maxArchiveEntries && offset <= reader.size-60 {
		header, ok, err := reader.readAt(offset, 60)
		if err != nil || !ok {
			return Result{}, false, err
		}
		if !bytes.Equal(header[58:60], []byte("`\n")) {
			return Result{}, false, nil
		}
		name := strings.TrimSpace(string(header[:16]))
		name = strings.TrimSuffix(name, "/")
		length, parseErr := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if parseErr != nil || length < 0 || offset > reader.size-60-length {
			return Result{}, false, nil
		}
		entries++
		switch {
		case name == "debian-binary":
			if length <= 0 || length > maxDebianVersionBytes {
				debianOrderValid = false
				break
			}
			content, contentOK, readErr := reader.readAt(offset+60, length)
			if readErr != nil {
				return Result{}, false, readErr
			}
			debianVersion, hasDebianVersion = parseDebianBinaryVersion(content)
			hasDebianVersion = entries == 1 && contentOK && hasDebianVersion
		case validDebianMember(name, "control.tar"):
			if !hasDebianVersion || hasControl || hasData {
				debianOrderValid = false
			}
			hasControl = true
		case validDebianMember(name, "data.tar"):
			if !hasControl || hasData {
				debianOrderValid = false
			}
			hasData = true
		default:
			if !hasData && !strings.HasPrefix(name, "_") {
				debianOrderValid = false
			}
		}
		next := offset + 60 + length
		if next&1 != 0 {
			next++
		}
		if next <= offset || next > reader.size {
			return Result{}, false, nil
		}
		offset = next
	}
	metadata := map[string]any{"entries": entries}
	if entries == maxArchiveEntries && offset < reader.size {
		metadata["classification_limited"] = true
		return result("ar", "application/x-archive", "", metadata), true, nil
	}
	if offset == reader.size &&
		debianOrderValid && hasDebianVersion && hasControl && hasData {
		metadata["version"] = debianVersion
		return result("deb", "application/vnd.debian.binary-package", "", metadata), true, nil
	}
	return result("ar", "application/x-archive", "", metadata), true, nil
}

func parseDebianBinaryVersion(content []byte) (string, bool) {
	if len(content) == 0 || int64(len(content)) > maxDebianVersionBytes ||
		content[len(content)-1] != '\n' || bytes.IndexByte(content, 0) >= 0 {
		return "", false
	}
	lineEnd := bytes.IndexByte(content, '\n')
	if lineEnd < 3 || content[0] != '2' || content[1] != '.' {
		return "", false
	}
	for _, value := range content[2:lineEnd] {
		if value < '0' || value > '9' {
			return "", false
		}
	}
	return string(content[:lineEnd]), true
}

func validDebianMember(name, base string) bool {
	if name == base {
		return true
	}
	suffixes := []string{".gz", ".xz", ".zst"}
	if base == "data.tar" {
		suffixes = append(suffixes, ".bz2", ".lzma")
	}
	for _, suffix := range suffixes {
		if name == base+suffix {
			return true
		}
	}
	return false
}

func detectRPM(reader *boundedReader) (Result, bool, error) {
	magic, ok, err := reader.readAt(0, 4)
	if err != nil || !ok ||
		!bytes.Equal(magic, []byte{0xed, 0xab, 0xee, 0xdb}) {
		return Result{}, false, err
	}
	// Header parsing is intentionally deferred. A fixed magic probe keeps
	// classification stable for corrupt packages and adversarial headers.
	return result(
		"rpm",
		"application/x-rpm",
		"",
		map[string]any{
			"probe":               "lead_magic",
			"metadata_validation": "deferred_to_extractor",
		},
	), true, nil
}

func detectCPIO(reader *boundedReader) (Result, bool, error) {
	magic, ok, err := reader.readAt(0, 6)
	if err != nil || !ok {
		return Result{}, false, err
	}
	if bytes.Equal(magic, []byte("070701")) ||
		bytes.Equal(magic, []byte("070702")) {
		header, ok, err := reader.readAt(0, 110)
		if err != nil || !ok {
			return Result{}, false, err
		}
		for _, field := range [][]byte{
			header[6:14], header[14:22], header[22:30], header[30:38],
			header[38:46], header[46:54], header[54:62], header[62:70],
			header[70:78], header[78:86], header[86:94], header[94:102],
			header[102:110],
		} {
			if _, parseErr := strconv.ParseUint(string(field), 16, 32); parseErr != nil {
				return Result{}, false, nil
			}
		}
		nameSize, _ := strconv.ParseUint(string(header[94:102]), 16, 32)
		if nameSize == 0 || nameSize > uint64(reader.size-110) {
			return Result{}, false, nil
		}
		name, nameOK, readErr := reader.readAt(110, int64(nameSize))
		if readErr != nil || !nameOK {
			return Result{}, false, readErr
		}
		if name[len(name)-1] != 0 {
			return Result{}, false, nil
		}
		return result("cpio", "application/x-cpio", "", map[string]any{
			"encoding": string(header[:6]),
		}), true, nil
	}
	if bytes.Equal(magic, []byte("070707")) {
		short, ok, err := reader.readAt(0, 76)
		if err != nil || !ok {
			return Result{}, false, err
		}
		for offset := 6; offset < 76; offset++ {
			if short[offset] < '0' || short[offset] > '7' {
				return Result{}, false, nil
			}
		}
		return result("cpio", "application/x-cpio", "", map[string]any{
			"encoding": "odc",
		}), true, nil
	}
	if binary.LittleEndian.Uint16(magic[:2]) == 0x71c7 ||
		binary.BigEndian.Uint16(magic[:2]) == 0x71c7 {
		short, ok, err := reader.readAt(0, 26)
		if err != nil || !ok {
			return Result{}, false, err
		}
		var order binary.ByteOrder = binary.LittleEndian
		if binary.BigEndian.Uint16(short[:2]) == 0x71c7 {
			order = binary.BigEndian
		}
		nameSize := uint64(order.Uint16(short[20:22]))
		fileSize := uint64(order.Uint16(short[22:24]))<<16 |
			uint64(order.Uint16(short[24:26]))
		if nameSize == 0 || 26+nameSize > uint64(reader.size) ||
			fileSize > uint64(reader.size)-26-nameSize {
			return Result{}, false, nil
		}
		name, nameOK, readErr := reader.readAt(26, int64(nameSize))
		if readErr != nil || !nameOK {
			return Result{}, false, readErr
		}
		if name[len(name)-1] != 0 {
			return Result{}, false, nil
		}
		return result("cpio", "application/x-cpio", "", map[string]any{
			"encoding": "binary",
		}), true, nil
	}
	return Result{}, false, nil
}

func detectCAB(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 36)
	if err != nil || !ok || !bytes.Equal(header[:4], []byte("MSCF")) {
		return Result{}, false, err
	}
	cabinetSize := binary.LittleEndian.Uint32(header[8:12])
	filesOffset := binary.LittleEndian.Uint32(header[16:20])
	if !allZero(header[4:8]) || !allZero(header[12:16]) ||
		!allZero(header[20:24]) ||
		cabinetSize < 36 || int64(cabinetSize) > reader.size ||
		filesOffset < 36 || filesOffset >= cabinetSize ||
		header[24] == 0 || header[25] == 0 {
		return Result{}, false, nil
	}
	return result("cab", "application/vnd.ms-cab-compressed", "", map[string]any{
		"version": strconv.Itoa(int(header[25])) + "." + strconv.Itoa(int(header[24])),
		"folders": binary.LittleEndian.Uint16(header[26:28]),
		"files":   binary.LittleEndian.Uint16(header[28:30]),
	}), true, nil
}

func min64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
