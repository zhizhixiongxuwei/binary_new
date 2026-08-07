package filetype

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
)

type identificationCandidate struct {
	Format   string `json:"format"`
	Category string `json:"category"`
	MIMEType string `json:"mime_type"`
	Evidence string `json:"evidence"`
}

type candidateDescriptor struct {
	category string
	mimeType string
	evidence string
}

// candidateDescriptors is intentionally static. Candidate evidence is a
// controlled vocabulary and can never contain bytes or names from the sample.
var candidateDescriptors = map[string]candidateDescriptor{
	"7z": {
		category: "archive", mimeType: "application/x-7z-compressed",
		evidence: "seven_zip_start_and_next_header_crc",
	},
	"apk": {
		category: "zip-derived", mimeType: "application/vnd.android.package-archive",
		evidence: "zip_directory_and_android_manifest_entry",
	},
	"ar": {
		category: "archive", mimeType: "application/x-archive",
		evidence: "ar_member_header_chain",
	},
	"bzip2": {
		category: "compression", mimeType: "application/x-bzip2",
		evidence: "bzip2_stream_and_block_header",
	},
	"cab": {
		category: "archive", mimeType: "application/vnd.ms-cab-compressed",
		evidence: "cabinet_header_and_file_table_bounds",
	},
	"cpio": {
		category: "archive", mimeType: "application/x-cpio",
		evidence: "cpio_header_fields_and_name_bounds",
	},
	"deb": {
		category: "ar-derived", mimeType: "application/vnd.debian.binary-package",
		evidence: "ar_members_and_debian_package_order",
	},
	"dex": {
		category: "bytecode", mimeType: "application/vnd.android.dex",
		evidence: "dex_version_header_and_container_bounds",
	},
	"docker-tar": {
		category: "container-image", mimeType: "application/vnd.docker.image.rootfs.diff.tar",
		evidence: "tar_chain_and_docker_manifest_references",
	},
	"ear": {
		category: "zip-derived", mimeType: "application/java-archive",
		evidence: "zip_directory_and_ear_application_entry",
	},
	"elf32": {
		category: "executable", mimeType: "application/x-elf",
		evidence: "elf_header_and_bounded_program_tables",
	},
	"elf64": {
		category: "executable", mimeType: "application/x-elf",
		evidence: "elf_header_and_bounded_program_tables",
	},
	"ext2": {
		category: "filesystem-image", mimeType: "application/vnd.linux.ext-filesystem",
		evidence: "ext_superblock_and_geometry_fields",
	},
	"ext3": {
		category: "filesystem-image", mimeType: "application/vnd.linux.ext-filesystem",
		evidence: "ext_superblock_journal_feature_and_geometry",
	},
	"ext4": {
		category: "filesystem-image", mimeType: "application/vnd.linux.ext-filesystem",
		evidence: "ext_superblock_ext4_features_and_geometry",
	},
	"gpt-img": {
		category: "disk-image", mimeType: "application/x-raw-disk-image",
		evidence: "protective_mbr_and_gpt_header_crc_bounds",
	},
	"gzip": {
		category: "compression", mimeType: "application/gzip",
		evidence: "gzip_header_fields_and_trailer_bounds",
	},
	"iso9660": {
		category: "optical-image", mimeType: "application/x-iso9660-image",
		evidence: "iso9660_volume_descriptor_sequence",
	},
	"jar": {
		category: "zip-derived", mimeType: "application/java-archive",
		evidence: "zip_directory_and_jar_manifest_entry",
	},
	"java-class": {
		category: "bytecode", mimeType: "application/java-vm",
		evidence: "java_constant_pool_members_and_attributes",
	},
	"macho-fat": {
		category: "executable", mimeType: "application/x-mach-binary",
		evidence: "mach_fat_table_and_validated_thin_slices",
	},
	"macho-thin": {
		category: "executable", mimeType: "application/x-mach-binary",
		evidence: "mach_header_and_load_command_table",
	},
	"mbr-img": {
		category: "disk-image", mimeType: "application/x-raw-disk-image",
		evidence: "mbr_signature_and_partition_bounds",
	},
	"oci-tar": {
		category: "container-image", mimeType: "application/vnd.oci.image.layout.v1+tar",
		evidence: "tar_chain_oci_layout_index_and_blob_references",
	},
	"pe32": {
		category: "executable", mimeType: "application/vnd.microsoft.portable-executable",
		evidence: "pe_coff_optional_and_section_tables",
	},
	"pe32+": {
		category: "executable", mimeType: "application/vnd.microsoft.portable-executable",
		evidence: "pe_coff_optional_and_section_tables",
	},
	"pyc": {
		category: "bytecode", mimeType: "application/x-python-bytecode",
		evidence: "cpython_magic_header_and_code_object_marker",
	},
	"rar": {
		category: "archive", mimeType: "application/vnd.rar",
		evidence: "rar_archive_header_structure",
	},
	"rpm": {
		category: "package", mimeType: "application/x-rpm",
		evidence: "rpm_lead_signature_and_main_header_tables",
	},
	"squashfs": {
		category: "filesystem-image", mimeType: "application/vnd.squashfs",
		evidence: "squashfs_superblock_and_storage_bounds",
	},
	"tar": {
		category: "archive", mimeType: "application/x-tar",
		evidence: "tar_header_chain_and_entry_bounds",
	},
	"udf": {
		category: "optical-image", mimeType: "application/vnd.osta-udf",
		evidence: "udf_volume_recognition_sequence",
	},
	"war": {
		category: "zip-derived", mimeType: "application/java-archive",
		evidence: "zip_directory_and_web_application_entry",
	},
	"xz": {
		category: "compression", mimeType: "application/x-xz",
		evidence: "xz_stream_header_flags_and_crc",
	},
	"zip": {
		category: "archive", mimeType: "application/zip",
		evidence: "zip_eocd_central_directory_and_local_headers",
	},
	"zstd": {
		category: "compression", mimeType: "application/zstd",
		evidence: "zstd_frame_and_block_header_bounds",
	},
}

func addIdentificationCandidates(
	primary *Result,
	reader *boundedReader,
	primaryDetector int,
) {
	primaryCandidate, strictPrimary := strictIdentificationCandidate(
		*primary,
		reader,
	)
	if !strictPrimary {
		// A deferred or limited primary is kept for backward compatibility, but
		// it cannot anchor a strict polyglot claim. Stopping here also guarantees
		// that ambiguity always means multiple strict candidates.
		primary.Metadata["identification_candidates"] =
			[]identificationCandidate{}
		return
	}
	type candidateRecord struct {
		priority  int
		candidate identificationCandidate
	}
	records := []candidateRecord{{
		priority:  primaryDetector,
		candidate: primaryCandidate,
	}}
	seen := map[string]struct{}{primaryCandidate.Format: {}}
	for index, definition := range contentDetectors {
		if index == primaryDetector || len(records) >= maxCandidates {
			continue
		}
		detect := definition.candidateDetect
		if index < primaryDetector && detect == nil {
			// The normal primary pass already rejected this verifier.
			continue
		}
		if detect == nil {
			detect = definition.detect
		}
		detected, found, err := detect(reader)
		if err != nil {
			// Supplementary probing must not turn an already validated primary
			// result into an I/O failure.
			break
		}
		if !found {
			continue
		}
		candidate, strict := strictIdentificationCandidate(detected, reader)
		if !strict {
			continue
		}
		if _, duplicate := seen[candidate.Format]; duplicate {
			continue
		}
		seen[candidate.Format] = struct{}{}
		records = append(records, candidateRecord{
			priority:  index,
			candidate: candidate,
		})
	}
	sort.Slice(records, func(left, right int) bool {
		return records[left].priority < records[right].priority
	})
	candidates := make([]identificationCandidate, len(records))
	for index, record := range records {
		candidates[index] = record.candidate
	}
	primary.Metadata["identification_candidates"] = candidates
	if len(candidates) > 1 {
		primary.Metadata["identification_ambiguous"] = true
	}
}

func detectStrictZIPCandidate(
	reader *boundedReader,
) (Result, bool, error) {
	directoryOffset, directorySize, entries, valid, err := zipDirectory(reader)
	if err != nil {
		if errors.Is(err, errZIPMultiVolume) ||
			errors.Is(err, errZIPDeferredValidation) {
			return Result{}, false, nil
		}
		return Result{}, false, err
	}
	if !valid || entries > maxArchiveEntries ||
		directorySize > maxDirectoryBytes {
		return Result{}, false, nil
	}
	metadata := map[string]any{"entries": entries}
	if entries == 0 {
		signature, ok, readErr := reader.readAt(directoryOffset, 4)
		if readErr != nil || !ok ||
			!bytes.Equal(signature, []byte{'P', 'K', 5, 6}) {
			return Result{}, false, readErr
		}
		return result("zip", "application/zip", "", metadata), true, nil
	}
	directory, ok, err := reader.readAt(directoryOffset, directorySize)
	if err != nil || !ok {
		return Result{}, false, err
	}
	names, valid, err := zipEntryNames(reader, directory, entries)
	if err != nil || !valid {
		return Result{}, false, err
	}
	format, mimeType := classifyZIP(names)
	return result(format, mimeType, "", metadata), true, nil
}

func strictIdentificationCandidate(
	detected Result,
	reader *boundedReader,
) (identificationCandidate, bool) {
	descriptor, known := candidateDescriptors[detected.Format]
	if !known || detected.MIMEType != descriptor.mimeType {
		return identificationCandidate{}, false
	}
	if detected.Format == "rpm" {
		valid, err := verifyRPMCandidate(reader)
		if err != nil || !valid {
			return identificationCandidate{}, false
		}
	} else if detected.Metadata["classification_limited"] == true ||
		detected.Metadata["multi_volume"] == true ||
		detected.Metadata["metadata_validation"] == "deferred_to_extractor" {
		return identificationCandidate{}, false
	}
	return identificationCandidate{
		Format:   detected.Format,
		Category: descriptor.category,
		MIMEType: descriptor.mimeType,
		Evidence: descriptor.evidence,
	}, true
}

const (
	rpmLeadSize               = int64(96)
	maxRPMCandidateIndexCount = uint32(100_000)
	maxRPMCandidateStoreBytes = uint32(8 << 20)
)

type rpmCandidateHeader struct {
	nextOffset uint64
	required   map[uint32]string
}

func verifyRPMCandidate(reader *boundedReader) (bool, error) {
	lead, ok, err := reader.readAt(0, rpmLeadSize)
	if err != nil || !ok {
		return false, err
	}
	if !bytes.Equal(lead[:4], []byte{0xed, 0xab, 0xee, 0xdb}) ||
		lead[4] != 3 ||
		lead[5] > 1 ||
		binary.BigEndian.Uint16(lead[6:8]) > 1 ||
		binary.BigEndian.Uint16(lead[8:10]) == 0 ||
		binary.BigEndian.Uint16(lead[76:78]) == 0 ||
		binary.BigEndian.Uint16(lead[78:80]) != 5 ||
		!allZero(lead[80:96]) {
		return false, nil
	}
	signature, valid, err := verifyRPMCandidateHeader(
		reader,
		uint64(rpmLeadSize),
		false,
	)
	if err != nil || !valid {
		return false, err
	}
	mainOffset := alignUint64(signature.nextOffset, 8)
	main, valid, err := verifyRPMCandidateHeader(reader, mainOffset, true)
	if err != nil || !valid || main.nextOffset > uint64(reader.size) {
		return false, err
	}
	return main.required[1022] != "" &&
		main.required[1124] != "" &&
		main.required[1125] != "", nil
}

func verifyRPMCandidateHeader(
	reader *boundedReader,
	offset uint64,
	requirePackageTags bool,
) (rpmCandidateHeader, bool, error) {
	if offset > uint64(reader.size) ||
		uint64(reader.size)-offset < 16 {
		return rpmCandidateHeader{}, false, nil
	}
	header, ok, err := reader.readAt(int64(offset), 16)
	if err != nil || !ok {
		return rpmCandidateHeader{}, false, err
	}
	if !bytes.Equal(header[:4], []byte{0x8e, 0xad, 0xe8, 1}) ||
		!allZero(header[4:8]) {
		return rpmCandidateHeader{}, false, nil
	}
	indexCount := binary.BigEndian.Uint32(header[8:12])
	storeSize := binary.BigEndian.Uint32(header[12:16])
	if indexCount > maxRPMCandidateIndexCount ||
		storeSize > maxRPMCandidateStoreBytes {
		return rpmCandidateHeader{}, false, nil
	}
	indexBytes := uint64(indexCount) * 16
	totalBytes := uint64(16) + indexBytes + uint64(storeSize)
	if !uint64RangeWithin(offset, totalBytes, uint64(reader.size)) {
		return rpmCandidateHeader{}, false, nil
	}
	indexes, ok, err := reader.readAt(
		int64(offset+16),
		int64(indexBytes),
	)
	if err != nil || !ok {
		return rpmCandidateHeader{}, false, err
	}
	store, ok, err := reader.readAt(
		int64(offset+16+indexBytes),
		int64(storeSize),
	)
	if err != nil || !ok {
		return rpmCandidateHeader{}, false, err
	}
	required := make(map[uint32]string, 3)
	for index := uint32(0); index < indexCount; index++ {
		entry := indexes[index*16 : (index+1)*16]
		tag := binary.BigEndian.Uint32(entry[0:4])
		valueType := binary.BigEndian.Uint32(entry[4:8])
		valueOffset := binary.BigEndian.Uint32(entry[8:12])
		valueCount := binary.BigEndian.Uint32(entry[12:16])
		if !validRPMCandidateEntry(
			store,
			valueType,
			valueOffset,
			valueCount,
		) {
			return rpmCandidateHeader{}, false, nil
		}
		if requirePackageTags &&
			(tag == 1022 || tag == 1124 || tag == 1125) {
			if valueType != 6 || valueCount != 1 {
				return rpmCandidateHeader{}, false, nil
			}
			required[tag] = rpmCandidateString(store, valueOffset)
			if required[tag] == "" {
				return rpmCandidateHeader{}, false, nil
			}
		}
	}
	return rpmCandidateHeader{
		nextOffset: offset + totalBytes,
		required:   required,
	}, true, nil
}

func validRPMCandidateEntry(
	store []byte,
	valueType uint32,
	offset uint32,
	count uint32,
) bool {
	if uint64(offset) > uint64(len(store)) {
		return false
	}
	remaining := uint64(len(store)) - uint64(offset)
	switch valueType {
	case 0:
		return count == 0
	case 1, 2, 7:
		return uint64(count) <= remaining
	case 3:
		return uint64(count) <= remaining/2
	case 4:
		return uint64(count) <= remaining/4
	case 5:
		return uint64(count) <= remaining/8
	case 6:
		return count == 1 && rpmCandidateString(store, offset) != ""
	case 8, 9:
		if count == 0 {
			return true
		}
		value := store[offset:]
		for index := uint32(0); index < count; index++ {
			end := bytes.IndexByte(value, 0)
			if end < 0 {
				return false
			}
			value = value[end+1:]
		}
		return true
	default:
		return false
	}
}

func rpmCandidateString(store []byte, offset uint32) string {
	if uint64(offset) >= uint64(len(store)) {
		return ""
	}
	value := store[offset:]
	end := bytes.IndexByte(value, 0)
	if end <= 0 {
		return ""
	}
	for _, current := range value[:end] {
		if current < 0x20 || current > 0x7e {
			return ""
		}
	}
	return string(value[:end])
}

func alignUint64(value, alignment uint64) uint64 {
	if alignment <= 1 {
		return value
	}
	remainder := value % alignment
	if remainder == 0 {
		return value
	}
	return value + alignment - remainder
}
