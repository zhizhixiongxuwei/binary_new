package filetype

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

type diskPartitionRange struct {
	first   uint64
	sectors uint64
}

func detectSquashFS(reader *boundedReader) (Result, bool, error) {
	header, ok, err := reader.readAt(0, 96)
	if err != nil || !ok {
		return Result{}, false, err
	}
	var order binary.ByteOrder
	endian := ""
	switch string(header[:4]) {
	case "hsqs":
		order, endian = binary.LittleEndian, "little"
	case "sqsh":
		order, endian = binary.BigEndian, "big"
	default:
		return Result{}, false, nil
	}
	major := order.Uint16(header[28:30])
	blockSize := order.Uint32(header[12:16])
	blockLog := order.Uint16(header[22:24])
	compression := order.Uint16(header[20:22])
	bytesUsed := order.Uint64(header[40:48])
	if major != 4 || blockSize < 4096 || blockSize > 1<<20 ||
		blockSize&(blockSize-1) != 0 || uint32(1)<<blockLog != blockSize ||
		compression < 1 || compression > 6 ||
		bytesUsed < 96 || bytesUsed > uint64(reader.size) {
		return Result{}, false, nil
	}
	return result("squashfs", "application/vnd.squashfs", "", map[string]any{
		"endianness":  endian,
		"version":     fmt.Sprintf("%d.%d", major, order.Uint16(header[30:32])),
		"block_size":  blockSize,
		"compression": compression,
	}), true, nil
}

func detectExt(reader *boundedReader) (Result, bool, error) {
	superblock, ok, err := reader.readAt(1024, 1024)
	if err != nil || !ok ||
		binary.LittleEndian.Uint16(superblock[0x38:0x3a]) != 0xef53 {
		return Result{}, false, err
	}
	inodes := binary.LittleEndian.Uint32(superblock[0:4])
	blocks := binary.LittleEndian.Uint32(superblock[4:8])
	logBlockSize := binary.LittleEndian.Uint32(superblock[0x18:0x1c])
	inodeSize := binary.LittleEndian.Uint16(superblock[0x58:0x5a])
	if inodes == 0 || blocks == 0 || logBlockSize > 6 ||
		(inodeSize != 0 && (inodeSize < 128 || inodeSize > 4096 ||
			inodeSize&(inodeSize-1) != 0)) {
		return Result{}, false, nil
	}
	compat := binary.LittleEndian.Uint32(superblock[0x5c:0x60])
	incompat := binary.LittleEndian.Uint32(superblock[0x60:0x64])
	readOnlyCompat := binary.LittleEndian.Uint32(superblock[0x64:0x68])
	format := "ext2"
	if compat&0x4 != 0 {
		format = "ext3"
	}
	if incompat&(0x40|0x80) != 0 || readOnlyCompat&0x200 != 0 {
		format = "ext4"
	}
	return result(format, "application/vnd.linux.ext-filesystem", "", map[string]any{
		"block_size": uint64(1024) << logBlockSize,
		"inodes":     inodes,
		"blocks":     blocks,
	}), true, nil
}

func detectOpticalImage(reader *boundedReader) (Result, bool, error) {
	const sectorSize int64 = 2048
	hasISO := false
	hasBEA := false
	hasTEA := false
	udfRevision := ""
	for sector := int64(16); sector <= 256; sector++ {
		offset := sector * sectorSize
		descriptor, ok, err := reader.readAt(offset, 7)
		if err != nil {
			return Result{}, false, err
		}
		if !ok {
			break
		}
		if descriptor[0] >= 1 && descriptor[0] <= 3 &&
			bytes.Equal(descriptor[1:6], []byte("CD001")) &&
			descriptor[6] == 1 {
			hasISO = true
		}
		identifier := string(descriptor[1:6])
		switch identifier {
		case "BEA01":
			hasBEA = true
		case "NSR02", "NSR03":
			if hasBEA {
				udfRevision = identifier
			}
		case "TEA01":
			if udfRevision != "" {
				hasTEA = true
			}
		}
	}
	if hasBEA && hasTEA && udfRevision != "" {
		return result("udf", "application/vnd.osta-udf", "", map[string]any{
			"revision": udfRevision,
		}), true, nil
	}
	if hasISO {
		return result("iso9660", "application/x-iso9660-image", "", nil), true, nil
	}
	return Result{}, false, nil
}

func detectDiskImage(reader *boundedReader) (Result, bool, error) {
	mbr, ok, err := reader.readAt(0, 512)
	if err != nil || !ok || !bytes.Equal(mbr[510:512], []byte{0x55, 0xaa}) {
		return Result{}, false, err
	}
	validPartitions := 0
	protectiveGPT := false
	partitions := make([]diskPartitionRange, 0, 4)
	for index := 0; index < 4; index++ {
		entry := mbr[446+index*16 : 446+(index+1)*16]
		if entry[0] != 0 && entry[0] != 0x80 {
			return Result{}, false, nil
		}
		partitionType := entry[4]
		firstLBA := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		sectors := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		if partitionType == 0 && firstLBA == 0 && sectors == 0 {
			continue
		}
		if partitionType == 0 || sectors == 0 {
			return Result{}, false, nil
		}
		partitions = append(partitions, diskPartitionRange{
			first: firstLBA, sectors: sectors,
		})
		validPartitions++
		if partitionType == 0xee && firstLBA == 1 {
			protectiveGPT = true
		}
	}
	if validPartitions == 0 {
		return Result{}, false, nil
	}
	if protectiveGPT {
		for _, sectorSize := range []uint64{512, 4096} {
			totalSectors := uint64(reader.size) / sectorSize
			if !partitionRangesFit(partitions, totalSectors) {
				continue
			}
			gpt, valid, readErr := readGPTHeader(
				reader,
				totalSectors,
				sectorSize,
			)
			if readErr != nil {
				return Result{}, false, readErr
			}
			if valid {
				return gpt, true, nil
			}
		}
		return Result{}, false, nil
	}
	if !partitionRangesFit(partitions, uint64(reader.size/512)) {
		return Result{}, false, nil
	}
	return result("mbr-img", "application/x-raw-disk-image", "", map[string]any{
		"partition_table": "mbr",
		"partitions":      validPartitions,
		"sector_size":     512,
	}), true, nil
}

func partitionRangesFit(
	partitions []diskPartitionRange,
	totalSectors uint64,
) bool {
	if totalSectors == 0 {
		return false
	}
	for _, partition := range partitions {
		if partition.first >= totalSectors ||
			partition.sectors > totalSectors-partition.first {
			return false
		}
	}
	return true
}

func readGPTHeader(
	reader *boundedReader,
	totalSectors uint64,
	sectorSize uint64,
) (Result, bool, error) {
	offset := int64(sectorSize)
	fixed, ok, err := reader.readAt(offset, 92)
	if err != nil || !ok || !bytes.Equal(fixed[:8], []byte("EFI PART")) {
		return Result{}, false, err
	}
	headerSize := binary.LittleEndian.Uint32(fixed[12:16])
	if binary.LittleEndian.Uint32(fixed[8:12]) != 0x00010000 ||
		headerSize < 92 || uint64(headerSize) > sectorSize {
		return Result{}, false, nil
	}
	header, ok, err := reader.readAt(offset, int64(headerSize))
	if err != nil || !ok {
		return Result{}, false, err
	}
	expectedCRC := binary.LittleEndian.Uint32(header[16:20])
	copyForCRC := append([]byte(nil), header...)
	clear(copyForCRC[16:20])
	if crc32.ChecksumIEEE(copyForCRC) != expectedCRC {
		return Result{}, false, nil
	}
	currentLBA := binary.LittleEndian.Uint64(header[24:32])
	backupLBA := binary.LittleEndian.Uint64(header[32:40])
	firstUsable := binary.LittleEndian.Uint64(header[40:48])
	lastUsable := binary.LittleEndian.Uint64(header[48:56])
	entryLBA := binary.LittleEndian.Uint64(header[72:80])
	entryCount := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])
	if currentLBA != 1 || backupLBA >= totalSectors ||
		firstUsable > lastUsable || lastUsable >= totalSectors ||
		entryLBA < 2 || entryLBA >= totalSectors ||
		entryCount == 0 || entryCount > 1_000_000 ||
		entrySize < 128 || entrySize > 4096 || entrySize%8 != 0 {
		return Result{}, false, nil
	}
	if entryLBA > ^uint64(0)/sectorSize {
		return Result{}, false, nil
	}
	entryOffset := entryLBA * sectorSize
	entryBytes := uint64(entryCount) * uint64(entrySize)
	if entryOffset > uint64(reader.size) ||
		entryBytes > uint64(reader.size)-entryOffset {
		return Result{}, false, nil
	}
	return result("gpt-img", "application/x-raw-disk-image", "", map[string]any{
		"partition_table":  "gpt",
		"partition_slots":  entryCount,
		"partition_stride": entrySize,
		"sector_size":      sectorSize,
	}), true, nil
}
