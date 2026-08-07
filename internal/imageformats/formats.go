// Package imageformats adapts the built-in read-only image parsers to the
// common imageextract contract.
package imageformats

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"binaryscan/internal/diskimage"
	"binaryscan/internal/imageextract"
	"binaryscan/internal/iso9660"

	"golang.org/x/text/unicode/norm"
)

// RegisterBuiltins registers every in-process image parser. The adapters only
// read from the bounded source supplied by imageextract; they never mount an
// image or attach a host loop device.
func RegisterBuiltins(
	registry *imageextract.Registry,
	limits imageextract.Limits,
) error {
	if registry == nil {
		return fmt.Errorf("imageformats: registry is nil")
	}
	iso := isoExtractor{limits: limits}
	for _, format := range []string{"iso9660"} {
		if err := registry.Register(format, iso); err != nil {
			return err
		}
	}
	disk := diskExtractor{limits: limits}
	for _, format := range []string{"raw-img", "mbr-img", "gpt-img"} {
		if err := registry.Register(format, disk); err != nil {
			return err
		}
	}
	return nil
}

type isoExtractor struct {
	limits imageextract.Limits
}

func (extractor isoExtractor) Extract(
	ctx context.Context,
	request imageextract.Request,
	sink imageextract.Sink,
) error {
	reader, openErr := iso9660.Open(
		ctx,
		request.Source,
		request.SizeBytes,
		iso9660.Limits{
			MaxNodes:   extractor.limits.MaxEntries,
			MaxDepth:   extractor.limits.MaxDepth,
			MaxExtents: extractor.limits.MaxExtents,
			MaxBytes:   extractor.limits.MaxExpandedBytes,
		},
	)
	if reader == nil {
		return mapISOError(openErr)
	}

	identifiers := make(map[string]uint64)
	for _, item := range reader.Entries() {
		if err := ctx.Err(); err != nil {
			return err
		}
		identifier := uint64(len(identifiers) + 1)
		parentID := uint64(0)
		parentPath := path.Dir(item.Path)
		if parentPath != "." {
			var found bool
			parentID, found = identifiers[parentPath]
			if !found {
				return fmt.Errorf(
					"%w: ISO parent %q was not indexed",
					imageextract.ErrCorruptImage,
					parentPath,
				)
			}
		}
		normalizedPath := norm.NFC.String(item.Path)
		entry := imageextract.Entry{
			ID:          identifier,
			ParentID:    parentID,
			LogicalPath: "/" + normalizedPath,
			Kind:        isoEntryKind(item.Type),
			LinkTarget:  item.SymlinkTarget,
			Depth:       request.Depth + strings.Count(item.Path, "/") + 1,
			SizeBytes:   item.Size,
		}
		if item.Type == iso9660.TypeFile && item.Size > 0 {
			extents, extentErr := reader.Extents(item.Path)
			if extentErr != nil {
				return fmt.Errorf(
					"%w: read ISO extents for %q: %v",
					imageextract.ErrCorruptImage,
					item.Path,
					extentErr,
				)
			}
			entry.Extents = make([]imageextract.Extent, len(extents))
			for index, extent := range extents {
				entry.Extents[index] = imageextract.Extent{
					OffsetBytes: extent.OffsetBytes,
					SizeBytes:   extent.SizeBytes,
				}
			}
		}
		if err := sink.AddEntry(entry); err != nil {
			return err
		}
		identifiers[item.Path] = identifier
	}
	if openErr != nil {
		return mapISOError(openErr)
	}
	return nil
}

func isoEntryKind(value iso9660.EntryType) imageextract.EntryKind {
	switch value {
	case iso9660.TypeFile:
		return imageextract.EntryFile
	case iso9660.TypeDirectory:
		return imageextract.EntryDirectory
	case iso9660.TypeSymlink:
		return imageextract.EntrySymlink
	default:
		return imageextract.EntrySpecial
	}
}

func mapISOError(err error) error {
	var limit *iso9660.LimitError
	if errors.As(err, &limit) {
		code := imageextract.LimitMaxExpandedBytes
		switch limit.Limit {
		case iso9660.LimitNodes:
			code = imageextract.LimitMaxEntries
		case iso9660.LimitDepth:
			code = imageextract.LimitMaxDepth
		case iso9660.LimitExtents:
			code = imageextract.LimitMaxExtents
		case iso9660.LimitBytes:
			code = imageextract.LimitMaxExpandedBytes
		}
		return &imageextract.LimitError{Code: code}
	}
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %v", imageextract.ErrCorruptImage, err)
}

type diskExtractor struct {
	limits imageextract.Limits
}

func (extractor diskExtractor) Extract(
	ctx context.Context,
	request imageextract.Request,
	sink imageextract.Sink,
) error {
	result, err := diskimage.Parse(
		ctx,
		request.Source,
		request.SizeBytes,
		diskimage.Options{MaxPartitions: extractor.limits.MaxPartitions},
	)
	limitReached := errors.Is(err, diskimage.ErrLimit)
	if err != nil && !limitReached {
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("%w: %v", imageextract.ErrCorruptImage, err)
	}
	if limitReached && result.Table == "" {
		return &imageextract.LimitError{
			Code: imageextract.LimitMaxPartitions,
		}
	}
	wanted := imageextractFormatTable(request.Format)
	if wanted != "" && result.Table != wanted {
		return fmt.Errorf(
			"%w: expected %s partition table, found %s",
			imageextract.ErrCorruptImage,
			wanted,
			result.Table,
		)
	}
	for _, item := range result.Partitions {
		if err := sink.AddPartition(imageextract.Partition{
			ID:               fmt.Sprintf("partition-%d", item.Index),
			Index:            uint32(item.Index),
			Scheme:           string(item.Table),
			Type:             item.Type,
			StartOffsetBytes: item.OffsetBytes,
			SizeBytes:        item.SizeBytes,
		}); err != nil {
			return err
		}
	}
	if limitReached {
		return &imageextract.LimitError{
			Code: imageextract.LimitMaxPartitions,
		}
	}
	if result.Partial {
		code := "partition_table_partial"
		if len(result.Diagnostics) > 0 {
			code = result.Diagnostics[0].Code
		}
		return fmt.Errorf(
			"%w: %s",
			imageextract.ErrCorruptImage,
			code,
		)
	}
	return nil
}

func imageextractFormatTable(format string) diskimage.TableKind {
	switch format {
	case "mbr-img":
		return diskimage.TableMBR
	case "gpt-img":
		return diskimage.TableGPT
	case "raw-img":
		return diskimage.TableRaw
	default:
		return ""
	}
}
