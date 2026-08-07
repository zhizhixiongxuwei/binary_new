package containerarchive

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	quotaAllocationUnitBytes = int64(4 << 10)
	layerDecoderMemoryBytes  = uint64(64 << 20)

	mediaOCILayerTar             = "application/vnd.oci.image.layer.v1.tar"
	mediaOCILayerGzip            = "application/vnd.oci.image.layer.v1.tar+gzip"
	mediaOCILayerZstd            = "application/vnd.oci.image.layer.v1.tar+zstd"
	mediaOCINondistributableTar  = "application/vnd.oci.image.layer.nondistributable.v1.tar"
	mediaOCINondistributableGzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
	mediaOCINondistributableZstd = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
	mediaDockerLayerGzip         = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mediaDockerForeignLayerGzip  = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"

	flattenedIndexPrefix = `{"schemaVersion":2,"mediaType":"` +
		mediaOCIIndex + `","manifests":[`
	flattenedIndexSuffix = `]}`
)

// OCIUsage is a conservative, deduplicated storage plan for one validated OCI
// archive. MaterializedBudgetBytes includes filesystem allocation rounding and
// directory-entry charges; expanded layer values count the decoded TAR stream.
type OCIUsage struct {
	MaterializedLogicalBytes int64
	MaterializedBudgetBytes  int64
	CompressedLayerBytes     int64
	ExpandedLayerBytes       int64
	MaxTargetExpandedBytes   int64
	UniqueBlobCount          int
	UniqueLayerCount         int
	TargetCount              int
}

// EstimateUsage validates supported layer compression and bounds both the
// materialized layout and decoded layer streams before any workspace is
// created. The plan source must remain immutable, as required by Materialize.
func (plan *OCIPlan) EstimateUsage(
	ctx context.Context,
	maxBytes int64,
) (OCIUsage, error) {
	return plan.EstimateUsageWithin(ctx, maxBytes, maxBytes)
}

// EstimateUsageWithin applies independent limits to the flattened OCI layout
// and decoded layer streams. Batch callers use the remaining value for each
// dimension so a large compressed layout cannot mask a layer-expansion limit,
// or vice versa.
func (plan *OCIPlan) EstimateUsageWithin(
	ctx context.Context,
	maxMaterializedBytes int64,
	maxExpandedBytes int64,
) (OCIUsage, error) {
	if ctx == nil {
		return OCIUsage{}, errors.New("containerarchive: nil context")
	}
	if plan == nil || plan.index == nil || plan.index.source == nil ||
		len(plan.targets) == 0 ||
		maxMaterializedBytes <= 0 ||
		maxExpandedBytes <= 0 {
		return OCIUsage{}, errors.New("containerarchive: invalid OCI quota plan")
	}
	if err := ctx.Err(); err != nil {
		return OCIUsage{}, err
	}

	usage, err := plan.materializedUsage(ctx, maxMaterializedBytes)
	if err != nil {
		return OCIUsage{}, err
	}
	if usage.MaterializedBudgetBytes > maxMaterializedBytes {
		return OCIUsage{}, validationError(
			"oci_materialized_size_limit",
			"OCI materialized layout exceeds the configured temporary-space limit",
		)
	}

	type layerRecord struct {
		descriptor descriptor
		expanded   int64
	}
	layers := make(map[string]layerRecord)
	for _, target := range plan.targets {
		for _, layer := range target.layers {
			path, err := layerBlobPath(layer)
			if err != nil {
				return OCIUsage{}, err
			}
			if existing, found := layers[path]; found {
				if existing.descriptor.Size != layer.Size ||
					existing.descriptor.MediaType != layer.MediaType {
					return OCIUsage{}, validationError(
						"oci_descriptor_invalid",
						"OCI layer digest has conflicting descriptor metadata",
					)
				}
				continue
			}
			if layer.Size > maxExpandedBytes-usage.CompressedLayerBytes {
				return OCIUsage{}, validationError(
					"oci_layer_expanded_limit",
					"OCI layer data exceeds the configured expanded-data limit",
				)
			}
			usage.CompressedLayerBytes += layer.Size
			remaining := maxExpandedBytes - usage.ExpandedLayerBytes
			expandedLimit := remaining
			limitCode := "oci_layer_expanded_limit"
			if compressedLayerMediaType(layer.MediaType) {
				ratioLimit, ok := checkedMultiply(
					layer.Size,
					int64(plan.index.limits.MaxArchiveRatio),
				)
				if !ok {
					ratioLimit = math.MaxInt64
				}
				if ratioLimit < expandedLimit {
					expandedLimit = ratioLimit
					limitCode = "oci_layer_ratio_limit"
				}
			}
			expanded, err := plan.expandedLayerBytes(
				ctx,
				path,
				layer,
				expandedLimit,
				limitCode,
			)
			if err != nil {
				return OCIUsage{}, err
			}
			usage.ExpandedLayerBytes += expanded
			layers[path] = layerRecord{
				descriptor: layer,
				expanded:   expanded,
			}
		}
	}
	usage.UniqueLayerCount = len(layers)

	for _, target := range plan.targets {
		var expanded int64
		for _, layer := range target.layers {
			path, err := layerBlobPath(layer)
			if err != nil {
				return OCIUsage{}, err
			}
			value := layers[path].expanded
			if value > maxExpandedBytes-expanded {
				return OCIUsage{}, validationError(
					"oci_layer_expanded_limit",
					"OCI target layers exceed the configured expanded-data limit",
				)
			}
			expanded += value
		}
		if expanded > usage.MaxTargetExpandedBytes {
			usage.MaxTargetExpandedBytes = expanded
		}
	}
	return usage, nil
}

func (plan *OCIPlan) materializedUsage(
	ctx context.Context,
	maximum int64,
) (OCIUsage, error) {
	layoutJSON, err := json.Marshal(ociLayout{ImageLayoutVersion: "1.0.0"})
	if err != nil {
		return OCIUsage{}, fmt.Errorf("encode OCI layout marker: %w", err)
	}
	manifests := make([]descriptor, 0, len(plan.targets))
	blobPaths := make(map[string]struct{})
	for _, target := range plan.targets {
		manifests = append(manifests, target.descriptor)
		for _, blobPath := range target.blobPaths {
			blobPaths[blobPath] = struct{}{}
		}
	}
	indexSize, err := flattenedIndexSize(ctx, manifests, maximum)
	if err != nil {
		return OCIUsage{}, err
	}

	usage := OCIUsage{
		UniqueBlobCount: len(blobPaths),
		TargetCount:     len(plan.targets),
	}
	// The root layout plus blobs/sha256 account for three directories.
	usage.MaterializedBudgetBytes = 3 * quotaAllocationUnitBytes
	for _, size := range []int64{int64(len(layoutJSON)), indexSize} {
		if err := addMaterializedFile(&usage, size); err != nil {
			return OCIUsage{}, err
		}
		if usage.MaterializedBudgetBytes > maximum {
			return OCIUsage{}, validationError(
				"oci_materialized_size_limit",
				"OCI materialized layout exceeds the configured temporary-space limit",
			)
		}
	}
	for blobPath := range blobPaths {
		if err := ctx.Err(); err != nil {
			return OCIUsage{}, err
		}
		entry, err := plan.index.regular(blobPath)
		if err != nil {
			return OCIUsage{}, err
		}
		if err := addMaterializedFile(&usage, entry.size); err != nil {
			return OCIUsage{}, err
		}
		if usage.MaterializedBudgetBytes > maximum {
			return OCIUsage{}, validationError(
				"oci_materialized_size_limit",
				"OCI materialized layout exceeds the configured temporary-space limit",
			)
		}
	}
	return usage, nil
}

func flattenedIndexSize(
	ctx context.Context,
	manifests []descriptor,
	maximum int64,
) (int64, error) {
	size := int64(len(flattenedIndexPrefix) + len(flattenedIndexSuffix))
	for index, manifest := range manifests {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		content, err := json.Marshal(manifest)
		if err != nil {
			return 0, fmt.Errorf("encode flattened OCI descriptor: %w", err)
		}
		addition := int64(len(content))
		if index > 0 {
			addition++
		}
		if addition > math.MaxInt64-size {
			return 0, validationError(
				"oci_materialized_size_limit",
				"OCI materialized index size overflows",
			)
		}
		size += addition
		if size > maximum {
			return 0, validationError(
				"oci_materialized_size_limit",
				"OCI materialized layout exceeds the configured temporary-space limit",
			)
		}
	}
	return size, nil
}

func addMaterializedFile(usage *OCIUsage, size int64) error {
	if size < 0 ||
		size > math.MaxInt64-usage.MaterializedLogicalBytes {
		return validationError(
			"oci_materialized_size_limit",
			"OCI materialized layout size overflows",
		)
	}
	usage.MaterializedLogicalBytes += size
	allocated, ok := allocationCharge(size)
	if !ok ||
		allocated > math.MaxInt64-quotaAllocationUnitBytes ||
		allocated+quotaAllocationUnitBytes >
			math.MaxInt64-usage.MaterializedBudgetBytes {
		return validationError(
			"oci_materialized_size_limit",
			"OCI materialized layout budget overflows",
		)
	}
	// Charge both allocated data blocks and one metadata block per directory
	// entry. Tiny non-empty files otherwise consume their entire charge in data
	// allocation and leave inode/dentry growth unaccounted for.
	usage.MaterializedBudgetBytes += allocated + quotaAllocationUnitBytes
	return nil
}

func allocationCharge(size int64) (int64, bool) {
	if size < 0 || size > math.MaxInt64-(quotaAllocationUnitBytes-1) {
		return 0, false
	}
	rounded := (size + quotaAllocationUnitBytes - 1) &
		^(quotaAllocationUnitBytes - 1)
	if rounded == 0 {
		rounded = quotaAllocationUnitBytes
	}
	return rounded, true
}

func layerBlobPath(layer descriptor) (string, error) {
	if !sha256DigestPattern.MatchString(layer.Digest) || layer.Size < 0 {
		return "", validationError(
			"oci_descriptor_invalid",
			"OCI layer descriptor is invalid",
		)
	}
	switch layer.MediaType {
	case mediaOCILayerTar,
		mediaOCILayerGzip,
		mediaOCILayerZstd,
		mediaOCINondistributableTar,
		mediaOCINondistributableGzip,
		mediaOCINondistributableZstd,
		mediaDockerLayerGzip,
		mediaDockerForeignLayerGzip:
	default:
		return "", validationError(
			"oci_layer_media_type_unsupported",
			"OCI layer compression format is unsupported",
		)
	}
	return "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:"), nil
}

func (plan *OCIPlan) expandedLayerBytes(
	ctx context.Context,
	blobPath string,
	layer descriptor,
	maximum int64,
	limitCode string,
) (int64, error) {
	if maximum < 0 {
		return 0, validationError(
			"oci_layer_expanded_limit",
			"OCI layer data exceeds the configured expanded-data limit",
		)
	}
	entry, err := plan.index.regular(blobPath)
	if err != nil {
		return 0, err
	}
	source := io.NewSectionReader(
		plan.index.source,
		entry.offset,
		entry.size,
	)
	digest := sha256.New()
	compressed := io.TeeReader(
		&contextReader{ctx: ctx, reader: source},
		digest,
	)
	switch layer.MediaType {
	case mediaOCILayerTar, mediaOCINondistributableTar:
		if entry.size > maximum {
			return 0, validationError(
				"oci_layer_expanded_limit",
				"OCI layer data exceeds the configured expanded-data limit",
			)
		}
		if err := verifyExpandedLayerSource(
			ctx,
			compressed,
			digest,
			layer.Digest,
		); err != nil {
			return 0, err
		}
		return entry.size, nil
	case mediaOCILayerGzip,
		mediaOCINondistributableGzip,
		mediaDockerLayerGzip,
		mediaDockerForeignLayerGzip:
		decoder, err := gzip.NewReader(compressed)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, ctxErr
			}
			return 0, validationError(
				"oci_layer_compression_invalid",
				"OCI gzip layer is invalid",
			)
		}
		count, countErr := countExpandedBytes(
			ctx,
			decoder,
			maximum,
			limitCode,
		)
		closeErr := decoder.Close()
		if countErr != nil {
			return 0, countErr
		}
		if closeErr != nil {
			return 0, validationError(
				"oci_layer_compression_invalid",
				"OCI gzip layer checksum is invalid",
			)
		}
		if err := verifyExpandedLayerSource(
			ctx,
			compressed,
			digest,
			layer.Digest,
		); err != nil {
			return 0, err
		}
		return count, nil
	case mediaOCILayerZstd, mediaOCINondistributableZstd:
		decoder, err := zstd.NewReader(
			compressed,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(layerDecoderMemoryBytes),
			zstd.WithDecoderMaxWindow(layerDecoderMemoryBytes),
		)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, ctxErr
			}
			return 0, validationError(
				"oci_layer_compression_invalid",
				"OCI zstd layer is invalid",
			)
		}
		count, countErr := countExpandedBytes(
			ctx,
			decoder,
			maximum,
			limitCode,
		)
		decoder.Close()
		if countErr != nil {
			return 0, countErr
		}
		if err := verifyExpandedLayerSource(
			ctx,
			compressed,
			digest,
			layer.Digest,
		); err != nil {
			return 0, err
		}
		return count, nil
	default:
		return 0, validationError(
			"oci_layer_media_type_unsupported",
			"OCI layer compression format is unsupported",
		)
	}
}

func verifyExpandedLayerSource(
	ctx context.Context,
	source io.Reader,
	digest hash.Hash,
	expected string,
) error {
	if _, err := io.CopyBuffer(
		io.Discard,
		source,
		make([]byte, 1<<20),
	); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("verify OCI layer source: %w", err)
	}
	if hex.EncodeToString(digest.Sum(nil)) !=
		strings.TrimPrefix(expected, "sha256:") {
		return validationError(
			"oci_descriptor_digest_mismatch",
			"OCI source changed after validation",
		)
	}
	return nil
}

func countExpandedBytes(
	ctx context.Context,
	reader io.Reader,
	maximum int64,
	limitCode string,
) (int64, error) {
	if maximum < 0 ||
		(limitCode != "oci_layer_expanded_limit" &&
			limitCode != "oci_layer_ratio_limit") {
		return 0, errors.New("containerarchive: invalid expanded layer limit")
	}
	bounded := &contextReader{ctx: ctx, reader: reader}
	var source io.Reader = bounded
	if maximum < math.MaxInt64 {
		source = &io.LimitedReader{
			R: bounded,
			N: maximum + 1,
		}
	}
	count, err := io.CopyBuffer(io.Discard, source, make([]byte, 1<<20))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, ctxErr
		}
		return 0, validationError(
			"oci_layer_compression_invalid",
			"OCI compressed layer could not be decoded",
		)
	}
	if count < 0 || count > maximum {
		message := "OCI layer data exceeds the configured expanded-data limit"
		if limitCode == "oci_layer_ratio_limit" {
			message = "OCI compressed layer exceeds the configured expansion ratio"
		}
		return 0, validationError(
			limitCode,
			message,
		)
	}
	return count, nil
}

func compressedLayerMediaType(mediaType string) bool {
	switch mediaType {
	case mediaOCILayerGzip,
		mediaOCILayerZstd,
		mediaOCINondistributableGzip,
		mediaOCINondistributableZstd,
		mediaDockerLayerGzip,
		mediaDockerForeignLayerGzip:
		return true
	default:
		return false
	}
}

func checkedMultiply(left, right int64) (int64, bool) {
	if left < 0 || right < 0 ||
		(left != 0 && right > math.MaxInt64/left) {
		return 0, false
	}
	return left * right, true
}
