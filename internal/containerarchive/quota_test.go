package containerarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestOCIUsageMatchesMaterializedLogicalFiles(t *testing.T) {
	data, _ := ociFixture(t, []Platform{{
		OS: "linux", Architecture: "amd64",
	}})
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := plan.EstimateUsage(context.Background(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if usage.TargetCount != 1 ||
		usage.UniqueLayerCount != 1 ||
		usage.ExpandedLayerBytes != int64(len("layer-linux/amd64")) ||
		usage.MaxTargetExpandedBytes != usage.ExpandedLayerBytes ||
		usage.MaterializedBudgetBytes < usage.MaterializedLogicalBytes {
		t.Fatalf("usage = %+v", usage)
	}

	destination := filepath.Join(t.TempDir(), "layout")
	if err := plan.Materialize(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	var logical int64
	err = filepath.Walk(destination, func(
		_ string,
		info os.FileInfo,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode().IsRegular() {
			logical += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if logical != usage.MaterializedLogicalBytes {
		t.Fatalf(
			"materialized logical bytes = %d, estimate = %d",
			logical,
			usage.MaterializedLogicalBytes,
		)
	}
}

func TestOCIUsageDeduplicatesSharedLayersAcrossTargets(t *testing.T) {
	layer := []byte(strings.Repeat("shared-layer", 32))
	data := ociQuotaFixture(
		t,
		mediaOCILayerTar,
		layer,
		[]Platform{
			{OS: "linux", Architecture: "amd64"},
			{OS: "linux", Architecture: "arm64"},
		},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := plan.EstimateUsage(context.Background(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if usage.TargetCount != 2 ||
		usage.UniqueLayerCount != 1 ||
		usage.ExpandedLayerBytes != int64(len(layer)) ||
		usage.MaxTargetExpandedBytes != int64(len(layer)) {
		t.Fatalf("deduplicated usage = %+v", usage)
	}
}

func TestOCIUsageCountsRepeatedLayersWithinTarget(t *testing.T) {
	layer := []byte(strings.Repeat("repeated-layer", 16))
	data := ociQuotaFixture(
		t,
		mediaOCILayerTar,
		layer,
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.targets[0].layers = append(
		plan.targets[0].layers,
		plan.targets[0].layers[0],
	)

	usage, err := plan.EstimateUsage(context.Background(), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if usage.UniqueLayerCount != 1 ||
		usage.ExpandedLayerBytes != int64(len(layer)) ||
		usage.MaxTargetExpandedBytes != 2*int64(len(layer)) {
		t.Fatalf("repeated-layer usage = %+v", usage)
	}
}

func TestOCIUsageRejectsConflictingLayerMediaTypes(t *testing.T) {
	data := ociQuotaFixture(
		t,
		mediaOCILayerTar,
		[]byte("shared-layer"),
		[]Platform{
			{OS: "linux", Architecture: "amd64"},
			{OS: "linux", Architecture: "arm64"},
		},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan.targets[1].layers[0].MediaType = mediaOCILayerGzip

	_, err = plan.EstimateUsage(context.Background(), 1<<30)
	assertValidationCode(t, err, "oci_descriptor_invalid")
}

func TestOCIUsageAppliesIndependentMaterializedAndExpandedLimits(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	layer := []byte(strings.Repeat("mixed-quota", 256))
	if _, err := writer.Write(layer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := ociQuotaFixture(
		t,
		mediaOCILayerGzip,
		compressed.Bytes(),
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := plan.EstimateUsageWithin(
		context.Background(),
		1<<20,
		int64(len(layer)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if usage.ExpandedLayerBytes != int64(len(layer)) {
		t.Fatalf("expanded bytes = %d", usage.ExpandedLayerBytes)
	}
	_, err = plan.EstimateUsageWithin(
		context.Background(),
		usage.MaterializedBudgetBytes-1,
		int64(len(layer)),
	)
	assertValidationCode(t, err, "oci_materialized_size_limit")
	_, err = plan.EstimateUsageWithin(
		context.Background(),
		1<<20,
		int64(len(layer))-1,
	)
	assertValidationCode(t, err, "oci_layer_expanded_limit")
}

func TestOCIUsageDetectsLayerSourceMutation(t *testing.T) {
	data := ociQuotaFixture(
		t,
		mediaOCILayerTar,
		[]byte("immutable-layer"),
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	layerPath, err := layerBlobPath(plan.targets[0].layers[0])
	if err != nil {
		t.Fatal(err)
	}
	entry, err := plan.index.regular(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), data...)
	mutated[int(entry.offset)] ^= 0xff
	plan.index.source = bytes.NewReader(mutated)

	_, err = plan.EstimateUsage(context.Background(), 1<<30)
	assertValidationCode(t, err, "oci_descriptor_digest_mismatch")
}

func TestOCIUsageRejectsExpandedGzipBombBeforeMaterialization(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat("x", 128<<10))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := ociQuotaFixture(
		t,
		mediaOCILayerGzip,
		compressed.Bytes(),
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan.EstimateUsage(context.Background(), 64<<10)
	assertValidationCode(t, err, "oci_layer_ratio_limit")
}

func TestOCIUsageHonorsConfiguredCompressionRatio(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat("ratio", 2048))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := ociQuotaFixture(
		t,
		mediaOCILayerGzip,
		compressed.Bytes(),
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{MaxArchiveRatio: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan.EstimateUsage(context.Background(), 1<<30)
	assertValidationCode(t, err, "oci_layer_ratio_limit")
}

func TestOCIUsageBoundsZstdLayerExpansion(t *testing.T) {
	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(
		&compressed,
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(strings.Repeat("zstd", 4096))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := ociQuotaFixture(
		t,
		mediaOCILayerZstd,
		compressed.Bytes(),
		[]Platform{{OS: "linux", Architecture: "amd64"}},
	)
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{MaxArchiveRatio: 3},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan.EstimateUsage(context.Background(), 1<<30)
	assertValidationCode(t, err, "oci_layer_ratio_limit")
}

func TestOCIUsageRejectsUnsupportedAndCorruptLayerCompression(t *testing.T) {
	tests := []struct {
		name      string
		mediaType string
		body      []byte
		code      string
	}{
		{
			name:      "unsupported",
			mediaType: "application/vnd.example.layer",
			body:      []byte("layer"),
			code:      "oci_layer_media_type_unsupported",
		},
		{
			name:      "corrupt gzip",
			mediaType: mediaOCILayerGzip,
			body:      []byte("not-gzip"),
			code:      "oci_layer_compression_invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := ociQuotaFixture(
				t,
				test.mediaType,
				test.body,
				[]Platform{{OS: "linux", Architecture: "amd64"}},
			)
			plan, err := PlanOCI(
				context.Background(),
				bytes.NewReader(data),
				int64(len(data)),
				Limits{},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = plan.EstimateUsage(context.Background(), 1<<30)
			assertValidationCode(t, err, test.code)
		})
	}
}

func TestOCIUsageHonorsCancellation(t *testing.T) {
	data, _ := ociFixture(t, []Platform{{
		OS: "linux", Architecture: "amd64",
	}})
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = plan.EstimateUsage(ctx, 1<<30)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EstimateUsage() error = %v, want cancellation", err)
	}
}

func TestAllocationChargeRejectsOverflow(t *testing.T) {
	if _, ok := allocationCharge(int64(^uint64(0) >> 1)); ok {
		t.Fatal("allocation charge accepted overflowing size")
	}
}

func TestCheckedMultiplyRejectsOverflow(t *testing.T) {
	if _, ok := checkedMultiply(int64(^uint64(0)>>1), 2); ok {
		t.Fatal("checkedMultiply accepted overflow")
	}
}

func TestCountExpandedBytesAcceptsMaximumInt64Limit(t *testing.T) {
	count, err := countExpandedBytes(
		context.Background(),
		strings.NewReader("layer"),
		math.MaxInt64,
		"oci_layer_expanded_limit",
	)
	if err != nil {
		t.Fatal(err)
	}
	if count != int64(len("layer")) {
		t.Fatalf("count = %d", count)
	}
}

func TestFlattenedIndexSizeMatchesMaterializedEncoding(t *testing.T) {
	manifests := []descriptor{{
		MediaType: mediaOCIManifest,
		Digest:    "sha256:" + strings.Repeat("a", 64),
		Size:      123,
		Platform: &Platform{
			OS: "linux", Architecture: "amd64",
		},
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name": "example:latest",
		},
	}}
	size, err := flattenedIndexSize(
		context.Background(),
		manifests,
		1<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded := mustJSON(t, ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
		Manifests:     manifests,
	})
	if size != int64(len(encoded)) {
		t.Fatalf("flattened index size = %d, encoded = %d", size, len(encoded))
	}
}

func ociQuotaFixture(
	t *testing.T,
	layerMediaType string,
	layer []byte,
	platforms []Platform,
) []byte {
	t.Helper()
	entries := map[string]tarFixtureEntry{
		"oci-layout": {
			body: []byte(`{"imageLayoutVersion":"1.0.0"}`),
		},
	}
	layerDescriptor := blobDescriptor(
		t,
		entries,
		layerMediaType,
		layer,
	)
	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
	}
	for _, platform := range platforms {
		config := mustJSON(t, imageConfiguration{
			Architecture: platform.Architecture,
			OS:           platform.OS,
			Variant:      platform.Variant,
		})
		configDescriptor := blobDescriptor(
			t,
			entries,
			"application/vnd.oci.image.config.v1+json",
			config,
		)
		manifest := mustJSON(t, ociManifest{
			SchemaVersion: 2,
			MediaType:     mediaOCIManifest,
			Config:        configDescriptor,
			Layers:        []descriptor{layerDescriptor},
		})
		manifestDescriptor := blobDescriptor(
			t,
			entries,
			mediaOCIManifest,
			manifest,
		)
		manifestDescriptor.Platform = &platform
		index.Manifests = append(index.Manifests, manifestDescriptor)
	}
	entries["index.json"] = tarFixtureEntry{body: mustJSON(t, index)}
	return tarFixture(t, entries)
}
