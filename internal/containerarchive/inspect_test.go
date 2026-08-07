package containerarchive

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestInspectDockerSaveBuildsEveryTarget(t *testing.T) {
	manifest := []dockerManifestEntry{
		{
			Config: "amd64.json",
			RepoTags: []string{
				"example.local/api:1.0",
				"example.local/api:stable",
			},
			Layers: []string{"layers/amd64.tar"},
		},
		{
			Config:   "arm64.json",
			RepoTags: []string{"example.local/api:arm64"},
			Layers:   []string{"layers/arm64.tar"},
		},
	}
	data := tarFixture(t, map[string]tarFixtureEntry{
		"manifest.json": {
			body: mustJSON(t, manifest),
		},
		"amd64.json": {
			body: []byte(`{"architecture":"amd64","os":"linux"}`),
		},
		"arm64.json": {
			body: []byte(`{"architecture":"arm64","os":"linux","variant":"v8"}`),
		},
		"layers/amd64.tar": {body: []byte("amd64-layer")},
		"layers/arm64.tar": {body: []byte("arm64-layer")},
	})

	inspection, err := Inspect(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		FormatDocker,
		Limits{},
	)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspection.Format != FormatDocker ||
		inspection.EntryCount != 5 ||
		len(inspection.Targets) != 2 {
		t.Fatalf("inspection = %+v", inspection)
	}
	if got := inspection.Targets[0].Platform.String(); got != "linux/amd64" {
		t.Fatalf("first platform = %q", got)
	}
	if got := inspection.Targets[1].Platform.String(); got != "linux/arm64/v8" {
		t.Fatalf("second platform = %q", got)
	}
	if len(inspection.Targets[0].References) != 2 {
		t.Fatalf("first references = %#v", inspection.Targets[0].References)
	}
}

func TestInspectDockerRejectsControlCharactersInReferences(t *testing.T) {
	data := tarFixture(t, map[string]tarFixtureEntry{
		"manifest.json": {body: mustJSON(t, []dockerManifestEntry{{
			Config:   "config.json",
			RepoTags: []string{"example.local/image:latest\nforged"},
			Layers:   []string{"layer.tar"},
		}})},
		"config.json": {
			body: []byte(`{"architecture":"amd64","os":"linux"}`),
		},
		"layer.tar": {body: []byte("layer")},
	})

	assertValidationCode(
		t,
		InspectError(context.Background(), data, FormatDocker, Limits{}),
		"docker_reference_invalid",
	)
}

func TestInspectOCIIndexReturnsAllPlatforms(t *testing.T) {
	data, manifests := ociFixture(t, []Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64", Variant: "v8"},
	})

	inspection, err := Inspect(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		FormatOCI,
		Limits{},
	)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspection.Format != FormatOCI || len(inspection.Targets) != 2 {
		t.Fatalf("inspection = %+v", inspection)
	}
	for index, target := range inspection.Targets {
		if target.ManifestDigest != manifests[index] {
			t.Fatalf(
				"target %d digest = %q, want %q",
				index,
				target.ManifestDigest,
				manifests[index],
			)
		}
		if !samePlatform(target.Platform, []Platform{
			{OS: "linux", Architecture: "amd64"},
			{OS: "linux", Architecture: "arm64", Variant: "v8"},
		}[index]) {
			t.Fatalf("target %d platform = %+v", index, target.Platform)
		}
	}
}

func TestOCIPlanValidatesAndSkipsDockerAttestationManifest(t *testing.T) {
	data, imageDigest := ociFixtureWithDockerAttestation(t, "")
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatalf("PlanOCI() error = %v", err)
	}
	inspection := plan.Inspection()
	if len(inspection.Targets) != 1 ||
		inspection.Targets[0].ManifestDigest != imageDigest ||
		inspection.Targets[0].Platform.String() != "linux/amd64" {
		t.Fatalf("inspection targets = %+v", inspection.Targets)
	}
	usage, err := plan.EstimateUsage(context.Background(), 1<<20)
	if err != nil {
		t.Fatalf("EstimateUsage() error = %v", err)
	}
	if usage.TargetCount != 1 || usage.UniqueLayerCount != 1 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestOCIPlanRejectsDockerAttestationWithoutScannedSubject(t *testing.T) {
	missing := "sha256:" + strings.Repeat("f", 64)
	data, _ := ociFixtureWithDockerAttestation(t, missing)
	_, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	assertValidationCode(t, err, "oci_attestation_invalid")
}

func TestInspectOCIRejectsControlCharactersInReferenceAnnotation(
	t *testing.T,
) {
	data, _ := ociFixtureWithRootReference(
		t,
		[]Platform{{OS: "linux", Architecture: "amd64"}},
		"fixture:latest\nforged",
	)
	assertValidationCode(
		t,
		InspectError(context.Background(), data, FormatOCI, Limits{}),
		"oci_reference_invalid",
	)
}

func TestInspectOCINestedIndexReturnsAllLeafManifests(t *testing.T) {
	entries := map[string]tarFixtureEntry{
		"oci-layout": {
			body: []byte(`{"imageLayoutVersion":"1.0.0"}`),
		},
	}
	nested := ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
	}
	for _, platform := range []Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
	} {
		configDescriptor := blobDescriptor(
			t,
			entries,
			"application/vnd.oci.image.config.v1+json",
			mustJSON(t, imageConfiguration{
				Architecture: platform.Architecture,
				OS:           platform.OS,
			}),
		)
		layerDescriptor := blobDescriptor(
			t,
			entries,
			"application/vnd.oci.image.layer.v1.tar",
			[]byte("layer-"+platform.String()),
		)
		manifestDescriptor := blobDescriptor(
			t,
			entries,
			mediaOCIManifest,
			mustJSON(t, ociManifest{
				SchemaVersion: 2,
				MediaType:     mediaOCIManifest,
				Config:        configDescriptor,
				Layers:        []descriptor{layerDescriptor},
			}),
		)
		manifestDescriptor.Platform = &platform
		nested.Manifests = append(nested.Manifests, manifestDescriptor)
	}
	nestedDescriptor := blobDescriptor(
		t,
		entries,
		mediaOCIIndex,
		mustJSON(t, nested),
	)
	entries["index.json"] = tarFixtureEntry{body: mustJSON(t, ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
		Manifests:     []descriptor{nestedDescriptor},
	})}
	data := tarFixture(t, entries)

	inspection, err := Inspect(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		FormatOCI,
		Limits{},
	)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if len(inspection.Targets) != 2 ||
		inspection.Targets[0].Platform.Architecture != "amd64" ||
		inspection.Targets[1].Platform.Architecture != "arm64" {
		t.Fatalf("nested targets = %+v", inspection.Targets)
	}
}

func TestInspectRejectsOrdinaryAndAmbiguousTAR(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries map[string]tarFixtureEntry
		code    string
	}{
		{
			name: "ordinary",
			entries: map[string]tarFixtureEntry{
				"payload.txt": {body: []byte("not an image")},
			},
			code: "container_archive_unrecognized",
		},
		{
			name: "ambiguous",
			entries: map[string]tarFixtureEntry{
				"manifest.json": {body: []byte("[]")},
				"oci-layout":    {body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
				"index.json":    {body: []byte(`{"schemaVersion":2,"manifests":[]}`)},
			},
			code: "container_archive_ambiguous",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := tarFixture(t, test.entries)
			assertValidationCode(
				t,
				InspectError(
					context.Background(),
					data,
					"",
					Limits{},
				),
				test.code,
			)
		})
	}
}

func TestExplicitOCIFormatAcceptsDockerCompatibilityManifest(t *testing.T) {
	data, manifests := ociFixture(t, []Platform{{
		OS: "linux", Architecture: "amd64",
	}})
	data = appendTarFixtureEntry(
		t,
		data,
		"manifest.json",
		[]byte(`[{"Config":"compatibility-only"}]`),
	)

	inspection, err := Inspect(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		FormatOCI,
		Limits{},
	)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if inspection.Format != FormatOCI || len(inspection.Targets) != 1 ||
		inspection.Targets[0].ManifestDigest != manifests[0] {
		t.Fatalf("inspection = %+v", inspection)
	}

	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatalf("PlanOCI() error = %v", err)
	}
	if planned := plan.Inspection(); planned.Format != FormatOCI ||
		len(planned.Targets) != 1 ||
		planned.Targets[0].ManifestDigest != manifests[0] {
		t.Fatalf("plan inspection = %+v", planned)
	}

	assertValidationCode(
		t,
		InspectError(context.Background(), data, "", Limits{}),
		"container_archive_ambiguous",
	)
}

func TestInspectRejectsUnsafeSpecialAndDuplicateEntries(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries []tarFixtureNamedEntry
		code    string
	}{
		{
			name: "traversal",
			entries: []tarFixtureNamedEntry{
				{name: "../manifest.json", body: []byte("[]")},
			},
			code: "container_archive_unsafe_path",
		},
		{
			name: "symlink",
			entries: []tarFixtureNamedEntry{
				{name: "manifest.json", typeFlag: tar.TypeSymlink},
			},
			code: "container_archive_unsafe_entry",
		},
		{
			name: "duplicate",
			entries: []tarFixtureNamedEntry{
				{name: "manifest.json", body: []byte("[]")},
				{name: "manifest.json", body: []byte("[]")},
			},
			code: "container_archive_duplicate_path",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := tarFixtureOrdered(t, test.entries)
			assertValidationCode(
				t,
				InspectError(
					context.Background(),
					data,
					"",
					Limits{},
				),
				test.code,
			)
		})
	}
}

func TestInspectDockerRejectsMissingLayerAndPlatform(t *testing.T) {
	for _, test := range []struct {
		name     string
		manifest []dockerManifestEntry
		config   string
		code     string
	}{
		{
			name: "missing-layer",
			manifest: []dockerManifestEntry{{
				Config: "config.json", Layers: []string{"missing.tar"},
			}},
			config: `{"architecture":"amd64","os":"linux"}`,
			code:   "container_archive_missing_blob",
		},
		{
			name: "missing-platform",
			manifest: []dockerManifestEntry{{
				Config: "config.json", Layers: []string{"layer.tar"},
			}},
			config: `{}`,
			code:   "docker_platform_invalid",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := map[string]tarFixtureEntry{
				"manifest.json": {body: mustJSON(t, test.manifest)},
				"config.json":   {body: []byte(test.config)},
			}
			if test.name != "missing-layer" {
				entries["layer.tar"] = tarFixtureEntry{body: []byte("layer")}
			}
			data := tarFixture(t, entries)
			assertValidationCode(
				t,
				InspectError(
					context.Background(),
					data,
					FormatDocker,
					Limits{},
				),
				test.code,
			)
		})
	}
}

func TestInspectOCIRejectsDigestAndPlatformMismatch(t *testing.T) {
	data, _ := ociFixture(t, []Platform{{
		OS: "linux", Architecture: "amd64",
	}})

	digestCorrupt := append([]byte(nil), data...)
	index := bytes.Index(digestCorrupt, []byte(`"architecture":"amd64"`))
	if index < 0 {
		t.Fatal("fixture config not found")
	}
	digestCorrupt[index+len(`"architecture":"`)] = 'x'
	assertValidationCode(
		t,
		InspectError(
			context.Background(),
			digestCorrupt,
			FormatOCI,
			Limits{},
		),
		"oci_descriptor_digest_mismatch",
	)

	platformMismatch, _ := ociFixtureWithDescriptorPlatforms(
		t,
		[]Platform{{OS: "linux", Architecture: "amd64"}},
		[]Platform{{OS: "linux", Architecture: "arm64"}},
	)
	assertValidationCode(
		t,
		InspectError(
			context.Background(),
			platformMismatch,
			FormatOCI,
			Limits{},
		),
		"oci_platform_mismatch",
	)
}

func TestInspectEnforcesExpectedFormatLimitsAndCancellation(t *testing.T) {
	docker := validDockerFixture(t)
	assertValidationCode(
		t,
		InspectError(
			context.Background(),
			docker,
			FormatOCI,
			Limits{},
		),
		"container_archive_format_mismatch",
	)
	assertValidationCode(
		t,
		InspectError(
			context.Background(),
			docker,
			FormatDocker,
			Limits{MaxEntries: 1},
		),
		"container_archive_entry_limit",
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Inspect(
		ctx,
		bytes.NewReader(docker),
		int64(len(docker)),
		FormatDocker,
		Limits{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Inspect() error = %v", err)
	}
}

func TestInspectRejectsNonZeroTrailingData(t *testing.T) {
	data := validDockerFixture(t)
	data = append(data, make([]byte, tarBlockBytes)...)
	data[len(data)-int(tarBlockBytes)] = 1
	assertValidationCode(
		t,
		InspectError(
			context.Background(),
			data,
			FormatDocker,
			Limits{},
		),
		"container_archive_trailing_data",
	)
}

func TestOCIPlanMaterializesFlattenedReadOnlyLayout(t *testing.T) {
	data, manifests := ociFixture(t, []Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
	})
	plan, err := PlanOCI(
		context.Background(),
		bytes.NewReader(data),
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatalf("PlanOCI() error = %v", err)
	}
	if inspection := plan.Inspection(); len(inspection.Targets) != 2 {
		t.Fatalf("plan inspection = %+v", inspection)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "layout")
	if err := plan.Materialize(
		context.Background(),
		destination,
	); err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	layoutRaw, err := os.ReadFile(filepath.Join(destination, "oci-layout"))
	if err != nil {
		t.Fatal(err)
	}
	if string(layoutRaw) != `{"imageLayoutVersion":"1.0.0"}` {
		t.Fatalf("oci-layout = %s", layoutRaw)
	}
	indexRaw, err := os.ReadFile(filepath.Join(destination, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var flattened ociIndex
	if err := json.Unmarshal(indexRaw, &flattened); err != nil {
		t.Fatal(err)
	}
	if len(flattened.Manifests) != 2 ||
		flattened.Manifests[0].Digest != manifests[0] ||
		flattened.Manifests[1].Digest != manifests[1] {
		t.Fatalf("flattened index = %+v", flattened)
	}
	files := 0
	err = filepath.Walk(destination, func(
		path string,
		info os.FileInfo,
		walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("materialized symlink at %s", path)
		}
		if info.Mode().IsRegular() {
			files++
			if info.Mode().Perm() != 0o400 {
				t.Fatalf("%s mode = %o, want 0400", path, info.Mode().Perm())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two root metadata files plus config, layer, and manifest for each target.
	if files != 8 {
		t.Fatalf("materialized regular file count = %d, want 8", files)
	}
}

func TestOCIPlanMaterializeDetectsSourceMutationAndCleansDestination(t *testing.T) {
	data, _ := ociFixture(t, []Platform{{
		OS: "linux", Architecture: "amd64",
	}})
	reader := bytes.NewReader(data)
	plan, err := PlanOCI(
		context.Background(),
		reader,
		int64(len(data)),
		Limits{},
	)
	if err != nil {
		t.Fatalf("PlanOCI() error = %v", err)
	}
	mutated := append([]byte(nil), data...)
	layer := bytes.Index(mutated, []byte("layer-linux/amd64"))
	if layer < 0 {
		t.Fatal("fixture layer not found")
	}
	mutated[layer] ^= 0xff
	plan.index.source = bytes.NewReader(mutated)

	destination := filepath.Join(t.TempDir(), "layout")
	err = plan.Materialize(context.Background(), destination)
	assertValidationCode(t, err, "oci_descriptor_digest_mismatch")
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed destination remains: %v", statErr)
	}
}

func TestOCIPlanMaterializeDoesNotReplaceExistingDestination(t *testing.T) {
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
	destination := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(destination, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	assertValidationCode(
		t,
		plan.Materialize(context.Background(), destination),
		"oci_destination_exists",
	)
	if content, err := os.ReadFile(sentinel); err != nil ||
		string(content) != "keep" {
		t.Fatalf("sentinel = %q, %v", content, err)
	}
}

func InspectError(
	ctx context.Context,
	data []byte,
	expected string,
	limits Limits,
) error {
	_, err := Inspect(
		ctx,
		bytes.NewReader(data),
		int64(len(data)),
		expected,
		limits,
	)
	return err
}

func assertValidationCode(t *testing.T, err error, code string) {
	t.Helper()
	var validation *Error
	if !errors.As(err, &validation) {
		t.Fatalf("error = %v, want *Error with code %q", err, code)
	}
	if validation.Code != code {
		t.Fatalf("error code = %q, want %q (%v)", validation.Code, code, err)
	}
}

type tarFixtureEntry struct {
	body     []byte
	typeFlag byte
}

type tarFixtureNamedEntry struct {
	name     string
	body     []byte
	typeFlag byte
}

func tarFixture(
	t *testing.T,
	entries map[string]tarFixtureEntry,
) []byte {
	t.Helper()
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make([]tarFixtureNamedEntry, 0, len(names))
	for _, name := range names {
		ordered = append(ordered, tarFixtureNamedEntry{
			name: name, body: entries[name].body,
			typeFlag: entries[name].typeFlag,
		})
	}
	return tarFixtureOrdered(t, ordered)
}

func tarFixtureOrdered(
	t *testing.T,
	entries []tarFixtureNamedEntry,
) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range entries {
		typeFlag := entry.typeFlag
		if typeFlag == 0 {
			typeFlag = tar.TypeReg
		}
		header := &tar.Header{
			Name: entry.name, Mode: 0o600,
			Size: int64(len(entry.body)), Typeflag: typeFlag,
			Format: tar.FormatUSTAR,
		}
		if typeFlag == tar.TypeSymlink {
			header.Size = 0
			header.Linkname = "target"
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func appendTarFixtureEntry(
	t *testing.T,
	data []byte,
	name string,
	body []byte,
) []byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(data))
	entries := make([]tarFixtureNamedEntry, 0)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, tarFixtureNamedEntry{
			name: header.Name, body: content, typeFlag: header.Typeflag,
		})
	}
	entries = append(entries, tarFixtureNamedEntry{name: name, body: body})
	return tarFixtureOrdered(t, entries)
}

func validDockerFixture(t *testing.T) []byte {
	t.Helper()
	return tarFixture(t, map[string]tarFixtureEntry{
		"manifest.json": {body: mustJSON(t, []dockerManifestEntry{{
			Config: "config.json", Layers: []string{"layer.tar"},
		}})},
		"config.json": {
			body: []byte(`{"architecture":"amd64","os":"linux"}`),
		},
		"layer.tar": {body: []byte("layer")},
	})
}

func ociFixture(
	t *testing.T,
	platforms []Platform,
) ([]byte, []string) {
	return ociFixtureWithDescriptorPlatforms(t, platforms, platforms)
}

func ociFixtureWithDescriptorPlatforms(
	t *testing.T,
	configPlatforms []Platform,
	descriptorPlatforms []Platform,
) ([]byte, []string) {
	return ociFixtureWithPlatformsAndReference(
		t,
		configPlatforms,
		descriptorPlatforms,
		"fixture:latest",
	)
}

func ociFixtureWithRootReference(
	t *testing.T,
	platforms []Platform,
	reference string,
) ([]byte, []string) {
	return ociFixtureWithPlatformsAndReference(
		t,
		platforms,
		platforms,
		reference,
	)
}

func ociFixtureWithPlatformsAndReference(
	t *testing.T,
	configPlatforms []Platform,
	descriptorPlatforms []Platform,
	reference string,
) ([]byte, []string) {
	t.Helper()
	if len(configPlatforms) != len(descriptorPlatforms) {
		t.Fatal("platform fixture lengths differ")
	}
	entries := map[string]tarFixtureEntry{
		"oci-layout": {
			body: []byte(`{"imageLayoutVersion":"1.0.0"}`),
		},
	}
	index := ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
		Annotations: map[string]string{
			"org.opencontainers.image.ref.name": reference,
		},
	}
	manifestDigests := make([]string, 0, len(configPlatforms))
	for position, platform := range configPlatforms {
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
		layer := []byte("layer-" + platform.String())
		layerDescriptor := blobDescriptor(
			t,
			entries,
			"application/vnd.oci.image.layer.v1.tar",
			layer,
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
		manifestDescriptor.Platform = &descriptorPlatforms[position]
		index.Manifests = append(index.Manifests, manifestDescriptor)
		manifestDigests = append(
			manifestDigests,
			manifestDescriptor.Digest,
		)
	}
	entries["index.json"] = tarFixtureEntry{body: mustJSON(t, index)}
	return tarFixture(t, entries), manifestDigests
}

func ociFixtureWithDockerAttestation(
	t *testing.T,
	referenceOverride string,
) ([]byte, string) {
	t.Helper()
	entries := map[string]tarFixtureEntry{
		"oci-layout": {
			body: []byte(`{"imageLayoutVersion":"1.0.0"}`),
		},
	}
	platform := Platform{OS: "linux", Architecture: "amd64"}
	configDescriptor := blobDescriptor(
		t,
		entries,
		mediaOCIImageConfig,
		mustJSON(t, imageConfiguration{
			Architecture: platform.Architecture,
			OS:           platform.OS,
		}),
	)
	layerDescriptor := blobDescriptor(
		t,
		entries,
		mediaOCILayerTar,
		[]byte("image-layer"),
	)
	imageDescriptor := blobDescriptor(
		t,
		entries,
		mediaOCIManifest,
		mustJSON(t, ociManifest{
			SchemaVersion: 2,
			MediaType:     mediaOCIManifest,
			Config:        configDescriptor,
			Layers:        []descriptor{layerDescriptor},
		}),
	)
	imageDescriptor.Platform = &platform

	unknownPlatform := Platform{OS: "unknown", Architecture: "unknown"}
	attestationConfig := blobDescriptor(
		t,
		entries,
		mediaOCIImageConfig,
		mustJSON(t, imageConfiguration{
			Architecture: unknownPlatform.Architecture,
			OS:           unknownPlatform.OS,
		}),
	)
	attestationLayer := blobDescriptor(
		t,
		entries,
		mediaInTotoJSON,
		[]byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`),
	)
	attestationDescriptor := blobDescriptor(
		t,
		entries,
		mediaOCIManifest,
		mustJSON(t, ociManifest{
			SchemaVersion: 2,
			MediaType:     mediaOCIManifest,
			Config:        attestationConfig,
			Layers:        []descriptor{attestationLayer},
		}),
	)
	attestationDescriptor.Platform = &unknownPlatform
	reference := imageDescriptor.Digest
	if referenceOverride != "" {
		reference = referenceOverride
	}
	attestationDescriptor.Annotations = map[string]string{
		dockerReferenceTypeAnnotation:   dockerAttestationManifestType,
		dockerReferenceDigestAnnotation: reference,
	}
	entries["index.json"] = tarFixtureEntry{body: mustJSON(t, ociIndex{
		SchemaVersion: 2,
		MediaType:     mediaOCIIndex,
		Manifests:     []descriptor{imageDescriptor, attestationDescriptor},
	})}
	return tarFixture(t, entries), imageDescriptor.Digest
}

func blobDescriptor(
	t *testing.T,
	entries map[string]tarFixtureEntry,
	mediaType string,
	content []byte,
) descriptor {
	t.Helper()
	digest := sha256.Sum256(content)
	encoded := hex.EncodeToString(digest[:])
	entries["blobs/sha256/"+encoded] = tarFixtureEntry{body: content}
	return descriptor{
		MediaType: mediaType,
		Digest:    "sha256:" + encoded,
		Size:      int64(len(content)),
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(encoded)) == "" {
		t.Fatal("empty JSON fixture")
	}
	return encoded
}
