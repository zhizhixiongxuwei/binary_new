package containerarchive

import (
	"context"
	"errors"
	"io"
	"path/filepath"
)

const (
	mediaOCIImageConfig = "application/vnd.oci.image.config.v1+json"
	mediaInTotoJSON     = "application/vnd.in-toto+json"

	dockerReferenceTypeAnnotation   = "vnd.docker.reference.type"
	dockerReferenceDigestAnnotation = "vnd.docker.reference.digest"
	dockerAttestationManifestType   = "attestation-manifest"
)

type ociLayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

type ociIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Manifests     []descriptor      `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type ociManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type ociWalker struct {
	ctx                   context.Context
	index                 *archiveIndex
	visiting              map[string]bool
	descriptor            int
	targets               []Target
	plans                 []ociTargetPlan
	targetByID            map[string]int
	attestationReferences []string
}

func inspectOCI(
	ctx context.Context,
	index *archiveIndex,
) (Inspection, error) {
	plan, err := buildOCIPlan(ctx, index)
	if err != nil {
		return Inspection{}, err
	}
	return plan.Inspection(), nil
}

// OCIPlan is a fully validated, flattened OCI image-layout plan. The source
// must remain open and immutable until Materialize returns.
type OCIPlan struct {
	index      *archiveIndex
	inspection Inspection
	targets    []ociTargetPlan
}

type ociTargetPlan struct {
	descriptor descriptor
	blobPaths  []string
	layers     []descriptor
}

// PlanOCI validates an OCI TAR and retains only the source offsets needed to
// materialize its referenced image graph. Docker Desktop may include a
// manifest.json compatibility view beside a complete OCI layout; the OCI
// graph remains authoritative and is independently digest-validated.
func PlanOCI(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
	limits Limits,
) (*OCIPlan, error) {
	if ctx == nil {
		return nil, errors.New("containerarchive: nil context")
	}
	if source == nil || size < 0 {
		return nil, errors.New("containerarchive: invalid source")
	}
	limits = normalizeLimits(limits)
	index, err := indexArchive(ctx, source, size, limits)
	if err != nil {
		return nil, err
	}
	_, docker := index.entries["manifest.json"]
	_, layout := index.entries["oci-layout"]
	_, rootIndex := index.entries["index.json"]
	if docker && (!layout || !rootIndex) {
		return nil, validationError(
			"container_archive_format_mismatch",
			"Docker Save TAR cannot be planned as an OCI layout",
		)
	}
	return buildOCIPlan(ctx, index)
}

func buildOCIPlan(
	ctx context.Context,
	index *archiveIndex,
) (*OCIPlan, error) {
	if index == nil {
		return nil, errors.New("containerarchive: nil OCI archive index")
	}
	layoutContent, err := index.readMetadata(ctx, "oci-layout")
	if err != nil {
		return nil, err
	}
	var layout ociLayout
	if err := decodeJSON(
		layoutContent,
		&layout,
		"oci_layout_invalid",
	); err != nil {
		return nil, err
	}
	if layout.ImageLayoutVersion != "1.0.0" {
		return nil, validationError(
			"oci_layout_unsupported",
			"only OCI image layout version 1.0.0 is supported",
		)
	}

	indexContent, err := index.readMetadata(ctx, "index.json")
	if err != nil {
		return nil, err
	}
	var root ociIndex
	if err := decodeJSON(
		indexContent,
		&root,
		"oci_index_invalid",
	); err != nil {
		return nil, err
	}
	if root.SchemaVersion != 2 || len(root.Manifests) == 0 ||
		len(root.Manifests) > index.limits.MaxDescriptors ||
		(root.MediaType != "" && root.MediaType != mediaOCIIndex &&
			root.MediaType != mediaDockerManifestSet) {
		return nil, validationError(
			"oci_index_invalid",
			"OCI index schema, media type, or descriptor count is invalid",
		)
	}

	walker := &ociWalker{
		ctx: ctx, index: index,
		visiting:   make(map[string]bool),
		targetByID: make(map[string]int),
	}
	rootReference, err := validatedReferenceFromAnnotations(root.Annotations)
	if err != nil {
		return nil, err
	}
	for _, current := range root.Manifests {
		if err := walker.walk(
			current,
			0,
			rootReference,
		); err != nil {
			return nil, err
		}
	}
	for _, reference := range walker.attestationReferences {
		if _, found := walker.targetByID[reference]; !found {
			return nil, validationError(
				"oci_attestation_invalid",
				"OCI attestation does not reference a scanned image manifest",
			)
		}
	}
	if len(walker.targets) == 0 {
		return nil, validationError(
			"oci_index_invalid",
			"OCI index does not contain an image manifest",
		)
	}
	return &OCIPlan{
		index: index,
		inspection: Inspection{
			Format:     FormatOCI,
			EntryCount: index.count,
			Targets:    walker.targets,
		},
		targets: walker.plans,
	}, nil
}

// Inspection returns a detached copy of the plan's scanner-visible targets.
func (plan *OCIPlan) Inspection() Inspection {
	if plan == nil {
		return Inspection{}
	}
	inspection := plan.inspection
	inspection.Targets = make([]Target, len(plan.inspection.Targets))
	for index, target := range plan.inspection.Targets {
		inspection.Targets[index] = target
		inspection.Targets[index].References = append(
			[]string(nil),
			target.References...,
		)
	}
	return inspection
}

func (walker *ociWalker) walk(
	current descriptor,
	depth int,
	inheritedReference string,
) error {
	if err := walker.ctx.Err(); err != nil {
		return err
	}
	walker.descriptor++
	if walker.descriptor > walker.index.limits.MaxDescriptors {
		return validationError(
			"oci_descriptor_limit",
			"OCI descriptor graph exceeds the configured limit",
		)
	}
	if depth > walker.index.limits.MaxIndexDepth {
		return validationError(
			"oci_index_depth_limit",
			"OCI nested index depth exceeds the configured limit",
		)
	}
	if walker.visiting[current.Digest] {
		return validationError(
			"oci_descriptor_cycle",
			"OCI descriptor graph contains a cycle",
		)
	}
	blobPath, err := walker.index.verifyDescriptor(walker.ctx, current)
	if err != nil {
		return err
	}
	content, err := walker.index.readMetadata(walker.ctx, blobPath)
	if err != nil {
		return err
	}

	reference, err := validatedReferenceFromAnnotations(current.Annotations)
	if err != nil {
		return err
	}
	if reference == "" {
		reference = inheritedReference
	}
	if current.MediaType == mediaOCIManifest &&
		current.Annotations[dockerReferenceTypeAnnotation] ==
			dockerAttestationManifestType {
		return walker.validateDockerAttestation(current, content)
	}
	switch current.MediaType {
	case mediaOCIIndex, mediaDockerManifestSet:
		var nested ociIndex
		if err := decodeJSON(
			content,
			&nested,
			"oci_index_invalid",
		); err != nil {
			return err
		}
		if nested.SchemaVersion != 2 || len(nested.Manifests) == 0 ||
			len(nested.Manifests) > walker.index.limits.MaxDescriptors ||
			(nested.MediaType != "" &&
				nested.MediaType != current.MediaType) {
			return validationError(
				"oci_index_invalid",
				"nested OCI index schema, media type, or descriptor count is invalid",
			)
		}
		walker.visiting[current.Digest] = true
		for _, child := range nested.Manifests {
			if err := walker.walk(child, depth+1, reference); err != nil {
				delete(walker.visiting, current.Digest)
				return err
			}
		}
		delete(walker.visiting, current.Digest)
		return nil
	case mediaOCIManifest, mediaDockerManifest:
		// Continue below.
	default:
		return validationError(
			"oci_media_type_unsupported",
			"OCI descriptor uses an unsupported manifest media type",
		)
	}

	var manifest ociManifest
	if err := decodeJSON(
		content,
		&manifest,
		"oci_manifest_invalid",
	); err != nil {
		return err
	}
	if manifest.SchemaVersion != 2 ||
		(manifest.MediaType != "" &&
			manifest.MediaType != current.MediaType) ||
		len(manifest.Layers) > walker.index.limits.MaxDescriptors {
		return validationError(
			"oci_manifest_invalid",
			"OCI image manifest schema, media type, or layer count is invalid",
		)
	}
	walker.descriptor++
	if walker.descriptor > walker.index.limits.MaxDescriptors {
		return validationError(
			"oci_descriptor_limit",
			"OCI descriptor graph exceeds the configured limit",
		)
	}
	configPath, err := walker.index.verifyDescriptor(
		walker.ctx,
		manifest.Config,
	)
	if err != nil {
		return err
	}
	blobPaths := []string{blobPath, configPath}
	for _, layer := range manifest.Layers {
		walker.descriptor++
		if walker.descriptor > walker.index.limits.MaxDescriptors {
			return validationError(
				"oci_descriptor_limit",
				"OCI descriptor graph exceeds the configured limit",
			)
		}
		layerPath, err := walker.index.verifyDescriptor(
			walker.ctx,
			layer,
		)
		if err != nil {
			return err
		}
		blobPaths = append(blobPaths, layerPath)
	}
	configContent, err := walker.index.readMetadata(walker.ctx, configPath)
	if err != nil {
		return err
	}
	var config imageConfiguration
	if err := decodeJSON(
		configContent,
		&config,
		"oci_config_invalid",
	); err != nil {
		return err
	}
	configPlatform := Platform{
		OS: config.OS, Architecture: config.Architecture,
		Variant: config.Variant,
	}
	if !validPlatform(configPlatform) {
		return validationError(
			"oci_platform_invalid",
			"OCI image config does not declare a valid OS and architecture",
		)
	}
	if current.Platform != nil {
		if !validPlatform(*current.Platform) ||
			!samePlatform(*current.Platform, configPlatform) {
			return validationError(
				"oci_platform_mismatch",
				"OCI descriptor platform does not match the image config",
			)
		}
	}
	manifestReference, err := validatedReferenceFromAnnotations(
		manifest.Annotations,
	)
	if err != nil {
		return err
	}
	if manifestReference != "" {
		reference = manifestReference
	}
	if reference == "" {
		reference = current.Digest
	}
	normalizedDescriptor := current
	normalizedPlatform := configPlatform
	normalizedDescriptor.Platform = &normalizedPlatform
	target := Target{
		ManifestDigest: current.Digest,
		References:     []string{reference},
		Platform:       configPlatform,
	}
	if existing, found := walker.targetByID[current.Digest]; found {
		currentTarget := &walker.targets[existing]
		for _, candidate := range target.References {
			if !containsString(currentTarget.References, candidate) {
				currentTarget.References = append(
					currentTarget.References,
					candidate,
				)
			}
		}
		return nil
	}
	walker.targetByID[current.Digest] = len(walker.targets)
	walker.targets = append(walker.targets, target)
	walker.plans = append(walker.plans, ociTargetPlan{
		descriptor: normalizedDescriptor,
		blobPaths:  blobPaths,
		layers:     append([]descriptor(nil), manifest.Layers...),
	})
	return nil
}

// Docker Desktop includes BuildKit provenance as an OCI image manifest with
// an unknown/unknown platform. It is an attestation artifact, not a rootfs
// image target, so validate its complete descriptor graph but do not hand it
// to Trivy as a container image.
func (walker *ociWalker) validateDockerAttestation(
	current descriptor,
	content []byte,
) error {
	reference := current.Annotations[dockerReferenceDigestAnnotation]
	if !sha256DigestPattern.MatchString(reference) ||
		current.Platform == nil ||
		current.Platform.OS != "unknown" ||
		current.Platform.Architecture != "unknown" ||
		current.Platform.Variant != "" {
		return validationError(
			"oci_attestation_invalid",
			"OCI attestation descriptor metadata is invalid",
		)
	}

	var manifest ociManifest
	if err := decodeJSON(
		content,
		&manifest,
		"oci_attestation_invalid",
	); err != nil {
		return err
	}
	if manifest.SchemaVersion != 2 ||
		(manifest.MediaType != "" && manifest.MediaType != mediaOCIManifest) ||
		manifest.Config.MediaType != mediaOCIImageConfig ||
		len(manifest.Layers) == 0 ||
		len(manifest.Layers) > walker.index.limits.MaxDescriptors {
		return validationError(
			"oci_attestation_invalid",
			"OCI attestation manifest is invalid",
		)
	}

	walker.descriptor++
	if walker.descriptor > walker.index.limits.MaxDescriptors {
		return validationError(
			"oci_descriptor_limit",
			"OCI descriptor graph exceeds the configured limit",
		)
	}
	configPath, err := walker.index.verifyDescriptor(
		walker.ctx,
		manifest.Config,
	)
	if err != nil {
		return err
	}
	configContent, err := walker.index.readMetadata(walker.ctx, configPath)
	if err != nil {
		return err
	}
	var config imageConfiguration
	if err := decodeJSON(
		configContent,
		&config,
		"oci_attestation_invalid",
	); err != nil {
		return err
	}
	if config.OS != "unknown" || config.Architecture != "unknown" ||
		config.Variant != "" {
		return validationError(
			"oci_attestation_invalid",
			"OCI attestation config platform is invalid",
		)
	}

	for _, layer := range manifest.Layers {
		walker.descriptor++
		if walker.descriptor > walker.index.limits.MaxDescriptors {
			return validationError(
				"oci_descriptor_limit",
				"OCI descriptor graph exceeds the configured limit",
			)
		}
		if layer.MediaType != mediaInTotoJSON {
			return validationError(
				"oci_attestation_invalid",
				"OCI attestation layer media type is invalid",
			)
		}
		if _, err := walker.index.verifyDescriptor(walker.ctx, layer); err != nil {
			return err
		}
	}
	walker.attestationReferences = append(
		walker.attestationReferences,
		reference,
	)
	return nil
}

func validatedReferenceFromAnnotations(
	annotations map[string]string,
) (string, error) {
	reference, exists := annotations["org.opencontainers.image.ref.name"]
	if !exists {
		return "", nil
	}
	if !validImageReference(reference) {
		return "", validationError(
			"oci_reference_invalid",
			"OCI image reference annotation is invalid",
		)
	}
	return reference, nil
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cleanMaterializeDestination(destination string) (string, string, error) {
	if destination == "" ||
		!filepath.IsAbs(destination) ||
		filepath.Clean(destination) != destination ||
		destination == string(filepath.Separator) {
		return "", "", errors.New(
			"containerarchive: OCI destination must be an absolute clean non-root path",
		)
	}
	parent := filepath.Dir(destination)
	base := filepath.Base(destination)
	if !safePath(base) {
		return "", "", errors.New(
			"containerarchive: OCI destination basename is invalid",
		)
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", "", err
	}
	return filepath.Clean(canonicalParent), base, nil
}
