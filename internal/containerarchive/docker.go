package containerarchive

import (
	"context"
	"fmt"
)

type dockerManifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type imageConfiguration struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

func inspectDocker(
	ctx context.Context,
	index *archiveIndex,
) (Inspection, error) {
	content, err := index.readMetadata(ctx, "manifest.json")
	if err != nil {
		return Inspection{}, err
	}
	var manifest []dockerManifestEntry
	if err := decodeJSON(
		content,
		&manifest,
		"docker_manifest_invalid",
	); err != nil {
		return Inspection{}, err
	}
	if len(manifest) == 0 ||
		len(manifest) > index.limits.MaxDescriptors {
		return Inspection{}, validationError(
			"docker_manifest_invalid",
			"Docker Save manifest image count is outside the configured limit",
		)
	}

	targets := make([]Target, 0, len(manifest))
	for _, image := range manifest {
		if !safePath(image.Config) || len(image.Layers) == 0 ||
			len(image.Layers) > index.limits.MaxDescriptors {
			return Inspection{}, validationError(
				"docker_manifest_invalid",
				"Docker Save manifest contains an invalid config or layer list",
			)
		}
		if _, err := index.regular(image.Config); err != nil {
			return Inspection{}, err
		}
		for _, layer := range image.Layers {
			if !safePath(layer) {
				return Inspection{}, validationError(
					"docker_manifest_invalid",
					"Docker Save manifest contains an unsafe layer path",
				)
			}
			if _, err := index.regular(layer); err != nil {
				return Inspection{}, err
			}
		}
		configContent, err := index.readMetadata(ctx, image.Config)
		if err != nil {
			return Inspection{}, err
		}
		var config imageConfiguration
		if err := decodeJSON(
			configContent,
			&config,
			"docker_config_invalid",
		); err != nil {
			return Inspection{}, err
		}
		platform := Platform{
			OS: config.OS, Architecture: config.Architecture,
			Variant: config.Variant,
		}
		if !validPlatform(platform) {
			return Inspection{}, validationError(
				"docker_platform_invalid",
				"Docker image config does not declare a valid OS and architecture",
			)
		}
		references := append([]string(nil), image.RepoTags...)
		if len(references) == 0 {
			references = []string{image.Config}
		}
		for _, reference := range references {
			if !validImageReference(reference) {
				return Inspection{}, validationError(
					"docker_reference_invalid",
					"Docker image reference is invalid",
				)
			}
		}
		targets = append(targets, Target{
			References: references,
			Platform:   platform,
		})
	}
	if len(targets) == 0 {
		return Inspection{}, fmt.Errorf("Docker Save archive has no scan targets")
	}
	return Inspection{Format: FormatDocker, Targets: targets}, nil
}
