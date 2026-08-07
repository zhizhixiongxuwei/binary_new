package bytecode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type cacheMaterial struct {
	CacheSchemaVersion    int         `json:"cache_schema_version"`
	ContractSchemaVersion string      `json:"contract_schema_version"`
	InputSHA256           string      `json:"input_sha256"`
	Format                Format      `json:"format"`
	EngineName            string      `json:"engine_name"`
	EngineVersion         string      `json:"engine_version"`
	Arguments             []string    `json:"arguments"`
	Limits                cacheLimits `json:"limits"`
}

type cacheLimits struct {
	MaxDurationNanoseconds int64 `json:"max_duration_nanoseconds"`
	MaxInputBytes          int64 `json:"max_input_bytes"`
	MaxClasses             int   `json:"max_classes"`
	MaxMethods             int   `json:"max_methods"`
	MaxArtifacts           int   `json:"max_artifacts"`
	MaxArtifactBytes       int64 `json:"max_artifact_bytes"`
	MaxClassErrors         int   `json:"max_class_errors"`
}

// CacheKey hashes an unambiguous canonical encoding. Argument order and empty
// arguments are significant; concatenation boundaries cannot collide.
func CacheKey(
	inputSHA256 string,
	format Format,
	engine Descriptor,
	arguments []string,
	limits Limits,
) (string, error) {
	if !sha256Pattern.MatchString(inputSHA256) || !format.Valid() {
		return "", fmt.Errorf("%w: cache input is invalid", ErrInvalidRequest)
	}
	if err := validateDescriptor(engine); err != nil {
		return "", err
	}
	normalizedLimits, err := normalizeLimits(limits)
	if err != nil {
		return "", err
	}
	cloned, err := validateAndCloneArguments(
		arguments,
		maxContractArguments,
		maxContractArgumentBytes,
		maxContractTotalArgumentBytes,
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(cacheMaterial{
		CacheSchemaVersion: 2, ContractSchemaVersion: SchemaVersion,
		InputSHA256: inputSHA256, Format: format,
		EngineName: engine.Name, EngineVersion: engine.Version,
		Arguments: cloned,
		Limits: cacheLimits{
			MaxDurationNanoseconds: normalizedLimits.MaxDuration.Nanoseconds(),
			MaxInputBytes:          normalizedLimits.MaxInputBytes,
			MaxClasses:             normalizedLimits.MaxClasses,
			MaxMethods:             normalizedLimits.MaxMethods,
			MaxArtifacts:           normalizedLimits.MaxArtifacts,
			MaxArtifactBytes:       normalizedLimits.MaxArtifactBytes,
			MaxClassErrors:         normalizedLimits.MaxClassErrors,
		},
	})
	if err != nil {
		return "", fmt.Errorf("%w: encode cache material", ErrInvalidRequest)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
