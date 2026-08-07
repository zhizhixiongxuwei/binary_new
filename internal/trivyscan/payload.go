package trivyscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"

	"binaryscan/internal/trivyhandoff"
)

var lowercaseSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var analyzerVersionPattern = regexp.MustCompile(
	`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`,
)

// DecodePayload accepts exactly one bounded JSON object and rejects missing or
// unknown fields. The source key is content-addressed and bound to its SHA-256.
func DecodePayload(raw json.RawMessage, maxSourceBytes int64) (HandoffPayload, error) {
	value, err := trivyhandoff.Decode(
		raw,
		maxSourceBytes,
		trivyhandoff.MaxSources,
	)
	if err != nil {
		return HandoffPayload{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	return HandoffPayload{
		SchemaVersion:    value.SchemaVersion,
		Sources:          value.Sources,
		MaxExpandedBytes: value.MaxExpandedBytes,
		MaxArchiveRatio:  value.MaxArchiveRatio,
		UpstreamPartial:  value.UpstreamPartial,
	}, nil
}

func validErrorCode(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character > unicode.MaxASCII ||
			!(character == '_' ||
				character >= 'a' && character <= 'z' ||
				index > 0 && character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validMessage(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
