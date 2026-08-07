package imageextract

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Registry maps canonical detector format names to Extractors. It is safe for
// concurrent lookup and registration.
type Registry struct {
	mu         sync.RWMutex
	extractors map[string]Extractor
}

func NewRegistry() *Registry {
	return &Registry{extractors: make(map[string]Extractor)}
}

func (registry *Registry) Register(
	format string,
	extractor Extractor,
) error {
	if registry == nil {
		return invalidRequest("registry is nil")
	}
	canonical, err := canonicalFormat(format)
	if err != nil {
		return err
	}
	if extractor == nil {
		return invalidRequest("extractor is nil")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.extractors == nil {
		registry.extractors = make(map[string]Extractor)
	}
	if _, exists := registry.extractors[canonical]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateFormat, canonical)
	}
	registry.extractors[canonical] = extractor
	return nil
}

func (registry *Registry) Lookup(format string) (Extractor, bool) {
	if registry == nil {
		return nil, false
	}
	canonical, err := canonicalFormat(format)
	if err != nil {
		return nil, false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	extractor, found := registry.extractors[canonical]
	return extractor, found
}

func (registry *Registry) Formats() []string {
	if registry == nil {
		return []string{}
	}
	registry.mu.RLock()
	formats := make([]string, 0, len(registry.extractors))
	for format := range registry.extractors {
		formats = append(formats, format)
	}
	registry.mu.RUnlock()
	slices.Sort(formats)
	return formats
}

func (registry *Registry) snapshot() map[string]Extractor {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	extractors := make(map[string]Extractor, len(registry.extractors))
	for format, extractor := range registry.extractors {
		extractors[format] = extractor
	}
	return extractors
}

func canonicalFormat(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) == 0 || len(value) > 64 {
		return "", invalidRequest("format is invalid")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '-' || character == '_' ||
				character == '.' || character == '+')
		if !valid {
			return "", invalidRequest("format is invalid")
		}
	}
	return value, nil
}
