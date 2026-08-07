package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
)

const (
	RoutingEngineName    = "go-bytecode-router"
	routingEngineVersion = "1.0.0"
)

// RoutingEngine presents format-disjoint fallback engines as one immutable
// worker capability. Its descriptor binds every routed child descriptor, so a
// child upgrade necessarily changes Execute's cache key.
type RoutingEngine struct {
	routes      map[Format]Engine
	descriptor  Descriptor
	fingerprint string
}

func NewRoutingEngine(engines ...Engine) (*RoutingEngine, error) {
	if len(engines) == 0 {
		return nil, fmt.Errorf("%w: routing engine has no children", ErrInvalidConfiguration)
	}
	routes := make(map[Format]Engine)
	material := make([]string, 0)
	for _, engine := range engines {
		if engine == nil || nilEngine(engine) {
			return nil, fmt.Errorf("%w: routing engine child is nil", ErrInvalidConfiguration)
		}
		descriptor := engine.Descriptor()
		if err := validateDescriptor(descriptor); err != nil {
			return nil, err
		}
		routed := 0
		for _, format := range allBytecodeFormats() {
			if !engine.Supports(format) {
				continue
			}
			if _, duplicate := routes[format]; duplicate {
				return nil, fmt.Errorf(
					"%w: multiple engines support %s",
					ErrInvalidConfiguration, format,
				)
			}
			routes[format] = engine
			material = append(material, string(format)+"\x00"+
				descriptor.Name+"\x00"+descriptor.Version)
			routed++
		}
		if routed == 0 {
			return nil, fmt.Errorf(
				"%w: routing engine child supports no known format",
				ErrInvalidConfiguration,
			)
		}
	}
	sort.Strings(material)
	hasher := sha256.New()
	for _, item := range material {
		_, _ = io.WriteString(hasher, strconv.Itoa(len(item)))
		_, _ = io.WriteString(hasher, ":")
		_, _ = io.WriteString(hasher, item)
	}
	fingerprint := hex.EncodeToString(hasher.Sum(nil))
	return &RoutingEngine{
		routes: routes,
		descriptor: Descriptor{
			Name:    RoutingEngineName,
			Version: routingEngineVersion + "-cfg" + fingerprint,
		},
		fingerprint: fingerprint,
	}, nil
}

func (engine *RoutingEngine) Descriptor() Descriptor {
	if engine == nil {
		return Descriptor{}
	}
	return engine.descriptor
}

func (engine *RoutingEngine) ConfigFingerprint() string {
	if engine == nil {
		return ""
	}
	return engine.fingerprint
}

func (engine *RoutingEngine) Supports(format Format) bool {
	if engine == nil {
		return false
	}
	_, ok := engine.routes[format]
	return ok
}

func (engine *RoutingEngine) Decompile(
	ctx context.Context,
	request Request,
) (Output, error) {
	if engine == nil {
		return Output{}, fmt.Errorf("%w: routing engine is nil", ErrInvalidConfiguration)
	}
	child := engine.routes[request.Input.Format]
	if child == nil {
		return Output{}, fmt.Errorf(
			"%w: no route for bytecode format %s",
			ErrInvalidRequest, request.Input.Format,
		)
	}
	return child.Decompile(ctx, request)
}

func allBytecodeFormats() []Format {
	return []Format{
		FormatClass, FormatJAR, FormatWAR, FormatEAR, FormatDEX, FormatAPK, FormatPYC,
	}
}
