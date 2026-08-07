package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"strings"
)

type SourceInspector interface {
	InspectSource(context.Context, io.Reader) error
}

type SourceInspectorFunc func(context.Context, io.Reader) error

func (function SourceInspectorFunc) InspectSource(
	ctx context.Context,
	reader io.Reader,
) error {
	return function(ctx, reader)
}

// FileArtifactValidator binds metadata to a real, root-confined regular file.
// Source artifacts additionally require a media-type-specific inspector.
type FileArtifactValidator struct {
	inspectors map[string]SourceInspector
}

func NewFileArtifactValidator(
	inspectors map[string]SourceInspector,
) (*FileArtifactValidator, error) {
	cloned := make(map[string]SourceInspector, len(inspectors))
	for mediaType, inspector := range inspectors {
		if !validMediaType(mediaType) || inspector == nil || nilInterface(inspector) {
			return nil, fmt.Errorf(
				"%w: source inspector is invalid", ErrInvalidConfiguration,
			)
		}
		cloned[mediaType] = inspector
	}
	return &FileArtifactValidator{inspectors: cloned}, nil
}

func (validator *FileArtifactValidator) ValidateArtifact(
	ctx context.Context,
	workspace string,
	artifact Artifact,
) (ArtifactValidation, error) {
	if validator == nil {
		return "", fmt.Errorf("%w: artifact validator is nil", ErrInvalidResult)
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validRelativePath(artifact.RelativePath) {
		return "", fmt.Errorf("%w: artifact path is invalid", ErrInvalidResult)
	}
	if artifact.SizeBytes <= 0 || artifact.SizeBytes > 50<<30 {
		return "", fmt.Errorf("%w: artifact size is invalid", ErrInvalidResult)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return "", fmt.Errorf("%w: open artifact workspace", ErrInvalidResult)
	}
	defer root.Close()
	rootInfo, err := root.Lstat(".")
	trustedDevice, ok := trustedRootDevice(rootInfo)
	if err != nil || !ok {
		return "", fmt.Errorf("%w: artifact workspace is unsafe", ErrInvalidResult)
	}
	expected, err := validateRootFile(root, artifact.RelativePath, trustedDevice)
	if err != nil {
		return "", err
	}
	file, err := root.Open(artifact.RelativePath)
	if err != nil {
		return "", fmt.Errorf("%w: open artifact", ErrInvalidResult)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(expected, info) ||
		!trustedEntry(info, trustedDevice) ||
		!info.Mode().IsRegular() || info.Size() != artifact.SizeBytes {
		return "", fmt.Errorf(
			"%w: artifact size or type changed", ErrInvalidResult,
		)
	}

	hasher := sha256.New()
	limited := &io.LimitedReader{
		R: &contextReader{ctx: ctx, reader: file},
		N: artifact.SizeBytes + 1,
	}
	reader := io.TeeReader(limited, hasher)
	validation := ValidationHashVerified
	if artifact.Kind == ArtifactSource {
		inspector := validator.inspectors[artifact.MediaType]
		if inspector == nil {
			return "", fmt.Errorf(
				"%w: no source inspector for %s",
				ErrInvalidResult, artifact.MediaType,
			)
		}
		if err := inspector.InspectSource(ctx, reader); err != nil {
			return "", fmt.Errorf(
				"%w: source inspection failed: %v", ErrInvalidResult, err,
			)
		}
		validation = ValidationContentVerified
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return "", contextErr
		}
		return "", fmt.Errorf("%w: read artifact", ErrInvalidResult)
	}
	consumed := artifact.SizeBytes + 1 - limited.N
	if consumed != artifact.SizeBytes {
		return "", fmt.Errorf(
			"%w: artifact was appended or truncated while reading",
			ErrInvalidResult,
		)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != artifact.SHA256 {
		return "", fmt.Errorf("%w: artifact digest mismatch", ErrInvalidResult)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) ||
		!trustedEntry(after, trustedDevice) ||
		after.Size() != artifact.SizeBytes {
		return "", fmt.Errorf(
			"%w: artifact changed while validating", ErrInvalidResult,
		)
	}
	return validation, nil
}

func validateRootFile(
	root *os.Root,
	relativePath string,
	trustedDevice uint64,
) (os.FileInfo, error) {
	components := strings.Split(relativePath, "/")
	var final os.FileInfo
	for index := range components {
		current := path.Join(components[:index+1]...)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("%w: inspect artifact path", ErrInvalidResult)
		}
		if info.Mode()&os.ModeSymlink != 0 || !trustedEntry(info, trustedDevice) {
			return nil, fmt.Errorf(
				"%w: artifact path contains a link or mount crossing",
				ErrInvalidResult,
			)
		}
		if index < len(components)-1 && !info.IsDir() {
			return nil, fmt.Errorf("%w: artifact parent is not a directory", ErrInvalidResult)
		}
		if index == len(components)-1 && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: artifact is not a regular file", ErrInvalidResult)
		}
		final = info
	}
	return final, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(payload []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(payload)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
