package bytecode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

type verifiedInput struct {
	mu   sync.RWMutex
	file *os.File
}

func (input *verifiedInput) reader(size int64) (*io.SectionReader, error) {
	input.mu.RLock()
	defer input.mu.RUnlock()
	if input.file == nil {
		return nil, fmt.Errorf("%w: verified input is closed", ErrInvalidRequest)
	}
	return io.NewSectionReader(input.file, 0, size), nil
}

func (input *verifiedInput) close() error {
	input.mu.Lock()
	defer input.mu.Unlock()
	if input.file == nil {
		return nil
	}
	err := input.file.Close()
	input.file = nil
	return err
}

// bindInput copies exactly the declared bytes from a fixed source descriptor
// into an unlinked, read-only snapshot. The engine never receives the original
// pathname. This turns the digest check and the bytes consumed by the engine
// into one object rather than two path lookups separated by a race window.
func bindInput(ctx context.Context, input Input, workspace string) (*verifiedInput, error) {
	before, err := os.Lstat(input.Path)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 || before.Size() != input.SizeBytes {
		return nil, fmt.Errorf("%w: input file is invalid", ErrInvalidRequest)
	}
	source, err := os.Open(input.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: open input file", ErrInvalidRequest)
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() ||
		!os.SameFile(before, opened) || opened.Size() != input.SizeBytes {
		return nil, fmt.Errorf("%w: input path changed while opening", ErrInvalidRequest)
	}
	afterOpen, err := os.Lstat(input.Path)
	if err != nil || !os.SameFile(opened, afterOpen) ||
		afterOpen.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: input path changed while opening", ErrInvalidRequest)
	}

	temporary, err := os.CreateTemp(workspace, ".bytecode-input-*")
	if err != nil {
		return nil, fmt.Errorf("%w: create private input snapshot", ErrInvalidRequest)
	}
	temporaryPath := temporary.Name()
	unlinked := false
	defer func() {
		_ = temporary.Close()
		if !unlinked {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("%w: protect input snapshot", ErrInvalidRequest)
	}
	hasher := sha256.New()
	limited := io.LimitReader(
		&contextReader{ctx: ctx, reader: source}, input.SizeBytes+1,
	)
	written, err := io.Copy(io.MultiWriter(temporary, hasher), limited)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: copy input snapshot", ErrInvalidRequest)
	}
	if written != input.SizeBytes || hex.EncodeToString(hasher.Sum(nil)) != input.SHA256 {
		return nil, fmt.Errorf("%w: input size or digest mismatch", ErrInvalidRequest)
	}
	openedAfterCopy, err := source.Stat()
	if err != nil || !os.SameFile(opened, openedAfterCopy) {
		return nil, fmt.Errorf("%w: input changed while copying", ErrInvalidRequest)
	}
	if err := temporary.Sync(); err != nil {
		return nil, fmt.Errorf("%w: sync input snapshot", ErrInvalidRequest)
	}
	snapshotInfo, err := temporary.Stat()
	if err != nil || !snapshotInfo.Mode().IsRegular() ||
		snapshotInfo.Size() != input.SizeBytes {
		return nil, fmt.Errorf("%w: input snapshot is invalid", ErrInvalidRequest)
	}
	reader, err := os.Open(temporaryPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open input snapshot read-only", ErrInvalidRequest)
	}
	readerInfo, err := reader.Stat()
	if err != nil || !os.SameFile(snapshotInfo, readerInfo) {
		reader.Close()
		return nil, fmt.Errorf("%w: input snapshot changed", ErrInvalidRequest)
	}
	if err := os.Remove(temporaryPath); err != nil {
		reader.Close()
		return nil, fmt.Errorf("%w: unlink input snapshot", ErrInvalidRequest)
	}
	unlinked = true
	if err := temporary.Close(); err != nil {
		reader.Close()
		return nil, fmt.Errorf("%w: close input snapshot writer", ErrInvalidRequest)
	}

	verification := sha256.New()
	verifiedBytes, err := io.Copy(
		verification,
		&contextReader{ctx: ctx, reader: io.NewSectionReader(reader, 0, input.SizeBytes)},
	)
	if err != nil || verifiedBytes != input.SizeBytes ||
		hex.EncodeToString(verification.Sum(nil)) != input.SHA256 {
		reader.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, fmt.Errorf("%w: verify input snapshot", ErrInvalidRequest)
	}
	return &verifiedInput{file: reader}, nil
}
