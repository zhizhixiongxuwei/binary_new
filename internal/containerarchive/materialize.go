package containerarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Materialize writes one validated, flattened OCI layout containing every leaf
// manifest from the plan. Callers select each Inspection target explicitly
// (for example layout@sha256:...) when invoking Trivy.
func (plan *OCIPlan) Materialize(
	ctx context.Context,
	destination string,
) (returnErr error) {
	if ctx == nil {
		return errors.New("containerarchive: nil context")
	}
	if plan == nil || plan.index == nil || plan.index.source == nil ||
		len(plan.targets) == 0 {
		return errors.New("containerarchive: invalid OCI plan")
	}
	parentPath, base, err := cleanMaterializeDestination(destination)
	if err != nil {
		return err
	}
	manifests := make([]descriptor, 0, len(plan.targets))
	blobPaths := make(map[string]struct{})
	for _, target := range plan.targets {
		manifests = append(manifests, target.descriptor)
		for _, blobPath := range target.blobPaths {
			blobPaths[blobPath] = struct{}{}
		}
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return fmt.Errorf("open OCI destination parent: %w", err)
	}
	defer parent.Close()
	if _, err := parent.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return validationError(
				"oci_destination_exists",
				"OCI materialization destination already exists",
			)
		}
		return fmt.Errorf("inspect OCI destination: %w", err)
	}
	if err := parent.Mkdir(base, 0o700); err != nil {
		return fmt.Errorf("create OCI destination: %w", err)
	}
	keep := false
	root, err := parent.OpenRoot(base)
	if err != nil {
		_ = parent.Remove(base)
		return fmt.Errorf("open OCI destination: %w", err)
	}
	defer func() {
		if !keep {
			returnErr = errors.Join(
				returnErr,
				cleanupMaterializedOCI(root, blobPaths),
			)
		}
		returnErr = errors.Join(
			returnErr,
			wrapMaterializeError(root.Close(), "close OCI destination"),
		)
		if !keep {
			returnErr = errors.Join(
				returnErr,
				wrapMaterializeError(
					parent.Remove(base),
					"remove incomplete OCI destination",
				),
			)
		}
	}()

	if err := root.Mkdir("blobs", 0o700); err != nil {
		return fmt.Errorf("create OCI blob root: %w", err)
	}
	if err := root.Mkdir("blobs/sha256", 0o700); err != nil {
		return fmt.Errorf("create OCI blob directory: %w", err)
	}
	layoutJSON, err := json.Marshal(ociLayout{
		ImageLayoutVersion: "1.0.0",
	})
	if err != nil {
		return fmt.Errorf("encode OCI layout marker: %w", err)
	}
	if err := writeRootFile(root, "oci-layout", layoutJSON); err != nil {
		return err
	}
	if err := writeFlattenedIndex(
		ctx,
		root,
		"index.json",
		manifests,
	); err != nil {
		return err
	}
	for blobPath := range blobPaths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := plan.copyBlob(ctx, root, blobPath); err != nil {
			return err
		}
	}
	if err := sealOCILayout(root, blobPaths); err != nil {
		return err
	}
	keep = true
	return nil
}

func cleanupMaterializedOCI(
	root *os.Root,
	blobPaths map[string]struct{},
) error {
	var cleanupErr error
	remove := func(name string) {
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(
				cleanupErr,
				fmt.Errorf("remove incomplete OCI path %s: %w", name, err),
			)
		}
	}
	for blobPath := range blobPaths {
		remove(blobPath)
	}
	remove("oci-layout")
	remove("index.json")
	remove("blobs/sha256")
	remove("blobs")
	return cleanupErr
}

func writeRootFile(root *os.Root, name string, content []byte) error {
	file, err := root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create OCI metadata %s: %w", name, err)
	}
	writeErr := error(nil)
	if _, err := file.Write(content); err != nil {
		writeErr = fmt.Errorf("write OCI metadata %s: %w", name, err)
	} else if err := file.Sync(); err != nil {
		writeErr = fmt.Errorf("sync OCI metadata %s: %w", name, err)
	}
	closeErr := file.Close()
	return errors.Join(
		writeErr,
		wrapMaterializeError(closeErr, "close OCI metadata "+name),
	)
}

func writeFlattenedIndex(
	ctx context.Context,
	root *os.Root,
	name string,
	manifests []descriptor,
) error {
	file, err := root.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create OCI metadata %s: %w", name, err)
	}
	writeErr := error(nil)
	write := func(value []byte) {
		if writeErr != nil {
			return
		}
		if _, err := file.Write(value); err != nil {
			writeErr = fmt.Errorf("write OCI metadata %s: %w", name, err)
		}
	}
	write([]byte(flattenedIndexPrefix))
	for index, manifest := range manifests {
		if err := ctx.Err(); err != nil {
			writeErr = err
			break
		}
		if index > 0 {
			write([]byte{','})
		}
		content, err := json.Marshal(manifest)
		if err != nil {
			writeErr = fmt.Errorf("encode flattened OCI descriptor: %w", err)
			break
		}
		write(content)
	}
	if writeErr == nil {
		write([]byte(flattenedIndexSuffix))
	}
	if writeErr == nil {
		if err := file.Sync(); err != nil {
			writeErr = fmt.Errorf("sync OCI metadata %s: %w", name, err)
		}
	}
	closeErr := file.Close()
	return errors.Join(
		writeErr,
		wrapMaterializeError(closeErr, "close OCI metadata "+name),
	)
}

func (plan *OCIPlan) copyBlob(
	ctx context.Context,
	root *os.Root,
	blobPath string,
) error {
	entry, err := plan.index.regular(blobPath)
	if err != nil {
		return err
	}
	_, hexDigest, found := strings.Cut(blobPath, "blobs/sha256/")
	if !found || len(hexDigest) != 64 {
		return validationError(
			"oci_descriptor_invalid",
			"planned OCI blob path is invalid",
		)
	}
	file, err := root.OpenFile(
		filepath.ToSlash(blobPath),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("create OCI blob: %w", err)
	}
	digest := sha256.New()
	source := &contextReader{
		ctx: ctx,
		reader: io.NewSectionReader(
			plan.index.source,
			entry.offset,
			entry.size,
		),
	}
	written, copyErr := io.CopyBuffer(
		io.MultiWriter(file, digest),
		source,
		make([]byte, 1<<20),
	)
	if copyErr == nil && written != entry.size {
		copyErr = io.ErrUnexpectedEOF
	}
	if copyErr == nil &&
		hex.EncodeToString(digest.Sum(nil)) != hexDigest {
		copyErr = validationError(
			"oci_descriptor_digest_mismatch",
			"OCI source changed after validation",
		)
	}
	if copyErr == nil {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil {
		return errors.Join(
			fmt.Errorf("copy OCI blob: %w", copyErr),
			wrapMaterializeError(closeErr, "close incomplete OCI blob"),
		)
	}
	if closeErr != nil {
		return fmt.Errorf("close OCI blob: %w", closeErr)
	}
	return nil
}

func sealOCILayout(
	root *os.Root,
	blobPaths map[string]struct{},
) error {
	for _, name := range []string{"oci-layout", "index.json"} {
		if err := chmodRootRegular(root, name, 0o400); err != nil {
			return fmt.Errorf("seal OCI metadata %s: %w", name, err)
		}
	}
	for blobPath := range blobPaths {
		if err := chmodRootRegular(root, blobPath, 0o400); err != nil {
			return fmt.Errorf("seal OCI blob: %w", err)
		}
	}
	// Keep directories owner-writable so workspace cleanup can unlink the
	// read-only files without a privileged chmod pass.
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open OCI layout for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(
		wrapMaterializeError(syncErr, "sync OCI layout"),
		wrapMaterializeError(closeErr, "close OCI layout"),
	)
}

func chmodRootRegular(root *os.Root, name string, mode os.FileMode) error {
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		closeErr := file.Close()
		return errors.Join(
			statErr,
			errors.New("OCI materialized path is not a regular file"),
			closeErr,
		)
	}
	chmodErr := file.Chmod(mode)
	closeErr := file.Close()
	return errors.Join(chmodErr, closeErr)
}

func wrapMaterializeError(err error, action string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", action, err)
}
