package trivy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"binaryscan/internal/filetype"

	"golang.org/x/sys/unix"
)

const maxOCIMetadataBytes = int64(1 << 20)
const maxOCIManifestBytes = int64(16 << 20)

// VerifyVMImage accepts a raw disk or filesystem image whose content is
// recognized as an ext2/ext3/ext4 filesystem or a partitioned disk image.
// Trivy's vm subcommand identifies the exact layout itself; this check only
// bounds the input to formats it can parse.
func VerifyVMImage(path string) (VerifiedSource, error) {
	canonical, err := canonicalLeaf(path, false)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: VM image: %v", ErrInvalidInput, err)
	}
	file, err := openRegularNoFollow(canonical)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: VM image: %v", ErrInvalidInput, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: stat VM image: %v", ErrInvalidInput, err)
	}
	detected, err := (filetype.Detector{}).Detect(file, info.Size())
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: identify VM image: %v", ErrInvalidInput, err)
	}
	switch detected.Format {
	// raw-img is defensive: the detector never emits it today, but Trivy's vm
	// subcommand accepts bare filesystem images without a partition table.
	case "ext2", "ext3", "ext4", "raw-img", "mbr-img", "gpt-img":
		return VerifiedSource{path: canonical, kind: SourceVMImage}, nil
	default:
		format := detected.Format
		if format == "" {
			format = "unknown"
		}
		return VerifiedSource{}, fmt.Errorf(
			"%w: expected a VM disk or filesystem image, detected %s",
			ErrInvalidInput,
			format,
		)
	}
}

// VerifyDockerSaveTAR accepts only a structurally identified Docker Save TAR.
func VerifyDockerSaveTAR(path string) (VerifiedSource, error) {
	canonical, err := canonicalLeaf(path, false)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: Docker Save TAR: %v", ErrInvalidInput, err)
	}
	file, err := openRegularNoFollow(canonical)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: Docker Save TAR: %v", ErrInvalidInput, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: stat Docker Save TAR: %v", ErrInvalidInput, err)
	}
	detected, err := (filetype.Detector{}).Detect(file, info.Size())
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: identify Docker Save TAR: %v", ErrInvalidInput, err)
	}
	if detected.Format != "docker-tar" {
		return VerifiedSource{}, fmt.Errorf(
			"%w: expected docker-tar, detected %s",
			ErrInvalidInput,
			detected.Format,
		)
	}
	return VerifiedSource{path: canonical, kind: SourceDockerSaveTAR}, nil
}

// VerifyOCILayout accepts a single-manifest OCI image layout. An index with
// multiple top-level manifests is rejected so no platform is selected silently.
func VerifyOCILayout(path string) (VerifiedSource, error) {
	return verifyOCILayout(path, "")
}

// VerifyOCILayoutTarget accepts one explicit manifest digest from an OCI
// index. It is the required constructor for multi-manifest layouts so callers
// can enqueue every platform deliberately instead of selecting the first.
func VerifyOCILayoutTarget(
	path string,
	manifestDigest string,
) (VerifiedSource, error) {
	if _, err := sha256Digest(manifestDigest); err != nil {
		return VerifiedSource{}, fmt.Errorf(
			"%w: OCI target digest: %v",
			ErrInvalidInput,
			err,
		)
	}
	return verifyOCILayout(path, manifestDigest)
}

func verifyOCILayout(path, selectedDigest string) (VerifiedSource, error) {
	canonical, err := canonicalLeaf(path, true)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI layout: %v", ErrInvalidInput, err)
	}
	layoutRaw, err := readRegularAt(canonical, "oci-layout", maxOCIMetadataBytes)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI layout marker: %v", ErrInvalidInput, err)
	}
	if err := validateJSONTokens(layoutRaw); err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI layout marker: %v", ErrInvalidInput, err)
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err := decodeSingleJSON(layoutRaw, &layout); err != nil ||
		layout.ImageLayoutVersion != "1.0.0" {
		return VerifiedSource{}, fmt.Errorf(
			"%w: OCI imageLayoutVersion must be 1.0.0",
			ErrInvalidInput,
		)
	}

	indexRaw, err := readRegularAt(canonical, "index.json", maxOCIMetadataBytes)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI index: %v", ErrInvalidInput, err)
	}
	if err := validateJSONTokens(indexRaw); err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI index: %v", ErrInvalidInput, err)
	}
	var index struct {
		SchemaVersion int `json:"schemaVersion"`
		Manifests     []struct {
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		} `json:"manifests"`
	}
	if err := decodeSingleJSON(indexRaw, &index); err != nil ||
		index.SchemaVersion != 2 || len(index.Manifests) == 0 {
		return VerifiedSource{}, fmt.Errorf(
			"%w: OCI index must use schemaVersion 2 and contain a manifest",
			ErrInvalidInput,
		)
	}
	if selectedDigest == "" && len(index.Manifests) != 1 {
		return VerifiedSource{}, ErrMultiPlatform
	}
	targetDigest := selectedDigest
	if targetDigest == "" {
		targetDigest = index.Manifests[0].Digest
	}
	found := false
	var targetSize int64
	for _, manifest := range index.Manifests {
		if _, digestErr := sha256Digest(manifest.Digest); digestErr != nil ||
			manifest.Size <= 0 ||
			manifest.Size > maxOCIManifestBytes {
			return VerifiedSource{}, fmt.Errorf(
				"%w: OCI index contains an invalid manifest descriptor",
				ErrInvalidInput,
			)
		}
		if manifest.Digest == targetDigest {
			found = true
			targetSize = manifest.Size
		}
	}
	if !found {
		return VerifiedSource{}, fmt.Errorf(
			"%w: selected OCI manifest digest is not present in index.json",
			ErrInvalidInput,
		)
	}
	digest, err := sha256Digest(targetDigest)
	if err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI manifest digest: %v", ErrInvalidInput, err)
	}
	if err := verifyRegularDigestAt(
		canonical,
		filepath.Join("blobs", "sha256", digest),
		digest,
		targetSize,
	); err != nil {
		return VerifiedSource{}, fmt.Errorf("%w: OCI manifest blob: %v", ErrInvalidInput, err)
	}
	return VerifiedSource{
		path: canonical, kind: SourceOCILayout,
		manifestDigest: targetDigest,
	}, nil
}

func verifySourceAgain(source VerifiedSource) error {
	switch source.kind {
	case SourceDockerSaveTAR:
		verified, err := VerifyDockerSaveTAR(source.path)
		if err != nil {
			return err
		}
		if verified.path != source.path {
			return fmt.Errorf("%w: Docker Save TAR path changed", ErrInvalidInput)
		}
	case SourceOCILayout:
		verified, err := VerifyOCILayoutTarget(
			source.path,
			source.manifestDigest,
		)
		if err != nil {
			return err
		}
		if verified.path != source.path ||
			verified.manifestDigest != source.manifestDigest {
			return fmt.Errorf("%w: OCI layout path changed", ErrInvalidInput)
		}
	case SourceVMImage:
		verified, err := VerifyVMImage(source.path)
		if err != nil {
			return err
		}
		if verified.path != source.path {
			return fmt.Errorf("%w: VM image path changed", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: unverified source", ErrInvalidInput)
	}
	return nil
}

func canonicalLeaf(path string, directory bool) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	cleaned := filepath.Clean(path)
	if cleaned == string(filepath.Separator) {
		return "", fmt.Errorf("filesystem root is not allowed")
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("leaf symlink is not allowed")
	}
	if directory && !info.IsDir() {
		return "", fmt.Errorf("path is not a directory")
	}
	if !directory && !info.Mode().IsRegular() {
		return "", fmt.Errorf("path is not a regular file")
	}
	canonical, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", err
	}
	return filepath.Clean(canonical), nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open returned an invalid descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("path is not a regular file")
	}
	return file, nil
}

func readRegularAt(root, relative string, maximum int64) ([]byte, error) {
	target, info, err := regularTargetAt(root, relative)
	if err != nil {
		return nil, err
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return raw, nil
}

func verifyRegularDigestAt(
	root string,
	relative string,
	expectedDigest string,
	expectedSize int64,
) error {
	target, info, err := regularTargetAt(root, relative)
	if err != nil {
		return err
	}
	if info.Size() != expectedSize || info.Size() > maxOCIManifestBytes {
		return fmt.Errorf("manifest blob size does not match index descriptor")
	}
	file, err := openRegularNoFollow(target)
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(file, maxOCIManifestBytes+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedDigest {
		return fmt.Errorf("manifest blob digest does not match index descriptor")
	}
	return nil
}

func regularTargetAt(root, relative string) (string, os.FileInfo, error) {
	if filepath.IsAbs(relative) {
		return "", nil, fmt.Errorf("relative path is absolute")
	}
	cleaned := filepath.Clean(relative)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", nil, fmt.Errorf("relative path escapes layout")
	}
	target := filepath.Join(root, cleaned)
	info, err := os.Lstat(target)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, fmt.Errorf("path is not a regular file")
	}
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", nil, err
	}
	canonical = filepath.Clean(canonical)
	if canonical != target || !sameOrDescendant(canonical, root) {
		return "", nil, fmt.Errorf("symlinked layout path is not allowed")
	}
	return canonical, info, nil
}

func decodeSingleJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func sha256Digest(value string) (string, error) {
	algorithm, digest, found := strings.Cut(value, ":")
	if !found || algorithm != "sha256" || len(digest) != 64 {
		return "", fmt.Errorf("expected sha256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil ||
		strings.ToLower(digest) != digest {
		return "", fmt.Errorf("expected lowercase hexadecimal digest")
	}
	return digest, nil
}
