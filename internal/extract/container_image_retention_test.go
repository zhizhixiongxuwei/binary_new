package extract

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"binaryscan/internal/filetype"
)

type retainedContainerDetector struct {
	imageSHA256 string
}

func (detector retainedContainerDetector) Detect(
	source io.ReaderAt,
	size int64,
) (filetype.Result, error) {
	content := make([]byte, size)
	if size > 0 {
		if _, err := source.ReadAt(content, 0); err != nil {
			return filetype.Result{}, err
		}
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) == detector.imageSHA256 {
		return filetype.Result{
			Format:   "docker-tar",
			MIMEType: "application/x-tar",
		}, nil
	}
	return filetype.Result{
		Format:   "unknown",
		MIMEType: "application/octet-stream",
	}, nil
}

func TestNestedContainerMaterializationLivesUntilWorkspaceCleanup(t *testing.T) {
	var nested bytes.Buffer
	writer := tar.NewWriter(&nested)
	manifest := []byte(`[]`)
	if err := writer.WriteHeader(&tar.Header{
		Name: "manifest.json",
		Mode: 0o600,
		Size: int64(len(manifest)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	nestedDigest := sha256.Sum256(nested.Bytes())
	outer := zipFixture(t, []zipEntry{{
		name: "images/nested.tar",
		body: nested.Bytes(),
	}})

	root := t.TempDir()
	sourcePath := filepath.Join(root, "outer.zip")
	if err := os.WriteFile(sourcePath, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	workRoot := filepath.Join(root, "work")
	if err := os.Mkdir(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(retainedContainerDetector{
		imageSHA256: hex.EncodeToString(nestedDigest[:]),
	}, generousLimits())
	result, err := engine.Extract(
		context.Background(),
		source,
		"zip",
		workRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ContainerImages) != 1 {
		t.Fatalf("container images = %+v", result.ContainerImages)
	}
	image := result.ContainerImages[0]
	if image.LogicalPath != "/images/nested.tar" ||
		image.Format != "docker-tar" ||
		image.SHA256 != hex.EncodeToString(nestedDigest[:]) ||
		image.SizeBytes != int64(nested.Len()) {
		t.Fatalf("retained image = %+v", image)
	}
	content, err := os.ReadFile(image.WorkPath)
	if err != nil {
		t.Fatalf("retained image disappeared before cleanup: %v", err)
	}
	if !bytes.Equal(content, nested.Bytes()) {
		t.Fatal("retained image content changed")
	}
	if err := os.RemoveAll(workRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(image.WorkPath); !os.IsNotExist(err) {
		t.Fatalf("retained image survived workspace cleanup: %v", err)
	}
}
