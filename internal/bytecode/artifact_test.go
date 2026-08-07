package bytecode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileArtifactValidatorBindsActualBytesAndInspectsSource(t *testing.T) {
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "source"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("public class A {}\n")
	path := filepath.Join(workspace, "source", "A.java")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	inspected := false
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source": SourceInspectorFunc(func(
			_ context.Context,
			reader io.Reader,
		) error {
			payload, err := io.ReadAll(reader)
			inspected = bytes.Contains(payload, []byte("class A"))
			return err
		}),
	})
	if err != nil {
		t.Fatalf("NewFileArtifactValidator() error = %v", err)
	}
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source",
		"source/A.java", content, "class:a",
	)
	validation, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	)
	if err != nil {
		t.Fatalf("ValidateArtifact() error = %v", err)
	}
	if validation != ValidationContentVerified || !inspected {
		t.Fatalf("validation = %q, inspected = %v", validation, inspected)
	}

	artifact.SHA256 = strings.Repeat("0", 64)
	if _, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("digest mismatch error = %v", err)
	}
}

func TestFileArtifactValidatorRejectsUninspectedOrUnsafeSource(t *testing.T) {
	workspace := t.TempDir()
	content := []byte("public class A {}")
	if err := os.WriteFile(
		filepath.Join(workspace, "A.java"), content, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source",
		"A.java", content, "class:a",
	)
	if _, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("missing inspector error = %v", err)
	}

	target := filepath.Join(workspace, "target.java")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.java", filepath.Join(workspace, "link.java")); err != nil {
		t.Fatal(err)
	}
	artifact.RelativePath = "link.java"
	if _, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestFileArtifactValidatorChecksContextAndInspectorFailures(t *testing.T) {
	workspace := t.TempDir()
	content := []byte("not source")
	if err := os.WriteFile(filepath.Join(workspace, "A.java"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source": SourceInspectorFunc(func(
			context.Context,
			io.Reader,
		) error {
			return errors.New("parse failed")
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source",
		"A.java", content, "class:a",
	)
	if _, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("inspector failure error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validator.ValidateArtifact(
		cancelled, workspace, artifact,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestFileArtifactValidatorRejectsHardLinkedArtifact(t *testing.T) {
	workspace := t.TempDir()
	content := []byte("public class A {}")
	original := filepath.Join(workspace, "original.java")
	linked := filepath.Join(workspace, "linked.java")
	if err := os.WriteFile(original, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, linked); err != nil {
		t.Fatal(err)
	}
	validator, err := NewFileArtifactValidator(map[string]SourceInspector{
		"text/x-java-source": SourceInspectorFunc(func(
			_ context.Context,
			reader io.Reader,
		) error {
			_, err := io.Copy(io.Discard, reader)
			return err
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactFor(
		"source-a", ArtifactSource, "text/x-java-source",
		"linked.java", content, "class:a",
	)
	if _, err := validator.ValidateArtifact(
		context.Background(), workspace, artifact,
	); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("hard-linked artifact error = %v", err)
	}
}

func TestFileArtifactValidatorRejectsAppendAndTruncateDuringRead(t *testing.T) {
	for _, operation := range []string{"append", "truncate"} {
		t.Run(operation, func(t *testing.T) {
			workspace := t.TempDir()
			content := []byte("public class A { int value; }")
			filePath := filepath.Join(workspace, "A.java")
			if err := os.WriteFile(filePath, content, 0o600); err != nil {
				t.Fatal(err)
			}
			validator, err := NewFileArtifactValidator(map[string]SourceInspector{
				"text/x-java-source": SourceInspectorFunc(func(
					_ context.Context,
					reader io.Reader,
				) error {
					first := make([]byte, 1)
					if _, err := io.ReadFull(reader, first); err != nil {
						return err
					}
					if operation == "append" {
						file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0)
						if err != nil {
							return err
						}
						_, writeErr := file.Write([]byte("x"))
						closeErr := file.Close()
						if writeErr != nil {
							return writeErr
						}
						if closeErr != nil {
							return closeErr
						}
					} else if err := os.Truncate(filePath, 1); err != nil {
						return err
					}
					_, err := io.Copy(io.Discard, reader)
					return err
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			artifact := artifactFor(
				"source-a", ArtifactSource, "text/x-java-source",
				"A.java", content, "class:a",
			)
			if _, err := validator.ValidateArtifact(
				context.Background(), workspace, artifact,
			); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("ValidateArtifact() error = %v", err)
			}
		})
	}
}

func artifactFor(
	id string,
	kind ArtifactKind,
	mediaType string,
	relativePath string,
	content []byte,
	classKey string,
) Artifact {
	digest := sha256.Sum256(content)
	classKeys := []string{}
	if classKey != "" {
		classKeys = []string{classKey}
	}
	return Artifact{
		ID: id, Kind: kind, MediaType: mediaType,
		RelativePath: relativePath,
		SHA256:       hex.EncodeToString(digest[:]), SizeBytes: int64(len(content)),
		Chunk:     ArtifactChunk{SetID: id, Index: 0, Count: 1},
		ClassKeys: classKeys,
	}
}
