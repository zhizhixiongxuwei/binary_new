package decompile

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func publishedProjectFixture(
	runID string,
	kind string,
	language string,
	symbolCount int,
	canonical bool,
) PublishedSourceProject {
	root := sourceProjectRoot(runID)
	project := PublishedSourceProject{
		ID: runID, LayoutVersion: sourceProjectLayoutV1,
		SourceKind: kind, Language: language, RootStorageKey: root,
		ManifestStorageKey: path.Join(root, sourceProjectManifestName),
		ManifestSHA256:     strings.Repeat("a", 64), ManifestSizeBytes: 128,
		SourceFileCount: 1, SymbolCount: symbolCount, SourceSizeBytes: 32,
	}
	if canonical {
		project.CanonicalStorageKey = path.Join(root, "src", "decompiled.c")
		project.CanonicalSHA256 = strings.Repeat("b", 64)
		project.CanonicalSizeBytes = 32
	}
	return project
}

func TestSourceProjectPublicationRejectsProjectInternalSymlinks(t *testing.T) {
	repositoryRoot := t.TempDir()
	runID := "123e4567-e89b-42d3-a456-426614174000"
	publication, err := newSourceProjectPublication(repositoryRoot, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = publication.Close()
		cleanupSourceProject(repositoryRoot, runID)
	}()
	projectRoot := filepath.Join(repositoryRoot, sourceProjectRootName, runID)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(projectRoot, "src")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := publication.MkdirAll("src"); err == nil {
		t.Fatal("publication followed an injected source directory symlink")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: %v, %v", entries, err)
	}
	if err := os.Remove(filepath.Join(projectRoot, "src")); err != nil {
		t.Fatal(err)
	}
	if err := publication.MkdirAll("src"); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "victim.c")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(projectRoot, "src", "decompiled.c")
	if err := os.Symlink(victim, destination); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := publication.CreateFile("src/decompiled.c"); err == nil {
		t.Fatal("publication followed or replaced an injected file symlink")
	}
	if value, err := os.ReadFile(victim); err != nil || string(value) != "unchanged" {
		t.Fatalf("symlink target changed: %q, %v", value, err)
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	file, err := publication.CreateFile("src/decompiled.c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("void f(void) {}\n")); err != nil {
		t.Fatal(err)
	}
	if err := file.Commit(); err != nil {
		t.Fatal(err)
	}
	manifest, err := publication.CreateFile(sourceProjectManifestName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Finalize(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSourceProjectPublicationFinalizeRejectsTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "file content",
			mutate: func(t *testing.T, projectRoot string) {
				if err := os.WriteFile(
					filepath.Join(projectRoot, sourceProjectManifestName),
					[]byte("no\n"), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "project directory chain",
			mutate: func(t *testing.T, projectRoot string) {
				if err := os.Rename(projectRoot, projectRoot+".replaced"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(projectRoot, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repositoryRoot := t.TempDir()
			runID := "223e4567-e89b-42d3-a456-426614174001"
			publication, err := newSourceProjectPublication(repositoryRoot, runID)
			if err != nil {
				t.Fatal(err)
			}
			defer publication.Close()
			manifest, err := publication.CreateFile(sourceProjectManifestName)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manifest.Write([]byte("{}\n")); err != nil {
				t.Fatal(err)
			}
			if err := manifest.Commit(); err != nil {
				t.Fatal(err)
			}
			projectRoot := filepath.Join(
				repositoryRoot, sourceProjectRootName, runID,
			)
			test.mutate(t, projectRoot)
			if err := publication.Finalize(context.Background()); err == nil {
				t.Fatal("tampered source project publication was finalized")
			}
		})
	}
}

func TestSourceProjectPublicationRejectsPreexistingProjectSymlink(t *testing.T) {
	repositoryRoot := t.TempDir()
	runID := "323e4567-e89b-42d3-a456-426614174002"
	projectsRoot := filepath.Join(repositoryRoot, sourceProjectRootName)
	if err := os.Mkdir(projectsRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(projectsRoot, runID)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	publication, err := newSourceProjectPublication(repositoryRoot, runID)
	if publication != nil {
		_ = publication.Close()
	}
	if err == nil {
		t.Fatal("publication accepted a preexisting project symlink")
	}
	if value, err := os.ReadFile(marker); err != nil || string(value) != "unchanged" {
		t.Fatalf("preexisting symlink target changed: %q, %v", value, err)
	}
}
