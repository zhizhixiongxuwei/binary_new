package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildBundle(t *testing.T) {
	root := t.TempDir()
	trivyDirectory := filepath.Join(root, "db")
	javaDirectory := filepath.Join(root, "java-db")
	for _, directory := range []string{trivyDirectory, javaDirectory} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	metadata := []byte(`{"Version":2,"UpdatedAt":"2026-08-05T13:23:37.971556067Z"}`)
	if err := os.WriteFile(filepath.Join(trivyDirectory, "metadata.json"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trivyDirectory, "trivy.db"), []byte("primary"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata = []byte(`{"Version":1,"UpdatedAt":"2026-08-05T01:25:20.15222691Z"}`)
	if err := os.WriteFile(filepath.Join(javaDirectory, "metadata.json"), metadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(javaDirectory, "trivy-java.db"), []byte("java"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(root, "bundle.json")
	environmentPath := filepath.Join(root, "bundle.env")
	if err := buildBundle(options{
		trivyDirectory: trivyDirectory,
		javaDirectory:  javaDirectory,
		output:         manifestPath,
		environment:    environmentPath,
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != "2026.08.05" || manifest.GeneratedAt != "2026-08-05T13:23:37Z" {
		t.Fatalf("unexpected bundle time identity: %#v", manifest)
	}
	if manifest.ContentSHA256 != bundleHash(manifest.Databases) || len(manifest.Databases) != 2 {
		t.Fatalf("unexpected bundle content identity: %#v", manifest)
	}
	environment, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BUNDLE_ID", "TRIVY_DB_ID", "TRIVY_JAVA_DB_ID"} {
		if !strings.Contains(string(environment), name+"=") {
			t.Fatalf("environment is missing %s: %s", name, environment)
		}
	}
}
