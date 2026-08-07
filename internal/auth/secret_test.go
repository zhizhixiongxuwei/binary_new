package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPasswordSecretAcceptsOneLineAndPreservesSpaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("  secure password value  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	password, err := ReadPasswordSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "  secure password value  " {
		t.Fatalf("password whitespace was changed: %q", password)
	}
}

func TestReadPasswordSecretRejectsMultipleLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("first-password\nsecond-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPasswordSecret(path); err == nil {
		t.Fatal("ReadPasswordSecret() error = nil, want multiline rejection")
	}
}
