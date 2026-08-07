package auth

import (
	"bytes"
	"errors"
	"fmt"
	"os"
)

func ReadPasswordSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("administrator password secret file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect administrator password secret: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("administrator password secret is not a regular file")
	}
	if info.Size() > 1026 {
		return nil, errors.New("administrator password secret exceeds 1024 bytes")
	}
	password, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read administrator password secret: %w", err)
	}
	password = bytes.TrimSuffix(password, []byte("\n"))
	password = bytes.TrimSuffix(password, []byte("\r"))
	if bytes.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("administrator password secret must contain exactly one line")
	}
	if err := validatePasswordLength(password, DefaultMinimumPasswordBytes); err != nil {
		return nil, err
	}
	return password, nil
}
