package javaanalysis

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

const sourceProjectSchemaVersion = "binaryscan-source-project/v1"

type sourceProjectManifest struct {
	SchemaVersion   string                      `json:"schema_version"`
	ProjectID       string                      `json:"project_id"`
	LayoutVersion   string                      `json:"layout_version"`
	SourceKind      string                      `json:"source_kind"`
	Language        string                      `json:"language"`
	EngineName      string                      `json:"engine_name"`
	EngineVersion   string                      `json:"engine_version"`
	Status          string                      `json:"status"`
	SourceFileCount uint64                      `json:"source_file_count"`
	SymbolCount     uint64                      `json:"symbol_count"`
	Files           []sourceProjectManifestFile `json:"files"`
}

type sourceProjectManifestFile struct {
	ResultID    string `json:"result_id"`
	SymbolKey   string `json:"symbol_key"`
	BinaryName  string `json:"binary_name"`
	DisplayName string `json:"display_name"`
	Language    string `json:"language"`
	Status      string `json:"status"`
	LogicalPath string `json:"logical_path,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	SizeBytes   uint64 `json:"size_bytes,omitempty"`
}

func canonicalInputSHA256(files []SourceFile) (string, error) {
	if len(files) == 0 || len(files) > MaxFiles {
		return "", ErrSourceUnavailable
	}
	copyFiles := append([]SourceFile(nil), files...)
	sort.Slice(copyFiles, func(i, j int) bool {
		return copyFiles[i].LogicalPath < copyFiles[j].LogicalPath
	})
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, RequestSchemaVersion+"\n")
	previous := ""
	for _, file := range copyFiles {
		if !validSourceFile(file) || file.LogicalPath == previous {
			return "", ErrSourceUnavailable
		}
		previous = file.LogicalPath
		values := []string{
			file.ResultID, file.LogicalPath, file.BinaryName,
			strconv.FormatUint(file.SizeBytes, 10), file.SHA256,
		}
		for index, value := range values {
			_, _ = io.WriteString(hasher, value)
			if index < len(values)-1 {
				_, _ = hasher.Write([]byte{0})
			}
		}
		_, _ = hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func validSourceFile(file SourceFile) bool {
	return uuidPattern.MatchString(file.ResultID) &&
		validJavaLogicalPath(file.LogicalPath) &&
		validText(file.BinaryName, 1024, false) &&
		sha256Pattern.MatchString(file.SHA256) &&
		file.SizeBytes > 0 && file.SizeBytes <= uint64(MaxSourceBytes)
}

func validJavaLogicalPath(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, `\`) ||
		!strings.HasPrefix(value, "src/main/java/") ||
		!strings.HasSuffix(strings.ToLower(value), ".java") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func decodeAndValidateManifest(
	reader io.Reader,
	project ProjectSnapshot,
) ([]SourceFile, error) {
	decoder := json.NewDecoder(bufio.NewReader(reader))
	decoder.DisallowUnknownFields()
	var manifest sourceProjectManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode Java source manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrSourceUnavailable
	}
	if manifest.SchemaVersion != sourceProjectSchemaVersion ||
		manifest.ProjectID != project.ProjectID ||
		manifest.LayoutVersion != "project-v1" ||
		manifest.SourceKind != project.SourceKind ||
		manifest.Language != project.Language ||
		manifest.EngineName != project.EngineName ||
		manifest.EngineVersion != project.EngineVersion ||
		manifest.Status != project.Status ||
		manifest.SourceFileCount != project.ProjectSourceFileCount ||
		manifest.SymbolCount != project.ProjectSymbolCount ||
		uint64(len(manifest.Files)) != manifest.SymbolCount {
		return nil, ErrSourceUnavailable
	}
	selected := make([]SourceFile, 0, len(project.Files))
	seenResult := make(map[string]struct{}, len(manifest.Files))
	seenPath := make(map[string]struct{}, len(manifest.Files))
	storedCount := uint64(0)
	storedBytes := uint64(0)
	for _, entry := range manifest.Files {
		if !uuidPattern.MatchString(entry.ResultID) ||
			!validText(entry.BinaryName, 1024, false) ||
			!validSafeASCII(entry.Language, 32) ||
			(entry.Status != "complete" && entry.Status != "bytecode_only" &&
				entry.Status != "unsupported" && entry.Status != "failed") {
			return nil, ErrSourceUnavailable
		}
		if _, duplicate := seenResult[entry.ResultID]; duplicate {
			return nil, ErrSourceUnavailable
		}
		seenResult[entry.ResultID] = struct{}{}
		if entry.LogicalPath == "" {
			if entry.SHA256 != "" || entry.SizeBytes != 0 {
				return nil, ErrSourceUnavailable
			}
			continue
		}
		if !validProjectLogicalPath(entry.LogicalPath) ||
			!sha256Pattern.MatchString(entry.SHA256) ||
			entry.SizeBytes == 0 {
			return nil, ErrSourceUnavailable
		}
		if _, duplicate := seenPath[entry.LogicalPath]; duplicate {
			return nil, ErrSourceUnavailable
		}
		seenPath[entry.LogicalPath] = struct{}{}
		storedCount++
		if storedBytes > ^uint64(0)-entry.SizeBytes {
			return nil, ErrSourceUnavailable
		}
		storedBytes += entry.SizeBytes
		if entry.Status != "complete" || entry.Language != "java" ||
			!validJavaLogicalPath(entry.LogicalPath) {
			continue
		}
		selected = append(selected, SourceFile{
			FileIdentity: FileIdentity{
				ResultID: entry.ResultID, LogicalPath: entry.LogicalPath,
				BinaryName: entry.BinaryName,
			},
			SHA256: entry.SHA256, SizeBytes: entry.SizeBytes,
		})
	}
	if storedCount != manifest.SourceFileCount ||
		storedBytes != project.ProjectSourceSizeBytes ||
		len(selected) != len(project.Files) {
		return nil, ErrSourceUnavailable
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].LogicalPath < selected[j].LogicalPath
	})
	for index := range selected {
		expected := project.Files[index]
		actual := selected[index]
		if actual.ResultID != expected.ResultID ||
			actual.LogicalPath != expected.LogicalPath ||
			actual.BinaryName != expected.BinaryName ||
			actual.SHA256 != expected.SHA256 ||
			actual.SizeBytes != expected.SizeBytes {
			return nil, ErrSourceUnavailable
		}
	}
	digest, err := canonicalInputSHA256(selected)
	if err != nil || digest != project.InputSHA256 {
		return nil, ErrSourceUnavailable
	}
	return selected, nil
}

func validProjectLogicalPath(value string) bool {
	if value == "" || len(value) > 1024 || path.IsAbs(value) ||
		path.Clean(value) != value || strings.Contains(value, `\`) ||
		(!strings.HasPrefix(value, "src/") &&
			!strings.HasPrefix(value, "artifacts/bytecode/")) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}
