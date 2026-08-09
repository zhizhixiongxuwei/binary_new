package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxDatabaseBytes = int64(4 << 30)

type fileEntry struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type databaseEntry struct {
	ID            string      `json:"id"`
	DatabaseType  string      `json:"database_type"`
	Version       string      `json:"version"`
	SchemaVersion int         `json:"schema_version"`
	StorageKey    string      `json:"storage_key"`
	Files         []fileEntry `json:"files"`
}

type bundleManifest struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Version       string          `json:"version"`
	GeneratedAt   string          `json:"generated_at"`
	ContentSHA256 string          `json:"content_sha256"`
	Databases     []databaseEntry `json:"databases"`
}

type databaseMetadata struct {
	UpdatedAt time.Time `json:"UpdatedAt"`
}

type options struct {
	trivyDirectory string
	javaDirectory  string
	version        string
	generatedAt    string
	output         string
	environment    string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "trivy-bundle: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("trivy-bundle", flag.ContinueOnError)
	value := options{}
	flags.StringVar(&value.trivyDirectory, "trivy-dir", "", "directory containing metadata.json and trivy.db")
	flags.StringVar(&value.javaDirectory, "java-dir", "", "directory containing metadata.json and trivy-java.db")
	flags.StringVar(&value.version, "version", "", "bundle version; defaults to the newest database update date")
	flags.StringVar(&value.generatedAt, "generated-at", "", "bundle UTC generation time; defaults to the newest database update")
	flags.StringVar(&value.output, "output", "", "new bundle.json path")
	flags.StringVar(&value.environment, "env-output", "", "new shell environment output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	return buildBundle(value)
}

func buildBundle(value options) error {
	for name, path := range map[string]string{
		"trivy-dir": value.trivyDirectory, "java-dir": value.javaDirectory,
		"output": value.output, "env-output": value.environment,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("--%s must be a canonical absolute path", name)
		}
	}
	trivyUpdated, err := readUpdatedAt(filepath.Join(value.trivyDirectory, "metadata.json"))
	if err != nil {
		return err
	}
	javaUpdated, err := readUpdatedAt(filepath.Join(value.javaDirectory, "metadata.json"))
	if err != nil {
		return err
	}
	newest := trivyUpdated
	if javaUpdated.After(newest) {
		newest = javaUpdated
	}
	newest = newest.UTC().Truncate(time.Second)
	if value.version == "" {
		value.version = newest.Format("2006.01.02")
	}
	if value.generatedAt == "" {
		value.generatedAt = newest.Format(time.RFC3339)
	}
	generatedAt, err := time.Parse(time.RFC3339, value.generatedAt)
	if err != nil || generatedAt.IsZero() || generatedAt.Location() != time.UTC ||
		generatedAt.Format(time.RFC3339) != value.generatedAt {
		return errors.New("--generated-at must be canonical UTC RFC3339")
	}
	if !safeVersion(value.version) {
		return errors.New("bundle version is invalid")
	}

	bundleID, err := newUUID()
	if err != nil {
		return err
	}
	trivyID, err := newUUID()
	if err != nil {
		return err
	}
	javaID, err := newUUID()
	if err != nil {
		return err
	}
	trivyFiles, err := inspectFiles(value.trivyDirectory, "metadata.json", "trivy.db")
	if err != nil {
		return err
	}
	javaFiles, err := inspectFiles(value.javaDirectory, "metadata.json", "trivy-java.db")
	if err != nil {
		return err
	}
	databases := []databaseEntry{
		{ID: trivyID, DatabaseType: "trivy-db", Version: value.version, SchemaVersion: 2, StorageKey: "trivy/db/versions/" + trivyID, Files: trivyFiles},
		{ID: javaID, DatabaseType: "trivy-java-db", Version: value.version, SchemaVersion: 1, StorageKey: "trivy/java-db/versions/" + javaID, Files: javaFiles},
	}
	manifest := bundleManifest{
		SchemaVersion: 1, ID: bundleID, Version: value.version,
		GeneratedAt: value.generatedAt, ContentSHA256: bundleHash(databases), Databases: databases,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode bundle manifest: %w", err)
	}
	raw = append(raw, '\n')
	if err := writeExclusive(value.output, raw, 0o444); err != nil {
		return err
	}
	environment := fmt.Sprintf(
		"BUNDLE_ID=%s\nTRIVY_DB_ID=%s\nTRIVY_JAVA_DB_ID=%s\nTRIVY_DB_VERSION=%s\n",
		bundleID, trivyID, javaID, value.version,
	)
	if err := writeExclusive(value.environment, []byte(environment), 0o444); err != nil {
		_ = os.Remove(value.output)
		return err
	}
	return nil
}

func readUpdatedAt(path string) (time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	var metadata databaseMetadata
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	if err := decoder.Decode(&metadata); err != nil || metadata.UpdatedAt.IsZero() {
		return time.Time{}, fmt.Errorf("read UpdatedAt from %s", path)
	}
	return metadata.UpdatedAt, nil
}

func inspectFiles(directory string, names ...string) ([]fileEntry, error) {
	entries := make([]fileEntry, 0, len(names))
	var total int64
	for _, name := range names {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
			info.Size() > maxDatabaseBytes-total {
			return nil, fmt.Errorf("database file is invalid: %s", path)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		written, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return nil, fmt.Errorf("hash database file: %s", path)
		}
		total += info.Size()
		entries = append(entries, fileEntry{Path: name, SHA256: hex.EncodeToString(hash.Sum(nil)), SizeBytes: info.Size()})
	}
	return entries, nil
}

func bundleHash(databases []databaseEntry) string {
	values := append([]databaseEntry(nil), databases...)
	sort.Slice(values, func(i, j int) bool { return values[i].DatabaseType < values[j].DatabaseType })
	hash := sha256.New()
	for _, database := range values {
		_, _ = io.WriteString(hash, database.DatabaseType+"\x00")
		_, _ = io.WriteString(hash, database.ID+"\x00")
		_, _ = io.WriteString(hash, database.Version+"\x00")
		_, _ = io.WriteString(hash, strconv.Itoa(database.SchemaVersion)+"\x00")
		_, _ = io.WriteString(hash, database.StorageKey+"\x00")
		for _, file := range database.Files {
			_, _ = io.WriteString(hash, file.Path+"\x00")
			_, _ = io.WriteString(hash, file.SHA256+"\x00")
			_, _ = io.WriteString(hash, strconv.FormatInt(file.SizeBytes, 10)+"\x00")
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func safeVersion(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._+-", character) {
			continue
		}
		return false
	}
	first := value[0]
	return (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')
}

func writeExclusive(path string, value []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(value); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
