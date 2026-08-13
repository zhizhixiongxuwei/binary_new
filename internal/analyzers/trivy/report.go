package trivy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxJSONDepth         = 64
	maxJSONTokens        = 1_000_000
	maxJSONStringBytes   = 1 << 20
	maxFindingReferences = 128
	maxReferenceURLBytes = 2048
)

var validSeverities = map[string]struct{}{
	"UNKNOWN":  {},
	"LOW":      {},
	"MEDIUM":   {},
	"HIGH":     {},
	"CRITICAL": {},
}

type trivyJSONReport struct {
	SchemaVersion int               `json:"SchemaVersion"`
	ArtifactName  string            `json:"ArtifactName"`
	ArtifactType  string            `json:"ArtifactType"`
	Results       []trivyJSONResult `json:"Results"`
}

type trivyJSONResult struct {
	Target            string                   `json:"Target"`
	Class             string                   `json:"Class"`
	Type              string                   `json:"Type"`
	Vulnerabilities   []trivyJSONVulnerability `json:"Vulnerabilities"`
	Misconfigurations json.RawMessage          `json:"Misconfigurations"`
	Secrets           json.RawMessage          `json:"Secrets"`
	Licenses          json.RawMessage          `json:"Licenses"`
}

type trivyJSONVulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgName          string              `json:"PkgName"`
	PkgPath          string              `json:"PkgPath"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion"`
	Severity         string              `json:"Severity"`
	Title            string              `json:"Title"`
	Description      string              `json:"Description"`
	PrimaryURL       string              `json:"PrimaryURL"`
	DataSource       trivyJSONDataSource `json:"DataSource"`
	References       []string            `json:"References"`
}

type trivyJSONDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

func readRawReport(
	path string,
	maximum int64,
) ([]byte, RawReportMetadata, error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return nil, RawReportMetadata{}, fmt.Errorf(
			"%w: open raw report: %v",
			ErrInvalidReport,
			err,
		)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, RawReportMetadata{}, fmt.Errorf("%w: stat raw report: %v", ErrInvalidReport, err)
	}
	if info.Size() > maximum {
		return nil, RawReportMetadata{}, fmt.Errorf(
			"%w: raw report exceeded %d bytes",
			ErrOutputLimit,
			maximum,
		)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, RawReportMetadata{}, fmt.Errorf("%w: read raw report: %v", ErrInvalidReport, err)
	}
	if int64(len(raw)) > maximum {
		return nil, RawReportMetadata{}, fmt.Errorf(
			"%w: raw report exceeded %d bytes",
			ErrOutputLimit,
			maximum,
		)
	}
	digest := sha256.Sum256(raw)
	return raw, RawReportMetadata{
		Path: path, SHA256: hex.EncodeToString(digest[:]),
		SizeBytes: int64(len(raw)),
	}, nil
}

func parseReport(
	raw []byte,
	metadata RawReportMetadata,
	maxResults int,
	maxFindings int,
) (Report, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Report{}, fmt.Errorf("%w: report must be non-empty UTF-8 JSON", ErrInvalidReport)
	}
	if err := validateJSONTokens(raw); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrInvalidReport, err)
	}
	if err := rejectUnknownTopLevel(raw); err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrInvalidReport, err)
	}
	var source trivyJSONReport
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&source); err != nil {
		return Report{}, fmt.Errorf("%w: decode report: %v", ErrInvalidReport, err)
	}
	if source.SchemaVersion != 2 {
		return Report{}, fmt.Errorf(
			"%w: unsupported SchemaVersion %d",
			ErrInvalidReport,
			source.SchemaVersion,
		)
	}
	if err := validateText("ArtifactName", source.ArtifactName, true, 4096); err != nil {
		return Report{}, err
	}
	if err := validateText("ArtifactType", source.ArtifactType, true, 128); err != nil {
		return Report{}, err
	}
	if len(source.Results) > maxResults {
		return Report{}, fmt.Errorf(
			"%w: result count %d exceeds %d",
			ErrInvalidReport,
			len(source.Results),
			maxResults,
		)
	}

	findings := make([]Finding, 0)
	for resultIndex, result := range source.Results {
		if nonEmptyJSONCollection(result.Misconfigurations) ||
			nonEmptyJSONCollection(result.Secrets) ||
			nonEmptyJSONCollection(result.Licenses) {
			return Report{}, fmt.Errorf(
				"%w: result %d contains a disabled scanner result",
				ErrInvalidReport,
				resultIndex,
			)
		}
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		if err := validateText("Target", result.Target, true, 4096); err != nil {
			return Report{}, annotateResultError(resultIndex, err)
		}
		if err := validateText("Class", result.Class, true, 128); err != nil {
			return Report{}, annotateResultError(resultIndex, err)
		}
		if err := validateText("Type", result.Type, true, 128); err != nil {
			return Report{}, annotateResultError(resultIndex, err)
		}
		if len(result.Vulnerabilities) > maxFindings-len(findings) {
			return Report{}, fmt.Errorf(
				"%w: finding count exceeds %d",
				ErrInvalidReport,
				maxFindings,
			)
		}
		for findingIndex, finding := range result.Vulnerabilities {
			normalized, err := normalizeFinding(source.ArtifactName, result, finding)
			if err != nil {
				return Report{}, fmt.Errorf(
					"%w: result %d vulnerability %d: %v",
					ErrInvalidReport,
					resultIndex,
					findingIndex,
					err,
				)
			}
			findings = append(findings, normalized)
		}
	}
	if findings == nil {
		findings = []Finding{}
	}
	metadata.SchemaVersion = source.SchemaVersion
	metadata.ArtifactName = source.ArtifactName
	metadata.ArtifactType = source.ArtifactType
	metadata.ResultCount = len(source.Results)
	metadata.FindingCount = len(findings)
	return Report{Findings: findings, Raw: metadata}, nil
}

func normalizeFinding(
	artifactName string,
	result trivyJSONResult,
	source trivyJSONVulnerability,
) (Finding, error) {
	id := strings.TrimSpace(source.VulnerabilityID)
	packageName := strings.TrimSpace(source.PkgName)
	installedVersion := strings.TrimSpace(source.InstalledVersion)
	fixedVersion := strings.TrimSpace(source.FixedVersion)
	packagePath := strings.TrimSpace(source.PkgPath)
	severity := strings.ToUpper(strings.TrimSpace(source.Severity))
	for name, bounded := range map[string]struct {
		value   string
		maximum int
	}{
		"VulnerabilityID":  {id, 128},
		"PkgName":          {packageName, 512},
		"InstalledVersion": {installedVersion, 512},
	} {
		if err := validateText(name, bounded.value, true, bounded.maximum); err != nil {
			return Finding{}, err
		}
	}
	if err := validateText("FixedVersion", fixedVersion, false, 512); err != nil {
		return Finding{}, err
	}
	if err := validateText("PkgPath", packagePath, false, 2048); err != nil {
		return Finding{}, err
	}
	if _, found := validSeverities[severity]; !found {
		return Finding{}, fmt.Errorf("unknown Severity %q", severity)
	}
	title, err := normalizeDisplayText("Title", source.Title, 1024)
	if err != nil {
		return Finding{}, err
	}
	description, err := normalizeDisplayText("Description", source.Description, 2048)
	if err != nil {
		return Finding{}, err
	}
	dataSource, err := normalizeDataSource(source.DataSource)
	if err != nil {
		return Finding{}, err
	}
	references := normalizeReferenceURLs(
		source.PrimaryURL,
		source.References,
		dataSource.URL,
	)
	return Finding{
		VulnerabilityID: id, Severity: severity,
		PackageName: packageName, PackagePath: packagePath,
		InstalledVersion: installedVersion, FixedVersion: fixedVersion,
		Title: title, DescriptionSummary: description,
		Target: normalizeTarget(artifactName, result.Target),
		Class:  strings.TrimSpace(result.Class), Type: strings.TrimSpace(result.Type),
		DataSource: dataSource, References: references,
	}, nil
}

func normalizeTarget(artifactName string, target string) string {
	artifactName = strings.TrimSpace(artifactName)
	target = strings.TrimSpace(target)
	if artifactName == "" {
		return target
	}
	if target == artifactName {
		return "container image"
	}
	if !strings.HasPrefix(target, artifactName+" ") {
		return target
	}
	suffix := strings.TrimSpace(strings.TrimPrefix(target, artifactName))
	if len(suffix) >= 2 && suffix[0] == '(' && suffix[len(suffix)-1] == ')' {
		if display := strings.TrimSpace(suffix[1 : len(suffix)-1]); display != "" {
			return display
		}
	}
	return suffix
}

func normalizeDisplayText(name string, value string, maximum int) (string, error) {
	var normalized strings.Builder
	pendingSpace := false
	for _, character := range strings.TrimSpace(value) {
		if character < 0x20 || character == 0x7f {
			switch character {
			case '\t', '\n', '\r':
				pendingSpace = normalized.Len() != 0
				continue
			default:
				return "", fmt.Errorf(
					"%w: %s contains control characters",
					ErrInvalidReport,
					name,
				)
			}
		}
		if unicode.IsSpace(character) {
			pendingSpace = normalized.Len() != 0
			continue
		}
		if pendingSpace {
			normalized.WriteByte(' ')
			pendingSpace = false
		}
		normalized.WriteRune(character)
	}
	return truncateUTF8(normalized.String(), maximum), nil
}

func truncateUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	cut := maximum - 3
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return strings.TrimSpace(value[:cut]) + "..."
}

func normalizeDataSource(source trivyJSONDataSource) (DataSource, error) {
	id, err := normalizeDisplayText("DataSource.ID", source.ID, 128)
	if err != nil {
		return DataSource{}, err
	}
	name, err := normalizeDisplayText("DataSource.Name", source.Name, 512)
	if err != nil {
		return DataSource{}, err
	}
	return DataSource{
		ID:   id,
		Name: name,
		URL:  normalizedHTTPURL(source.URL),
	}, nil
}

func normalizeReferenceURLs(primary string, references []string, source string) []string {
	values := make([]string, 0, min(len(references)+2, maxFindingReferences))
	seen := make(map[string]struct{}, cap(values))
	appendURL := func(candidate string) {
		if len(values) == maxFindingReferences {
			return
		}
		normalized := normalizedHTTPURL(candidate)
		if normalized == "" {
			return
		}
		if _, duplicate := seen[normalized]; duplicate {
			return
		}
		seen[normalized] = struct{}{}
		values = append(values, normalized)
	}
	appendURL(primary)
	for _, reference := range references {
		appendURL(reference)
	}
	appendURL(source)
	if values == nil {
		return []string{}
	}
	return values
}

func normalizedHTTPURL(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxReferenceURLBytes {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || unicode.IsSpace(character) {
			return ""
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return parsed.String()
}

func validateText(name, value string, required bool, maximum int) error {
	if required && strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidReport, name)
	}
	if len(value) > maximum {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidReport, name, maximum)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%w: %s contains control characters", ErrInvalidReport, name)
		}
	}
	return nil
}

func annotateResultError(index int, err error) error {
	return fmt.Errorf("%w: result %d: %v", ErrInvalidReport, index, err)
}

func nonEmptyJSONCollection(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 &&
		!bytes.Equal(trimmed, []byte("null")) &&
		!bytes.Equal(trimmed, []byte("[]")) &&
		!bytes.Equal(trimmed, []byte("{}"))
}

func rejectUnknownTopLevel(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	allowed := map[string]struct{}{
		"SchemaVersion": {},
		"CreatedAt":     {},
		"ArtifactID":    {},
		"ArtifactName":  {},
		"ArtifactType":  {},
		"Metadata":      {},
		"ReportID":      {},
		"Results":       {},
		"Trivy":         {},
	}
	for field := range fields {
		if _, found := allowed[field]; !found {
			return fmt.Errorf("unknown top-level field %q", field)
		}
	}
	for _, required := range []string{
		"SchemaVersion",
		"ArtifactName",
		"ArtifactType",
	} {
		if _, found := fields[required]; !found {
			return fmt.Errorf("required top-level field %q is missing", required)
		}
	}
	// Results may be absent only for the vm subcommand when no package
	// databases are found; container image reports must still carry it.
	var artifactType string
	if err := json.Unmarshal(fields["ArtifactType"], &artifactType); err == nil &&
		artifactType != "vm" {
		if _, found := fields["Results"]; !found {
			return fmt.Errorf("required top-level field %q is missing", "Results")
		}
	}
	return nil
}

func validateJSONTokens(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	if err := validateJSONValue(decoder, 0, &tokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateJSONValue(
	decoder *json.Decoder,
	depth int,
	tokens *int,
) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	*tokens++
	if *tokens > maxJSONTokens {
		return fmt.Errorf("JSON token count exceeds %d", maxJSONTokens)
	}
	if text, ok := token.(string); ok && len(text) > maxJSONStringBytes {
		return fmt.Errorf("JSON string exceeds %d bytes", maxJSONStringBytes)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			*tokens++
			if *tokens > maxJSONTokens {
				return fmt.Errorf("JSON token count exceeds %d", maxJSONTokens)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if len(key) > maxJSONStringBytes {
				return fmt.Errorf("JSON key exceeds %d bytes", maxJSONStringBytes)
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("unterminated JSON object")
		}
		*tokens++
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1, tokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("unterminated JSON array")
		}
		*tokens++
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	if *tokens > maxJSONTokens {
		return fmt.Errorf("JSON token count exceeds %d", maxJSONTokens)
	}
	return nil
}
