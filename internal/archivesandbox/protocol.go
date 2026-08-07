// Package archivesandbox implements the local Unix-socket protocol between
// the database-connected scan worker and the no-network archive tool service.
package archivesandbox

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	SchemaVersion = 1
	maxFrameBytes = 64 << 10
	ackByte       = byte(0xa5)

	OperationPing     = "ping"
	OperationIdentify = "identify"
	OperationExtract  = "extract"

	EngineLibmagic   = "libmagic"
	EngineLibarchive = "libarchive"
	EngineSevenZip   = "7zz"
)

var (
	requestIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	sha256Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	codePattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
)

type Request struct {
	SchemaVersion      int    `json:"schema_version"`
	RequestID          string `json:"request_id"`
	Operation          string `json:"operation"`
	Engine             string `json:"engine,omitempty"`
	Format             string `json:"format,omitempty"`
	InputName          string `json:"input_name,omitempty"`
	InputSHA256        string `json:"input_sha256,omitempty"`
	InputSizeBytes     int64  `json:"input_size_bytes,omitempty"`
	OutputName         string `json:"output_name,omitempty"`
	MaxEntries         int    `json:"max_entries,omitempty"`
	MaxEntryBytes      int64  `json:"max_entry_bytes,omitempty"`
	MaxExpandedBytes   int64  `json:"max_expanded_bytes,omitempty"`
	MaxDurationSeconds int64  `json:"max_duration_seconds,omitempty"`
}

type Response struct {
	SchemaVersion int    `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Status        string `json:"status"`
	MIMEType      string `json:"mime_type,omitempty"`
	EngineVersion string `json:"engine_version,omitempty"`
	OutputName    string `json:"output_name,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

func (request Request) validate() error {
	if request.SchemaVersion != SchemaVersion ||
		!requestIDPattern.MatchString(request.RequestID) {
		return errors.New("archive sandbox request identity is invalid")
	}
	switch request.Operation {
	case OperationPing:
		if request.Engine != "" || request.Format != "" ||
			request.InputName != "" || request.InputSHA256 != "" ||
			request.InputSizeBytes != 0 || request.OutputName != "" ||
			request.MaxEntries != 0 || request.MaxEntryBytes != 0 ||
			request.MaxExpandedBytes != 0 || request.MaxDurationSeconds != 0 {
			return errors.New("archive sandbox ping contains unexpected fields")
		}
		return nil
	case OperationIdentify:
		if request.Engine != EngineLibmagic || request.Format != "" ||
			request.OutputName != "" || request.MaxEntries != 0 ||
			request.MaxEntryBytes != 0 || request.MaxExpandedBytes != 0 {
			return errors.New("archive sandbox identify request is invalid")
		}
	case OperationExtract:
		validEngine := request.Engine == EngineSevenZip && request.Format == "7z" ||
			request.Engine == EngineLibarchive && request.Format == "cab"
		if !validEngine || request.OutputName != request.RequestID ||
			request.MaxEntries < 1 || request.MaxEntries > 100_000 ||
			request.MaxEntryBytes < 1 || request.MaxEntryBytes > 10<<30 ||
			request.MaxExpandedBytes < 1 || request.MaxExpandedBytes > 50<<30 {
			return errors.New("archive sandbox extraction request is invalid")
		}
	default:
		return errors.New("archive sandbox operation is invalid")
	}
	if request.InputName != request.RequestID+".bin" ||
		!sha256Pattern.MatchString(request.InputSHA256) ||
		request.InputSizeBytes < 0 || request.InputSizeBytes > 10<<30 ||
		request.MaxDurationSeconds < 1 || request.MaxDurationSeconds > 86_400 {
		return errors.New("archive sandbox input or duration is invalid")
	}
	return nil
}

func (response Response) validate(request Request) error {
	if response.SchemaVersion != SchemaVersion ||
		response.RequestID != request.RequestID ||
		(response.Status != "succeeded" && response.Status != "failed") {
		return errors.New("archive sandbox response identity is invalid")
	}
	if response.Status == "failed" {
		if !codePattern.MatchString(response.ErrorCode) ||
			!validBoundedText(response.ErrorMessage, 2048) ||
			response.MIMEType != "" || response.OutputName != "" {
			return errors.New("archive sandbox failure response is invalid")
		}
		return nil
	}
	if response.ErrorCode != "" || response.ErrorMessage != "" ||
		!validBoundedText(response.EngineVersion, 256) {
		return errors.New("archive sandbox success response is invalid")
	}
	switch request.Operation {
	case OperationPing:
		if response.MIMEType != "" || response.OutputName != "" {
			return errors.New("archive sandbox ping response is invalid")
		}
	case OperationIdentify:
		if !validMIME(response.MIMEType) || response.OutputName != "" {
			return errors.New("archive sandbox identify response is invalid")
		}
	case OperationExtract:
		if response.MIMEType != "" || response.OutputName != request.OutputName {
			return errors.New("archive sandbox extraction response is invalid")
		}
	default:
		return errors.New("archive sandbox response operation is invalid")
	}
	return nil
}

func writeFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode archive sandbox frame: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxFrameBytes {
		return errors.New("archive sandbox frame exceeds its limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return fmt.Errorf("write archive sandbox frame header: %w", err)
	}
	if _, err := writer.Write(payload); err != nil {
		return fmt.Errorf("write archive sandbox frame payload: %w", err)
	}
	return nil
}

func readFrame(reader io.Reader, destination any) error {
	buffered := bufio.NewReaderSize(reader, maxFrameBytes+4)
	var header [4]byte
	if _, err := io.ReadFull(buffered, header[:]); err != nil {
		return fmt.Errorf("read archive sandbox frame header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return errors.New("archive sandbox frame length is invalid")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(buffered, payload); err != nil {
		return fmt.Errorf("read archive sandbox frame payload: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode archive sandbox frame: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("archive sandbox frame has trailing JSON")
	}
	return nil
}

func validMIME(value string) bool {
	if value == "" || len(value) > 255 || strings.Count(value, "/") != 1 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$&^_.+-/", character)) {
			return false
		}
	}
	return true
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
