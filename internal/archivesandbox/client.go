package archivesandbox

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"binaryscan/internal/extract"
	"binaryscan/internal/filetype"
)

const (
	defaultClientTimeout = 20 * time.Minute
	clientCopyBufferSize = 1 << 20
)

type ClientConfig struct {
	SocketPath string
	InputRoot  string
	OutputRoot string
	Timeout    time.Duration
}

// Client stages inputs into a mount that is read-only in the archive service
// and consumes outputs from a separate mount that is read-only to this client.
type Client struct {
	config     ClientConfig
	inputRoot  *os.Root
	inputInfo  os.FileInfo
	outputRoot *os.Root
	outputInfo os.FileInfo
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Timeout == 0 {
		config.Timeout = defaultClientTimeout
	}
	if config.Timeout <= 0 || config.Timeout > 24*time.Hour {
		return nil, errors.New("archive sandbox client timeout is invalid")
	}
	for name, value := range map[string]string{
		"socket": config.SocketPath,
		"input":  config.InputRoot,
		"output": config.OutputRoot,
	} {
		if value == "" || !filepath.IsAbs(value) ||
			filepath.Clean(value) != value || value == string(filepath.Separator) {
			return nil, fmt.Errorf("archive sandbox %s path is invalid", name)
		}
	}
	if rootsOverlap(config.InputRoot, config.OutputRoot) {
		return nil, errors.New("archive sandbox input and output roots overlap")
	}
	inputRoot, inputInfo, err := openDirectoryRoot(config.InputRoot)
	if err != nil {
		return nil, fmt.Errorf("open archive sandbox input root: %w", err)
	}
	outputRoot, outputInfo, err := openDirectoryRoot(config.OutputRoot)
	if err != nil {
		_ = inputRoot.Close()
		return nil, fmt.Errorf("open archive sandbox output root: %w", err)
	}
	return &Client{
		config: config, inputRoot: inputRoot, inputInfo: inputInfo,
		outputRoot: outputRoot, outputInfo: outputInfo,
	}, nil
}

func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	return errors.Join(client.inputRoot.Close(), client.outputRoot.Close())
}

func (client *Client) Ping(ctx context.Context) error {
	requestID, err := newRequestID()
	if err != nil {
		return err
	}
	request := Request{
		SchemaVersion: SchemaVersion,
		RequestID:     requestID,
		Operation:     OperationPing,
	}
	connection, response, err := client.exchange(ctx, request)
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return err
	}
	if response.Status != "succeeded" {
		return responseError(response)
	}
	_, err = connection.Write([]byte{ackByte})
	return err
}

func (client *Client) Classify(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
) (filetype.MagicResult, error) {
	staged, err := client.stage(ctx, source, size)
	if err != nil {
		return filetype.MagicResult{}, err
	}
	defer staged.remove()
	request := Request{
		SchemaVersion:      SchemaVersion,
		RequestID:          staged.id,
		Operation:          OperationIdentify,
		Engine:             EngineLibmagic,
		InputName:          staged.name,
		InputSHA256:        staged.sha256,
		InputSizeBytes:     staged.size,
		MaxDurationSeconds: 15,
	}
	connection, response, err := client.exchange(ctx, request)
	if connection != nil {
		defer connection.Close()
	}
	if err != nil {
		return filetype.MagicResult{}, err
	}
	if response.Status != "succeeded" {
		return filetype.MagicResult{}, responseError(response)
	}
	if _, err := connection.Write([]byte{ackByte}); err != nil {
		return filetype.MagicResult{}, fmt.Errorf(
			"acknowledge libmagic response: %w",
			err,
		)
	}
	return filetype.MagicResult{
		MIMEType: response.MIMEType,
		Version:  response.EngineVersion,
	}, nil
}

func (client *Client) Extract(
	ctx context.Context,
	source *os.File,
	size int64,
	request extract.ExternalArchiveRequest,
) (extract.ExternalArchiveSession, error) {
	if source == nil {
		return nil, errors.New("archive sandbox source is nil")
	}
	staged, err := client.stage(ctx, source, size)
	if err != nil {
		return nil, err
	}
	engine := request.Engine
	if engine != extract.ExternalEngineSevenZip &&
		engine != extract.ExternalEngineLibarchive {
		staged.remove()
		return nil, errors.New("archive sandbox extraction engine is invalid")
	}
	protocolRequest := Request{
		SchemaVersion:      SchemaVersion,
		RequestID:          staged.id,
		Operation:          OperationExtract,
		Engine:             engine,
		Format:             request.Format,
		InputName:          staged.name,
		InputSHA256:        staged.sha256,
		InputSizeBytes:     staged.size,
		OutputName:         staged.id,
		MaxEntries:         request.MaxEntries,
		MaxEntryBytes:      request.MaxEntryBytes,
		MaxExpandedBytes:   request.MaxExpandedBytes,
		MaxDurationSeconds: request.MaxDurationSeconds,
	}
	connection, response, err := client.exchange(ctx, protocolRequest)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		staged.remove()
		return nil, err
	}
	if response.Status != "succeeded" {
		_ = connection.Close()
		staged.remove()
		return nil, responseError(response)
	}
	if err := validateDirectoryIdentity(
		client.config.OutputRoot,
		client.outputRoot,
		client.outputInfo,
	); err != nil {
		_ = connection.Close()
		staged.remove()
		return nil, fmt.Errorf("archive sandbox output root changed: %w", err)
	}
	info, err := client.outputRoot.Lstat(response.OutputName)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		_ = connection.Close()
		staged.remove()
		return nil, errors.New("archive sandbox output directory is invalid")
	}
	return &clientSession{
		client: client,
		staged: staged,
		conn:   connection,
		path:   filepath.Join(client.config.OutputRoot, response.OutputName),
	}, nil
}

func (client *Client) exchange(
	ctx context.Context,
	request Request,
) (net.Conn, Response, error) {
	if ctx == nil {
		return nil, Response{}, errors.New("archive sandbox context is nil")
	}
	if err := request.validate(); err != nil {
		return nil, Response{}, err
	}
	if err := client.validateSocket(); err != nil {
		return nil, Response{}, err
	}
	operationContext, cancel := context.WithTimeout(ctx, client.config.Timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(
		operationContext,
		"unix",
		client.config.SocketPath,
	)
	if err != nil {
		return nil, Response{}, fmt.Errorf("connect archive sandbox: %w", err)
	}
	if deadline, ok := operationContext.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := writeFrame(connection, request); err != nil {
		_ = connection.Close()
		return nil, Response{}, err
	}
	var response Response
	if err := readFrame(connection, &response); err != nil {
		_ = connection.Close()
		return nil, Response{}, err
	}
	if err := response.validate(request); err != nil {
		_ = connection.Close()
		return nil, Response{}, err
	}
	return connection, response, nil
}

func (client *Client) validateSocket() error {
	parent := filepath.Dir(client.config.SocketPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() ||
		parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox socket parent is invalid")
	}
	info, err := os.Lstat(client.config.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 ||
		info.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive sandbox socket is unavailable")
	}
	return nil
}

type stagedInput struct {
	client *Client
	id     string
	name   string
	sha256 string
	size   int64
	once   sync.Once
}

func (client *Client) stage(
	ctx context.Context,
	source io.ReaderAt,
	size int64,
) (_ *stagedInput, returnedErr error) {
	if ctx == nil || source == nil || size < 0 || size > 10<<30 {
		return nil, errors.New("archive sandbox input is invalid")
	}
	if err := validateDirectoryIdentity(
		client.config.InputRoot,
		client.inputRoot,
		client.inputInfo,
	); err != nil {
		return nil, fmt.Errorf("archive sandbox input root changed: %w", err)
	}
	id, err := newRequestID()
	if err != nil {
		return nil, err
	}
	staged := &stagedInput{
		client: client,
		id:     id,
		name:   id + ".bin",
		size:   size,
	}
	defer func() {
		if returnedErr != nil {
			staged.remove()
		}
	}()
	file, err := client.inputRoot.OpenFile(
		staged.name,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o640,
	)
	if err != nil {
		return nil, fmt.Errorf("create archive sandbox input: %w", err)
	}
	hash := sha256.New()
	reader := io.NewSectionReader(source, 0, size)
	written, copyErr := copyContext(
		ctx,
		io.MultiWriter(file, hash),
		reader,
		size,
	)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != size {
		combined := errors.Join(copyErr, syncErr, closeErr)
		if written != size {
			combined = errors.Join(combined, io.ErrUnexpectedEOF)
		}
		return nil, combined
	}
	info, err := client.inputRoot.Lstat(staged.name)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		return nil, errors.New("archive sandbox staged input is invalid")
	}
	staged.sha256 = hex.EncodeToString(hash.Sum(nil))
	return staged, nil
}

func (staged *stagedInput) remove() {
	if staged == nil || staged.client == nil {
		return
	}
	staged.once.Do(func() {
		_ = staged.client.inputRoot.Remove(staged.name)
	})
}

type clientSession struct {
	client *Client
	staged *stagedInput
	conn   net.Conn
	path   string
	once   sync.Once
	err    error
}

func (session *clientSession) OutputPath() string {
	if session == nil {
		return ""
	}
	return session.path
}

func (session *clientSession) Close() error {
	if session == nil {
		return nil
	}
	session.once.Do(func() {
		if session.conn != nil {
			_ = session.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := session.conn.Write([]byte{ackByte}); err != nil {
				session.err = fmt.Errorf(
					"acknowledge archive sandbox output: %w",
					err,
				)
			}
			session.err = errors.Join(session.err, session.conn.Close())
		}
		session.staged.remove()
	})
	return session.err
}

func responseError(response Response) error {
	return fmt.Errorf(
		"archive sandbox %s: %s",
		response.ErrorCode,
		response.ErrorMessage,
	)
}

func newRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate archive sandbox request ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func copyContext(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	expected int64,
) (int64, error) {
	buffer := make([]byte, clientCopyBufferSize)
	var total int64
	for total < expected {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		maximum := int64(len(buffer))
		if remaining := expected - total; remaining < maximum {
			maximum = remaining
		}
		count, readErr := source.Read(buffer[:maximum])
		if count > 0 {
			written, writeErr := destination.Write(buffer[:count])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != count {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && total == expected {
				break
			}
			return total, readErr
		}
		if count == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func openDirectoryRoot(path string) (*os.Root, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("directory root is invalid")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	if err := validateDirectoryIdentity(path, root, info); err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return root, info, nil
}

func validateDirectoryIdentity(
	path string,
	root *os.Root,
	expected os.FileInfo,
) error {
	if root == nil || expected == nil {
		return errors.New("directory identity is missing")
	}
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(expected, current) {
		return errors.New("directory path identity changed")
	}
	opened, err := root.Lstat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(expected, opened) {
		return errors.New("opened directory identity changed")
	}
	return nil
}

func rootsOverlap(left string, right string) bool {
	for _, pair := range [][2]string{{left, right}, {right, left}} {
		relative, err := filepath.Rel(pair[1], pair[0])
		if err == nil && !filepath.IsAbs(relative) &&
			(relative == "." ||
				(relative != ".." && !strings.HasPrefix(
					relative,
					".."+string(filepath.Separator),
				))) {
			return true
		}
	}
	return false
}
