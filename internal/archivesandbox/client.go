package archivesandbox

import (
	"bytes"
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
	"runtime"
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
	SocketPath       string
	InputRoot        string
	OutputRoot       string
	Timeout          time.Duration
	MinimumFreeBytes int64
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

type managedConnection struct {
	net.Conn
	cancel context.CancelFunc
	stop   func() bool
	once   sync.Once
	err    error
}

func (connection *managedConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.once.Do(func() {
		if connection.stop != nil {
			connection.stop()
		}
		if connection.cancel != nil {
			connection.cancel()
		}
		if connection.Conn != nil {
			connection.err = connection.Conn.Close()
		}
	})
	return connection.err
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Timeout == 0 {
		config.Timeout = defaultClientTimeout
	}
	if config.Timeout <= 0 || config.Timeout > 24*time.Hour {
		return nil, errors.New("archive sandbox client timeout is invalid")
	}
	if config.MinimumFreeBytes == 0 {
		config.MinimumFreeBytes = 1
	}
	if config.MinimumFreeBytes < 1 || config.MinimumFreeBytes > 50<<30 {
		return nil, errors.New("archive sandbox minimum free bytes is invalid")
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

// SelfTest exercises every production tool path, including the Linux
// confinement launcher and descriptor-bound output consumer. Ping alone
// cannot detect a broken 7zz flag, libarchive frontend, or Landlock failure.
func (client *Client) SelfTest(ctx context.Context) error {
	if ctx == nil {
		return errors.New("archive sandbox self-test context is nil")
	}
	for _, fixture := range []struct {
		name, engine, format string
		content              []byte
	}{
		{
			name: "7z", engine: extract.ExternalEngineSevenZip, format: "7z",
			content: selfTestSevenZip,
		},
		{
			name: "cab", engine: extract.ExternalEngineLibarchive, format: "cab",
			content: selfTestCAB,
		},
	} {
		classified, err := client.Classify(
			ctx, bytes.NewReader(fixture.content), int64(len(fixture.content)),
		)
		if err != nil || classified.MIMEType == "" {
			return fmt.Errorf("archive sandbox %s identify self-test: %w", fixture.name, err)
		}
		temporary, err := os.CreateTemp("", ".archive-selftest-")
		if err != nil {
			return err
		}
		name := temporary.Name()
		_ = os.Remove(name)
		if _, err := temporary.Write(fixture.content); err != nil {
			_ = temporary.Close()
			return err
		}
		if _, err := temporary.Seek(0, io.SeekStart); err != nil {
			_ = temporary.Close()
			return err
		}
		session, err := client.Extract(ctx, temporary, int64(len(fixture.content)), extract.ExternalArchiveRequest{
			Engine: fixture.engine, Format: fixture.format,
			MaxEntries: 4, MaxEntryBytes: 1024,
			MaxExpandedBytes: 4096, MaxDurationSeconds: 15,
		})
		_ = temporary.Close()
		if err != nil {
			return fmt.Errorf("archive sandbox %s extraction self-test: %w", fixture.name, err)
		}
		rootSession, ok := session.(extract.ExternalArchiveRootSession)
		if !ok {
			_ = session.Close()
			return errors.New("archive sandbox self-test output is not descriptor bound")
		}
		root, _, err := rootSession.OpenOutputRoot()
		if err != nil {
			_ = session.Close()
			return err
		}
		contents, readErr := root.ReadFile("payload.txt")
		closeRootErr := root.Close()
		closeErr := session.Close()
		if readErr != nil || closeRootErr != nil || closeErr != nil ||
			string(contents) != "ok" {
			return errors.Join(
				fmt.Errorf("archive sandbox %s consumer self-test failed", fixture.name),
				readErr, closeRootErr, closeErr,
			)
		}
	}
	return nil
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
	output, err := client.createOutput(staged.id)
	if err != nil {
		staged.remove()
		return nil, err
	}
	engine := request.Engine
	if engine != extract.ExternalEngineSevenZip &&
		engine != extract.ExternalEngineLibarchive {
		staged.remove()
		output.remove()
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
		OutputDevice:       output.device,
		OutputInode:        output.inode,
		MaxEntries:         request.MaxEntries,
		MaxEntryBytes:      request.MaxEntryBytes,
		MaxExpandedBytes:   request.MaxExpandedBytes,
		MinimumFreeBytes:   client.config.MinimumFreeBytes,
		MaxDurationSeconds: request.MaxDurationSeconds,
	}
	connection, response, err := client.exchange(ctx, protocolRequest)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		staged.remove()
		output.remove()
		return nil, err
	}
	if response.Status != "succeeded" {
		_ = connection.Close()
		staged.remove()
		output.remove()
		return nil, responseError(response)
	}
	if err := output.validate(); err != nil {
		_ = connection.Close()
		staged.remove()
		output.remove()
		return nil, fmt.Errorf("archive sandbox output root changed: %w", err)
	}
	return &clientSession{
		client: client,
		staged: staged,
		output: output,
		conn:   connection,
		path:   output.path(),
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
	rawConnection, err := (&net.Dialer{}).DialContext(
		operationContext,
		"unix",
		client.config.SocketPath,
	)
	if err != nil {
		cancel()
		return nil, Response{}, fmt.Errorf("connect archive sandbox: %w", err)
	}
	connection := &managedConnection{Conn: rawConnection, cancel: cancel}
	connection.stop = context.AfterFunc(operationContext, func() {
		_ = rawConnection.Close()
	})
	if deadline, ok := operationContext.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := writeFrame(connection, request); err != nil {
		_ = connection.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, Response{}, contextErr
		}
		return nil, Response{}, err
	}
	var response Response
	if err := readFrame(connection, &response); err != nil {
		_ = connection.Close()
		if contextErr := operationContext.Err(); contextErr != nil {
			return nil, Response{}, contextErr
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, Response{}, contextErr
		}
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
	output *stagedOutput
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

func (session *clientSession) OpenOutputRoot() (*os.Root, os.FileInfo, error) {
	if session == nil || session.output == nil {
		return nil, nil, errors.New("archive sandbox output is missing")
	}
	if err := session.output.validate(); err != nil {
		return nil, nil, err
	}
	root, err := session.output.root.OpenRoot(".")
	if err != nil {
		return nil, nil, fmt.Errorf("duplicate archive sandbox output root: %w", err)
	}
	info, err := root.Lstat(".")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(session.output.info, info) {
		_ = root.Close()
		return nil, nil, errors.New("archive sandbox output descriptor changed")
	}
	return root, info, nil
}

func (session *clientSession) Close() error {
	if session == nil {
		return nil
	}
	session.once.Do(func() {
		if session.output != nil {
			session.err = session.output.validate()
		}
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
		if session.output != nil {
			session.err = errors.Join(session.err, session.output.remove())
		}
	})
	return session.err
}

type stagedOutput struct {
	client    *Client
	name      string
	info      os.FileInfo
	root      *os.Root
	directory *os.File
	device    uint64
	inode     uint64
	once      sync.Once
	err       error
}

func (client *Client) createOutput(name string) (_ *stagedOutput, returnedErr error) {
	if !requestIDPattern.MatchString(name) {
		return nil, errors.New("archive sandbox output name is invalid")
	}
	if err := validateDirectoryIdentity(
		client.config.OutputRoot, client.outputRoot, client.outputInfo,
	); err != nil {
		return nil, fmt.Errorf("archive sandbox output root changed: %w", err)
	}
	output := &stagedOutput{client: client, name: name}
	defer func() {
		if returnedErr != nil {
			_ = output.remove()
		}
	}()
	if err := client.outputRoot.Mkdir(name, 0o700); err != nil {
		return nil, fmt.Errorf("create archive sandbox output: %w", err)
	}
	info, err := client.outputRoot.Lstat(name)
	if err != nil || !realDirectory(info) {
		return nil, errors.New("archive sandbox output identity is invalid")
	}
	output.info = info
	output.device = fileDevice(info)
	output.inode = fileInode(info)
	if output.device == 0 || output.inode == 0 {
		return nil, errors.New("archive sandbox output filesystem identity is unavailable")
	}
	output.root, err = client.outputRoot.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("open archive sandbox output root: %w", err)
	}
	opened, err := output.root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("archive sandbox output changed while opening")
	}
	output.directory, err = output.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("bind archive sandbox client output: %w", err)
	}
	return output, nil
}

func (output *stagedOutput) path() string {
	if output == nil || output.directory == nil {
		return ""
	}
	descriptor := output.directory.Fd()
	if runtime.GOOS == "linux" {
		return fmt.Sprintf("/proc/self/fd/%d", descriptor)
	}
	// Darwin exposes directory descriptors in /dev/fd but does not permit
	// walking children through them. Production is Linux; other platforms keep
	// the descriptor pinned and validate the name before acknowledgement.
	return filepath.Join(output.client.config.OutputRoot, output.name)
}

func (output *stagedOutput) validate() error {
	if output == nil || output.client == nil || output.root == nil ||
		output.directory == nil || output.info == nil {
		return errors.New("archive sandbox output identity is missing")
	}
	if err := validateDirectoryIdentity(
		output.client.config.OutputRoot,
		output.client.outputRoot,
		output.client.outputInfo,
	); err != nil {
		return err
	}
	opened, err := output.root.Stat(".")
	if err != nil || !os.SameFile(output.info, opened) ||
		fileDevice(opened) != output.device || fileInode(opened) != output.inode {
		return errors.New("archive sandbox output descriptor changed")
	}
	current, err := output.client.outputRoot.Lstat(output.name)
	if err != nil || !os.SameFile(output.info, current) {
		return errors.New("archive sandbox output name was replaced")
	}
	return nil
}

func (output *stagedOutput) remove() error {
	if output == nil {
		return nil
	}
	output.once.Do(func() {
		if output.root != nil {
			output.err = errors.Join(output.err, clearSandboxRoot(output.root))
		}
		if output.directory != nil {
			output.err = errors.Join(output.err, output.directory.Close())
		}
		if output.root != nil {
			output.err = errors.Join(output.err, output.root.Close())
		}
		if output.client != nil && output.info != nil {
			current, err := output.client.outputRoot.Lstat(output.name)
			if err == nil && os.SameFile(output.info, current) {
				output.err = errors.Join(
					output.err, output.client.outputRoot.RemoveAll(output.name),
				)
			}
		}
	})
	return output.err
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
