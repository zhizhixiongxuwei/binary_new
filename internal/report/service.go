package report

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	uuidPattern = regexp.MustCompile(
		`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
	)
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Config struct {
	RepositoryRoot string
	LeaseDuration  time.Duration
}

type Service struct {
	repository     Repository
	repositoryRoot string
	now            func() time.Time
	newID          func() (string, error)
	leaseOwner     string
	leaseDuration  time.Duration
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil {
		return nil, errors.New("report repository is required")
	}
	root := filepath.Clean(config.RepositoryRoot)
	if !filepath.IsAbs(root) || root == string(filepath.Separator) {
		return nil, errors.New(
			"report repository root must be an absolute non-root path",
		)
	}
	leaseDuration := config.LeaseDuration
	if leaseDuration == 0 {
		leaseDuration = 30 * time.Second
	}
	if leaseDuration <= 0 || leaseDuration/3 <= 0 {
		return nil, errors.New("report generation lease duration is invalid")
	}
	var ownerEntropy [12]byte
	if _, err := io.ReadFull(rand.Reader, ownerEntropy[:]); err != nil {
		return nil, fmt.Errorf("create report generation lease owner: %w", err)
	}
	return &Service{
		repository: repository, repositoryRoot: root,
		now: time.Now, newID: newUUID,
		leaseOwner:    hex.EncodeToString(ownerEntropy[:]),
		leaseDuration: leaseDuration,
	}, nil
}

func (s *Service) List(ctx context.Context, taskID string) (List, error) {
	if err := ctx.Err(); err != nil {
		return List{}, err
	}
	if !uuidPattern.MatchString(taskID) {
		return List{}, ErrInvalidInput
	}
	value, err := s.repository.List(ctx, taskID)
	if err != nil {
		return List{}, err
	}
	if value.Items == nil {
		value.Items = []Report{}
	}
	return value, nil
}

func (s *Service) Generate(
	ctx context.Context,
	taskID string,
	format Format,
	idempotencyKey string,
) (Report, bool, error) {
	if err := ctx.Err(); err != nil {
		return Report{}, false, err
	}
	if !uuidPattern.MatchString(taskID) ||
		(format != FormatJSON && format != FormatHTML && format != FormatDOCX) ||
		!validIdempotencyKey(idempotencyKey) {
		return Report{}, false, ErrInvalidInput
	}
	reportID, err := s.newID()
	if err != nil {
		return Report{}, false, fmt.Errorf("generate report ID: %w", err)
	}
	createdAt := s.now().UTC()
	value, generate, err := s.repository.Claim(ctx, Claim{
		TaskID: taskID, ReportID: reportID, Format: format,
		SchemaVersion: SchemaVersion, CreatedAt: createdAt,
		LeaseOwner: s.leaseOwner, LeaseDuration: s.leaseDuration,
	})
	if err != nil || !generate {
		return value, false, err
	}

	generationCtx, cancelGeneration := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go func() {
		heartbeatDone <- s.heartbeatGeneration(
			generationCtx, cancelGeneration, value,
		)
	}()
	artifact, err := s.generateArtifact(generationCtx, value, createdAt)
	cancelGeneration()
	heartbeatErr := <-heartbeatDone
	if err == nil && heartbeatErr != nil {
		err = heartbeatErr
	}
	if err != nil {
		failErr := s.persistFailure(ctx, value, err)
		if failErr != nil {
			return Report{}, false, errors.Join(err, failErr)
		}
		return Report{}, false, err
	}
	completed, err := s.repository.Complete(
		ctx, value.TaskID, value.ID, value.GenerationOwner,
		value.GenerationFence, artifact,
	)
	if err != nil {
		cleanupErr := s.removeArtifact(artifact.StorageKey)
		failErr := s.persistFailure(ctx, value, err)
		return Report{}, false, errors.Join(err, cleanupErr, failErr)
	}
	return completed, true, nil
}

func (s *Service) heartbeatGeneration(
	ctx context.Context,
	cancel context.CancelFunc,
	value Report,
) error {
	ticker := time.NewTicker(s.leaseDuration / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			renewCtx, renewCancel := context.WithTimeout(
				context.WithoutCancel(ctx), s.leaseDuration/3,
			)
			renewed, err := s.repository.Renew(
				renewCtx, value.TaskID, value.ID,
				value.GenerationOwner, value.GenerationFence,
				s.leaseDuration,
			)
			renewCancel()
			if err != nil {
				cancel()
				return fmt.Errorf("renew report generation lease: %w", err)
			}
			if !renewed {
				cancel()
				return ErrReportConflict
			}
		}
	}
}

func (s *Service) Download(
	ctx context.Context,
	taskID string,
	reportID string,
) (Download, error) {
	if err := ctx.Err(); err != nil {
		return Download{}, err
	}
	if !uuidPattern.MatchString(taskID) || !uuidPattern.MatchString(reportID) {
		return Download{}, ErrInvalidInput
	}
	descriptor, err := s.repository.Download(ctx, taskID, reportID)
	if err != nil {
		return Download{}, err
	}
	if descriptor.TaskID != taskID ||
		descriptor.ReportID != reportID ||
		descriptor.Status != "complete" ||
		!sha256Pattern.MatchString(descriptor.SHA256) ||
		descriptor.SizeBytes > math.MaxInt64 ||
		(descriptor.Format != FormatJSON && descriptor.Format != FormatHTML &&
			descriptor.Format != FormatDOCX) {
		return Download{}, ErrArtifactUnavailable
	}
	expectedKey := reportStorageKey(taskID, reportID, descriptor.Format)
	if descriptor.StorageKey != expectedKey {
		return Download{}, ErrArtifactUnavailable
	}

	file, info, err := openRegularRepositoryFile(
		ctx, s.repositoryRoot, descriptor.StorageKey,
	)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return Download{}, contextErr
		}
		return Download{}, fmt.Errorf("%w: %v", ErrArtifactUnavailable, err)
	}
	if uint64(info.Size()) != descriptor.SizeBytes {
		file.Close()
		return Download{}, fmt.Errorf(
			"%w: stored report size does not match metadata",
			ErrArtifactUnavailable,
		)
	}
	actual, err := hashOpenFile(ctx, file)
	if err != nil {
		file.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return Download{}, contextErr
		}
		return Download{}, fmt.Errorf("%w: %v", ErrArtifactUnavailable, err)
	}
	if actual != descriptor.SHA256 {
		file.Close()
		return Download{}, fmt.Errorf(
			"%w: stored report digest does not match metadata",
			ErrArtifactUnavailable,
		)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return Download{}, fmt.Errorf(
			"%w: rewind stored report: %v", ErrArtifactUnavailable, err,
		)
	}
	contentType := "application/json"
	if descriptor.Format == FormatHTML {
		contentType = "text/html; charset=utf-8"
	}
	if descriptor.Format == FormatDOCX {
		contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	}
	return Download{
		Content: file, ContentType: contentType,
		Filename: "binaryscan-" + taskID + "-report." + string(descriptor.Format),
		SHA256:   descriptor.SHA256, SizeBytes: descriptor.SizeBytes,
	}, nil
}

func (s *Service) generateArtifact(
	ctx context.Context,
	value Report,
	generatedAt time.Time,
) (artifact ArtifactMetadata, returnErr error) {
	rootInfo, err := os.Lstat(s.repositoryRoot)
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("inspect repository root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return ArtifactMetadata{}, errors.New(
			"repository root is not a regular directory",
		)
	}
	root, err := os.OpenRoot(s.repositoryRoot)
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("open repository root: %w", err)
	}
	defer root.Close()
	taskDirectory := path.Join("reports", value.TaskID)
	if err := ensureRootDirectory(root, "reports"); err != nil {
		return ArtifactMetadata{}, err
	}
	if err := ensureRootDirectory(root, taskDirectory); err != nil {
		return ArtifactMetadata{}, err
	}

	stagingKey, err := newStagingKey(taskDirectory, value.ID)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	file, err := root.OpenFile(
		stagingKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("create report staging file: %w", err)
	}
	fileOpen := true
	defer func() {
		if fileOpen {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if returnErr != nil {
			if removeErr := root.Remove(stagingKey); removeErr != nil &&
				!errors.Is(removeErr, os.ErrNotExist) {
				returnErr = errors.Join(
					returnErr,
					fmt.Errorf("remove report staging file: %w", removeErr),
				)
			}
		}
	}()

	hasher := sha256.New()
	counter := &byteCounter{}
	writer := io.MultiWriter(file, hasher, counter)
	dependencies := make([]CAnalysisDependency, 0)
	javaDependencies := make([]JavaAnalysisDependency, 0)
	pythonDependencies := make([]PythonAnalysisDependency, 0)
	request := SnapshotRequest{
		TaskID: value.TaskID, ReportID: value.ID, GeneratedAt: generatedAt,
		Dependencies: &dependencies, JavaDependencies: &javaDependencies,
		PythonDependencies: &pythonDependencies,
	}
	switch value.Format {
	case FormatJSON:
		err = s.repository.WriteJSONSnapshot(ctx, request, writer)
	case FormatHTML:
		err = s.repository.WriteHTMLSnapshot(ctx, request, writer)
	case FormatDOCX:
		err = s.repository.WriteDOCXSnapshot(ctx, request, writer)
	default:
		err = ErrInvalidInput
	}
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("write report snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return ArtifactMetadata{}, err
	}
	if err := file.Sync(); err != nil {
		return ArtifactMetadata{}, fmt.Errorf("sync report staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		fileOpen = false
		return ArtifactMetadata{}, fmt.Errorf("close report staging file: %w", err)
	}
	fileOpen = false

	if err := s.repository.AuthorizePublish(
		ctx,
		value.TaskID,
		value.ID,
		value.GenerationOwner,
		value.GenerationFence,
	); err != nil {
		return ArtifactMetadata{}, fmt.Errorf(
			"authorize report artifact publication: %w",
			err,
		)
	}
	finalKey := reportStorageKey(value.TaskID, value.ID, value.Format)
	if info, err := root.Lstat(finalKey); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ArtifactMetadata{}, errors.New(
				"existing report artifact is not a regular file",
			)
		}
		if err := root.Remove(finalKey); err != nil {
			return ArtifactMetadata{}, fmt.Errorf(
				"remove stale report artifact: %w", err,
			)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArtifactMetadata{}, fmt.Errorf(
			"inspect existing report artifact: %w", err,
		)
	}
	directoryFD, err := openRepositoryDirectory(
		s.repositoryRoot, taskDirectory,
	)
	if err != nil {
		return ArtifactMetadata{}, fmt.Errorf(
			"open report artifact directory: %w", err,
		)
	}
	if err := unix.Renameat(
		directoryFD, path.Base(stagingKey),
		directoryFD, path.Base(finalKey),
	); err != nil {
		_ = unix.Close(directoryFD)
		return ArtifactMetadata{}, fmt.Errorf("publish report artifact: %w", err)
	}
	if err := unix.Fsync(directoryFD); err != nil {
		_ = unix.Close(directoryFD)
		_ = root.Remove(finalKey)
		return ArtifactMetadata{}, fmt.Errorf(
			"sync report artifact directory: %w", err,
		)
	}
	if err := unix.Close(directoryFD); err != nil {
		_ = root.Remove(finalKey)
		return ArtifactMetadata{}, fmt.Errorf(
			"close report artifact directory: %w", err,
		)
	}
	return ArtifactMetadata{
		StorageKey:       finalKey,
		SHA256:           hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:        counter.total,
		CompletedAt:      s.now().UTC(),
		Dependencies:     dependencies,
		JavaDependencies: javaDependencies,
	}, nil
}

func (s *Service) persistFailure(
	ctx context.Context,
	value Report,
	generationErr error,
) error {
	errorCode := "report_generation_failed"
	errorMessage := "Report generation failed."
	if errors.Is(generationErr, context.Canceled) ||
		errors.Is(generationErr, context.DeadlineExceeded) {
		errorCode = "report_generation_cancelled"
		errorMessage = "Report generation was cancelled."
	}
	cleanupContext, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), 5*time.Second,
	)
	defer cancel()
	return s.repository.Fail(
		cleanupContext,
		value.TaskID,
		value.ID,
		value.GenerationOwner,
		value.GenerationFence,
		errorCode,
		errorMessage,
		s.now().UTC(),
	)
}

func (s *Service) removeArtifact(storageKey string) error {
	if storageKey == "" {
		return nil
	}
	if !validReportStorageKey(storageKey) {
		return errors.New("unpublished report storage key is invalid")
	}
	root, err := os.OpenRoot(s.repositoryRoot)
	if err != nil {
		return fmt.Errorf("open repository for artifact cleanup: %w", err)
	}
	defer root.Close()
	if err := root.Remove(storageKey); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove unpublished report artifact: %w", err)
	}
	taskDirectory := path.Dir(storageKey)
	if err := root.Remove(taskDirectory); err != nil &&
		!errors.Is(err, os.ErrNotExist) &&
		!errors.Is(err, unix.ENOTEMPTY) &&
		!errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("remove empty report task directory: %w", err)
	}
	return nil
}

func ensureRootDirectory(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(name, 0o700); err != nil &&
			!errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create report directory %q: %w", name, err)
		}
		info, err = root.Lstat(name)
	}
	if err != nil {
		return fmt.Errorf("inspect report directory %q: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("report directory %q is not a regular directory", name)
	}
	return nil
}

func openRegularRepositoryFile(
	ctx context.Context,
	repositoryRoot string,
	storageKey string,
) (*os.File, os.FileInfo, error) {
	if !validReportStorageKey(storageKey) {
		return nil, nil, errors.New("report storage key is invalid")
	}
	components := strings.Split(storageKey, "/")
	directoryFD, err := unix.Open(
		repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open repository root: %w", err)
	}
	for index := 0; index < len(components)-1; index++ {
		if err := ctx.Err(); err != nil {
			_ = unix.Close(directoryFD)
			return nil, nil, err
		}
		nextFD, err := unix.Openat(
			directoryFD,
			components[index],
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeErr := unix.Close(directoryFD)
		if err != nil {
			return nil, nil, fmt.Errorf("open report path directory: %w", err)
		}
		if closeErr != nil {
			_ = unix.Close(nextFD)
			return nil, nil, fmt.Errorf(
				"close report path directory: %w", closeErr,
			)
		}
		directoryFD = nextFD
	}
	fileFD, err := unix.Openat(
		directoryFD,
		components[len(components)-1],
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	closeErr := unix.Close(directoryFD)
	if err != nil {
		return nil, nil, fmt.Errorf("open report artifact: %w", err)
	}
	if closeErr != nil {
		_ = unix.Close(fileFD)
		return nil, nil, fmt.Errorf("close report path directory: %w", closeErr)
	}
	file := os.NewFile(uintptr(fileFD), filepath.Join(repositoryRoot, storageKey))
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, nil, errors.New("wrap report artifact file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect open report artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, errors.New("report artifact is not a regular file")
	}
	return file, info, nil
}

func openRepositoryDirectory(
	repositoryRoot string,
	relativePath string,
) (int, error) {
	if relativePath == "" || path.IsAbs(relativePath) ||
		path.Clean(relativePath) != relativePath {
		return -1, errors.New("repository directory path is invalid")
	}
	directoryFD, err := unix.Open(
		repositoryRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, err
	}
	for _, component := range strings.Split(relativePath, "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(directoryFD)
			return -1, errors.New("repository directory path is invalid")
		}
		nextFD, openErr := unix.Openat(
			directoryFD,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		closeErr := unix.Close(directoryFD)
		if openErr != nil {
			return -1, openErr
		}
		if closeErr != nil {
			_ = unix.Close(nextFD)
			return -1, closeErr
		}
		directoryFD = nextFD
	}
	return directoryFD, nil
}

func hashOpenFile(ctx context.Context, file *os.File) (string, error) {
	hasher := sha256.New()
	buffer := make([]byte, 256<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			_, _ = hasher.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			return hex.EncodeToString(hasher.Sum(nil)), nil
		}
		if readErr != nil {
			return "", fmt.Errorf("hash report artifact: %w", readErr)
		}
		if read == 0 {
			return "", errors.New("hash report artifact made no progress")
		}
	}
}

func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func reportStorageKey(taskID string, reportID string, format Format) string {
	return path.Join(
		"reports", taskID, reportID+"."+string(format),
	)
}

func validReportStorageKey(value string) bool {
	if value == "" || len(value) > 256 || strings.Contains(value, "\\") ||
		path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func newStagingKey(directory string, reportID string) (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate report staging name: %w", err)
	}
	return path.Join(
		directory, "."+reportID+"."+hex.EncodeToString(random[:])+".staging",
	), nil
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" +
		encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

type byteCounter struct {
	total uint64
}

func (w *byteCounter) Write(value []byte) (int, error) {
	w.total += uint64(len(value))
	return len(value), nil
}
