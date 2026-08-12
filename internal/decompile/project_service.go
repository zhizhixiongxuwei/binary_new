package decompile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"binaryscan/internal/auth"
	"binaryscan/internal/taskcleanup"
)

func (s *Service) ListProjects(
	ctx context.Context,
	query SourceProjectListQuery,
) (SourceProjectPage, error) {
	if err := ctx.Err(); err != nil {
		return SourceProjectPage{}, err
	}
	if !uuidPattern.MatchString(query.TaskID) || query.PageSize < 1 ||
		query.PageSize > MaxPageSize || query.After != nil {
		return SourceProjectPage{}, ErrInvalidInput
	}
	repository, err := s.projectRepository()
	if err != nil {
		return SourceProjectPage{}, err
	}
	repositoryQuery := query
	if query.Cursor != "" {
		cursor, err := decodeSourceProjectCursor(query.Cursor)
		if err != nil {
			return SourceProjectPage{}, ErrInvalidInput
		}
		repositoryQuery.After = &cursor
	}
	page, err := repository.ListSourceProjects(ctx, repositoryQuery)
	if err != nil {
		return SourceProjectPage{}, err
	}
	if page.Items == nil {
		page.Items = []SourceProject{}
	}
	page.NextCursor = ""
	if page.HasMore {
		if len(page.Items) == 0 {
			return SourceProjectPage{}, errors.New(
				"source project repository returned an empty page with more results",
			)
		}
		cursor, err := encodeSourceProjectCursor(page.Items[len(page.Items)-1])
		if err != nil {
			return SourceProjectPage{}, fmt.Errorf("encode source project cursor: %w", err)
		}
		page.NextCursor = cursor
	}
	return page, nil
}

func (s *Service) GetProject(
	ctx context.Context,
	query SourceProjectQuery,
) (SourceProject, error) {
	if err := ctx.Err(); err != nil {
		return SourceProject{}, err
	}
	if !validSourceProjectQuery(query) {
		return SourceProject{}, ErrInvalidInput
	}
	repository, err := s.projectRepository()
	if err != nil {
		return SourceProject{}, err
	}
	record, err := repository.GetSourceProject(ctx, query)
	if err != nil {
		return SourceProject{}, err
	}
	return record.SourceProject, nil
}

func (s *Service) DeleteProject(
	ctx context.Context,
	input DeleteSourceProjectInput,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	query := SourceProjectQuery{TaskID: input.TaskID, ProjectID: input.ProjectID}
	if !validSourceProjectQuery(query) || input.UserID == 0 ||
		(input.Role != auth.RoleAdministrator && input.Role != auth.RoleOperator) {
		return ErrInvalidInput
	}
	return ErrDeletionConfirmationRequired
}

func (s *Service) projectRepository() (sourceProjectRepository, error) {
	repository, ok := s.repository.(sourceProjectRepository)
	if !ok {
		return nil, errors.New("decompile source project repository is unavailable")
	}
	return repository, nil
}

func validSourceProjectQuery(query SourceProjectQuery) bool {
	return uuidPattern.MatchString(query.TaskID) &&
		uuidPattern.MatchString(query.ProjectID)
}

type sourceProjectCursorPayload struct {
	CreatedAt string `json:"created_at"`
	ID        string `json:"id"`
}

func encodeSourceProjectCursor(project SourceProject) (string, error) {
	if project.CreatedAt.IsZero() || !uuidPattern.MatchString(project.ID) {
		return "", errors.New("source project cursor fields are invalid")
	}
	payload := sourceProjectCursorPayload{
		CreatedAt: project.CreatedAt.UTC().Format(time.RFC3339Nano),
		ID:        project.ID,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeSourceProjectCursor(encoded string) (SourceProjectCursor, error) {
	if encoded == "" || len(encoded) > maxListCursorLength {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload sourceProjectCursorPayload
	if err := decoder.Decode(&payload); err != nil {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	createdAt, err := time.Parse(time.RFC3339Nano, payload.CreatedAt)
	if err != nil || payload.CreatedAt != createdAt.UTC().Format(time.RFC3339Nano) ||
		!uuidPattern.MatchString(payload.ID) {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(canonical) != encoded {
		return SourceProjectCursor{}, ErrInvalidInput
	}
	return SourceProjectCursor{CreatedAt: createdAt.UTC(), ID: payload.ID}, nil
}

func (s *Service) removeSourceProjectFiles(
	ctx context.Context,
	taskID string,
	deletion sourceProjectDeletion,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deleter, err := taskcleanup.NewRepositoryFileDeleter(s.repositoryRoot)
	if err != nil {
		return fmt.Errorf("%w: initialize source project deletion: %v", ErrSourceUnavailable, err)
	}

	switch deletion.Project.LayoutVersion {
	case SourceProjectLayoutV1:
		expected := sourceProjectRoot(deletion.Project.ID)
		if deletion.Project.RootStorageKey != expected {
			return fmt.Errorf("%w: source project root does not match its ID", ErrSourceUnavailable)
		}
		if err := deleter.DeleteScope(ctx, taskcleanup.Scope{
			Kind: taskcleanup.FileSourceProject, TaskID: taskID,
			RecordID: deletion.Project.ID,
		}); err != nil {
			return fmt.Errorf("%w: remove source project directory: %v", ErrSourceUnavailable, err)
		}
	case SourceProjectLayoutLegacyV1:
		resultIDs := make(map[string]struct{}, len(deletion.LegacyFiles))
		for _, file := range deletion.LegacyFiles {
			directory, err := legacySourceDirectory(file.StorageKey)
			if err != nil {
				return err
			}
			if directory != path.Join("decompile", file.ResultID) ||
				!uuidPattern.MatchString(file.ResultID) {
				return fmt.Errorf(
					"%w: legacy source path does not match its result",
					ErrSourceUnavailable,
				)
			}
			resultIDs[file.ResultID] = struct{}{}
		}
		for resultID := range resultIDs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := deleter.DeleteScope(ctx, taskcleanup.Scope{
				Kind: taskcleanup.FileDecompile, TaskID: taskID,
				RecordID: resultID,
			}); err != nil {
				return fmt.Errorf("%w: remove legacy source directory: %v", ErrSourceUnavailable, err)
			}
		}
	default:
		return fmt.Errorf("%w: unsupported source project layout", ErrSourceUnavailable)
	}
	return nil
}

func legacySourceDirectory(storageKey string) (string, error) {
	if validateStorageKey(storageKey) != nil {
		return "", fmt.Errorf("%w: invalid legacy source storage key", ErrSourceUnavailable)
	}
	components := strings.Split(storageKey, "/")
	if len(components) != 3 || components[0] != "decompile" ||
		!uuidPattern.MatchString(components[1]) || components[2] == "" {
		return "", fmt.Errorf("%w: unexpected legacy source storage layout", ErrSourceUnavailable)
	}
	return path.Join(components[0], components[1]), nil
}
