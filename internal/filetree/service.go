package filetree

import (
	"context"
	"errors"
	"regexp"
)

const MaxPageSize = 200

var uuidPattern = regexp.MustCompile(
	`^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`,
)

type Repository interface {
	List(context.Context, ListQuery) (Page, error)
	Get(context.Context, GetQuery) (Detail, error)
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("file tree repository is required")
	}
	return &Service{repository: repository}, nil
}

func (s *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	if !uuidPattern.MatchString(query.TaskID) ||
		query.PageSize < 1 || query.PageSize > MaxPageSize ||
		(query.ParentID != nil && *query.ParentID == 0) {
		return Page{}, ErrInvalidInput
	}
	page, err := s.repository.List(ctx, query)
	if err != nil {
		return Page{}, err
	}
	if page.Items == nil {
		page.Items = []Node{}
	}
	return page, nil
}

func (s *Service) Get(ctx context.Context, query GetQuery) (Detail, error) {
	if !uuidPattern.MatchString(query.TaskID) || query.FileID == 0 {
		return Detail{}, ErrInvalidInput
	}
	return s.repository.Get(ctx, query)
}
