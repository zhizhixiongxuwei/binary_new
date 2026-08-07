package taskevent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"binaryscan/internal/taskprogress"
)

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) List(
	ctx context.Context,
	query Query,
) (events []Event, returnErr error) {
	transaction, err := r.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("begin task event snapshot: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		if err := transaction.Rollback(); err != nil &&
			!errors.Is(err, sql.ErrTxDone) {
			rollbackErr := fmt.Errorf("rollback task event snapshot: %w", err)
			if returnErr == nil {
				events = nil
				returnErr = rollbackErr
				return
			}
			returnErr = errors.Join(returnErr, rollbackErr)
		}
	}()

	var marker uint8
	err = transaction.QueryRowContext(ctx, `
SELECT 1
FROM tasks
WHERE id = ?
LIMIT 1`, query.TaskID).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find task event stream: %w", err)
	}

	rows, err := transaction.QueryContext(ctx, `
SELECT event_sequence, event_type, stage, progress_basis_points,
       severity, message, payload, created_at
FROM task_events
WHERE task_id = ? AND event_sequence > ?
ORDER BY event_sequence ASC
LIMIT ?`, query.TaskID, query.AfterSequence, query.Limit)
	if err != nil {
		return nil, fmt.Errorf("list task events: %w", err)
	}
	defer rows.Close()

	events = make([]Event, 0, query.Limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan task event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate task events: %w", err)
	}
	finished = true
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit task event snapshot: %w", err)
	}
	return events, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanEvent(scanner rowScanner) (Event, error) {
	var event Event
	var stage sql.NullString
	var progress sql.NullInt64
	var message sql.NullString
	var payload []byte
	if err := scanner.Scan(
		&event.Sequence,
		&event.Type,
		&stage,
		&progress,
		&event.Severity,
		&message,
		&payload,
		&event.CreatedAt,
	); err != nil {
		return Event{}, err
	}
	if stage.Valid {
		event.Stage = &stage.String
	}
	if progress.Valid {
		if progress.Int64 < 0 || progress.Int64 > 10_000 {
			return Event{}, errors.New("task event progress is outside database bounds")
		}
		value := float64(progress.Int64) / 100
		event.Progress = &value
		event.ProgressIndeterminate = stage.Valid && taskprogress.IsIndeterminate(
			stage.String,
			uint16(progress.Int64),
		)
	}
	if message.Valid {
		event.Message = &message.String
	}
	event.Payload = payload
	return event, nil
}
