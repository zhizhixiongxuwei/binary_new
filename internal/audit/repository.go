package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type Recorder interface {
	Record(context.Context, Event) error
}

type Repository interface {
	Recorder
	List(context.Context, RepositoryListQuery) (Page, error)
}

type MySQLRepository struct {
	db *sql.DB
}

func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

func (r *MySQLRepository) Record(ctx context.Context, event Event) error {
	return Append(ctx, r.db, event)
}

// Append is shared with transaction owners that need the audit row and the
// protected state change to commit atomically. This package exposes no update
// or delete operation for audit rows.
func Append(ctx context.Context, executor Executor, event Event) error {
	if executor == nil {
		return errors.New("audit executor is required")
	}
	normalized, metadata, err := normalizeEvent(event)
	if err != nil {
		return err
	}
	_, err = executor.ExecContext(ctx, `
INSERT INTO audit_logs (
    actor_user_id, request_id, action, object_type, object_id, outcome,
    client_ip, user_agent, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalized.ActorUserID,
		nullableString(normalized.RequestID),
		normalized.Action,
		nullableString(normalized.ObjectType),
		nullableString(normalized.ObjectID),
		normalized.Outcome,
		nullableBytes(normalized.ClientIP),
		nullableString(normalized.UserAgent),
		metadata,
	)
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

func (r *MySQLRepository) List(ctx context.Context, query RepositoryListQuery) (Page, error) {
	where := []string{"1 = 1"}
	arguments := make([]any, 0, 8)
	if query.Cursor != 0 {
		where = append(where, "a.id < ?")
		arguments = append(arguments, query.Cursor)
	}
	if query.Action != "" {
		where = append(where, "a.action = ?")
		arguments = append(arguments, query.Action)
	}
	if query.Outcome != "" {
		where = append(where, "a.outcome = ?")
		arguments = append(arguments, query.Outcome)
	}
	if query.Actor != "" {
		where = append(where, `(u.public_id = ? OR u.username LIKE ? ESCAPE '\\' OR u.display_name LIKE ? ESCAPE '\\')`)
		keyword := "%" + escapeLike(query.Actor) + "%"
		arguments = append(arguments, query.Actor, keyword, keyword)
	}
	if query.CreatedFrom != nil {
		where = append(where, "a.created_at >= ?")
		arguments = append(arguments, *query.CreatedFrom)
	}
	if query.CreatedTo != nil {
		where = append(where, "a.created_at <= ?")
		arguments = append(arguments, *query.CreatedTo)
	}
	arguments = append(arguments, query.PageSize+1)

	rows, err := r.db.QueryContext(ctx, `
SELECT a.id, u.public_id, u.username, u.display_name, a.request_id,
       a.action, a.object_type, a.object_id, a.outcome, a.metadata_json,
       a.created_at
FROM audit_logs a
LEFT JOIN users u ON u.id = a.actor_user_id
WHERE `+strings.Join(where, " AND ")+`
ORDER BY a.id DESC
LIMIT ?`, arguments...)
	if err != nil {
		return Page{}, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	items := make([]Log, 0, query.PageSize)
	var continuation uint64
	for rows.Next() {
		var (
			id                            uint64
			actorID, username, display    sql.NullString
			requestID, objectType, object sql.NullString
			action, outcome               string
			metadata                      []byte
			createdAt                     sql.NullTime
		)
		if err := rows.Scan(
			&id, &actorID, &username, &display, &requestID, &action,
			&objectType, &object, &outcome, &metadata, &createdAt,
		); err != nil {
			return Page{}, fmt.Errorf("scan audit log: %w", err)
		}
		if len(items) == query.PageSize {
			continuation = items[len(items)-1].numericID()
			break
		}
		item := Log{
			ID:         strconv.FormatUint(id, 10),
			RequestID:  requestID.String,
			Action:     action,
			ObjectType: objectType.String,
			Outcome:    Outcome(outcome),
			Metadata:   normalizedReadMetadata(metadata),
			CreatedAt:  createdAt.Time.UTC(),
		}
		if object.Valid {
			value := object.String
			item.ObjectID = &value
		}
		if actorID.Valid {
			item.Actor = &Actor{
				ID: actorID.String, Username: username.String,
				DisplayName: display.String,
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("iterate audit logs: %w", err)
	}
	page := Page{Items: items}
	if continuation != 0 {
		page.NextCursor = encodeCursor("audit", continuation)
	}
	return page, nil
}

func (l Log) numericID() uint64 {
	value, _ := strconv.ParseUint(l.ID, 10, 64)
	return value
}

func normalizedReadMetadata(raw []byte) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return json.RawMessage(`{}`)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return json.RawMessage(`{}`)
	}
	cleaned := sanitizeValue(value, 0)
	encoded, err := json.Marshal(cleaned)
	if err != nil || len(encoded) > maxMetadataBytes {
		return json.RawMessage(`{"redacted":true}`)
	}
	return encoded
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(value)
}
