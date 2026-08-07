-- +goose Up
ALTER TABLE task_events
    ADD INDEX idx_task_events_stage_created (
        stage,
        created_at,
        task_id,
        event_sequence
    );

-- +goose Down
ALTER TABLE task_events
    DROP INDEX idx_task_events_stage_created;
