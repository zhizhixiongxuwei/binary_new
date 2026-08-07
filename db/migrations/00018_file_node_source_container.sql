-- +goose Up

ALTER TABLE file_nodes
    ADD COLUMN source_container_id BIGINT UNSIGNED NULL AFTER parent_id,
    ADD KEY idx_file_nodes_source_container (
        task_id, source_container_id, id
    ),
    ADD CONSTRAINT fk_file_nodes_source_container
        FOREIGN KEY (task_id, source_container_id)
        REFERENCES file_nodes (task_id, id)
        ON DELETE CASCADE;

-- Root samples have no source container. Newly extracted descendants point to
-- the task root or to the concrete archive/image node that produced them.
-- The composite foreign key prevents a source edge from crossing tasks.

-- +goose Down

ALTER TABLE file_nodes
    DROP FOREIGN KEY fk_file_nodes_source_container,
    DROP INDEX idx_file_nodes_source_container,
    DROP COLUMN source_container_id;
