-- +goose Up

CREATE TABLE IF NOT EXISTS file_node_blob_refs (
    task_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    file_node_id BIGINT UNSIGNED NOT NULL,
    blob_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (file_node_id),
    KEY idx_file_node_blob_refs_task (task_id, file_node_id),
    KEY idx_file_node_blob_refs_blob (blob_id, file_node_id),
    CONSTRAINT fk_file_node_blob_refs_node
        FOREIGN KEY (task_id, file_node_id)
        REFERENCES file_nodes (task_id, id)
        ON DELETE CASCADE,
    CONSTRAINT fk_file_node_blob_refs_blob
        FOREIGN KEY (blob_id)
        REFERENCES blobs (id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- +goose Down

DROP TABLE IF EXISTS file_node_blob_refs;
