-- +goose NO TRANSACTION
-- +goose Up
ALTER TABLE archive_imports
    DROP CHECK chk_archive_imports_root_format,
    ADD CONSTRAINT chk_archive_imports_root_format CHECK (root_format IN (
        'zip', '7z', 'rar', 'tar', 'gzip', 'bzip2', 'xz', 'zstd',
        'cab', 'cpio', 'ar', 'deb', 'rpm', 'iso9660'
    ));

-- +goose Down
ALTER TABLE archive_imports
    DROP CHECK chk_archive_imports_root_format,
    ADD CONSTRAINT chk_archive_imports_root_format CHECK (root_format IN (
        'zip', '7z', 'rar', 'tar', 'gzip', 'bzip2', 'xz', 'zstd',
        'cab', 'cpio', 'ar', 'deb', 'rpm'
    ));
