-- Drop triggers
DROP TRIGGER IF EXISTS update_files_updated_at ON files;
DROP TRIGGER IF EXISTS update_buckets_updated_at ON buckets;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_file_versions_metadata;
DROP INDEX IF EXISTS idx_file_versions_created_at;
DROP INDEX IF EXISTS idx_file_versions_version;
DROP INDEX IF EXISTS idx_file_versions_file_id;
DROP INDEX IF EXISTS idx_buckets_config;
DROP INDEX IF EXISTS idx_files_permissions;
DROP INDEX IF EXISTS idx_files_metadata;
DROP INDEX IF EXISTS idx_files_size;
DROP INDEX IF EXISTS idx_files_mime_type;
DROP INDEX IF EXISTS idx_files_created_at;
DROP INDEX IF EXISTS idx_files_path;
DROP INDEX IF EXISTS idx_files_bucket;

-- Drop tables (file_versions first, then files, then buckets due to foreign key constraints)
DROP TABLE IF EXISTS file_versions;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS buckets;