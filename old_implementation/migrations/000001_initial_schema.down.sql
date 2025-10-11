-- Drop triggers
DROP TRIGGER IF EXISTS update_column_metadata_updated_at ON column_metadata;
DROP TRIGGER IF EXISTS update_table_metadata_updated_at ON table_metadata;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop indexes
DROP INDEX IF EXISTS idx_column_metadata_name;
DROP INDEX IF EXISTS idx_column_metadata_table_id;
DROP INDEX IF EXISTS idx_table_metadata_schema;
DROP INDEX IF EXISTS idx_table_metadata_name;
DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_phone;
DROP INDEX IF EXISTS idx_users_email;

-- Drop tables
DROP TABLE IF EXISTS column_metadata;
DROP TABLE IF EXISTS table_metadata;
DROP TABLE IF EXISTS migrations_metadata;
DROP TABLE IF EXISTS users;

-- Drop functions
DROP FUNCTION IF EXISTS update_updated_at_column();