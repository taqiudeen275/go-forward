-- Rollback Admin Security System Schema Migration

-- Drop triggers first
DROP TRIGGER IF EXISTS update_table_configurations_updated_at ON table_configurations;
DROP TRIGGER IF EXISTS update_admin_capabilities_updated_at ON admin_capabilities;
DROP TRIGGER IF EXISTS update_admin_roles_updated_at ON admin_roles;

-- Drop indexes
DROP INDEX IF EXISTS idx_table_configurations_custom_filters;
DROP INDEX IF EXISTS idx_table_configurations_writable_fields;
DROP INDEX IF EXISTS idx_table_configurations_readable_fields;
DROP INDEX IF EXISTS idx_table_configurations_hidden_fields;
DROP INDEX IF EXISTS idx_table_configurations_rate_limit;
DROP INDEX IF EXISTS idx_table_configurations_ip_whitelist;
DROP INDEX IF EXISTS idx_table_configurations_allowed_roles;
DROP INDEX IF EXISTS idx_table_configurations_updated_by;
DROP INDEX IF EXISTS idx_table_configurations_created_by;
DROP INDEX IF EXISTS idx_table_configurations_active;
DROP INDEX IF EXISTS idx_table_configurations_schema_name;
DROP INDEX IF EXISTS idx_table_configurations_table_name;

DROP INDEX IF EXISTS idx_admin_capabilities_scope;
DROP INDEX IF EXISTS idx_admin_capabilities_value;
DROP INDEX IF EXISTS idx_admin_capabilities_name;
DROP INDEX IF EXISTS idx_admin_capabilities_role_id;

DROP INDEX IF EXISTS idx_user_admin_roles_expires_at;
DROP INDEX IF EXISTS idx_user_admin_roles_active;
DROP INDEX IF EXISTS idx_user_admin_roles_granted_by;
DROP INDEX IF EXISTS idx_user_admin_roles_role_id;
DROP INDEX IF EXISTS idx_user_admin_roles_user_id;

DROP INDEX IF EXISTS idx_admin_roles_created_by;
DROP INDEX IF EXISTS idx_admin_roles_name;
DROP INDEX IF EXISTS idx_admin_roles_level;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS table_configurations;
DROP TABLE IF EXISTS admin_capabilities;
DROP TABLE IF EXISTS user_admin_roles;
DROP TABLE IF EXISTS admin_roles;