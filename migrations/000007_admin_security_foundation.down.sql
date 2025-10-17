-- Rollback Admin Security Foundation Migration
-- This migration removes all admin security tables and functions

-- Drop functions first (they depend on tables)
DROP FUNCTION IF EXISTS current_user_id();
DROP FUNCTION IF EXISTS user_has_admin_capability(UUID, VARCHAR, VARCHAR);
DROP FUNCTION IF EXISTS get_user_admin_level(UUID);

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS admin_capabilities;
DROP TABLE IF EXISTS table_security_config;
DROP TABLE IF EXISTS user_admin_roles;
DROP TABLE IF EXISTS admin_roles;

-- Note: We don't need to drop indexes or triggers explicitly
-- as they are automatically dropped when tables are dropped
