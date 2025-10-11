-- Rollback Row Level Security (RLS) Policies Migration

-- Drop test function
DROP FUNCTION IF EXISTS test_rls_policies();

-- Drop context management functions
DROP FUNCTION IF EXISTS clear_user_context();
DROP FUNCTION IF EXISTS set_user_context(UUID);

-- Drop all RLS policies
DROP POLICY IF EXISTS admin_sessions_self_access ON admin_sessions;
DROP POLICY IF EXISTS admin_sessions_super_admin ON admin_sessions;
DROP POLICY IF EXISTS admin_sessions_system_admin ON admin_sessions;

DROP POLICY IF EXISTS security_events_regular_admin ON security_events;
DROP POLICY IF EXISTS security_events_super_admin ON security_events;
DROP POLICY IF EXISTS security_events_system_admin ON security_events;

DROP POLICY IF EXISTS sql_execution_logs_system_admin_only ON sql_execution_logs;

DROP POLICY IF EXISTS admin_access_logs_moderator ON admin_access_logs;
DROP POLICY IF EXISTS admin_access_logs_regular_admin ON admin_access_logs;
DROP POLICY IF EXISTS admin_access_logs_super_admin ON admin_access_logs;
DROP POLICY IF EXISTS admin_access_logs_system_admin ON admin_access_logs;

DROP POLICY IF EXISTS table_configurations_moderator_read ON table_configurations;
DROP POLICY IF EXISTS table_configurations_regular_admin ON table_configurations;
DROP POLICY IF EXISTS table_configurations_admin_access ON table_configurations;

DROP POLICY IF EXISTS admin_capabilities_view_access ON admin_capabilities;
DROP POLICY IF EXISTS admin_capabilities_system_admin_only ON admin_capabilities;

DROP POLICY IF EXISTS user_admin_roles_self_view ON user_admin_roles;
DROP POLICY IF EXISTS user_admin_roles_super_admin ON user_admin_roles;
DROP POLICY IF EXISTS user_admin_roles_system_admin ON user_admin_roles;

DROP POLICY IF EXISTS admin_roles_view_access ON admin_roles;
DROP POLICY IF EXISTS admin_roles_system_admin_only ON admin_roles;

DROP POLICY IF EXISTS files_ownership_access ON files;
DROP POLICY IF EXISTS files_moderator_read ON files;
DROP POLICY IF EXISTS files_regular_admin_access ON files;
DROP POLICY IF EXISTS files_admin_full_access ON files;

DROP POLICY IF EXISTS users_self_access ON users;
DROP POLICY IF EXISTS users_moderator_read ON users;
DROP POLICY IF EXISTS users_regular_admin_access ON users;
DROP POLICY IF EXISTS users_admin_full_access ON users;

-- Drop helper functions
DROP FUNCTION IF EXISTS current_user_can_access_table(TEXT);
DROP FUNCTION IF EXISTS current_user_has_capability(TEXT);
DROP FUNCTION IF EXISTS get_current_user_admin_level();

-- Disable Row Level Security on all tables
ALTER TABLE admin_sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE security_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE sql_execution_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE admin_access_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE table_configurations DISABLE ROW LEVEL SECURITY;
ALTER TABLE admin_capabilities DISABLE ROW LEVEL SECURITY;
ALTER TABLE user_admin_roles DISABLE ROW LEVEL SECURITY;
ALTER TABLE admin_roles DISABLE ROW LEVEL SECURITY;
ALTER TABLE files DISABLE ROW LEVEL SECURITY;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;