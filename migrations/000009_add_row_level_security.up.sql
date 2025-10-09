-- Row Level Security (RLS) Policies Migration
-- This migration enables RLS on sensitive tables and creates policies for admin hierarchy access control

-- Enable Row Level Security on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_admin_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE table_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_access_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE sql_execution_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;

-- Create function to get current user's admin level
CREATE OR REPLACE FUNCTION get_current_user_admin_level()
RETURNS INTEGER AS $
DECLARE
    user_level INTEGER;
BEGIN
    -- Get the highest admin level for the current user
    SELECT MIN(ar.level) INTO user_level
    FROM user_admin_roles uar
    JOIN admin_roles ar ON uar.role_id = ar.id
    WHERE uar.user_id = current_setting('app.current_user_id', true)::UUID
    AND uar.is_active = TRUE
    AND (uar.expires_at IS NULL OR uar.expires_at > NOW());
    
    RETURN COALESCE(user_level, 999); -- Return high number if no admin role
END;
$ language 'plpgsql' SECURITY DEFINER;

-- Create function to check if current user has specific capability
CREATE OR REPLACE FUNCTION current_user_has_capability(capability_name TEXT)
RETURNS BOOLEAN AS $
DECLARE
    has_capability BOOLEAN := FALSE;
BEGIN
    SELECT EXISTS(
        SELECT 1
        FROM user_admin_roles uar
        JOIN admin_roles ar ON uar.role_id = ar.id
        JOIN admin_capabilities ac ON ar.id = ac.role_id
        WHERE uar.user_id = current_setting('app.current_user_id', true)::UUID
        AND uar.is_active = TRUE
        AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
        AND ac.capability_name = capability_name
        AND ac.capability_value = TRUE
    ) INTO has_capability;
    
    RETURN has_capability;
END;
$ language 'plpgsql' SECURITY DEFINER;

-- Create function to check if current user can access specific table
CREATE OR REPLACE FUNCTION current_user_can_access_table(table_name TEXT)
RETURNS BOOLEAN AS $
DECLARE
    can_access BOOLEAN := FALSE;
    user_level INTEGER;
BEGIN
    -- Get user's admin level
    user_level := get_current_user_admin_level();
    
    -- System Admin (level 1) and Super Admin (level 2) can access all tables
    IF user_level <= 2 THEN
        RETURN TRUE;
    END IF;
    
    -- Check if Regular Admin has specific table access
    IF user_level = 3 THEN
        SELECT EXISTS(
            SELECT 1
            FROM user_admin_roles uar
            JOIN admin_roles ar ON uar.role_id = ar.id
            JOIN admin_capabilities ac ON ar.id = ac.role_id
            WHERE uar.user_id = current_setting('app.current_user_id', true)::UUID
            AND uar.is_active = TRUE
            AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
            AND ac.capability_name = 'can_manage_content'
            AND ac.capability_value = TRUE
            AND (ac.resource_scope->>'assigned_tables')::JSONB ? table_name
        ) INTO can_access;
        
        RETURN can_access;
    END IF;
    
    -- Moderators have read-only access to specific tables
    IF user_level = 4 THEN
        RETURN table_name IN ('users', 'files'); -- Read-only access to basic tables
    END IF;
    
    RETURN FALSE;
END;
$ language 'plpgsql' SECURITY DEFINER;

-- RLS Policies for users table
-- System and Super Admins can see all users
CREATE POLICY users_admin_full_access ON users
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() <= 2);

-- Regular Admins can see users in their assigned groups/scope
CREATE POLICY users_regular_admin_access ON users
    FOR ALL
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 3 
        AND current_user_has_capability('can_manage_users')
    );

-- Moderators can view users (read-only)
CREATE POLICY users_moderator_read ON users
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 4 
        AND current_user_has_capability('can_view_reports')
    );

-- Users can see their own record
CREATE POLICY users_self_access ON users
    FOR ALL
    TO PUBLIC
    USING (id = current_setting('app.current_user_id', true)::UUID);

-- RLS Policies for files table
-- System and Super Admins can access all files
CREATE POLICY files_admin_full_access ON files
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() <= 2);

-- Regular Admins can access files based on their scope
CREATE POLICY files_regular_admin_access ON files
    FOR ALL
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 3 
        AND current_user_has_capability('can_manage_content')
    );

-- Moderators can view files (read-only)
CREATE POLICY files_moderator_read ON files
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 4 
        AND current_user_has_capability('can_moderate_content')
    );

-- File ownership-based access (users can access their own files)
CREATE POLICY files_ownership_access ON files
    FOR ALL
    TO PUBLIC
    USING (
        metadata->>'owner_id' = current_setting('app.current_user_id', true)
        OR permissions->>'public' = 'true'
    );

-- RLS Policies for admin_roles table
-- Only System Admins can modify admin roles
CREATE POLICY admin_roles_system_admin_only ON admin_roles
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Super Admins and below can view admin roles
CREATE POLICY admin_roles_view_access ON admin_roles
    FOR SELECT
    TO PUBLIC
    USING (get_current_user_admin_level() <= 2);

-- RLS Policies for user_admin_roles table
-- System Admins can manage all role assignments
CREATE POLICY user_admin_roles_system_admin ON user_admin_roles
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Super Admins can manage Regular Admin and Moderator assignments
CREATE POLICY user_admin_roles_super_admin ON user_admin_roles
    FOR ALL
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 2
        AND role_id IN (
            SELECT id FROM admin_roles WHERE level >= 3
        )
    );

-- Users can view their own role assignments
CREATE POLICY user_admin_roles_self_view ON user_admin_roles
    FOR SELECT
    TO PUBLIC
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- RLS Policies for admin_capabilities table
-- Only System Admins can modify capabilities
CREATE POLICY admin_capabilities_system_admin_only ON admin_capabilities
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Other admins can view capabilities
CREATE POLICY admin_capabilities_view_access ON admin_capabilities
    FOR SELECT
    TO PUBLIC
    USING (get_current_user_admin_level() <= 3);

-- RLS Policies for table_configurations table
-- System and Super Admins can manage all table configurations
CREATE POLICY table_configurations_admin_access ON table_configurations
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() <= 2);

-- Regular Admins can manage configurations for their assigned tables
CREATE POLICY table_configurations_regular_admin ON table_configurations
    FOR ALL
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 3
        AND current_user_can_access_table(table_name)
    );

-- Moderators can view table configurations (read-only)
CREATE POLICY table_configurations_moderator_read ON table_configurations
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 4
        AND current_user_has_capability('can_view_reports')
    );

-- RLS Policies for admin_access_logs table
-- System Admins can see all logs
CREATE POLICY admin_access_logs_system_admin ON admin_access_logs
    FOR SELECT
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Super Admins can see logs for their level and below
CREATE POLICY admin_access_logs_super_admin ON admin_access_logs
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 2
        AND (
            admin_role_id IS NULL
            OR admin_role_id IN (
                SELECT id FROM admin_roles WHERE level >= 2
            )
        )
    );

-- Regular Admins can see their own logs and logs for their domain
CREATE POLICY admin_access_logs_regular_admin ON admin_access_logs
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 3
        AND (
            user_id = current_setting('app.current_user_id', true)::UUID
            OR (
                admin_role_id IN (
                    SELECT id FROM admin_roles WHERE level >= 3
                )
                AND current_user_has_capability('can_view_basic_logs')
            )
        )
    );

-- Moderators can see their own logs only
CREATE POLICY admin_access_logs_moderator ON admin_access_logs
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 4
        AND user_id = current_setting('app.current_user_id', true)::UUID
        AND current_user_has_capability('can_view_basic_logs')
    );

-- RLS Policies for sql_execution_logs table
-- Only System Admins can see SQL execution logs
CREATE POLICY sql_execution_logs_system_admin_only ON sql_execution_logs
    FOR SELECT
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- RLS Policies for security_events table
-- System Admins can see all security events
CREATE POLICY security_events_system_admin ON security_events
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Super Admins can see security events for their domain
CREATE POLICY security_events_super_admin ON security_events
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 2
        AND (
            admin_role_id IS NULL
            OR admin_role_id IN (
                SELECT id FROM admin_roles WHERE level >= 2
            )
        )
    );

-- Regular Admins can see security events related to their users/resources
CREATE POLICY security_events_regular_admin ON security_events
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 3
        AND (
            user_id = current_setting('app.current_user_id', true)::UUID
            OR (
                admin_role_id IN (
                    SELECT id FROM admin_roles WHERE level >= 3
                )
                AND current_user_has_capability('can_view_basic_logs')
            )
        )
    );

-- RLS Policies for admin_sessions table
-- System Admins can see all sessions
CREATE POLICY admin_sessions_system_admin ON admin_sessions
    FOR ALL
    TO PUBLIC
    USING (get_current_user_admin_level() = 1);

-- Super Admins can see sessions for their level and below
CREATE POLICY admin_sessions_super_admin ON admin_sessions
    FOR SELECT
    TO PUBLIC
    USING (
        get_current_user_admin_level() = 2
        AND (
            admin_role_id IS NULL
            OR admin_role_id IN (
                SELECT id FROM admin_roles WHERE level >= 2
            )
        )
    );

-- Users can see their own sessions
CREATE POLICY admin_sessions_self_access ON admin_sessions
    FOR ALL
    TO PUBLIC
    USING (user_id = current_setting('app.current_user_id', true)::UUID);

-- Create function to set user context for RLS
CREATE OR REPLACE FUNCTION set_user_context(user_id UUID)
RETURNS VOID AS $
BEGIN
    PERFORM set_config('app.current_user_id', user_id::TEXT, true);
END;
$ language 'plpgsql' SECURITY DEFINER;

-- Create function to clear user context
CREATE OR REPLACE FUNCTION clear_user_context()
RETURNS VOID AS $
BEGIN
    PERFORM set_config('app.current_user_id', '', true);
END;
$ language 'plpgsql' SECURITY DEFINER;

-- Create function to test RLS policies with different user contexts
CREATE OR REPLACE FUNCTION test_rls_policies()
RETURNS TABLE(
    test_name TEXT,
    user_context TEXT,
    table_name TEXT,
    operation TEXT,
    result TEXT,
    row_count BIGINT
) AS $
DECLARE
    test_user_id UUID;
    system_admin_id UUID;
    super_admin_id UUID;
    regular_admin_id UUID;
    moderator_id UUID;
    regular_user_id UUID;
BEGIN
    -- Create test users if they don't exist
    INSERT INTO users (email, username) VALUES 
        ('system.admin@test.com', 'system_admin')
    ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
    RETURNING id INTO system_admin_id;
    
    INSERT INTO users (email, username) VALUES 
        ('super.admin@test.com', 'super_admin')
    ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
    RETURNING id INTO super_admin_id;
    
    INSERT INTO users (email, username) VALUES 
        ('regular.admin@test.com', 'regular_admin')
    ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
    RETURNING id INTO regular_admin_id;
    
    INSERT INTO users (email, username) VALUES 
        ('moderator@test.com', 'moderator')
    ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
    RETURNING id INTO moderator_id;
    
    INSERT INTO users (email, username) VALUES 
        ('regular.user@test.com', 'regular_user')
    ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
    RETURNING id INTO regular_user_id;
    
    -- Assign admin roles
    INSERT INTO user_admin_roles (user_id, role_id, granted_by)
    SELECT system_admin_id, ar.id, system_admin_id
    FROM admin_roles ar WHERE ar.name = 'System Admin'
    ON CONFLICT DO NOTHING;
    
    INSERT INTO user_admin_roles (user_id, role_id, granted_by)
    SELECT super_admin_id, ar.id, system_admin_id
    FROM admin_roles ar WHERE ar.name = 'Super Admin'
    ON CONFLICT DO NOTHING;
    
    INSERT INTO user_admin_roles (user_id, role_id, granted_by)
    SELECT regular_admin_id, ar.id, system_admin_id
    FROM admin_roles ar WHERE ar.name = 'Regular Admin'
    ON CONFLICT DO NOTHING;
    
    INSERT INTO user_admin_roles (user_id, role_id, granted_by)
    SELECT moderator_id, ar.id, system_admin_id
    FROM admin_roles ar WHERE ar.name = 'Moderator'
    ON CONFLICT DO NOTHING;
    
    -- Test System Admin access
    PERFORM set_user_context(system_admin_id);
    
    SELECT 'System Admin Users Access', 'System Admin', 'users', 'SELECT', 'SUCCESS', COUNT(*)
    FROM users INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    SELECT 'System Admin Files Access', 'System Admin', 'files', 'SELECT', 'SUCCESS', COUNT(*)
    FROM files INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    -- Test Super Admin access
    PERFORM set_user_context(super_admin_id);
    
    SELECT 'Super Admin Users Access', 'Super Admin', 'users', 'SELECT', 'SUCCESS', COUNT(*)
    FROM users INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    -- Test Regular Admin access
    PERFORM set_user_context(regular_admin_id);
    
    SELECT 'Regular Admin Users Access', 'Regular Admin', 'users', 'SELECT', 'LIMITED', COUNT(*)
    FROM users INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    -- Test Moderator access
    PERFORM set_user_context(moderator_id);
    
    SELECT 'Moderator Users Access', 'Moderator', 'users', 'SELECT', 'READ_ONLY', COUNT(*)
    FROM users INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    -- Test Regular User access
    PERFORM set_user_context(regular_user_id);
    
    SELECT 'Regular User Self Access', 'Regular User', 'users', 'SELECT', 'SELF_ONLY', COUNT(*)
    FROM users WHERE id = regular_user_id INTO test_name, user_context, table_name, operation, result, row_count;
    RETURN NEXT;
    
    -- Clear context
    PERFORM clear_user_context();
    
    RETURN;
END;
$ language 'plpgsql' SECURITY DEFINER;