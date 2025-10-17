-- Admin Security Foundation Migration
-- This migration creates the core admin role hierarchy and table security configuration

-- Create admin roles table with hierarchy support
CREATE TABLE IF NOT EXISTS admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL, -- 'system_admin', 'super_admin', 'admin', 'moderator'
    level INTEGER NOT NULL, -- Hierarchy level (1=system_admin, 4=moderator)
    description TEXT,
    permissions JSONB DEFAULT '{}', -- Role-specific permissions
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create user admin role assignments table
CREATE TABLE IF NOT EXISTS user_admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES admin_roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional role expiration
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, role_id, is_active) DEFERRABLE INITIALLY DEFERRED
);

-- Create table security configuration
CREATE TABLE IF NOT EXISTS table_security_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(255) NOT NULL,
    schema_name VARCHAR(255) NOT NULL DEFAULT 'public',
    auth_required BOOLEAN DEFAULT TRUE,
    ownership_column VARCHAR(255), -- Column that determines ownership (e.g., 'user_id')
    allowed_roles TEXT[], -- Roles allowed to access this table
    api_permissions JSONB DEFAULT '{}', -- Per-role API permissions
    custom_filters JSONB DEFAULT '{}', -- Custom SQL filters per role
    rate_limit_config JSONB DEFAULT '{}', -- Rate limiting configuration
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(table_name, schema_name)
);

-- Create admin capabilities table for granular permissions
CREATE TABLE IF NOT EXISTS admin_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID REFERENCES admin_roles(id) ON DELETE CASCADE,
    capability VARCHAR(100) NOT NULL, -- 'sql_execute', 'user_create', 'table_config', etc.
    resource_pattern VARCHAR(255), -- Pattern for resource matching (e.g., 'table:users', 'system:*')
    permissions JSONB DEFAULT '{}', -- Specific permissions for this capability
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_admin_roles_name ON admin_roles(name);
CREATE INDEX IF NOT EXISTS idx_admin_roles_level ON admin_roles(level);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_user_id ON user_admin_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_role_id ON user_admin_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_active ON user_admin_roles(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_table_security_config_table ON table_security_config(table_name, schema_name);
CREATE INDEX IF NOT EXISTS idx_admin_capabilities_role ON admin_capabilities(role_id, capability);

-- Create triggers for updated_at columns
CREATE TRIGGER update_admin_roles_updated_at
    BEFORE UPDATE ON admin_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_admin_roles_updated_at
    BEFORE UPDATE ON user_admin_roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_table_security_config_updated_at
    BEFORE UPDATE ON table_security_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_capabilities_updated_at
    BEFORE UPDATE ON admin_capabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin roles
INSERT INTO admin_roles (name, level, description, permissions) VALUES
('system_admin', 1, 'Full system access including SQL execution and system configuration',
 '{"sql_execute": true, "system_config": true, "admin_management": true, "user_management": true, "table_config": true}'),
('super_admin', 2, 'Business-level administration without system access',
 '{"user_management": true, "table_config": true, "storage_management": true, "analytics": true}'),
('admin', 3, 'Limited administrative access to assigned tables and user management',
 '{"user_management": "scoped", "table_config": "assigned", "basic_analytics": true}'),
('moderator', 4, 'Read-only access with content moderation capabilities',
 '{"read_only": true, "content_moderation": true, "basic_reports": true}');

-- Insert default table security configurations for core tables
INSERT INTO table_security_config (table_name, schema_name, auth_required, ownership_column, allowed_roles, api_permissions) VALUES
('users', 'public', true, 'id',
 ARRAY['system_admin', 'super_admin', 'admin'],
 '{"system_admin": {"read": true, "write": true, "delete": true}, "super_admin": {"read": true, "write": true, "delete": false}, "admin": {"read": "scoped", "write": "scoped", "delete": false}}'),

('user_admin_roles', 'public', true, 'user_id',
 ARRAY['system_admin', 'super_admin'],
 '{"system_admin": {"read": true, "write": true, "delete": true}, "super_admin": {"read": true, "write": false, "delete": false}}'),

('admin_roles', 'public', true, null,
 ARRAY['system_admin'],
 '{"system_admin": {"read": true, "write": true, "delete": true}}'),

('table_security_config', 'public', true, null,
 ARRAY['system_admin', 'super_admin'],
 '{"system_admin": {"read": true, "write": true, "delete": true}, "super_admin": {"read": true, "write": true, "delete": false}}');

-- Create function to get user's highest admin role level
CREATE OR REPLACE FUNCTION get_user_admin_level(p_user_id UUID)
RETURNS INTEGER AS $$
DECLARE
    min_level INTEGER;
BEGIN
    SELECT MIN(ar.level) INTO min_level
    FROM user_admin_roles uar
    JOIN admin_roles ar ON uar.role_id = ar.id
    WHERE uar.user_id = p_user_id
    AND uar.is_active = TRUE
    AND ar.is_active = TRUE
    AND (uar.expires_at IS NULL OR uar.expires_at > NOW());

    RETURN COALESCE(min_level, 999); -- Return high number if no admin role
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create function to check if user has admin capability
CREATE OR REPLACE FUNCTION user_has_admin_capability(p_user_id UUID, p_capability VARCHAR, p_resource VARCHAR DEFAULT NULL)
RETURNS BOOLEAN AS $$
DECLARE
    has_capability BOOLEAN := FALSE;
BEGIN
    SELECT EXISTS(
        SELECT 1
        FROM user_admin_roles uar
        JOIN admin_roles ar ON uar.role_id = ar.id
        JOIN admin_capabilities ac ON ac.role_id = ar.id
        WHERE uar.user_id = p_user_id
        AND uar.is_active = TRUE
        AND ar.is_active = TRUE
        AND ac.is_active = TRUE
        AND ac.capability = p_capability
        AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
        AND (p_resource IS NULL OR ac.resource_pattern = '*' OR p_resource LIKE ac.resource_pattern)
    ) INTO has_capability;

    RETURN has_capability;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create function to get current user ID (to be set by application context)
CREATE OR REPLACE FUNCTION current_user_id()
RETURNS UUID AS $$
BEGIN
    -- This will be set by the application using set_config
    RETURN COALESCE(current_setting('app.current_user_id', true)::UUID, NULL);
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- Grant necessary permissions for the authenticated role (application user)
-- Note: This assumes your application connects with a role named 'authenticated'
-- Adjust the role name based on your actual database setup
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON admin_roles TO authenticated;
        GRANT SELECT, INSERT, UPDATE, DELETE ON user_admin_roles TO authenticated;
        GRANT SELECT, INSERT, UPDATE, DELETE ON table_security_config TO authenticated;
        GRANT SELECT, INSERT, UPDATE, DELETE ON admin_capabilities TO authenticated;
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO authenticated;
    END IF;
END $$;

-- Add comments for documentation
COMMENT ON TABLE admin_roles IS 'Administrative roles with hierarchical levels';
COMMENT ON TABLE user_admin_roles IS 'User assignments to administrative roles';
COMMENT ON TABLE table_security_config IS 'Security configuration for database tables';
COMMENT ON TABLE admin_capabilities IS 'Granular capabilities for admin roles';
COMMENT ON FUNCTION get_user_admin_level(UUID) IS 'Returns the highest admin level for a user (lowest number)';
COMMENT ON FUNCTION user_has_admin_capability(UUID, VARCHAR, VARCHAR) IS 'Checks if user has a specific admin capability';
COMMENT ON FUNCTION current_user_id() IS 'Returns the current application user ID from session context';
