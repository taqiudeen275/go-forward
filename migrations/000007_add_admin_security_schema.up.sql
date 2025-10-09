-- Admin Security System Schema Migration
-- This migration creates the foundational tables for the hierarchical admin system

-- Create admin_roles table with hierarchical structure
CREATE TABLE IF NOT EXISTS admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    level INTEGER NOT NULL CHECK (level IN (1, 2, 3, 4)), -- 1=System, 2=Super, 3=Regular, 4=Moderator
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for admin_roles
CREATE INDEX IF NOT EXISTS idx_admin_roles_level ON admin_roles(level);
CREATE INDEX IF NOT EXISTS idx_admin_roles_name ON admin_roles(name);
CREATE INDEX IF NOT EXISTS idx_admin_roles_created_by ON admin_roles(created_by);

-- Create user_admin_roles junction table for role assignments
CREATE TABLE IF NOT EXISTS user_admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    
    -- Ensure unique active role assignment per user
    CONSTRAINT unique_active_user_role UNIQUE (user_id, role_id, is_active) DEFERRABLE INITIALLY DEFERRED
);

-- Create indexes for user_admin_roles
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_user_id ON user_admin_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_role_id ON user_admin_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_granted_by ON user_admin_roles(granted_by);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_active ON user_admin_roles(is_active);
CREATE INDEX IF NOT EXISTS idx_user_admin_roles_expires_at ON user_admin_roles(expires_at);

-- Create admin_capabilities table for granular permissions
CREATE TABLE IF NOT EXISTS admin_capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    capability_name VARCHAR(100) NOT NULL,
    capability_value BOOLEAN DEFAULT FALSE,
    resource_scope JSONB DEFAULT '{}', -- For scoped permissions like assigned tables
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure unique capability per role
    CONSTRAINT unique_role_capability UNIQUE (role_id, capability_name)
);

-- Create indexes for admin_capabilities
CREATE INDEX IF NOT EXISTS idx_admin_capabilities_role_id ON admin_capabilities(role_id);
CREATE INDEX IF NOT EXISTS idx_admin_capabilities_name ON admin_capabilities(capability_name);
CREATE INDEX IF NOT EXISTS idx_admin_capabilities_value ON admin_capabilities(capability_value);
CREATE INDEX IF NOT EXISTS idx_admin_capabilities_scope ON admin_capabilities USING GIN(resource_scope);

-- Create table_configurations table for API security settings
CREATE TABLE IF NOT EXISTS table_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(255) NOT NULL,
    schema_name VARCHAR(255) NOT NULL DEFAULT 'public',
    display_name VARCHAR(255),
    description TEXT,
    
    -- API Security Configuration
    require_auth BOOLEAN DEFAULT TRUE,
    require_verified BOOLEAN DEFAULT FALSE,
    allowed_roles JSONB DEFAULT '[]',
    require_ownership BOOLEAN DEFAULT FALSE,
    ownership_column VARCHAR(255),
    public_read BOOLEAN DEFAULT FALSE,
    public_write BOOLEAN DEFAULT FALSE,
    
    -- Enhanced security features
    require_mfa BOOLEAN DEFAULT FALSE,
    ip_whitelist JSONB DEFAULT '[]',
    rate_limit_config JSONB DEFAULT '{}',
    audit_actions BOOLEAN DEFAULT TRUE,
    
    -- Field-level controls
    readable_fields JSONB DEFAULT '[]',
    writable_fields JSONB DEFAULT '[]',
    hidden_fields JSONB DEFAULT '[]',
    
    -- Advanced filters
    custom_filters JSONB DEFAULT '{}',
    time_based_access JSONB DEFAULT '{}',
    
    -- Metadata
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Ensure unique configuration per table
    CONSTRAINT unique_table_config UNIQUE (table_name, schema_name)
);

-- Create indexes for table_configurations
CREATE INDEX IF NOT EXISTS idx_table_configurations_table_name ON table_configurations(table_name);
CREATE INDEX IF NOT EXISTS idx_table_configurations_schema_name ON table_configurations(schema_name);
CREATE INDEX IF NOT EXISTS idx_table_configurations_active ON table_configurations(is_active);
CREATE INDEX IF NOT EXISTS idx_table_configurations_created_by ON table_configurations(created_by);
CREATE INDEX IF NOT EXISTS idx_table_configurations_updated_by ON table_configurations(updated_by);

-- Create GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_table_configurations_allowed_roles ON table_configurations USING GIN(allowed_roles);
CREATE INDEX IF NOT EXISTS idx_table_configurations_ip_whitelist ON table_configurations USING GIN(ip_whitelist);
CREATE INDEX IF NOT EXISTS idx_table_configurations_rate_limit ON table_configurations USING GIN(rate_limit_config);
CREATE INDEX IF NOT EXISTS idx_table_configurations_readable_fields ON table_configurations USING GIN(readable_fields);
CREATE INDEX IF NOT EXISTS idx_table_configurations_writable_fields ON table_configurations USING GIN(writable_fields);
CREATE INDEX IF NOT EXISTS idx_table_configurations_hidden_fields ON table_configurations USING GIN(hidden_fields);
CREATE INDEX IF NOT EXISTS idx_table_configurations_custom_filters ON table_configurations USING GIN(custom_filters);

-- Create triggers for updated_at columns
CREATE TRIGGER update_admin_roles_updated_at 
    BEFORE UPDATE ON admin_roles 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_admin_capabilities_updated_at 
    BEFORE UPDATE ON admin_capabilities 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_table_configurations_updated_at 
    BEFORE UPDATE ON table_configurations 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin roles
INSERT INTO admin_roles (name, level, description, is_system_role) VALUES
    ('System Admin', 1, 'Full system access including SQL execution and system configuration', TRUE),
    ('Super Admin', 2, 'Business-level administrative capabilities without system access', TRUE),
    ('Regular Admin', 3, 'Limited administrative access to assigned tables and user management', TRUE),
    ('Moderator', 4, 'Read-only access with content moderation capabilities', TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert default capabilities for System Admin role
INSERT INTO admin_capabilities (role_id, capability_name, capability_value)
SELECT 
    r.id,
    capability,
    TRUE
FROM admin_roles r
CROSS JOIN (
    VALUES 
        ('can_access_sql'),
        ('can_manage_database'),
        ('can_manage_system'),
        ('can_create_super_admin'),
        ('can_create_admins'),
        ('can_manage_all_tables'),
        ('can_manage_auth'),
        ('can_manage_storage'),
        ('can_view_all_logs'),
        ('can_manage_users'),
        ('can_manage_content'),
        ('can_view_reports'),
        ('can_moderate_content'),
        ('can_view_basic_logs'),
        ('can_view_dashboard'),
        ('can_export_data')
) AS caps(capability)
WHERE r.name = 'System Admin'
ON CONFLICT (role_id, capability_name) DO NOTHING;

-- Insert default capabilities for Super Admin role
INSERT INTO admin_capabilities (role_id, capability_name, capability_value)
SELECT 
    r.id,
    capability,
    TRUE
FROM admin_roles r
CROSS JOIN (
    VALUES 
        ('can_create_admins'),
        ('can_manage_all_tables'),
        ('can_manage_auth'),
        ('can_manage_storage'),
        ('can_view_all_logs'),
        ('can_manage_users'),
        ('can_manage_content'),
        ('can_view_reports'),
        ('can_moderate_content'),
        ('can_view_basic_logs'),
        ('can_view_dashboard'),
        ('can_export_data')
) AS caps(capability)
WHERE r.name = 'Super Admin'
ON CONFLICT (role_id, capability_name) DO NOTHING;

-- Insert default capabilities for Regular Admin role
INSERT INTO admin_capabilities (role_id, capability_name, capability_value)
SELECT 
    r.id,
    capability,
    TRUE
FROM admin_roles r
CROSS JOIN (
    VALUES 
        ('can_manage_users'),
        ('can_manage_content'),
        ('can_view_reports'),
        ('can_moderate_content'),
        ('can_view_basic_logs'),
        ('can_view_dashboard'),
        ('can_export_data')
) AS caps(capability)
WHERE r.name = 'Regular Admin'
ON CONFLICT (role_id, capability_name) DO NOTHING;

-- Insert default capabilities for Moderator role
INSERT INTO admin_capabilities (role_id, capability_name, capability_value)
SELECT 
    r.id,
    capability,
    TRUE
FROM admin_roles r
CROSS JOIN (
    VALUES 
        ('can_view_reports'),
        ('can_moderate_content'),
        ('can_view_basic_logs'),
        ('can_view_dashboard')
) AS caps(capability)
WHERE r.name = 'Moderator'
ON CONFLICT (role_id, capability_name) DO NOTHING;