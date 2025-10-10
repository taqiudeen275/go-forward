-- Table Configuration Versioning and Templates Migration
-- This migration adds support for configuration templates and versioning

-- Create table_configuration_templates table for predefined security templates
CREATE TABLE IF NOT EXISTS table_configuration_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    category VARCHAR(100) NOT NULL,
    config JSONB NOT NULL,
    is_built_in BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for table_configuration_templates
CREATE INDEX IF NOT EXISTS idx_table_config_templates_name ON table_configuration_templates(name);
CREATE INDEX IF NOT EXISTS idx_table_config_templates_category ON table_configuration_templates(category);
CREATE INDEX IF NOT EXISTS idx_table_config_templates_built_in ON table_configuration_templates(is_built_in);
CREATE INDEX IF NOT EXISTS idx_table_config_templates_created_by ON table_configuration_templates(created_by);

-- Create GIN index for config JSONB
CREATE INDEX IF NOT EXISTS idx_table_config_templates_config ON table_configuration_templates USING GIN(config);

-- Create table_configuration_versions table for configuration versioning
CREATE TABLE IF NOT EXISTS table_configuration_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_id UUID NOT NULL REFERENCES table_configurations(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    config JSONB NOT NULL,
    change_reason TEXT,
    changed_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Ensure unique version per configuration
    CONSTRAINT unique_config_version UNIQUE (config_id, version)
);

-- Create indexes for table_configuration_versions
CREATE INDEX IF NOT EXISTS idx_table_config_versions_config_id ON table_configuration_versions(config_id);
CREATE INDEX IF NOT EXISTS idx_table_config_versions_version ON table_configuration_versions(version);
CREATE INDEX IF NOT EXISTS idx_table_config_versions_changed_by ON table_configuration_versions(changed_by);
CREATE INDEX IF NOT EXISTS idx_table_config_versions_created_at ON table_configuration_versions(created_at DESC);

-- Create GIN index for config JSONB
CREATE INDEX IF NOT EXISTS idx_table_config_versions_config ON table_configuration_versions USING GIN(config);

-- Create composite index for common queries
CREATE INDEX IF NOT EXISTS idx_table_config_versions_config_version ON table_configuration_versions(config_id, version DESC);

-- Create trigger for updated_at on templates
CREATE TRIGGER update_table_config_templates_updated_at 
    BEFORE UPDATE ON table_configuration_templates 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Insert built-in configuration templates
INSERT INTO table_configuration_templates (name, description, category, config, is_built_in) VALUES
(
    'Public Read Only',
    'Allow public read access with no authentication required',
    'Basic',
    '{
        "require_auth": false,
        "require_verified": false,
        "allowed_roles": {"roles": []},
        "require_ownership": false,
        "ownership_column": null,
        "public_read": true,
        "public_write": false,
        "require_mfa": false,
        "ip_whitelist": {"ips": []},
        "rate_limit_config": {"config": {"requests_per_minute": 100, "requests_per_hour": 1000, "requests_per_day": 10000, "burst_limit": 10}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": []},
        "hidden_fields": {"fields": []},
        "custom_filters": {"filters": {}},
        "time_based_access": {"config": {}}
    }',
    true
),
(
    'Authenticated Users Only',
    'Require authentication for all access',
    'Basic',
    '{
        "require_auth": true,
        "require_verified": true,
        "allowed_roles": {"roles": []},
        "require_ownership": false,
        "ownership_column": null,
        "public_read": false,
        "public_write": false,
        "require_mfa": false,
        "ip_whitelist": {"ips": []},
        "rate_limit_config": {"config": {"requests_per_minute": 60, "requests_per_hour": 500, "requests_per_day": 5000, "burst_limit": 5}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": []},
        "hidden_fields": {"fields": []},
        "custom_filters": {"filters": {}},
        "time_based_access": {"config": {}}
    }',
    true
),
(
    'Admin Only Access',
    'Restrict access to admin users only',
    'Security',
    '{
        "require_auth": true,
        "require_verified": true,
        "allowed_roles": {"roles": ["System Admin", "Super Admin", "Regular Admin"]},
        "require_ownership": false,
        "ownership_column": null,
        "public_read": false,
        "public_write": false,
        "require_mfa": true,
        "ip_whitelist": {"ips": []},
        "rate_limit_config": {"config": {"requests_per_minute": 30, "requests_per_hour": 200, "requests_per_day": 1000, "burst_limit": 3}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": []},
        "hidden_fields": {"fields": ["password_hash", "secret", "private_key"]},
        "custom_filters": {"filters": {}},
        "time_based_access": {"config": {}}
    }',
    true
),
(
    'User Owned Content',
    'Users can only access their own content',
    'Ownership',
    '{
        "require_auth": true,
        "require_verified": true,
        "allowed_roles": {"roles": []},
        "require_ownership": true,
        "ownership_column": "user_id",
        "public_read": false,
        "public_write": false,
        "require_mfa": false,
        "ip_whitelist": {"ips": []},
        "rate_limit_config": {"config": {"requests_per_minute": 60, "requests_per_hour": 500, "requests_per_day": 5000, "burst_limit": 5}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": []},
        "hidden_fields": {"fields": []},
        "custom_filters": {"filters": {}},
        "time_based_access": {"config": {}}
    }',
    true
),
(
    'High Security',
    'Maximum security with MFA, IP restrictions, and comprehensive auditing',
    'Security',
    '{
        "require_auth": true,
        "require_verified": true,
        "allowed_roles": {"roles": ["System Admin", "Super Admin"]},
        "require_ownership": false,
        "ownership_column": null,
        "public_read": false,
        "public_write": false,
        "require_mfa": true,
        "ip_whitelist": {"ips": ["192.168.1.0/24", "10.0.0.0/8"]},
        "rate_limit_config": {"config": {"requests_per_minute": 10, "requests_per_hour": 50, "requests_per_day": 200, "burst_limit": 2}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": []},
        "hidden_fields": {"fields": ["password_hash", "secret", "private_key", "token", "api_key"]},
        "custom_filters": {"filters": {}},
        "time_based_access": {"config": {"timezone": "UTC", "allowed_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17], "allowed_days": [1, 2, 3, 4, 5], "exceptions": []}}
    }',
    true
),
(
    'Content Moderation',
    'Configuration for content that requires moderation',
    'Content',
    '{
        "require_auth": true,
        "require_verified": true,
        "allowed_roles": {"roles": ["System Admin", "Super Admin", "Regular Admin", "Moderator"]},
        "require_ownership": true,
        "ownership_column": "created_by",
        "public_read": true,
        "public_write": false,
        "require_mfa": false,
        "ip_whitelist": {"ips": []},
        "rate_limit_config": {"config": {"requests_per_minute": 30, "requests_per_hour": 300, "requests_per_day": 2000, "burst_limit": 5}},
        "audit_actions": true,
        "readable_fields": {"fields": []},
        "writable_fields": {"fields": ["title", "content", "tags", "status"]},
        "hidden_fields": {"fields": ["internal_notes", "moderation_flags"]},
        "custom_filters": {"filters": {"status": "published OR status = draft"}},
        "time_based_access": {"config": {}}
    }',
    true
);

-- Create function to apply configuration template
CREATE OR REPLACE FUNCTION apply_configuration_template(
    p_template_id UUID,
    p_table_name VARCHAR(255),
    p_schema_name VARCHAR(255) DEFAULT 'public',
    p_display_name VARCHAR(255) DEFAULT NULL,
    p_description TEXT DEFAULT NULL,
    p_created_by UUID DEFAULT NULL
)
RETURNS UUID AS $
DECLARE
    template_config JSONB;
    new_config_id UUID;
BEGIN
    -- Get template configuration
    SELECT config INTO template_config
    FROM table_configuration_templates
    WHERE id = p_template_id;
    
    IF template_config IS NULL THEN
        RAISE EXCEPTION 'Template not found with id %', p_template_id;
    END IF;
    
    -- Insert new configuration based on template
    INSERT INTO table_configurations (
        table_name, schema_name, display_name, description,
        require_auth, require_verified, allowed_roles, require_ownership, ownership_column,
        public_read, public_write, require_mfa, ip_whitelist, rate_limit_config,
        audit_actions, readable_fields, writable_fields, hidden_fields,
        custom_filters, time_based_access, created_by, is_active
    ) VALUES (
        p_table_name, p_schema_name, p_display_name, p_description,
        (template_config->>'require_auth')::BOOLEAN,
        (template_config->>'require_verified')::BOOLEAN,
        template_config->'allowed_roles',
        (template_config->>'require_ownership')::BOOLEAN,
        NULLIF(template_config->>'ownership_column', 'null'),
        (template_config->>'public_read')::BOOLEAN,
        (template_config->>'public_write')::BOOLEAN,
        (template_config->>'require_mfa')::BOOLEAN,
        template_config->'ip_whitelist',
        template_config->'rate_limit_config',
        (template_config->>'audit_actions')::BOOLEAN,
        template_config->'readable_fields',
        template_config->'writable_fields',
        template_config->'hidden_fields',
        template_config->'custom_filters',
        template_config->'time_based_access',
        p_created_by,
        true
    ) RETURNING id INTO new_config_id;
    
    RETURN new_config_id;
END;
$ language 'plpgsql';

-- Create function to get configuration statistics
CREATE OR REPLACE FUNCTION get_table_configuration_stats()
RETURNS TABLE (
    total_configurations INTEGER,
    active_configurations INTEGER,
    configurations_with_auth INTEGER,
    configurations_with_mfa INTEGER,
    configurations_with_ownership INTEGER,
    public_read_configurations INTEGER,
    public_write_configurations INTEGER,
    configurations_with_rate_limits INTEGER
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_configurations,
        COUNT(*) FILTER (WHERE is_active = TRUE)::INTEGER as active_configurations,
        COUNT(*) FILTER (WHERE require_auth = TRUE)::INTEGER as configurations_with_auth,
        COUNT(*) FILTER (WHERE require_mfa = TRUE)::INTEGER as configurations_with_mfa,
        COUNT(*) FILTER (WHERE require_ownership = TRUE)::INTEGER as configurations_with_ownership,
        COUNT(*) FILTER (WHERE public_read = TRUE)::INTEGER as public_read_configurations,
        COUNT(*) FILTER (WHERE public_write = TRUE)::INTEGER as public_write_configurations,
        COUNT(*) FILTER (WHERE rate_limit_config != '{}')::INTEGER as configurations_with_rate_limits
    FROM table_configurations;
END;
$ language 'plpgsql';

-- Create function to validate configuration conflicts
CREATE OR REPLACE FUNCTION validate_table_configuration_conflicts(
    p_table_name VARCHAR(255),
    p_schema_name VARCHAR(255),
    p_config_id UUID DEFAULT NULL
)
RETURNS TABLE (
    conflict_type VARCHAR(50),
    description TEXT,
    severity VARCHAR(20)
) AS $
BEGIN
    -- Check for duplicate table configurations
    IF EXISTS (
        SELECT 1 FROM table_configurations 
        WHERE table_name = p_table_name 
        AND schema_name = p_schema_name 
        AND is_active = TRUE
        AND (p_config_id IS NULL OR id != p_config_id)
    ) THEN
        RETURN QUERY SELECT 
            'DUPLICATE_TABLE'::VARCHAR(50),
            format('Configuration already exists for table %s.%s', p_schema_name, p_table_name)::TEXT,
            'ERROR'::VARCHAR(20);
    END IF;
    
    -- Add more conflict checks as needed
    RETURN;
END;
$ language 'plpgsql';