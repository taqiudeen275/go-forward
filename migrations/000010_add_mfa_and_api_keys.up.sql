-- MFA and API Keys Schema Migration
-- This migration creates tables for multi-factor authentication and API key management

-- Create mfa_configurations table for user MFA settings
CREATE TABLE IF NOT EXISTS mfa_configurations (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL CHECK (method IN ('totp', 'backup_codes')),
    secret TEXT, -- TOTP secret (encrypted)
    backup_codes JSONB DEFAULT '[]', -- Array of backup codes (hashed)
    is_enabled BOOLEAN DEFAULT FALSE,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for mfa_configurations
CREATE INDEX IF NOT EXISTS idx_mfa_configurations_method ON mfa_configurations(method);
CREATE INDEX IF NOT EXISTS idx_mfa_configurations_enabled ON mfa_configurations(is_enabled);
CREATE INDEX IF NOT EXISTS idx_mfa_configurations_last_used ON mfa_configurations(last_used);

-- Create api_keys table for service authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, -- Hashed API key
    scopes JSONB DEFAULT '[]', -- Array of allowed scopes/permissions
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Create indexes for api_keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_last_used ON api_keys(last_used);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at DESC);

-- Create GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_api_keys_scopes ON api_keys USING GIN(scopes);
CREATE INDEX IF NOT EXISTS idx_api_keys_metadata ON api_keys USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_mfa_configurations_backup_codes ON mfa_configurations USING GIN(backup_codes);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_api_keys_user_active ON api_keys(user_id, is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_active_expires ON api_keys(is_active, expires_at) WHERE is_active = TRUE;

-- Create triggers for updated_at columns
CREATE TRIGGER update_mfa_configurations_updated_at 
    BEFORE UPDATE ON mfa_configurations 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at 
    BEFORE UPDATE ON api_keys 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create function to clean up expired API keys
CREATE OR REPLACE FUNCTION cleanup_expired_api_keys()
RETURNS INTEGER AS $
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE api_keys 
    SET 
        is_active = FALSE,
        updated_at = NOW()
    WHERE 
        is_active = TRUE 
        AND expires_at IS NOT NULL 
        AND expires_at < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$ language 'plpgsql';

-- Create function to validate API key scopes
CREATE OR REPLACE FUNCTION validate_api_key_scopes(scopes JSONB)
RETURNS BOOLEAN AS $
BEGIN
    -- Validate that scopes is an array
    IF jsonb_typeof(scopes) != 'array' THEN
        RETURN FALSE;
    END IF;
    
    -- Validate that all scope values are strings
    IF EXISTS (
        SELECT 1 
        FROM jsonb_array_elements(scopes) AS scope 
        WHERE jsonb_typeof(scope) != 'string'
    ) THEN
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$ language 'plpgsql';

-- Add constraint to validate API key scopes
ALTER TABLE api_keys 
ADD CONSTRAINT check_api_key_scopes 
CHECK (validate_api_key_scopes(scopes));

-- Create function to hash backup codes (placeholder for application-level hashing)
CREATE OR REPLACE FUNCTION hash_backup_codes(codes JSONB)
RETURNS JSONB AS $
BEGIN
    -- In production, backup codes should be hashed at the application level
    -- This function is a placeholder for validation
    RETURN codes;
END;
$ language 'plpgsql';

-- Create function to generate API key statistics
CREATE OR REPLACE FUNCTION get_api_key_stats(p_user_id UUID DEFAULT NULL)
RETURNS TABLE (
    total_keys INTEGER,
    active_keys INTEGER,
    expired_keys INTEGER,
    recently_used INTEGER
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_keys,
        COUNT(*) FILTER (WHERE is_active = TRUE)::INTEGER as active_keys,
        COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW())::INTEGER as expired_keys,
        COUNT(*) FILTER (WHERE last_used IS NOT NULL AND last_used > NOW() - INTERVAL '30 days')::INTEGER as recently_used
    FROM api_keys
    WHERE (p_user_id IS NULL OR user_id = p_user_id);
END;
$ language 'plpgsql';

-- Create function to get MFA statistics
CREATE OR REPLACE FUNCTION get_mfa_stats()
RETURNS TABLE (
    total_users_with_mfa INTEGER,
    totp_enabled INTEGER,
    backup_codes_enabled INTEGER,
    recently_used INTEGER
) AS $
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_users_with_mfa,
        COUNT(*) FILTER (WHERE method = 'totp' AND is_enabled = TRUE)::INTEGER as totp_enabled,
        COUNT(*) FILTER (WHERE method = 'backup_codes' AND is_enabled = TRUE)::INTEGER as backup_codes_enabled,
        COUNT(*) FILTER (WHERE last_used IS NOT NULL AND last_used > NOW() - INTERVAL '30 days')::INTEGER as recently_used
    FROM mfa_configurations
    WHERE is_enabled = TRUE;
END;
$ language 'plpgsql';