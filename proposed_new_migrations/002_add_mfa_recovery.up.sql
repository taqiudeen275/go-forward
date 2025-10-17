-- Migration: Add MFA Recovery
-- Description: Add MFA recovery functionality for account recovery
-- Created: 2024-01-02T00:00:00Z

-- Create MFA recovery method enum
CREATE TYPE mfa_recovery_method AS ENUM ('email', 'sms', 'admin');

-- MFA recovery table
CREATE TABLE mfa_recovery (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recovery_code VARCHAR(255) UNIQUE NOT NULL,
    method mfa_recovery_method NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for MFA recovery
CREATE INDEX idx_mfa_recovery_user_id ON mfa_recovery(user_id);
CREATE INDEX idx_mfa_recovery_code ON mfa_recovery(recovery_code);
CREATE INDEX idx_mfa_recovery_expires_at ON mfa_recovery(expires_at);

-- Row Level Security for MFA recovery
ALTER TABLE mfa_recovery ENABLE ROW LEVEL SECURITY;

-- Users can see their own recovery records
CREATE POLICY mfa_recovery_own ON mfa_recovery
    FOR ALL
    TO public
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Admins can see all recovery records
CREATE POLICY mfa_recovery_admin ON mfa_recovery
    FOR ALL
    TO public
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level IS NOT NULL
        )
    );

-- Update the clean_expired_records function to include MFA recovery
CREATE OR REPLACE FUNCTION clean_expired_records()
RETURNS void AS $$
BEGIN
    -- Clean expired OTP codes
    DELETE FROM otp_codes WHERE expires_at < NOW();
    
    -- Clean expired admin sessions
    DELETE FROM admin_sessions WHERE expires_at < NOW();
    
    -- Clean expired rate limits
    DELETE FROM rate_limits WHERE expires_at < NOW();
    
    -- Clean expired MFA recovery codes
    DELETE FROM mfa_recovery WHERE expires_at < NOW();
    
    -- Clean old audit logs (based on retention policy)
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;