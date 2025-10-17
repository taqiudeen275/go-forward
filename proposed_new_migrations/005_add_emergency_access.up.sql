-- Migration: Add Emergency Access System
-- Description: Create emergency access table for time-limited admin access
-- Created: 2024-01-01T00:00:00Z

-- Emergency access table
CREATE TABLE emergency_access (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    access_token VARCHAR(255) UNIQUE NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    admin_level admin_level NOT NULL,
    ip_restriction INET,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    used_by UUID REFERENCES users(id),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for emergency access
CREATE INDEX idx_emergency_access_token ON emergency_access(access_token);
CREATE INDEX idx_emergency_access_created_by ON emergency_access(created_by);
CREATE INDEX idx_emergency_access_expires_at ON emergency_access(expires_at);
CREATE INDEX idx_emergency_access_active ON emergency_access(expires_at, revoked_at) 
    WHERE revoked_at IS NULL;

-- Row Level Security for emergency access
ALTER TABLE emergency_access ENABLE ROW LEVEL SECURITY;

-- Only system admins can manage emergency access
CREATE POLICY emergency_access_system_admin ON emergency_access
    FOR ALL
    TO public
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level = 'system_admin'
        )
    );

-- Function to clean expired emergency access
CREATE OR REPLACE FUNCTION clean_expired_emergency_access()
RETURNS void AS $$
BEGIN
    -- Clean expired emergency access entries (keep for audit trail but mark as expired)
    UPDATE emergency_access 
    SET revoked_at = NOW(), revoked_by = NULL
    WHERE expires_at < NOW() AND revoked_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Update the main cleanup function to include emergency access
CREATE OR REPLACE FUNCTION clean_expired_records()
RETURNS void AS $$
BEGIN
    -- Clean expired OTP codes
    DELETE FROM otp_codes WHERE expires_at < NOW();
    
    -- Clean expired admin sessions
    DELETE FROM admin_sessions WHERE expires_at < NOW();
    
    -- Clean expired rate limits
    DELETE FROM rate_limits WHERE expires_at < NOW();
    
    -- Clean old audit logs (based on retention policy)
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '90 days';
    
    -- Clean expired emergency access
    PERFORM clean_expired_emergency_access();
END;
$$ LANGUAGE plpgsql;