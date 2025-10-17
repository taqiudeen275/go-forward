-- Migration: Add MFA Recovery (Rollback)
-- Description: Remove MFA recovery functionality
-- Created: 2024-01-02T00:00:00Z

-- Drop the MFA recovery table
DROP TABLE IF EXISTS mfa_recovery;

-- Drop the MFA recovery method enum
DROP TYPE IF EXISTS mfa_recovery_method;

-- Restore the original clean_expired_records function
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
END;
$$ LANGUAGE plpgsql;