-- Migration: Remove Emergency Access System
-- Description: Drop emergency access table and related functions
-- Created: 2024-01-01T00:00:00Z

-- Drop the emergency access table
DROP TABLE IF EXISTS emergency_access CASCADE;

-- Drop the emergency access cleanup function
DROP FUNCTION IF EXISTS clean_expired_emergency_access();

-- Restore the original cleanup function without emergency access
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