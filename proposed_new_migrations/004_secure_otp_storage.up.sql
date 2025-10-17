-- Migration to enhance OTP security by updating storage method
-- This migration updates the OTP code column to reflect that we store hashed codes

BEGIN;

-- Add comment to clarify that code column stores hashed values
COMMENT ON COLUMN otp_codes.code IS 'SHA-256 hashed OTP code for secure storage';

-- Increase code column size to accommodate hash (64 hex characters)
ALTER TABLE otp_codes ALTER COLUMN code TYPE VARCHAR(64);

-- Add index on code column for faster lookups (if not already exists)
CREATE INDEX IF NOT EXISTS idx_otp_codes_code ON otp_codes(code);

-- Add security audit function for OTP operations
CREATE OR REPLACE FUNCTION audit_otp_operation()
RETURNS TRIGGER AS $$
BEGIN
    -- Log OTP creation, usage, and cleanup operations
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (
            id, user_id, action, table_name, record_id, 
            success, metadata, created_at
        ) VALUES (
            uuid_generate_v4(),
            NEW.user_id,
            'otp_created',
            'otp_codes',
            NEW.id::text,
            true,
            jsonb_build_object(
                'purpose', NEW.purpose,
                'email', NEW.email,
                'phone', NEW.phone,
                'expires_at', NEW.expires_at
            ),
            NOW()
        );
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Log when OTP is used or attempts are updated
        IF OLD.used_at IS NULL AND NEW.used_at IS NOT NULL THEN
            INSERT INTO audit_logs (
                id, user_id, action, table_name, record_id,
                success, metadata, created_at
            ) VALUES (
                uuid_generate_v4(),
                NEW.user_id,
                'otp_used',
                'otp_codes',
                NEW.id::text,
                true,
                jsonb_build_object(
                    'purpose', NEW.purpose,
                    'attempts', NEW.attempts,
                    'used_at', NEW.used_at
                ),
                NOW()
            );
        ELSIF OLD.attempts != NEW.attempts THEN
            INSERT INTO audit_logs (
                id, user_id, action, table_name, record_id,
                success, metadata, created_at
            ) VALUES (
                uuid_generate_v4(),
                NEW.user_id,
                'otp_attempt_failed',
                'otp_codes',
                NEW.id::text,
                false,
                jsonb_build_object(
                    'purpose', NEW.purpose,
                    'attempts', NEW.attempts,
                    'max_attempts', NEW.max_attempts
                ),
                NOW()
            );
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_logs (
            id, user_id, action, table_name, record_id,
            success, metadata, created_at
        ) VALUES (
            uuid_generate_v4(),
            OLD.user_id,
            'otp_deleted',
            'otp_codes',
            OLD.id::text,
            true,
            jsonb_build_object(
                'purpose', OLD.purpose,
                'was_used', CASE WHEN OLD.used_at IS NOT NULL THEN true ELSE false END,
                'expired', CASE WHEN OLD.expires_at < NOW() THEN true ELSE false END
            ),
            NOW()
        );
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for OTP audit logging
DROP TRIGGER IF EXISTS otp_audit_trigger ON otp_codes;
CREATE TRIGGER otp_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON otp_codes
    FOR EACH ROW EXECUTE FUNCTION audit_otp_operation();

-- Note: Row Level Security policies can be added later when user roles are properly configured
-- For now, we rely on application-level security

COMMIT;