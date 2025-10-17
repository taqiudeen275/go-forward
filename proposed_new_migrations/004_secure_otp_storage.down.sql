-- Rollback migration for OTP security enhancements

BEGIN;

-- Remove security policies
DROP POLICY IF EXISTS otp_user_access ON otp_codes;
DROP POLICY IF EXISTS otp_system_access ON otp_codes;

-- Disable Row Level Security
ALTER TABLE otp_codes DISABLE ROW LEVEL SECURITY;

-- Remove audit trigger
DROP TRIGGER IF EXISTS otp_audit_trigger ON otp_codes;

-- Remove audit function
DROP FUNCTION IF EXISTS audit_otp_operation();

-- Remove index
DROP INDEX IF EXISTS idx_otp_codes_code;

-- Revert code column size (back to VARCHAR(10))
ALTER TABLE otp_codes ALTER COLUMN code TYPE VARCHAR(10);

-- Remove comment
COMMENT ON COLUMN otp_codes.code IS NULL;

COMMIT;