-- Migration: Hash Existing Backup Codes
-- Description: Updates existing backup codes to use bcrypt hashing for security
-- Created: 2024-01-XX
--
-- Note: This migration will invalidate existing backup codes.
-- Users with MFA enabled should regenerate their backup codes after this migration.

-- Create a table to track users who need to regenerate backup codes
CREATE TABLE IF NOT EXISTS backup_code_migration_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    had_backup_codes BOOLEAN DEFAULT FALSE,
    backup_codes_count INTEGER DEFAULT 0,
    migrated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    notified BOOLEAN DEFAULT FALSE
);

-- Log all users who currently have backup codes
INSERT INTO backup_code_migration_log (user_id, had_backup_codes, backup_codes_count)
SELECT
    id,
    TRUE,
    COALESCE(array_length(backup_codes, 1), 0)
FROM users
WHERE backup_codes IS NOT NULL
  AND array_length(backup_codes, 1) > 0
  AND mfa_enabled = TRUE;

-- Clear existing unhashed backup codes
-- Users will need to regenerate them through the application
UPDATE users
SET
    backup_codes = '{}',
    updated_at = NOW()
WHERE backup_codes IS NOT NULL
  AND array_length(backup_codes, 1) > 0
  AND mfa_enabled = TRUE;

-- Create index for migration log
CREATE INDEX idx_backup_code_migration_user_id ON backup_code_migration_log(user_id);
CREATE INDEX idx_backup_code_migration_notified ON backup_code_migration_log(notified) WHERE notified = FALSE;

-- Add comment to document the migration
COMMENT ON TABLE backup_code_migration_log IS 'Tracks users who had backup codes cleared during security upgrade and need to regenerate them';

-- Note: After running this migration, administrators should:
-- 1. Notify affected users via email/notification system
-- 2. Prompt users to regenerate backup codes on next MFA login
-- 3. Consider adding a banner in the admin dashboard about this security update
