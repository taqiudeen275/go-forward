-- Migration Rollback: Hash Existing Backup Codes
-- Description: Rollback for backup code hashing migration
-- Created: 2024-01-XX
--
-- WARNING: This rollback cannot restore the original unhashed backup codes.
-- The original codes were cleared for security reasons and cannot be recovered.

-- Drop indexes
DROP INDEX IF EXISTS idx_backup_code_migration_notified;
DROP INDEX IF EXISTS idx_backup_code_migration_user_id;

-- Drop the migration log table
DROP TABLE IF EXISTS backup_code_migration_log;

-- Note: We cannot restore the original backup codes as they were cleared for security.
-- Users will need to regenerate their backup codes regardless of migration direction.
-- The backup_codes column remains as an empty array for affected users.
