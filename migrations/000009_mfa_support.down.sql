-- Rollback Multi-Factor Authentication Support Migration
-- This migration removes all MFA-related tables and functions

-- Drop trigger first
DROP TRIGGER IF EXISTS auto_enforce_mfa_trigger ON user_admin_roles;

-- Drop views
DROP VIEW IF EXISTS mfa_security_overview;

-- Drop functions
DROP FUNCTION IF EXISTS auto_enforce_mfa_for_admins();
DROP FUNCTION IF EXISTS cleanup_expired_mfa_data();
DROP FUNCTION IF EXISTS is_trusted_device(UUID, VARCHAR);
DROP FUNCTION IF EXISTS log_mfa_attempt(UUID, VARCHAR, VARCHAR, BOOLEAN, VARCHAR, VARCHAR, INET, TEXT);
DROP FUNCTION IF EXISTS user_requires_mfa(UUID);
DROP FUNCTION IF EXISTS user_has_mfa_enabled(UUID);

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS mfa_trusted_devices;
DROP TABLE IF EXISTS mfa_bypass_tokens;
DROP TABLE IF EXISTS mfa_attempts;
DROP TABLE IF EXISTS user_mfa_settings;

-- Note: Indexes and triggers are automatically dropped with their tables
